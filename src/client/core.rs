use tonic::transport::Channel;
use crate::proto::kt::key_transparency_service_client::KeyTransparencyServiceClient;
use crate::proto::transparency::{
    TreeSearchRequest, UpdateRequest, SignedUpdateRequest, 
    MonitorRequest, MonitorLabel, Consistency,
    TreeHead, UpdateResponse, TreeSearchResponse, MonitorResponse
};
use crate::crypto::{self, ServiceVerifyingKey, construct_tree_head_tbs, verify_data, construct_vrf_input};
use crate::client::verifier::{LogVerifier, PrefixVerifier, CommitmentVerifier};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct TrustedState {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub timestamp: u64,
}

pub struct KtClient {
    client: KeyTransparencyServiceClient<Channel>,
    sig_pk: ServiceVerifyingKey,
    vrf_pk: Vec<u8>,
    pub state: Option<TrustedState>,
    config: crate::crypto::PrivateConfig,
}

impl KtClient {
    pub async fn connect(dst: String, sig_pk: ServiceVerifyingKey, vrf_pk: Vec<u8>) -> Result<Self> {
        let client = KeyTransparencyServiceClient::connect(dst).await?;
        
        // Construct dummy config for client usage (mostly for verifying structs)
        let config = crate::crypto::PrivateConfig::new(
            crate::crypto::CIPHER_SUITE_KT_128_SHA256_ED25519,
            1, 
            crypto::generate_sig_keypair().0, 
            vec![0u8; 32],
            HashMap::new(),
            0,0,0,None,None,100
        )?;

        Ok(Self {
            client,
            sig_pk,
            vrf_pk,
            state: None,
            config,
        })
    }

    pub async fn update(&mut self, user: Vec<u8>, value: Vec<u8>) -> Result<UpdateResponse> {
        let req = UpdateRequest {
            search_key: user.clone(),
            value: value.clone(),
            consistency: self.get_consistency_req(),
            expected_pre_update_value: vec![],
            return_update_response: true,
        };

        let signed_req = SignedUpdateRequest {
            request: Some(req),
            signature: vec![],
        };

        let resp = self.client.clone().update(signed_req).await?.into_inner();
        
        self.verify_update_response(&user, &value, &resp).await?;
        
        Ok(resp)
    }

    pub async fn search(&mut self, user: Vec<u8>, version: Option<u32>) -> Result<TreeSearchResponse> {
        let req = TreeSearchRequest {
            search_key: user.clone(),
            consistency: self.get_consistency_req(),
            version,
        };

        let resp = self.client.clone().search(req).await?.into_inner();
        
        self.verify_search_response(&user, &resp).await?;
        
        Ok(resp)
    }

    pub async fn monitor(&mut self, user: Vec<u8>, position: u64, version: u32) -> Result<MonitorResponse> {
        let req = MonitorRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            labels: vec![MonitorLabel {
                label: user.clone(),
                entries: vec![crate::proto::transparency::MonitorMapEntry {
                    position,
                    version,
                }],
                rightmost: None,
            }],
            consistency: self.get_consistency_req(),
        };

        let resp = self.client.clone().monitor(req).await?.into_inner();
        
        self.verify_monitor_response(&resp).await?;

        Ok(resp)
    }

    // --- Helpers ---

    fn get_consistency_req(&self) -> Option<Consistency> {
        self.state.as_ref().map(|s| Consistency {
            last: Some(s.tree_size),
            distinguished: None,
        })
    }

    async fn verify_update_response(&mut self, label: &[u8], value: &[u8], resp: &UpdateResponse) -> Result<()> {
        let proof = resp.search.as_ref().ok_or(anyhow!("Missing search proof"))?;
        
        let ladder = &resp.binary_ladder;
        if ladder.is_empty() { return Err(anyhow!("Empty binary ladder")); }
        
        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        let th = fth.tree_head.as_ref().ok_or(anyhow!("Missing TreeHead"))?;

        if th.tree_size == 0 {
            return Err(anyhow!("Tree size is 0"));
        }

        let vrf_output = crypto::ecvrf_verify(
            crypto::CIPHER_SUITE_KT_128_SHA256_ED25519, 
            &self.vrf_pk, 
            &construct_vrf_input(label, th.tree_size as u32 - 1).unwrap_or(vec![]), 
            &ladder[0].proof
        ).context("VRF verification failed")?;

        let comm = ladder[0].commitment.as_ref().ok_or(anyhow!("Missing commitment"))?;
        CommitmentVerifier::verify(label, value, &resp.opening, comm)?;

        if proof.prefix_proofs.is_empty() { return Err(anyhow!("Missing prefix proof")); }
        
        // Update state
        self.state = Some(TrustedState {
            tree_size: th.tree_size,
            root_hash: vec![0u8; 32], 
            timestamp: th.timestamp as u64,
        });
        
        Ok(())
    }

    async fn verify_search_response(&mut self, label: &[u8], resp: &TreeSearchResponse) -> Result<()> {
        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        
        if let Some(th) = &fth.tree_head {
            if let Some(state) = &self.state {
                if th.tree_size < state.tree_size {
                    return Err(anyhow!("Server rolled back tree size"));
                }
            }
            
            // Basic update of trusted state if newer
            if self.state.is_none() || th.tree_size > self.state.as_ref().unwrap().tree_size {
                 self.state = Some(TrustedState {
                    tree_size: th.tree_size,
                    root_hash: vec![0u8; 32], // Todo: verify sig to get root
                    timestamp: th.timestamp as u64,
                });
            }
        }
        
        Ok(())
    }
    
    async fn verify_monitor_response(&mut self, resp: &MonitorResponse) -> Result<()> {
        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        
        // 1. Verify Tree Head State
        if let Some(th) = &fth.tree_head {
            if let Some(state) = &self.state {
                if th.tree_size < state.tree_size {
                    return Err(anyhow!("Server rolled back tree size in Monitor response"));
                }
            }
             // Update state if newer
             if self.state.is_none() || th.tree_size > self.state.as_ref().unwrap().tree_size {
                 self.state = Some(TrustedState {
                    tree_size: th.tree_size,
                    root_hash: vec![0u8; 32], 
                    timestamp: th.timestamp as u64,
                });
            }
        }

        // 2. Verify CombinedTreeProof structure (Draft Section 11.3)
        if let Some(monitor_proof) = &resp.monitor {
            // Verify timestamps monotonicity
            let mut prev_ts = 0;
            for &ts in &monitor_proof.timestamps {
                if ts < prev_ts {
                    return Err(anyhow!("Monitor timestamps are not monotonic"));
                }
                prev_ts = ts;
            }

            // Must have inclusion proof for consistency
            if monitor_proof.inclusion.is_none() {
                return Err(anyhow!("Missing inclusion proof in monitor response"));
            }
        } else {
             return Err(anyhow!("Missing monitor proof"));
        }

        Ok(())
    }
}