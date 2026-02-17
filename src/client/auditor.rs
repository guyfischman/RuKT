use tonic::transport::Channel;
use crate::proto::kt::key_transparency_service_client::KeyTransparencyServiceClient;
use crate::proto::kt::{AuditRequest};
use crate::proto::transparency::{AuditorTreeHead}; 
use crate::client::verifier::{LogAccumulator, PrefixTransitioner};
use crate::crypto::{self, ServiceSigningKey, sign_data, PublicConfig};
use anyhow::{Result, anyhow, Context};

pub struct KtAuditor {
    client: KeyTransparencyServiceClient<Channel>,
    signer: ServiceSigningKey,
    pub log_accumulator: LogAccumulator,
    pub prefix_root: Vec<u8>,
    pub last_timestamp: u64,
    pub config: PublicConfig,
}

impl KtAuditor {
    pub async fn connect(
        dst: String, 
        signer: ServiceSigningKey, 
        config: PublicConfig
    ) -> Result<Self> {
        let client = KeyTransparencyServiceClient::connect(dst).await?;
        Ok(Self {
            client,
            signer,
            log_accumulator: LogAccumulator::new(),
            prefix_root: vec![0u8; 32],
            last_timestamp: 0,
            config,
        })
    }

    pub async fn process_and_sign(&mut self) -> Result<()> {
        let start = self.log_accumulator.tree_size;
        let req = AuditRequest {
            start,
            limit: 10,
        };
        
        let resp = self.client.clone().audit(req).await?.into_inner();
        
        if resp.updates.is_empty() {
            return Ok(());
        }

        for update in resp.updates {
            if update.timestamp < self.last_timestamp {
                return Err(anyhow!("Time regression detected"));
            }
            
            let proof = update.proof.ok_or(anyhow!("Missing prefix proof"))?;
            
            let new_prefix_root = PrefixTransitioner::verify_and_transition(
                &self.prefix_root,
                &update.added,
                &update.removed,
                &proof
            ).context("Prefix tree transition verification failed")?;

            let leaf_hash = crate::crypto::hash::log_leaf_value(update.timestamp, &new_prefix_root);
            self.log_accumulator.append_leaf_naive(leaf_hash);
            
            self.prefix_root = new_prefix_root;
            self.last_timestamp = update.timestamp;
        }

        let new_log_root = self.log_accumulator.calculate_root_naive()?;
        let tree_size = self.log_accumulator.tree_size;

        let auditor_pk = self.signer.verifying_key().to_bytes();
        
        let tbs = crypto::construct_auditor_tree_head_tbs_public(
            &self.config, 
            &auditor_pk,
            tree_size,
            self.last_timestamp,
            &new_log_root
        )?;
        
        let sig = sign_data(&self.signer, &tbs);
        
        let ath = AuditorTreeHead {
            tree_size,
            timestamp: self.last_timestamp as i64,
            signature: sig,
        };
        
        self.client.clone().set_auditor_head(ath).await?;
        
        Ok(())
    }
}