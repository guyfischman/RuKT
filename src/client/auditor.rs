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
            // §15.2 step 1
            if update.timestamp < self.last_timestamp {
                return Err(anyhow!("Time regression detected"));
            }

            // §15.2 step 2
            for list in [&update.added, &update.removed] {
                for pair in list.windows(2) {
                    if pair[0].vrf_output >= pair[1].vrf_output {
                        return Err(anyhow!("Audit leaves are not sorted ascending without duplicates"));
                    }
                }
            }

            let proof = update.proof.ok_or(anyhow!("Missing prefix proof"))?;
            if proof.results.len() != update.added.len() + update.removed.len() {
                return Err(anyhow!("Audit proof result count mismatch"));
            }

            // §15.2 steps 3-4
            let removed_keys: std::collections::HashSet<&[u8]> =
                update.removed.iter().map(|l| l.vrf_output.as_slice()).collect();
            for (i, leaf) in update.added.iter().enumerate() {
                if !removed_keys.contains(leaf.vrf_output.as_slice())
                    && proof.results[i].result_type == 1
                {
                    return Err(anyhow!("Added leaf has an inclusion result but is not being removed"));
                }
            }
            for (i, _) in update.removed.iter().enumerate() {
                if proof.results[update.added.len() + i].result_type != 1 {
                    return Err(anyhow!("Removed leaf lacks an inclusion result"));
                }
            }
            // TODO: step 5 (removed leaves published in a distinguished entry) once removals are used

            // §15.2 steps 6-7
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

        let tbs = crypto::construct_auditor_tree_head_tbs_public(
            &self.config,
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