use super::{Tree, PreUpdateData, PostUpdateData};
use crate::db::AuditorTreeHead;
use crate::proto::transparency::{
    AuditorUpdate, AuditorTreeHead as PbAuditorTreeHead,
};
use crate::crypto::{verify_data, construct_auditor_tree_head_tbs, ServiceVerifyingKey};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use prost::Message;

impl Tree {
    pub async fn audit(&self, start: u64, limit: u64) -> Result<(Vec<AuditorUpdate>, bool)> {
        let current_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);

        if start > current_size { return Err(anyhow!("Auditing cannot start past end of tree")); }
        if start == current_size { return Ok((vec![], false)); }
        
        let mut end = start + limit;
        if end > current_size { end = current_size; }
        
        let mut updates = Vec::new();
        
        // Retrieve pre-computed blobs stored during write path
        for i in start..end {
            if let Some(blob) = self.store.get_audit_blob(i)? {
                let update = AuditorUpdate::decode(&blob[..])?;
                updates.push(update);
            } else {
                return Err(anyhow!("Missing audit blob for log index {}", i));
            }
        }
        
        Ok((updates, end < current_size))
    }

    pub async fn set_auditor_head(&mut self, head: PbAuditorTreeHead, auditor_keys: &HashMap<Vec<u8>, ServiceVerifyingKey>) -> Result<()> {
        let current_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);

        // Defense 1: Future State Attack
        if head.tree_size > current_size {
            return Err(anyhow!("Auditor tree head is ahead of service tree head"));
        }

        let root_hash = self.log.get_root(head.tree_size)?;

        let mut verified = false;
        let mut matched_auditor_name = String::new();

        for (auditor_pk_bytes, key) in auditor_keys {
            let tbs_data = construct_auditor_tree_head_tbs(
                &self.config,
                auditor_pk_bytes,
                head.tree_size,
                head.timestamp as u64,
                &root_hash
            )?;

            if verify_data(key, &tbs_data, &head.signature).is_ok() {
                verified = true;
                matched_auditor_name = hex::encode(auditor_pk_bytes);
                break;
            }
        }

        if !verified {
            return Err(anyhow!("Failed to verify auditor signature"));
        }
        
        // Defense 2: Rewind Attack (Check against stored state)
        if let Some(existing) = self.auditors.get(&matched_auditor_name) {
            if head.tree_size < existing.tree_size {
                return Err(anyhow!("Auditor tree size regression: {} < {}", head.tree_size, existing.tree_size));
            }
            if head.timestamp < existing.timestamp {
                return Err(anyhow!("Auditor timestamp regression: {} < {}", head.timestamp, existing.timestamp));
            }
        }

        let mut consistency = Vec::new();
        // If the auditor is catching up (not just re-signing current head), fetch consistency proof
        if head.tree_size < current_size {
             consistency = self.log.get_consistency_proof(head.tree_size, current_size)?;
        }

        self.auditors.insert(matched_auditor_name, AuditorTreeHead {
            tree_size: head.tree_size,
            timestamp: head.timestamp,
            signature: head.signature,
            root_value: root_hash,
            consistency,
        });

        Ok(())
    }
}