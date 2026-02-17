use crate::proto::prefix_tree::LogEntry;
use crate::tree::prefix::{StepResult, PrefixTree};
use super::hasher::compute_seed;
use super::entry::CachedLogEntry;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use prost::Message;

impl PrefixTree {
    pub async fn log_entries(&self, start: u64, end: u64) -> Result<(Vec<LogEntry>, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let mut logs = Vec::new();
        let mut seeds = Vec::new();
        let mut prev_seeds = Vec::new();

        let ids: Vec<u64> = (start..end).collect();
        // Optimize retrieval by batch fetching from RocksDB
        let raw_batch = self.store.batch_get_prefix(&ids)?;
        
        let mut map = HashMap::new();
        for (k, v) in raw_batch {
            map.insert(k, v);
        }

        for id in start..end {
            let raw = map.get(&id).ok_or_else(|| anyhow!("Missing log entry {}", id))?;
            let entry = LogEntry::decode(&raw[..])?;
            
            let seed = compute_seed(&self.aes_key, entry.first_update_position);
            seeds.push(seed);
            
            let mut prev_seed = vec![];
            
            if id > 0 {
                // Determine if we need the previous seed for audit proofs
                let needs_prev = (entry.leaf.is_none() && !entry.copath.is_empty()) || 
                                 (entry.leaf.as_ref().map(|l| l.ctr == 0).unwrap_or(false));
                
                if needs_prev {
                    let mut search_idx = vec![0u8; 32];
                    let len = std::cmp::min(entry.index.len(), 32);
                    search_idx[0..len].copy_from_slice(&entry.index[0..len]);

                    // Look back in the tree to find where this key (or its prefix) was last modified/diverged
                    let res = self.search_for_prev_seed(id - 1, &search_idx).await?;
                    prev_seed = compute_seed(&self.aes_key, res);
                } else if entry.leaf.is_none() && entry.copath.is_empty() {
                    // Start of a new epoch or tree
                    prev_seed = compute_seed(&self.aes_key, id - 1);
                }
            }
            
            prev_seeds.push(prev_seed);
            logs.push(entry);
        }

        Ok((logs, seeds, prev_seeds))
    }

    /// Helper to find the log position of the previous version of a key (or where it would have been).
    async fn search_for_prev_seed(&self, tree_size: u64, index: &[u8]) -> Result<u64> {
        let mut ptr = tree_size;
        let mut copath = Vec::new();
        let overlay = HashMap::new();

        loop {
            let raw_entry = self.get_entry_bytes(ptr, &overlay)?;
            let entry = LogEntry::decode(&raw_entry[..])?;
            let cached = CachedLogEntry::new(entry, self.aes_key.clone());

            match self.step(index, ptr, &mut copath, &cached) {
                StepResult::Found(_) => {
                    // Found the exact key in the past
                    return Ok(0); // 0 acts as a sentinel here for "found exact match", logic handled in caller/hasher usually
                },
                StepResult::Continue(next_ptr) => {
                    ptr = next_ptr;
                },
                StepResult::Failed(_, pos) => {
                    // Stopped at a diversion or missing node, return that position
                    return Ok(pos);
                }
            }
        }
    }
}