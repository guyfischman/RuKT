use super::entry::CachedLogEntry;
use super::hasher::compute_seed;
use crate::proto::prefix_tree::LogEntry;
use crate::tree::prefix::{PrefixTree, StepResult};
use anyhow::{Result, anyhow};
use prost::Message;
use std::collections::HashMap;

impl PrefixTree {
    pub async fn log_entries(
        &self,
        start: u64,
        end: u64,
    ) -> Result<(Vec<LogEntry>, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let mut logs = Vec::new();
        let mut seeds = Vec::new();
        let mut prev_seeds = Vec::new();

        // Note: For bulk auditing, we currently hit RocksDB directly for throughput on cold data.
        // If auditing hot data, we could route this through the cache, but direct DB batching
        // is often preferred for linear scans.
        let ids: Vec<u64> = (start..end).collect();
        let raw_batch = self.store.batch_get_prefix(&ids)?;

        let mut map = HashMap::new();
        for (k, v) in raw_batch {
            map.insert(k, v);
        }

        for id in start..end {
            let raw = map
                .get(&id)
                .ok_or_else(|| anyhow!("Missing log entry {}", id))?;
            let entry = LogEntry::decode(&raw[..])?;

            let seed = compute_seed(&self.aes_key, entry.first_update_position);
            seeds.push(seed);

            let mut prev_seed = vec![];

            if id > 0 {
                let needs_prev = (entry.leaf.is_none() && !entry.copath.is_empty())
                    || (entry.leaf.as_ref().map(|l| l.ctr == 0).unwrap_or(false));

                if needs_prev {
                    let mut search_idx = vec![0u8; 32];
                    let len = std::cmp::min(entry.index.len(), 32);
                    search_idx[0..len].copy_from_slice(&entry.index[0..len]);

                    let res = self.search_for_prev_seed(id - 1, &search_idx).await?;
                    prev_seed = compute_seed(&self.aes_key, res);
                } else if entry.leaf.is_none() && entry.copath.is_empty() {
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
            // FIXED: Returns Arc<CachedLogEntry>
            let entry = self.get_entry(ptr, &overlay)?;

            match self.step(index, ptr, &mut copath, &entry) {
                StepResult::Found(_) => {
                    return Ok(0);
                }
                StepResult::Continue(next_ptr) => {
                    ptr = next_ptr;
                }
                StepResult::Failed(_, pos) => {
                    return Ok(pos);
                }
            }
        }
    }
}
