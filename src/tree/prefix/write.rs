// src/tree/prefix/write.rs
use super::entry::CachedLogEntry; // Import struct
use crate::proto::prefix_tree::{LeafNode, LogEntry};
use crate::tree::prefix::{PrefixTree, SearchResult, StepResult};
use anyhow::Result;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl PrefixTree {
    pub async fn batch_insert(
        &self,
        start_version: u64,
        current_root_ptr: Option<u64>,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(Vec<Vec<u8>>, Vec<SearchResult>, u64)> {
        let mut current_ptr = current_root_ptr;
        let mut db_batch = Vec::new();
        let mut roots = Vec::new();
        let mut search_results = Vec::new();
        let mut overlay: HashMap<u64, Arc<CachedLogEntry>> = HashMap::new();
        let mut new_cache_entries: Vec<(u64, Arc<CachedLogEntry>)> =
            Vec::with_capacity(entries.len() * 2);

        self.debug_hash_ops.store(0, Ordering::Relaxed);
        self.debug_steps.store(0, Ordering::Relaxed);

        for (i, (index, commitment)) in entries.iter().enumerate() {
            let alloc_version = start_version + i as u64;
            let (root, search_res, (pos, data), cached_obj) = self
                .insert_internal(alloc_version, current_ptr, index, commitment, &overlay)
                .await?;

            db_batch.push((pos, data));
            overlay.insert(pos, cached_obj.clone());

            // Push the fully constructed CachedLogEntry (with hashes!) to global cache
            new_cache_entries.push((pos, cached_obj));

            roots.push(root);
            search_results.push(search_res);

            current_ptr = Some(pos);
        }

        self.store.put_prefix_batch(db_batch)?;

        for (k, v) in new_cache_entries {
            self.node_cache.insert(k, v);
        }

        // ... debug log code ...
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let hashes = self.debug_hash_ops.load(Ordering::Relaxed);
        let steps = self.debug_steps.load(Ordering::Relaxed);
        let total = hits + misses;
        if total > 0 {
            let rate = (hits as f64 / total as f64) * 100.0;
            println!(
                "   🧠 Cache Stats: Hits: {} | Misses: {} | Rate: {:.1}% | HashOps: {} | Steps: {}",
                hits, misses, rate, hashes, steps
            );
        }

        Ok((roots, search_results, current_ptr.unwrap_or(0)))
    }

    pub(crate) async fn insert_internal(
        &self,
        new_pos: u64,
        current_ptr: Option<u64>,
        index: &[u8],
        commitment: &[u8],
        overlay: &HashMap<u64, Arc<CachedLogEntry>>,
    ) -> Result<(Vec<u8>, SearchResult, (u64, Vec<u8>), Arc<CachedLogEntry>)> {
        let mut copath = Vec::new();
        let mut current_ctr = 0;

        if let Some(ptr) = current_ptr {
            let mut curr = ptr;
            loop {
                // Returns Arc<CachedLogEntry> with populated hash cache!
                let entry = self.get_entry(curr, overlay)?;

                match self.step(index, curr, &mut copath, &entry) {
                    StepResult::Found(final_entry) => {
                        let leaf = final_entry.inner.leaf.as_ref().unwrap();
                        current_ctr = leaf.ctr + 1;
                        copath = final_entry.inner.copath.clone();
                        break;
                    }
                    StepResult::Continue(next_ptr) => {
                        curr = next_ptr;
                    }
                    StepResult::Failed(failed_copath, _) => {
                        copath = failed_copath;
                        break;
                    }
                }
            }
        }

        let new_entry = LogEntry {
            index: index.to_vec(),
            copath: copath.clone(),
            first_update_position: new_pos,
            leaf: Some(LeafNode {
                ctr: current_ctr,
                commitment: commitment.to_vec(),
            }),
            precomputed32: vec![],
        };

        let mut buf = Vec::new();
        new_entry.encode(&mut buf)?;

        // Create cache entry immediately
        let cached_new = Arc::new(CachedLogEntry::new(Arc::new(new_entry), &self.aes_key));

        // This rollup will populate the parents cache for the first time
        let root = cached_new.rollup(0, Some(&self.debug_hash_ops));

        let search_result = SearchResult {
            log_position: new_pos,
            commitment: commitment.to_vec(),
            inclusion_proof: copath.iter().map(|n| n.hash.clone()).collect(),
            counter: current_ctr,
            depth: copath.len() as u32,
        };

        Ok((root, search_result, (new_pos, buf), cached_new))
    }
}
// End src/tree/prefix/write.rs
