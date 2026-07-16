// src/tree/prefix/read.rs
use super::entry::CachedLogEntry;
use super::hasher;
use crate::proto::prefix_tree::{LogEntry, ParentNode};
use crate::tree::prefix::{PrefixTree, StepResult};
use anyhow::{Result, anyhow};
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Clone)]
pub struct SearchResult {
    pub log_position: u64,
    pub commitment: Vec<u8>,
    pub inclusion_proof: Vec<Vec<u8>>,
    pub counter: u32,
    pub depth: u32,
}

pub struct ProofResult {
    pub inclusion_proof: Vec<Vec<u8>>,
    pub commitment: Option<Vec<u8>>,
    pub result_type: u32,
    pub leaf_vrf_output: Option<Vec<u8>>,
    pub leaf_commitment: Option<Vec<u8>>,
    pub depth: u32,
}

impl PrefixTree {
    // CHANGED: Return Arc<CachedLogEntry>
    pub(crate) fn get_entry(
        &self,
        ptr: u64,
        overlay: &HashMap<u64, Vec<u8>>,
    ) -> Result<Arc<CachedLogEntry>> {
        // 1. Overlay (Construct fresh cache entry, don't store in global cache yet)
        if let Some(val) = overlay.get(&ptr) {
            let entry = LogEntry::decode(&val[..])?;
            let cached = CachedLogEntry::new(Arc::new(entry), &self.aes_key);
            return Ok(Arc::new(cached));
        }

        // 2. DashMap (Fast Path)
        if let Some(entry) = self.node_cache.get(&ptr) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(entry.clone());
        }

        self.misses.fetch_add(1, Ordering::Relaxed);

        // 3. RocksDB
        let bytes = self
            .store
            .get_prefix(ptr)?
            .ok_or_else(|| anyhow!("Missing prefix entry {}", ptr))?;
        let entry = Arc::new(LogEntry::decode(&bytes[..])?);

        // 4. Populate Cache
        let cached = Arc::new(CachedLogEntry::new(entry, &self.aes_key));
        self.node_cache.insert(ptr, cached.clone());

        Ok(cached)
    }

    pub(crate) fn step(
        &self,
        target_index: &[u8],
        current_ptr: u64,
        current_copath: &mut Vec<ParentNode>,
        cached_entry: &Arc<CachedLogEntry>, // Take Arc
    ) -> StepResult {
        self.debug_steps.fetch_add(1, Ordering::Relaxed);

        let entry = &cached_entry.inner;

        if entry.leaf.is_some() && entry.index == target_index {
            let merged_copath =
                super::entry::combine_copaths(current_copath.clone(), entry.copath.clone());
            let mut result_entry_struct = (**entry).clone();
            result_entry_struct.copath = merged_copath;
            // Create a new Cached wrapper for the result (this is rare, only on match)
            return StepResult::Found(Arc::new(CachedLogEntry::new(
                Arc::new(result_entry_struct),
                &self.aes_key,
            )));
        }

        loop {
            if current_copath.len() < entry.copath.len() {
                let depth = current_copath.len();
                let parent = &entry.copath[depth];

                if hasher::get_bit(&entry.index, depth) == hasher::get_bit(target_index, depth) {
                    current_copath.push(parent.clone());
                } else {
                    let hash = cached_entry.rollup(depth + 1, Some(&self.debug_hash_ops));
                    let node = ParentNode {
                        hash,
                        ptr: Some(current_ptr),
                        first_update_position: parent.first_update_position,
                    };
                    current_copath.push(node);

                    if let Some(next_ptr) = parent.ptr {
                        return StepResult::Continue(next_ptr);
                    } else {
                        return StepResult::Failed(
                            current_copath.clone(),
                            parent.first_update_position.unwrap_or(0),
                        );
                    }
                }
            } else if entry.leaf.is_none() {
                return StepResult::Failed(current_copath.clone(), entry.first_update_position);
            } else {
                let depth = current_copath.len();
                if hasher::get_bit(&entry.index, depth) == hasher::get_bit(target_index, depth) {
                    let hash = cached_entry.stand_in(depth + 1);
                    current_copath.push(ParentNode {
                        hash,
                        ptr: None,
                        first_update_position: Some(entry.first_update_position),
                    });
                } else {
                    let hash = cached_entry.rollup(depth + 1, Some(&self.debug_hash_ops));
                    current_copath.push(ParentNode {
                        hash,
                        ptr: Some(current_ptr),
                        first_update_position: Some(entry.first_update_position),
                    });
                    return StepResult::Failed(current_copath.clone(), entry.first_update_position);
                }
            }
        }
    }

    // ... search / search_for_proof ...
    // NOTE: Just remove `CachedLogEntry::new` calls inside loops in `search` and `search_for_proof`
    // `let entry = self.get_entry(...)` now returns exactly what `step` needs.
    pub async fn search(&self, ptr: u64, index: &[u8]) -> Result<Option<SearchResult>> {
        let mut curr = ptr;
        let mut copath = Vec::new();
        let overlay = HashMap::new();

        loop {
            let entry = self.get_entry(curr, &overlay)?;
            match self.step(index, curr, &mut copath, &entry) {
                StepResult::Found(final_entry) => {
                    let leaf = final_entry.inner.leaf.as_ref().unwrap();
                    let depth = final_entry.inner.copath.len() as u32;
                    return Ok(Some(SearchResult {
                        log_position: curr,
                        commitment: leaf.commitment.clone(),
                        inclusion_proof: final_entry
                            .inner
                            .copath
                            .iter()
                            .map(|n| n.hash.clone())
                            .collect(),
                        counter: leaf.ctr,
                        depth,
                    }));
                }
                StepResult::Continue(next_ptr) => {
                    curr = next_ptr;
                }
                StepResult::Failed(_, _) => {
                    return Ok(None);
                }
            }
        }
    }

    pub async fn search_for_proof(
        &self,
        ptr: u64,
        index: &[u8],
        overlay: &HashMap<u64, Vec<u8>>,
    ) -> Result<ProofResult> {
        let mut curr = ptr;
        let mut copath = Vec::new();
        loop {
            let entry = self.get_entry(curr, overlay)?;
            match self.step(index, curr, &mut copath, &entry) {
                StepResult::Found(final_entry) => {
                    let leaf = final_entry.inner.leaf.as_ref().unwrap();
                    return Ok(ProofResult {
                        inclusion_proof: final_entry
                            .inner
                            .copath
                            .iter()
                            .map(|n| n.hash.clone())
                            .collect(),
                        commitment: Some(leaf.commitment.clone()),
                        result_type: 1,
                        leaf_vrf_output: None,
                        leaf_commitment: None,
                        depth: final_entry.inner.copath.len() as u32,
                    });
                }
                StepResult::Continue(next_ptr) => {
                    curr = next_ptr;
                }
                StepResult::Failed(failed_copath, _) => {
                    let result_type;
                    let mut l_vrf = None;
                    let mut l_comm = None;
                    if let Some(l) = &entry.inner.leaf {
                        result_type = 2;
                        l_vrf = Some(entry.inner.index.clone());
                        l_comm = Some(l.commitment.clone());
                    } else {
                        result_type = 3;
                    }
                    return Ok(ProofResult {
                        inclusion_proof: failed_copath.iter().map(|n| n.hash.clone()).collect(),
                        commitment: None,
                        result_type,
                        leaf_vrf_output: l_vrf,
                        leaf_commitment: l_comm,
                        depth: failed_copath.len() as u32,
                    });
                }
            }
        }
    }

    pub async fn multi_search(
        &self,
        ptr: u64,
        keys: &[Vec<u8>],
    ) -> Result<Vec<Option<SearchResult>>> {
        let mut results = Vec::new();
        for k in keys {
            results.push(self.search(ptr, k).await?);
        }
        Ok(results)
    }
}
// End src/tree/prefix/read.rs
