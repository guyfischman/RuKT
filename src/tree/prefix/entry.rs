// src/tree/prefix/entry.rs
use super::hasher::*;
use crate::proto::prefix_tree::{LogEntry, ParentNode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct CachedLogEntry {
    pub inner: Arc<LogEntry>,
    pub seed: Vec<u8>,
    pub parents: RwLock<Vec<Option<Vec<u8>>>>,
}

impl CachedLogEntry {
    pub fn new(inner: Arc<LogEntry>, aes_key: &[u8]) -> Self {
        let depth = inner.copath.len();
        let seed = compute_seed(aes_key, inner.first_update_position);
        Self {
            inner,
            seed,
            parents: RwLock::new(vec![None; depth + 1]),
        }
    }

    pub fn get_seed(&self) -> &[u8] {
        &self.seed
    }

    // Weighed as if fully rolled up, since `parents` fills lazily after insertion.
    pub fn max_resident_bytes(&self) -> usize {
        const HASH: usize = 32 + size_of::<Vec<u8>>();
        let levels = 8 * INDEX_LENGTH + 1;
        levels * (HASH + size_of::<Option<Vec<u8>>>())
            + self.inner.copath.len() * (size_of::<ParentNode>() + HASH)
            + self.inner.index.len()
            + self.seed.len()
            + size_of::<Self>()
    }

    pub fn stand_in(&self, _level: usize) -> Vec<u8> {
        ZERO_VALUE.to_vec()
    }

    pub fn rollup(&self, level: usize, hash_counter: Option<&AtomicU64>) -> Vec<u8> {
        let mut curr;
        let mut acc;

        // OPTIMIZATION: Acquire Write Lock ONCE for the whole loop
        let mut parents_guard = self.parents.write().unwrap();

        if let Some(leaf) = &self.inner.leaf {
            curr = 8 * INDEX_LENGTH;
            if let Some(c) = hash_counter {
                c.fetch_add(1, Ordering::Relaxed);
            }
            acc = leaf_hash(&self.inner.index, &leaf.commitment);
        } else {
            curr = self.inner.copath.len();
            acc = self.stand_in(curr);
        }

        if parents_guard.len() <= curr {
            parents_guard.resize(curr + 1, None);
        }

        while curr > level {
            curr -= 1;

            // Access cache via the held lock
            if let Some(val) = &parents_guard[curr] {
                acc = val.clone();
                continue;
            }

            if let Some(c) = hash_counter {
                c.fetch_add(1, Ordering::Relaxed);
            }

            let sibling_hash = if curr < self.inner.copath.len() {
                self.inner.copath[curr].hash.clone()
            } else {
                self.stand_in(curr + 1)
            };

            if get_bit(&self.inner.index, curr) == 1 {
                acc = parent_hash(&sibling_hash, &acc);
            } else {
                acc = parent_hash(&acc, &sibling_hash);
            }

            // Write to cache via the held lock
            parents_guard[curr] = Some(acc.clone());
        }

        acc
    }
}

pub fn combine_copaths(primary: Vec<ParentNode>, secondary: Vec<ParentNode>) -> Vec<ParentNode> {
    if secondary.len() <= primary.len() {
        return primary;
    }
    let mut out = primary;
    out.extend_from_slice(&secondary[out.len()..]);
    out
}
