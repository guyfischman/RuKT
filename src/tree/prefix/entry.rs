// src/tree/prefix/entry.rs
use super::hasher::*;
use crate::proto::prefix_tree::{LogEntry, ParentNode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[derive(Debug)]
pub struct CachedLogEntry {
    pub inner: Arc<LogEntry>,
    parents: Vec<OnceLock<Vec<u8>>>,
}

impl CachedLogEntry {
    pub fn new(inner: Arc<LogEntry>) -> Self {
        // Leaf rollups start at the full index depth, so size for it up front:
        // OnceLock slots can't grow later.
        let levels = if inner.leaf.is_some() {
            8 * INDEX_LENGTH
        } else {
            inner.copath.len()
        } + 1;
        Self {
            inner,
            parents: (0..levels).map(|_| OnceLock::new()).collect(),
        }
    }

    // Weighed as if fully rolled up, since `parents` fills lazily after insertion.
    pub fn max_resident_bytes(&self) -> usize {
        const HASH: usize = 32 + size_of::<Vec<u8>>();
        self.parents.len() * (HASH + size_of::<OnceLock<Vec<u8>>>())
            + self.inner.copath.len() * (size_of::<ParentNode>() + HASH)
            + self.inner.index.len()
            + size_of::<Self>()
    }

    pub fn stand_in(&self, _level: usize) -> Vec<u8> {
        ZERO_VALUE.to_vec()
    }

    pub fn rollup(&self, level: usize, hash_counter: Option<&AtomicU64>) -> Vec<u8> {
        let mut curr;
        let mut acc;

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

        while curr > level {
            curr -= 1;

            if let Some(val) = self.parents[curr].get() {
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

            // Racing initializers compute the same deterministic hash; the loser's
            // set is a no-op.
            let _ = self.parents[curr].set(acc.clone());
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
