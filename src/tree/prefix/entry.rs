use crate::proto::prefix_tree::{LogEntry, ParentNode};
use super::hasher::*;
use std::cell::RefCell;

#[derive(Debug)]
pub struct CachedLogEntry {
    pub inner: LogEntry,
    aes_key: Vec<u8>,
    seed: RefCell<Option<Vec<u8>>>,
    // Cache technically unnecessary for constant zeros, but kept for structural compatibility
    stand_ins: RefCell<[Option<Vec<u8>>; 256]>,
    parents: RefCell<[Option<Vec<u8>>; 256]>,
}

impl CachedLogEntry {
    pub fn new(inner: LogEntry, aes_key: Vec<u8>) -> Self {
        Self {
            inner,
            aes_key,
            seed: RefCell::new(None),
            stand_ins: RefCell::new([const { None }; 256]),
            parents: RefCell::new([const { None }; 256]),
        }
    }

    pub fn get_seed(&self) -> Vec<u8> {
        let mut seed_ref = self.seed.borrow_mut();
        if let Some(s) = &*seed_ref {
            return s.clone();
        }
        let s = compute_seed(&self.aes_key, self.inner.first_update_position);
        *seed_ref = Some(s.clone());
        s
    }

    pub fn stand_in(&self, _level: usize) -> Vec<u8> {
        // IETF Draft-03 Section 10.9:
        // "If one of the children does not exist, an all-zero byte string of length Hash.Nh is used instead."
        ZERO_VALUE.to_vec()
    }

    pub fn rollup(&self, level: usize) -> Vec<u8> {
        let mut curr;
        let mut acc;

        if let Some(leaf) = &self.inner.leaf {
            curr = 8 * INDEX_LENGTH; // 256
            // Section 10.9 Leaf Hash
            acc = leaf_hash(&self.inner.index, &leaf.commitment);
        } else {
            curr = self.inner.copath.len();
            acc = self.stand_in(curr);
        }

        while curr > level {
            curr -= 1;

            {
                let parents = self.parents.borrow();
                if let Some(val) = &parents[curr] {
                    acc = val.clone();
                    continue;
                }
            }

            let sibling_hash = if curr < self.inner.copath.len() {
                self.inner.copath[curr].hash.clone()
            } else {
                self.stand_in(curr + 1)
            };

            // Draft 10.9: Parent hash is Hash(0x02 || left || right)
            if get_bit(&self.inner.index, curr) == 1 {
                // Sibling is Left, Acc is Right
                acc = parent_hash(&sibling_hash, &acc);
            } else {
                // Acc is Left, Sibling is Right
                acc = parent_hash(&acc, &sibling_hash);
            }

            self.parents.borrow_mut()[curr] = Some(acc.clone());
        }

        acc
    }
}

pub fn combine_copaths(primary: Vec<ParentNode>, secondary: Vec<ParentNode>) -> Vec<ParentNode> {
    if secondary.len() <= primary.len() {
        return primary;
    }
    let mut out = primary;
    for i in out.len()..secondary.len() {
        out.push(secondary[i].clone());
    }
    out
}