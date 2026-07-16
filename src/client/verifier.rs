// Start src/client/verifier.rs
use anyhow::{Result, anyhow, Context};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use std::collections::{BTreeMap, HashSet};
use crate::crypto::hash::{log_leaf_value, log_parent_value};
use crate::crypto::tls::TlsEncode;
use crate::proto::transparency::{PrefixProof, PrefixSearchResult, PrefixLeaf};

pub struct LogVerifier;

impl LogVerifier {
    pub fn calculate_root(
        node_indices: &[u64],
        node_hashes: &[Vec<u8>],
        tree_size: u64,
        proof_elements: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        Ok(Self::calculate_root_with_retained(
            node_indices, node_hashes, tree_size, proof_elements, &BTreeMap::new(),
        )?.0)
    }

    /// Folds provided leaves, proof elements, and retained full-subtree values into
    /// the root, returning it plus the full-subtree values of the new tree (§4.2).
    /// Using retained values where the server omitted them is what proves the new
    /// head extends the previously verified one.
    pub fn calculate_root_with_retained(
        node_indices: &[u64],
        node_hashes: &[Vec<u8>],
        tree_size: u64,
        proof_elements: &[Vec<u8>],
        retained: &BTreeMap<u64, Vec<u8>>,
    ) -> Result<(Vec<u8>, BTreeMap<u64, Vec<u8>>)> {
        if node_indices.len() != node_hashes.len() {
            return Err(anyhow!("Mismatch between indices and hashes length"));
        }
        if tree_size == 0 {
            return Ok((vec![0u8; 32], BTreeMap::new()));
        }
        let mut nodes: Vec<(u64, Vec<u8>)> = node_indices
            .iter()
            .zip(node_hashes.iter())
            .map(|(&i, h)| (i * 2, h.clone()))
            .collect();
        nodes.sort_by_key(|(i, _)| *i);
        let mut proof_iter = proof_elements.iter();
        let root = crate::tree::log_math::merkle_root(tree_size);

        let peak_set: HashSet<u64> = crate::tree::log_math::get_roots(tree_size).into_iter().collect();
        let mut new_peaks = BTreeMap::new();

        let root_hash = Self::recursive_hash(
            root, tree_size, &nodes, &mut proof_iter, retained, &peak_set, &mut new_peaks,
        )?;
        if proof_iter.next().is_some() {
            return Err(anyhow!("Unused inclusion proof elements"));
        }
        Ok((root_hash, new_peaks))
    }

    fn recursive_hash<'a>(
        node_id: u64,
        tree_size: u64,
        provided_leaves: &[(u64, Vec<u8>)],
        proof_iter: &mut impl Iterator<Item = &'a Vec<u8>>,
        retained: &BTreeMap<u64, Vec<u8>>,
        peak_set: &HashSet<u64>,
        new_peaks: &mut BTreeMap<u64, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        fn record(peak_set: &HashSet<u64>, new_peaks: &mut BTreeMap<u64, Vec<u8>>, id: u64, val: Vec<u8>) -> Vec<u8> {
            if peak_set.contains(&id) {
                new_peaks.insert(id, val.clone());
            }
            val
        }

        if let Ok(idx) = provided_leaves.binary_search_by_key(&node_id, |(k, _)| *k) {
            return Ok(record(peak_set, new_peaks, node_id, provided_leaves[idx].1.clone()));
        }

        let is_ancestor = provided_leaves.iter().any(|(leaf_node_id, _)| {
             let mut curr = *leaf_node_id;
             while curr != node_id {
                 if curr == crate::tree::log_math::merkle_root(tree_size) { return false; }
                 curr = crate::tree::log_math::parent(curr, tree_size);
             }
             true
        });

        if !is_ancestor {
            // mirrors the server's omission rule for retained full subtrees
            if let Some(val) = retained.get(&node_id) {
                return Ok(record(peak_set, new_peaks, node_id, val.clone()));
            }
            let val = proof_iter.next()
                .cloned()
                .ok_or_else(|| anyhow!("Ran out of proof elements at node {}", node_id))?;
            return Ok(record(peak_set, new_peaks, node_id, val));
        }

        if crate::tree::log_math::is_leaf(node_id) {
             return Err(anyhow!("Leaf node {} missing", node_id));
        }

        let l = crate::tree::log_math::left_child(node_id);
        let r = crate::tree::log_math::right_child(node_id, tree_size);

        let l_hash = Self::recursive_hash(l, tree_size, provided_leaves, proof_iter, retained, peak_set, new_peaks)?;
        if l == r { return Ok(record(peak_set, new_peaks, node_id, l_hash)); }

        let r_hash = Self::recursive_hash(r, tree_size, provided_leaves, proof_iter, retained, peak_set, new_peaks)?;
        let val = log_parent_value(&l_hash, crate::tree::log_math::is_leaf(l), &r_hash, crate::tree::log_math::is_leaf(r));
        Ok(record(peak_set, new_peaks, node_id, val))
    }
}

/// Incrementally maintains the log tree's full-subtree peaks, allowing an
/// auditor to run from an arbitrary starting size without leaf history.
#[derive(Debug, Clone)]
pub struct LogAccumulator {
    pub tree_size: u64,
    peaks: Vec<(u32, Vec<u8>)>,
}

impl LogAccumulator {
    pub fn new() -> Self {
        Self { tree_size: 0, peaks: Vec::new() }
    }

    /// Rebuilds the accumulator from the full-subtree values of a tree of
    /// `tree_size` leaves, ordered left to right.
    pub fn from_peaks(tree_size: u64, values: Vec<Vec<u8>>) -> Result<Self> {
        let roots = crate::tree::log_math::get_roots(tree_size);
        if roots.len() != values.len() {
            return Err(anyhow!("Expected {} peaks for tree size {}, got {}", roots.len(), tree_size, values.len()));
        }
        let peaks = roots.into_iter().zip(values)
            .map(|(node, v)| (crate::tree::log_math::level(node), v))
            .collect();
        Ok(Self { tree_size, peaks })
    }

    pub fn append_leaf(&mut self, leaf: Vec<u8>) {
        self.peaks.push((0, leaf));
        self.tree_size += 1;
        while self.peaks.len() >= 2 {
            let (rh, _) = self.peaks[self.peaks.len() - 1];
            let (lh, _) = self.peaks[self.peaks.len() - 2];
            if lh != rh { break; }
            let (_, r) = self.peaks.pop().unwrap();
            let (_, l) = self.peaks.pop().unwrap();
            let merged = log_parent_value(&l, lh == 0, &r, rh == 0);
            self.peaks.push((lh + 1, merged));
        }
    }

    pub fn calculate_root(&self) -> Result<Vec<u8>> {
        if self.tree_size == 0 { return Ok(vec![0u8; 32]); }
        let mut iter = self.peaks.iter().rev();
        let mut acc = iter.next().unwrap().1.clone();
        for (h, v) in iter {
            // the folded right side sits under a collapsed internal node id
            acc = log_parent_value(v, *h == 0, &acc, false);
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod accumulator_tests {
    use super::LogAccumulator;
    use crate::client::verifier::LogVerifier;

    #[test]
    fn peaks_match_full_reconstruction() {
        let mut acc = LogAccumulator::new();
        for n in 1..=20u64 {
            let leaf = vec![n as u8; 32];
            acc.append_leaf(leaf);

            let leaves: Vec<Vec<u8>> = (1..=n).map(|i| vec![i as u8; 32]).collect();
            let indices: Vec<u64> = (0..n).collect();
            let expected = LogVerifier::calculate_root(&indices, &leaves, n, &[]).unwrap();
            assert_eq!(acc.calculate_root().unwrap(), expected, "size {}", n);
        }
    }
}

// --- PREFIX VERIFIER ---
pub struct PrefixVerifier;

impl PrefixVerifier {
    pub fn verify_with_commitment(
        root_hash: &[u8],
        search_key_vrf_output: &[u8],
        commitment: &[u8],
        proof: &PrefixProof,
    ) -> Result<()> {
        use crate::tree::prefix::hasher::{get_bit, leaf_hash, parent_hash};

        if proof.results.is_empty() { return Err(anyhow!("Empty prefix proof results")); }

        let result = &proof.results[0];
        let mut curr_hash = leaf_hash(search_key_vrf_output, commitment);

        let depth = result.depth as usize;
        let mut element_idx = 0;

        // Note: The logic in `src/tree/prefix/read.rs` suggests iterating up from depth.
        // Elements in `PrefixProof` are the siblings along the path from leaf to root.
        for i in (0..depth).rev() {
            if element_idx >= proof.elements.len() {
                return Err(anyhow!("Insufficient proof elements"));
            }
            let sibling = &proof.elements[element_idx];
            element_idx += 1;

            let bit = get_bit(search_key_vrf_output, i);
            if bit == 1 {
                curr_hash = parent_hash(sibling, &curr_hash);
            } else {
                curr_hash = parent_hash(&curr_hash, sibling);
            }
        }

        if curr_hash != root_hash {
            return Err(anyhow!("Prefix tree root mismatch (Inclusion)."));
        }
        Ok(())
    }

    // §12.2; siblings at levels >= depth are implicit ZERO_VALUE stand-ins
    pub fn compute_root_from_result(
        proof: &PrefixProof,
        result_idx: usize,
        vrf_output: &[u8],
        commitment: Option<&[u8]>,
        elements_offset: usize,
    ) -> Result<(Vec<u8>, usize)> {
        use crate::tree::prefix::hasher::{get_bit, leaf_hash, parent_hash, INDEX_LENGTH, ZERO_VALUE};

        let result = proof.results.get(result_idx)
            .ok_or_else(|| anyhow!("Result index out of range"))?;

        let depth = result.depth as usize;
        let total_levels = INDEX_LENGTH * 8;
        if depth > total_levels {
            return Err(anyhow!("PrefixProof: depth exceeds tree height"));
        }

        // non-inclusion results terminate at an empty node on the searched path; the
        // diverging leaf's subtree sits in the copath, so both fold identically
        let (mut curr_hash, start_level): (Vec<u8>, usize) = match result.result_type {
            1 => {
                let comm = commitment.ok_or_else(|| anyhow!("Inclusion result needs commitment"))?;
                (leaf_hash(vrf_output, comm), total_levels)
            }
            2 => {
                let leaf = result.leaf.as_ref()
                    .ok_or_else(|| anyhow!("NonInclusionLeaf result missing leaf"))?;
                if leaf.vrf_output == vrf_output {
                    return Err(anyhow!("NonInclusionLeaf carries the searched key itself"));
                }
                (ZERO_VALUE.to_vec(), depth)
            }
            3 => (ZERO_VALUE.to_vec(), depth),
            _ => return Err(anyhow!("Unknown PrefixSearchResult.result_type")),
        };

        let end = elements_offset.checked_add(depth)
            .ok_or_else(|| anyhow!("Element offset overflow"))?;
        if end > proof.elements.len() {
            return Err(anyhow!("PrefixProof: insufficient elements for result"));
        }
        let elements = &proof.elements[elements_offset..end];

        for level in (0..start_level).rev() {
            let sibling: &[u8] = if level < depth {
                &elements[level]
            } else {
                &ZERO_VALUE
            };
            let bit = get_bit(vrf_output, level);
            if bit == 1 {
                curr_hash = parent_hash(sibling, &curr_hash);
            } else {
                curr_hash = parent_hash(&curr_hash, sibling);
            }
        }

        Ok((curr_hash, depth))
    }
}

// §10.2: the two lists must be a prefix/suffix of one another with >= 1 common root
pub fn compare_roots(roots_a: &[Vec<u8>], roots_b: &[Vec<u8>]) -> Result<()> {
    if roots_a.len() != roots_b.len() {
        return Err(anyhow!("Root lists must be the same size"));
    }
    let n = roots_a.len();
    for x in 0..n {
        if roots_a[..n - x] == roots_b[x..] || roots_b[..n - x] == roots_a[x..] {
            return Ok(());
        }
    }
    Err(anyhow!("No valid overlap between root lists: possible fork"))
}

#[cfg(test)]
mod tests {
    use super::compare_roots;

    fn r(b: u8) -> Vec<u8> { vec![b; 32] }

    #[test]
    fn compare_roots_accepts_overlap() {
        compare_roots(&[r(1), r(2), r(3)], &[r(1), r(2), r(3)]).unwrap();
        compare_roots(&[r(1), r(2), r(3)], &[r(2), r(3), r(4)]).unwrap();
        compare_roots(&[r(2), r(3), r(4)], &[r(1), r(2), r(3)]).unwrap();
    }

    #[test]
    fn compare_roots_rejects_fork() {
        assert!(compare_roots(&[r(1), r(2), r(3)], &[r(4), r(5), r(6)]).is_err());
        assert!(compare_roots(&[r(1), r(2), r(3)], &[r(1), r(5), r(6)]).is_err());
        assert!(compare_roots(&[r(1)], &[r(1), r(2)]).is_err());
    }
}

// --- COMMITMENT VERIFIER ---
pub struct CommitmentVerifier;

impl CommitmentVerifier {
    pub fn verify(
        label: &[u8],
        version: u32,
        value: &[u8],
        opening: &[u8],
        commitment: &[u8],
    ) -> Result<()> {
        let calculated = crate::crypto::hash::commit(label, version, value, opening)?;
        if calculated != commitment {
            return Err(anyhow!("Commitment verification failed"));
        }
        Ok(())
    }
}

// --- PREFIX TRANSITIONER ---

/// Sparse view of the 256-level prefix tree assembled from batch proof paths.
/// Node keys are (level, path bits masked below level).
struct PartialPrefixTree {
    nodes: std::collections::HashMap<(u16, [u8; 32]), Vec<u8>>,
}

impl PartialPrefixTree {
    fn new() -> Self {
        Self { nodes: std::collections::HashMap::new() }
    }

    fn masked(key: &[u8], level: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        let full = level / 8;
        out[..full].copy_from_slice(&key[..full]);
        if full < 32 && level % 8 != 0 {
            out[full] = key[full] & (0xffu8 << (8 - (level % 8)));
        }
        out
    }

    fn with_bit(mut path: [u8; 32], level: usize, bit: u8) -> [u8; 32] {
        if bit == 1 {
            path[level / 8] |= 1 << (7 - (level % 8));
        }
        path
    }

    fn insert(&mut self, level: usize, path: [u8; 32], value: Vec<u8>) -> Result<()> {
        match self.nodes.get(&(level as u16, path)) {
            Some(prev) if prev != &value => Err(anyhow!(
                "Batch proof paths disagree at level {}", level
            )),
            _ => {
                self.nodes.insert((level as u16, path), value);
                Ok(())
            }
        }
    }

    fn remove_leaf(&mut self, key: &[u8]) {
        self.nodes.remove(&(256, Self::masked(key, 256)));
    }

    fn set_leaf(&mut self, key: &[u8], value: Vec<u8>) {
        self.nodes.insert((256, Self::masked(key, 256)), value);
    }

    fn has_descendant(&self, level: usize, path: &[u8; 32]) -> bool {
        self.nodes.keys().any(|(lv, p)| {
            (*lv as usize) > level && Self::masked(p, level) == *path
        })
    }

    fn resolve(&self, level: usize, path: [u8; 32]) -> Vec<u8> {
        use crate::tree::prefix::hasher::{parent_hash, ZERO_VALUE};
        if let Some(v) = self.nodes.get(&(level as u16, path)) {
            return v.clone();
        }
        if level == 256 || !self.has_descendant(level, &path) {
            return ZERO_VALUE.to_vec();
        }
        let l = self.resolve(level + 1, Self::with_bit(path, level, 0));
        let r = self.resolve(level + 1, Self::with_bit(path, level, 1));
        parent_hash(&l, &r)
    }

    fn root(&self) -> Vec<u8> {
        self.resolve(0, [0u8; 32])
    }
}

pub struct PrefixTransitioner;

impl PrefixTransitioner {
    /// §15.2 steps 6-7: rebuild the previous prefix root from the batch proof,
    /// then apply the declared additions and removals for the new root.
    pub fn verify_and_transition(
        old_root: &[u8],
        added: &[PrefixLeaf],
        removed: &[PrefixLeaf],
        proof: &PrefixProof,
    ) -> Result<Vec<u8>> {
        use crate::tree::prefix::hasher::{leaf_hash, ZERO_VALUE};

        if proof.results.len() != added.len() + removed.len() {
            return Err(anyhow!(
                "Batch proof has {} results for {} added and {} removed leaves",
                proof.results.len(), added.len(), removed.len()
            ));
        }

        let removed_keys: std::collections::HashSet<&[u8]> =
            removed.iter().map(|l| l.vrf_output.as_slice()).collect();
        let batch_keys: Vec<&[u8]> = added.iter().chain(removed.iter())
            .map(|l| l.vrf_output.as_slice())
            .collect();

        let mut tree = PartialPrefixTree::new();
        // covering elements span another batch key; their value must be derived
        // from that key's own path data instead of trusted directly
        let mut covering: Vec<(usize, [u8; 32], Vec<u8>)> = Vec::new();
        let mut elements_offset = 0usize;

        for (i, item) in added.iter().chain(removed.iter()).enumerate() {
            let result = &proof.results[i];
            let key = &item.vrf_output;
            if key.len() != 32 {
                return Err(anyhow!("VRF output must be 32 bytes"));
            }
            let depth = result.depth as usize;
            if depth > 256 {
                return Err(anyhow!("Result depth exceeds tree height"));
            }
            let end = elements_offset.checked_add(depth)
                .ok_or_else(|| anyhow!("Element offset overflow"))?;
            if end > proof.elements.len() {
                return Err(anyhow!("Batch proof has insufficient elements"));
            }
            let elements = &proof.elements[elements_offset..end];
            elements_offset = end;

            // old-tree terminal for this key
            let is_removed_result = i >= added.len();
            match result.result_type {
                1 if is_removed_result => {
                    tree.set_leaf(key, leaf_hash(key, &item.commitment));
                }
                1 => {
                    // an added key with an inclusion result must be re-added (also in removed)
                    if !removed_keys.contains(key.as_slice()) {
                        return Err(anyhow!("Inclusion result for an added key that is not being removed"));
                    }
                }
                2 => {
                    let leaf = result.leaf.as_ref()
                        .ok_or_else(|| anyhow!("NonInclusionLeaf result missing leaf"))?;
                    if leaf.vrf_output == *key {
                        return Err(anyhow!("NonInclusionLeaf carries the searched key itself"));
                    }
                    tree.set_leaf(&leaf.vrf_output, leaf_hash(&leaf.vrf_output, &leaf.commitment));
                }
                3 => {}
                _ => return Err(anyhow!("Unknown PrefixSearchResult.result_type")),
            }

            for (k, element) in elements.iter().enumerate() {
                let bit = crate::tree::prefix::hasher::get_bit(key, k) ^ 1;
                let sib_path = PartialPrefixTree::with_bit(PartialPrefixTree::masked(key, k), k, bit);
                let covers_batch_key = batch_keys.iter().any(|other| {
                    *other != key.as_slice() && PartialPrefixTree::masked(other, k + 1) == sib_path
                });
                if covers_batch_key {
                    covering.push((k + 1, sib_path, element.clone()));
                } else {
                    tree.insert(k + 1, sib_path, element.clone())?;
                }
            }
        }

        if elements_offset != proof.elements.len() {
            return Err(anyhow!("Batch proof has unused elements"));
        }

        for (level, path, expected) in &covering {
            let derived = tree.resolve(*level, *path);
            if &derived != expected {
                return Err(anyhow!("Covering proof element disagrees with per-key data at level {}", level));
            }
        }

        let computed_old = tree.root();
        let old_is_empty = old_root.iter().all(|&b| b == 0);
        if computed_old != old_root && !(old_is_empty && computed_old == ZERO_VALUE.to_vec()) {
            return Err(anyhow!("Old prefix root mismatch"));
        }

        for item in removed {
            tree.remove_leaf(&item.vrf_output);
        }
        for item in added {
            tree.set_leaf(&item.vrf_output, leaf_hash(&item.vrf_output, &item.commitment));
        }

        Ok(tree.root())
    }
}
