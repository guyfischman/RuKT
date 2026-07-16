// Start src/client/verifier.rs
use anyhow::{Result, anyhow, Context};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
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
        if node_indices.len() != node_hashes.len() {
            return Err(anyhow!("Mismatch between indices and hashes length"));
        }
        if tree_size == 0 {
            return Ok(vec![0u8; 32]);
        }
        let mut nodes: Vec<(u64, Vec<u8>)> = node_indices
            .iter()
            .zip(node_hashes.iter())
            .map(|(&i, h)| (i * 2, h.clone()))
            .collect();
        nodes.sort_by_key(|(i, _)| *i);
        let mut proof_iter = proof_elements.iter();
        let root = crate::tree::log_math::merkle_root(tree_size);
        Self::recursive_hash(root, tree_size, &nodes, &mut proof_iter)
    }

    fn recursive_hash<'a>(
        node_id: u64,
        tree_size: u64,
        provided_leaves: &[(u64, Vec<u8>)],
        proof_iter: &mut impl Iterator<Item = &'a Vec<u8>>,
    ) -> Result<Vec<u8>> {
        if let Ok(idx) = provided_leaves.binary_search_by_key(&node_id, |(k, _)| *k) {
            return Ok(provided_leaves[idx].1.clone());
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
             return proof_iter.next()
                .cloned()
                .ok_or_else(|| anyhow!("Ran out of proof elements at node {}", node_id));
        }

        if crate::tree::log_math::is_leaf(node_id) {
             return Err(anyhow!("Leaf node {} missing", node_id));
        }

        let l = crate::tree::log_math::left_child(node_id);
        let r = crate::tree::log_math::right_child(node_id, tree_size);
        
        let l_hash = Self::recursive_hash(l, tree_size, provided_leaves, proof_iter)?;
        if l == r { return Ok(l_hash); }

        let r_hash = Self::recursive_hash(r, tree_size, provided_leaves, proof_iter)?;
        Ok(log_parent_value(&l_hash, crate::tree::log_math::is_leaf(l), &r_hash, crate::tree::log_math::is_leaf(r)))
    }
}

#[derive(Debug, Clone)]
pub struct LogAccumulator {
    pub tree_size: u64,
    pub peaks: Vec<Vec<u8>>, 
}

impl LogAccumulator {
    pub fn new() -> Self {
        Self { tree_size: 0, peaks: Vec::new() }
    }

    pub fn append_leaf_naive(&mut self, leaf: Vec<u8>) {
        self.peaks.push(leaf); 
        self.tree_size += 1;
    }
    
    pub fn calculate_root_naive(&self) -> Result<Vec<u8>> {
        if self.tree_size == 0 { return Ok(vec![0u8; 32]); }
        let leaves: Vec<(u64, Vec<u8>)> = self.peaks.iter().enumerate().map(|(i, h)| (i as u64 * 2, h.clone())).collect();
        Self::build_from_leaves(crate::tree::log_math::merkle_root(self.tree_size), self.tree_size, &leaves)
    }

    fn build_from_leaves(node_idx: u64, tree_size: u64, leaves: &[(u64, Vec<u8>)]) -> Result<Vec<u8>> {
        if crate::tree::log_math::is_leaf(node_idx) {
            let leaf_idx = node_idx / 2;
            if let Some((_, val)) = leaves.get(leaf_idx as usize) {
                return Ok(val.clone());
            } else {
                return Err(anyhow!("Missing leaf {}", leaf_idx));
            }
        }
        let l = crate::tree::log_math::left_child(node_idx);
        let r = crate::tree::log_math::right_child(node_idx, tree_size);
        
        let l_hash = Self::build_from_leaves(l, tree_size, leaves)?;
        if l == r { return Ok(l_hash); }
        let r_hash = Self::build_from_leaves(r, tree_size, leaves)?;
        
        Ok(log_parent_value(&l_hash, crate::tree::log_math::is_leaf(l), &r_hash, crate::tree::log_math::is_leaf(r)))
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
pub struct PrefixTransitioner;

impl PrefixTransitioner {
    pub fn verify_and_transition(
        old_root: &[u8],
        added: &[PrefixLeaf],
        removed: &[PrefixLeaf],
        proof: &PrefixProof
    ) -> Result<Vec<u8>> {
        use crate::tree::prefix::hasher::{leaf_hash, parent_hash, ZERO_VALUE};
        
        if added.len() == 1 && removed.is_empty() {
             // Handle Genesis Case: No previous tree exists.
             if proof.results.is_empty() {
                 if !old_root.iter().all(|&b| b == 0) && old_root != ZERO_VALUE {
                     return Err(anyhow!("Proof results empty but old root is not empty"));
                 }
                 
                 let item = &added[0];
                 let new_root = Self::compute_genesis_root(item);
                 return Ok(new_root);
             }

             let item = &added[0];
             let res = &proof.results[0];
             
             let computed_old = Self::compute_single_root(&item.vrf_output, None, res, &proof.elements)?;
             if computed_old != old_root {
                 if !(old_root.iter().all(|&b| b==0) && computed_old == ZERO_VALUE) {
                    return Err(anyhow!("Old prefix root mismatch."));
                 }
             }

             let computed_new = Self::compute_single_root(&item.vrf_output, Some(&item.commitment), res, &proof.elements)?;
             return Ok(computed_new);
        }
        Err(anyhow!("Multi-update batch verification not implemented in this client version"))
    }

    fn compute_genesis_root(item: &PrefixLeaf) -> Vec<u8> {
        use crate::tree::prefix::hasher::{leaf_hash, parent_hash, ZERO_VALUE, get_bit};
        
        let mut acc = leaf_hash(&item.vrf_output, &item.commitment);
        
        // Simulate rolling up from depth 256 to 0
        for i in (0..256).rev() {
            let bit = get_bit(&item.vrf_output, i);
            if bit == 1 {
                acc = parent_hash(&ZERO_VALUE, &acc);
            } else {
                acc = parent_hash(&acc, &ZERO_VALUE);
            }
        }
        acc
    }

    fn compute_single_root(
        key: &[u8],
        new_commitment: Option<&[u8]>,
        result: &PrefixSearchResult,
        elements: &[Vec<u8>]
    ) -> Result<Vec<u8>> {
        use crate::tree::prefix::hasher::{leaf_hash, parent_hash, ZERO_VALUE};
        
        let mut curr_hash = if let Some(comm) = new_commitment {
            leaf_hash(key, comm)
        } else {
            match result.result_type {
                2 => { 
                    if let Some(l) = &result.leaf {
                        leaf_hash(&l.vrf_output, &l.commitment)
                    } else { return Err(anyhow!("Missing leaf in NonInclusion result")); }
                },
                3 => ZERO_VALUE.to_vec(),
                _ => return Err(anyhow!("Invalid result type for reconstruction")),
            }
        };

        let depth = result.depth as usize;
        let mut element_idx = 0;
        
        for i in (0..depth).rev() {
            if element_idx >= elements.len() { return Err(anyhow!("Missing proof elements")); }
            let sibling = &elements[element_idx];
            element_idx += 1;
            
            let bit = crate::tree::prefix::hasher::get_bit(key, i);
            if bit == 1 {
                curr_hash = parent_hash(sibling, &curr_hash);
            } else {
                curr_hash = parent_hash(&curr_hash, sibling);
            }
        }
        Ok(curr_hash)
    }
}