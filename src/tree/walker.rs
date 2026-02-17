use super::Tree;
use crate::proto::transparency::{
    CombinedTreeProof, PrefixProof, InclusionProof,
    BinaryLadderStep, UpdateValue
};
use anyhow::Result;
use std::collections::{HashSet, HashMap};

/// Holds state for a traversal operation to ensure compliance with Draft Section 11.3.
pub struct TraversalSession<'a> {
    tree: &'a Tree,
    label: &'a [u8],
    
    // Draft 11.3 Accumulators
    visited_nodes: Vec<u64>,
    visited_set: HashSet<u64>,
    timestamps: HashMap<u64, u64>,
    prefix_proofs: HashMap<u64, PrefixProof>,
    prefix_roots: HashMap<u64, Vec<u8>>,

    // Result Accumulators
    pub binary_ladder: Vec<BinaryLadderStep>,
    pub found_value: Option<UpdateValue>,
    pub found_opening: Vec<u8>,
    
    // Dedup state
    ladder_versions_added: HashSet<u32>,
}

impl<'a> TraversalSession<'a> {
    pub fn new(tree: &'a Tree, label: &'a [u8]) -> Self {
        Self {
            tree,
            label,
            visited_nodes: Vec::new(),
            visited_set: HashSet::new(),
            timestamps: HashMap::new(),
            prefix_proofs: HashMap::new(),
            prefix_roots: HashMap::new(),
            binary_ladder: Vec::new(),
            found_value: None,
            found_opening: Vec::new(),
            ladder_versions_added: HashSet::new(),
        }
    }

    pub fn set_label(&mut self, label: &'a [u8]) {
        self.label = label;
    }

    pub async fn visit_frontier(&mut self, tree_size: u64) -> Result<()> {
        let frontier = self.tree.get_frontier_nodes(tree_size, 0);
        for &node in &frontier {
            let ts = self.tree.log.get_timestamp(node)?;
            self.add_node(node, ts);
            if let Ok(root) = self.tree.log.get_prefix_root(node) {
                self.add_root(node, root);
            }
        }
        Ok(())
    }

    /// Visits a specific node, generates required proofs, and optionally extracts value.
    /// `extract_target`: If Some(ver), attempts to retrieve the value/opening for `ver` from DB.
    pub async fn visit(&mut self, node_idx: u64, versions_to_prove: &[u32], extract_target: Option<u32>, tree_size: u64) -> Result<()> {
        let ts = self.tree.log.get_timestamp(node_idx)?;
        self.add_node(node_idx, ts);

        let prefix_ptr = self.tree.log.get_prefix_ptr(node_idx)?;
        let (proof_struct, ladder_results) = self.tree.generate_ladder_proof(
            prefix_ptr, 
            tree_size, 
            self.label, 
            versions_to_prove
        ).await?;

        self.add_proof(node_idx, proof_struct);

        for (ver, res) in ladder_results {
            if self.ladder_versions_added.insert(ver) {
                let (_, vrf_proof) = self.tree.config.vrf_prove(self.label, ver)?;
                let comm = res.map(|r| r.commitment);
                self.binary_ladder.push(BinaryLadderStep { 
                    proof: vrf_proof, 
                    commitment: comm 
                });
            }
        }

        if let Some(target_ver) = extract_target {
            let label_history = self.tree.store.get_label_history(self.label)?;
            // Attempt extraction. If it fails (doesn't exist), it returns Err(Unavailable)
            self.tree.extract_value_and_opening(
                &label_history, 
                target_ver, 
                &mut self.found_value, 
                &mut self.found_opening
            )?;
        }

        Ok(())
    }

    fn add_node(&mut self, idx: u64, ts: u64) {
        if self.visited_set.insert(idx) {
            self.visited_nodes.push(idx);
            self.timestamps.insert(idx, ts);
        }
    }

    fn add_proof(&mut self, idx: u64, proof: PrefixProof) {
        self.prefix_roots.remove(&idx);
        self.prefix_proofs.insert(idx, proof);
    }

    fn add_root(&mut self, idx: u64, root: Vec<u8>) {
        if !self.prefix_proofs.contains_key(&idx) {
            self.prefix_roots.insert(idx, root);
        }
    }

    pub fn finalize(mut self, tree_size: u64, consistency_last: u64) -> Result<(CombinedTreeProof, Vec<BinaryLadderStep>, Option<UpdateValue>, Vec<u8>)> {
        let mut combined = CombinedTreeProof::default();
        self.visited_nodes.sort(); 

        for &idx in &self.visited_nodes {
            if let Some(&ts) = self.timestamps.get(&idx) {
                combined.timestamps.push(ts);
            }
            if let Some(proof) = self.prefix_proofs.remove(&idx) {
                combined.prefix_proofs.push(proof);
            } else if let Some(root) = self.prefix_roots.remove(&idx) {
                combined.prefix_roots.push(root);
            }
        }

        let inc_proof = self.tree.log.get_batch_proof_for_nodes(
            self.visited_nodes, 
            tree_size, 
            consistency_last
        )?;
        
        combined.inclusion = Some(InclusionProof { elements: inc_proof });

        Ok((combined, self.binary_ladder, self.found_value, self.found_opening))
    }
}

// Re-export ProofBuilder logic specifically for Credential generation if needed manually
pub struct StandaloneProofBuilder {
    visited_nodes: Vec<u64>,
    visited_set: HashSet<u64>,
    timestamps: HashMap<u64, u64>,
    prefix_proofs: HashMap<u64, PrefixProof>,
    prefix_roots: HashMap<u64, Vec<u8>>,
}

impl StandaloneProofBuilder {
    pub fn new() -> Self {
        Self {
            visited_nodes: Vec::new(),
            visited_set: HashSet::new(),
            timestamps: HashMap::new(),
            prefix_proofs: HashMap::new(),
            prefix_roots: HashMap::new(),
        }
    }
    
    pub fn add_node(&mut self, idx: u64, ts: u64) {
        if self.visited_set.insert(idx) {
            self.visited_nodes.push(idx);
            self.timestamps.insert(idx, ts);
        }
    }

    pub fn add_proof(&mut self, idx: u64, proof: PrefixProof) {
        self.prefix_proofs.insert(idx, proof);
    }
    
    pub fn get_sorted_nodes(&self) -> Vec<u64> {
        let mut n = self.visited_nodes.clone();
        n.sort();
        n
    }

    pub fn finalize(mut self, inclusion: InclusionProof) -> CombinedTreeProof {
        let mut combined = CombinedTreeProof::default();
        combined.inclusion = Some(inclusion);
        self.visited_nodes.sort(); 

        for &idx in &self.visited_nodes {
            if let Some(&ts) = self.timestamps.get(&idx) { combined.timestamps.push(ts); }
            if let Some(proof) = self.prefix_proofs.remove(&idx) { combined.prefix_proofs.push(proof); }
            else if let Some(root) = self.prefix_roots.remove(&idx) { combined.prefix_roots.push(root); }
        }
        combined
    }
}