use super::Tree;
use crate::proto::transparency::{
    Credential, CredentialType, GetCredentialRequest,
    BinaryLadderStep,
    InclusionProof,
    PrefixProof 
};
use crate::tree::log_math;
use crate::tree::binary_ladder::greatest_version_binary_ladder;
use anyhow::{Result, anyhow};
use futures::future::BoxFuture; 

impl Tree {
    pub async fn get_credential(&self, req: &GetCredentialRequest) -> Result<Credential> {
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        if tree_size == 0 {
            return Err(anyhow!("Log is empty"));
        }

        let label_history = self.store.get_label_history(&req.search_key)?;
        let target_ver = if let Some((v, _)) = label_history.last() {
            *v
        } else {
             return Err(anyhow!("Key not found"));
        };

        let target_ptr = label_history.iter().find(|(v, _)| *v == target_ver).map(|(_, p)| *p).unwrap();

        let distinguished_nodes = self.find_distinguished_nodes(tree_size).await?;
        
        let mut standard_node = None;

        for &node_idx in distinguished_nodes.iter().rev() {
            let log_ptr = self.log.get_prefix_ptr(node_idx)?;
            if log_ptr >= target_ptr {
                standard_node = Some(node_idx);
                break;
            }
        }

        // Retrieve Value and Opening
        let mut val_struct = None;
        let mut open_vec = Vec::new();
        self.extract_value_and_opening(&label_history, target_ver, &mut val_struct, &mut open_vec)?;

        if let Some(dist_node) = standard_node {
            // STANDARD CREDENTIAL
            let snapshot_log_idx = dist_node;
            let n = self.get_max_version_at(&label_history, snapshot_log_idx);
            
            let versions = greatest_version_binary_ladder(target_ver, n, true, &[], &[], &[]);
            let prefix_ptr = self.log.get_prefix_ptr(dist_node)?;
            let (prefix_proof, ladder_results) = self.generate_ladder_proof(prefix_ptr, tree_size, &req.search_key, &versions).await?;
            
            let mut steps = Vec::new();
            for (ver, res) in ladder_results {
                let (_, vrf_proof) = self.config.vrf_prove(&req.search_key, ver)?;
                let comm: Option<Vec<u8>> = res.map(|r| r.commitment);
                steps.push(BinaryLadderStep {
                    proof: vrf_proof,
                    commitment: comm,
                });
            }

            Ok(Credential {
                credential_type: CredentialType::Standard.into(),
                version: target_ver,
                opening: open_vec,
                value: val_struct,
                binary_ladder: steps,
                
                tree_size, 
                distinguished: Some(prefix_proof),
                
                full_tree_head: None,
                search: None,
            })

        } else {
            // PROVISIONAL CREDENTIAL
            let mut builder = crate::tree::walker::StandaloneProofBuilder::new();
            let mut binary_ladder_steps = Vec::new();

            let frontier = log_math::get_frontier(tree_size);
            let start_idx = if let Some(d) = distinguished_nodes.last() {
                frontier.iter().position(|&x| x == *d).unwrap_or(0)
            } else { 0 };
            
            for &node in &frontier[start_idx..] {
                let ts = self.log.get_timestamp(node)?;
                builder.add_node(node, ts);

                let snapshot_idx = node;
                let n = self.get_max_version_at(&label_history, snapshot_idx);

                let versions = greatest_version_binary_ladder(target_ver, n, false, &[], &[], &[]);
                let prefix_ptr = self.log.get_prefix_ptr(node)?;
                let (proof_struct, results) = self.generate_ladder_proof(prefix_ptr, tree_size, &req.search_key, &versions).await?;
                
                builder.add_proof(node, proof_struct);

                if node == *frontier.last().unwrap() {
                    for (ver, res) in results {
                         let (_, vrf_proof) = self.config.vrf_prove(&req.search_key, ver)?;
                         let comm: Option<Vec<u8>> = res.map(|r| r.commitment);
                         binary_ladder_steps.push(BinaryLadderStep {
                             proof: vrf_proof,
                             commitment: comm,
                         });
                    }
                }
            }
            
            let sorted_nodes = builder.get_sorted_nodes();
            let inc_proof = self.log.get_batch_proof_for_nodes(sorted_nodes, tree_size, 0)?;
            let combined = builder.finalize(InclusionProof { elements: inc_proof });

            let fth = self.get_full_tree_head(None)?;

            Ok(Credential {
                credential_type: CredentialType::Provisional.into(),
                version: target_ver,
                opening: open_vec,
                value: val_struct,
                binary_ladder: binary_ladder_steps,
                
                tree_size: 0,
                distinguished: None,
                
                full_tree_head: Some(fth),
                search: Some(combined),
            })
        }
    }

    pub async fn find_distinguished_nodes(&self, tree_size: u64) -> Result<Vec<u64>> {
        let root_idx = log_math::root(tree_size);
        let rightmost_idx = tree_size - 1;
        let rightmost_ts = self.log.get_timestamp(rightmost_idx)?;
        
        let mut results = self.recursive_distinguished_wrapper(root_idx, 0, rightmost_ts, tree_size).await?;
        results.sort();
        Ok(results)
    }

    fn recursive_distinguished_wrapper<'a>(
        &'a self, 
        node_idx: u64, 
        left_ts: u64, 
        right_ts: u64, 
        tree_size: u64
    ) -> BoxFuture<'a, Result<Vec<u64>>> {
        Box::pin(async move {
            if right_ts.saturating_sub(left_ts) < self.config.reasonable_monitoring_window {
                return Ok(Vec::new());
            }
            
            let mut nodes = vec![node_idx];
            let node_ts = self.log.get_timestamp(node_idx)?;

            if !log_math::is_leaf(node_idx) {
                 let l = log_math::left_child(node_idx);
                 if l < tree_size {
                     let mut left_res = self.recursive_distinguished_wrapper(l, left_ts, node_ts, tree_size).await?;
                     nodes.append(&mut left_res);
                 }
            }
            
            if !log_math::is_leaf(node_idx) {
                 if let Some(r) = log_math::ibst_right_child(node_idx, tree_size) {
                     if r < tree_size && r != node_idx {
                         let mut right_res = self.recursive_distinguished_wrapper(r, node_ts, right_ts, tree_size).await?;
                         nodes.append(&mut right_res);
                     }
                 }
            }

            Ok(nodes)
        })
    }
}