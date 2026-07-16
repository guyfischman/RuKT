use super::Tree;
use crate::proto::transparency::{
    BinaryLadderStep, Credential, CredentialType, CredentialUpdate, GetCredentialRequest,
    GetCredentialUpdateRequest, MonitorMapEntry, PrefixProof,
};
use crate::tree::binary_ladder::search_binary_ladder;
use crate::tree::log_math;
use anyhow::{Result, anyhow};
use futures::future::BoxFuture;

impl Tree {
    // §14.2: proves the provisional credential's terminal entry is now covered by
    // the first distinguished entry to its right, via a §8.2 monitor proof
    pub async fn get_credential_update(
        &self,
        req: &GetCredentialUpdateRequest,
    ) -> Result<CredentialUpdate> {
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        if tree_size == 0 {
            return Err(anyhow!("Log is empty"));
        }

        let distinguished = self.find_distinguished_nodes(tree_size).await?;
        let position = *distinguished
            .iter()
            .find(|&&d| d > req.terminal_position)
            .ok_or_else(|| {
                anyhow!("No distinguished log entry to the right of the terminal entry yet")
            })?;

        // the monitor proof is computed against the tree as it was at position+1
        let entries = vec![MonitorMapEntry {
            position: req.terminal_position,
            version: req.terminal_version,
        }];
        let monitor = self
            .traverse_contact_monitoring(position + 1, &req.label, &entries, 0)
            .await?;

        Ok(CredentialUpdate {
            position,
            monitor: Some(monitor),
        })
    }
    pub async fn get_credential(&self, req: &GetCredentialRequest) -> Result<Credential> {
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        if tree_size == 0 {
            return Err(anyhow!("Log is empty"));
        }

        let label_history = self.store.get_label_history(&req.label)?;
        let target_ver = if let Some((v, _)) = label_history.last() {
            *v
        } else {
            return Err(anyhow!("Key not found"));
        };

        let target_ptr = label_history
            .iter()
            .find(|(v, _)| *v == target_ver)
            .map(|(_, p)| *p)
            .unwrap();

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
            let n = self
                .get_max_version_at(&label_history, snapshot_log_idx)
                .ok_or_else(|| anyhow!("Label absent at its own distinguished entry"))?;

            let versions = search_binary_ladder(target_ver, n, &[], &[]);
            let prefix_ptr = self.log.get_prefix_ptr(dist_node)?;
            let (prefix_proof, ladder_results) = self
                .generate_ladder_proof(prefix_ptr, tree_size, &req.label, &versions)
                .await?;

            let mut steps = Vec::new();
            for (ver, comm) in ladder_results {
                let (_, vrf_proof) = self.config.vrf_prove(&req.label, ver)?;
                steps.push(BinaryLadderStep {
                    proof: vrf_proof,
                    commitment: if ver == target_ver { None } else { comm },
                });
            }

            Ok(Credential {
                label: req.label.clone(),
                version: target_ver,
                opening: open_vec,
                value: val_struct,
                binary_ladder: steps,
                position: dist_node,
                credential_type: CredentialType::Standard.into(),

                distinguished: Some(prefix_proof),

                tree_head: None,
                search: None,
            })
        } else {
            // §14.2: a greatest-version search whose view updates from position+1,
            // anchored to the most recent distinguished entry
            let position = *distinguished_nodes
                .last()
                .ok_or_else(|| anyhow!("No distinguished log entry to anchor a credential"))?;

            let result = self
                .traverse_greatest_search(tree_size, &req.label, position + 1)
                .await?;

            Ok(Credential {
                label: req.label.clone(),
                version: result.greatest_version,
                opening: result.opening,
                value: result.value,
                binary_ladder: result.binary_ladder,
                position,
                credential_type: CredentialType::Provisional.into(),

                distinguished: None,

                tree_head: self.latest.clone(),
                search: Some(result.combined_proof),
            })
        }
    }

    pub async fn find_distinguished_nodes(&self, tree_size: u64) -> Result<Vec<u64>> {
        let root_idx = log_math::root(tree_size);
        let rightmost_idx = tree_size - 1;
        let rightmost_ts = self.log.get_timestamp(rightmost_idx)?;

        let mut results = self
            .recursive_distinguished_wrapper(root_idx, 0, rightmost_ts, tree_size)
            .await?;
        results.sort();
        Ok(results)
    }

    fn recursive_distinguished_wrapper<'a>(
        &'a self,
        node_idx: u64,
        left_ts: u64,
        right_ts: u64,
        tree_size: u64,
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
                    let mut left_res = self
                        .recursive_distinguished_wrapper(l, left_ts, node_ts, tree_size)
                        .await?;
                    nodes.append(&mut left_res);
                }
            }

            if !log_math::is_leaf(node_idx) {
                if let Some(r) = log_math::ibst_right_child(node_idx, tree_size) {
                    if r < tree_size && r != node_idx {
                        let mut right_res = self
                            .recursive_distinguished_wrapper(r, node_ts, right_ts, tree_size)
                            .await?;
                        nodes.append(&mut right_res);
                    }
                }
            }

            Ok(nodes)
        })
    }
}
