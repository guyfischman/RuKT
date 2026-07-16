use super::Tree;
use crate::proto::transparency::{
    SearchResponse, FullTreeHead, Consistency, FullAuditorTreeHead,
    AuditorTreeHead as PbAuditorTreeHead, FullTreeHeadType, UpdateValue
};
use crate::tree::errors::KtError;
use anyhow::{Result, anyhow};
use crate::tree::log_math;

impl Tree {
    pub fn get_full_tree_head(&self, consistency: Option<Consistency>) -> Result<FullTreeHead> {
        let (tree_head, current_size, _current_ts) = if let Some(th) = &self.latest {
            (Some(th.clone()), th.tree_size, th.timestamp)
        } else {
            (None, 0, 0)
        };

        let mut full_auditor_tree_heads = vec![];
        for (name, ath) in &self.auditors {
            if let Ok(key_bytes) = hex::decode(name) {
                if let Some(_pk) = self.config.auditor_keys.get(&key_bytes) {
                     full_auditor_tree_heads.push(FullAuditorTreeHead {
                         tree_head: Some(PbAuditorTreeHead {
                             tree_size: ath.tree_size,
                             timestamp: ath.timestamp,
                             signature: ath.signature.clone(),
                         }),
                         root_value: Some(ath.root_value.clone()),
                         consistency: ath.consistency.clone(),
                         public_key: key_bytes,
                     });
                }
            }
        }

        let last_seen = consistency.as_ref().and_then(|c| c.last).unwrap_or(0);

        if last_seen == current_size && current_size > 0 {
            return Ok(FullTreeHead {
                head_type: FullTreeHeadType::Same as i32,
                tree_head: None,
                last: vec![],
                distinguished: vec![],
                full_auditor_tree_heads,
            });
        }

        let mut last_proof = vec![];
        let mut dist_proof = vec![];

        if let Some(c) = consistency {
            if let Some(last) = c.last {
                if last > 0 && last < current_size {
                    last_proof = self.log.get_consistency_proof(last, current_size)?;
                }
            }
            if let Some(dist) = c.distinguished {
                if dist > 0 && dist < current_size {
                    dist_proof = self.log.get_consistency_proof(dist, current_size)?;
                }
            }
        }

        Ok(FullTreeHead {
            head_type: FullTreeHeadType::Updated as i32,
            tree_head,
            last: last_proof.into_iter().collect(),
            distinguished: dist_proof.into_iter().collect(),
            full_auditor_tree_heads,
        })
    }

    pub fn prove_consistency(&self, m: u64, n: u64) -> Result<Vec<Vec<u8>>> {
        self.log.get_consistency_proof(m, n)
    }

    pub(crate) fn get_max_version_at(&self, label_history: &[(u32, u64)], log_pos: u64) -> u32 {
        let mut max_ver = 0;
        let mut found = false;
        
        let log_prefix_ptr = self.log.get_prefix_ptr(log_pos).unwrap_or(0);

        for (ver, ptr) in label_history {
            if *ptr <= log_prefix_ptr {
                if !found || *ver > max_ver {
                    max_ver = *ver;
                    found = true;
                }
            }
        }
        if !found { return 0; } 
        max_ver
    }
    
    pub(crate) fn exists_at(&self, label_history: &[(u32, u64)], log_pos: u64) -> bool {
         let log_prefix_ptr = self.log.get_prefix_ptr(log_pos).unwrap_or(0);
         label_history.iter().any(|(_, p)| *p <= log_prefix_ptr)
    }

    pub(crate) fn get_frontier_nodes(&self, tree_size: u64, _last_size: u64) -> Vec<u64> {
        crate::tree::log_math::get_frontier(tree_size)
    }

    // Moved from traversal.rs
    pub(crate) fn extract_value_and_opening(
        &self, 
        history: &[(u32, u64)], 
        ver: u32, 
        val_out: &mut Option<UpdateValue>, 
        open_out: &mut Vec<u8>
    ) -> Result<()> {
        let pos = history.iter().find(|(v, _)| *v == ver).map(|(_, p)| *p);
        if let Some(p) = pos {
            let val = self.store.get_value(p)?.unwrap_or_default();
            *val_out = Some(UpdateValue { value: val });
            
            if let Some(op) = self.store.get_opening(p)? {
                *open_out = op;
            } else {
                return Err(anyhow::Error::new(KtError::Unavailable));
            }
            Ok(())
        } else {
            Err(anyhow::Error::new(KtError::Unavailable))
        }
    }

    // Moved from traversal.rs (needed for Owner Monitoring)
    pub(crate) fn owner_monitoring_traversal_collect<'a>(
        &'a self,
        node_idx: u64,
        left_ts: u64,
        right_ts: u64,
        tree_size: u64,
        user_advertised_rightmost: u64,
        history: &'a [(u32, u64)],
        limit: usize,
    ) -> futures::future::BoxFuture<'a, Result<(Vec<(u64, u32)>, usize)>> {
        Box::pin(async move {
            let mut current_limit = limit;
            if current_limit == 0 { return Ok((vec![], 0)); }

            if right_ts.saturating_sub(left_ts) < self.config.reasonable_monitoring_window {
                return Ok((Vec::new(), current_limit));
            }

            let node_ts = self.log.get_timestamp(node_idx)?;
            let mut results = Vec::new();

            if node_idx <= user_advertised_rightmost {
                if !log_math::is_leaf(node_idx) {
                    if let Some(r) = log_math::ibst_right_child(node_idx, tree_size) {
                        if r < tree_size && r != node_idx {
                            let (mut right_res, remaining) = self.owner_monitoring_traversal_collect(
                                r, node_ts, right_ts, tree_size, user_advertised_rightmost, history, current_limit
                            ).await?;
                            results.append(&mut right_res);
                            current_limit = remaining;
                        }
                    }
                }
                return Ok((results, current_limit));
            }

            if !log_math::is_leaf(node_idx) {
                let l = log_math::left_child(node_idx);
                if l < tree_size {
                    let (mut left_res, remaining) = self.owner_monitoring_traversal_collect(
                        l, left_ts, node_ts, tree_size, user_advertised_rightmost, history, current_limit
                    ).await?;
                    results.append(&mut left_res);
                    current_limit = remaining;
                }
            }

            if current_limit > 0 {
                let snapshot_idx = node_idx; 
                let ver = self.get_max_version_at(history, snapshot_idx);
                results.push((node_idx, ver));
                current_limit -= 1;
            }

            if current_limit > 0 && !log_math::is_leaf(node_idx) {
                if let Some(r) = log_math::ibst_right_child(node_idx, tree_size) {
                    if r < tree_size && r != node_idx {
                        let (mut right_res, remaining) = self.owner_monitoring_traversal_collect(
                            r, node_ts, right_ts, tree_size, user_advertised_rightmost, history, current_limit
                        ).await?;
                        results.append(&mut right_res);
                        current_limit = remaining;
                    }
                }
            }

            Ok((results, current_limit))
        })
    }

    pub async fn search(&self, req: &crate::proto::transparency::SearchRequest) -> Result<SearchResponse> {
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);

        if tree_size == 0 {
             return Ok(SearchResponse {
                 full_tree_head: Some(self.get_full_tree_head(None)?),
                 binary_ladder: vec![],
                 search: Some(crate::proto::transparency::CombinedTreeProof::default()),
                 opening: vec![],
                 value: None,
                 version: None,
             });
        }

        let last = req.last.unwrap_or(0);
        let is_greatest = req.version.is_none();

        let result_data = if let Some(target_ver) = req.version {
            self.traverse_fixed_search(tree_size, &req.label, target_ver, last).await?
        } else {
            self.traverse_greatest_search(tree_size, &req.label, last).await?
        };

        let consistency = Consistency { last: req.last, distinguished: None };
        let fth = self.get_full_tree_head(Some(consistency))?;

        Ok(SearchResponse {
            full_tree_head: Some(fth),
            binary_ladder: result_data.binary_ladder,
            search: Some(result_data.combined_proof),
            opening: result_data.opening,
            value: result_data.value,
            version: if is_greatest { Some(result_data.greatest_version) } else { None },
        })
    }
    
    /// Returns the PrefixProof for the requested versions plus, per version, the
    /// commitment when the version is included.
    pub(crate) async fn generate_ladder_proof(&self, prefix_ptr: u64, _tree_size: u64, label: &[u8], versions: &[u32])
        -> Result<(crate::proto::transparency::PrefixProof, Vec<(u32, Option<Vec<u8>>)>)> {

        let overlay = std::collections::HashMap::new();
        let mut proof_results = Vec::new();
        let mut elements = Vec::new();
        let mut ladder_tuples = Vec::new();

        for &v in versions {
            let (idx, _) = self.config.vrf_prove(label, v)?;
            let res = self.prefix.search_for_proof(prefix_ptr, &idx, &overlay).await?;

            // §12.2
            let leaf = match res.result_type {
                2 => Some(crate::proto::transparency::PrefixLeaf {
                    vrf_output: res.leaf_vrf_output.unwrap_or_default(),
                    commitment: res.leaf_commitment.unwrap_or_default(),
                }),
                _ => None,
            };
            proof_results.push(crate::proto::transparency::PrefixSearchResult {
                result_type: res.result_type,
                leaf,
                depth: res.depth,
            });
            elements.extend(res.inclusion_proof);
            ladder_tuples.push((v, res.commitment));
        }

        Ok((crate::proto::transparency::PrefixProof { results: proof_results, elements }, ladder_tuples))
    }
}