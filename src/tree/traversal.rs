use super::Tree;
use crate::proto::transparency::{CombinedTreeProof, MonitorLabelVersions, BinaryLadderStep, UpdateValue};
use crate::tree::walker::TraversalSession;
use crate::tree::log_math;
use crate::tree::binary_ladder::{fixed_version_binary_ladder, greatest_version_binary_ladder, monitor_binary_ladder};
use crate::tree::errors::KtError;
use anyhow::{Result, anyhow};
use std::collections::HashSet;

pub struct SearchResultData {
    pub combined_proof: CombinedTreeProof,
    pub binary_ladder: Vec<BinaryLadderStep>,
    pub value: Option<UpdateValue>,
    pub opening: Vec<u8>,
}

impl Tree {
    pub async fn traverse_update_verification(
        &self,
        current_tree_size: u64,
        insertion_log_index: u64,
        label: &[u8],
        new_version: u32,
        consistency_last: u64,
    ) -> Result<CombinedTreeProof> {
        let mut session = TraversalSession::new(self, label);
        
        let prev_frontier = self.get_frontier_nodes(insertion_log_index, 0);
        let target_ver_frontier = if new_version > 0 { new_version - 1 } else { 0 };

        for &node in &prev_frontier {
            let versions = crate::tree::binary_ladder::base_binary_ladder(target_ver_frontier);
            session.visit(node, &versions, None, current_tree_size).await?;
        }

        let mut versions_new = crate::tree::binary_ladder::base_binary_ladder(new_version);
        if !versions_new.contains(&new_version) { versions_new.push(new_version); }
        
        session.visit(insertion_log_index, &versions_new, None, current_tree_size).await?;

        Ok(session.finalize(current_tree_size, consistency_last)?.0)
    }

    pub async fn traverse_fixed_search(
        &self, 
        tree_size: u64, 
        label: &[u8], 
        target_ver: u32,
        consistency_last: u64
    ) -> Result<SearchResultData> {
        let mut session = TraversalSession::new(self, label);
        let label_history = self.store.get_label_history(label)?;
        let rightmost_ts = self.log.get_timestamp(tree_size - 1)?;
        let max_life = self.config.maximum_lifetime;

        session.visit_frontier(tree_size).await?;

        let mut curr = log_math::root(tree_size);
        let mut candidate_node: Option<u64> = None;

        loop {
            let ts = self.log.get_timestamp(curr)?;
            let is_expired = if let Some(ml) = max_life { rightmost_ts.saturating_sub(ts) >= ml } else { false };
            let n = self.get_max_version_at(&label_history, curr);

            // Update candidate: leftmost (visited) node where n >= target
            if n >= target_ver {
                candidate_node = Some(curr);
            }

            let mut right_child = curr;
            let mut has_right = false;
            if !log_math::is_leaf(curr) {
                if let Some(rc) = log_math::ibst_right_child(curr, tree_size) {
                    right_child = rc;
                    has_right = true;
                }
            }

            if is_expired {
                if has_right {
                     let rc_ts = self.log.get_timestamp(right_child)?;
                     let rc_expired = if let Some(ml) = max_life { rightmost_ts.saturating_sub(rc_ts) >= ml } else { false };
                     if !rc_expired {
                         // Skip expired node, visit right child instead
                         session.visit(curr, &[], None, tree_size).await?; 
                         curr = right_child;
                         continue;
                     }
                }
                return Err(anyhow::Error::new(KtError::Expired));
            }

            let versions = fixed_version_binary_ladder(target_ver, n, &[], &[]);
            let found_target = n == target_ver;
            let extract = if found_target { Some(target_ver) } else { None };
            
            session.visit(curr, &versions, extract, tree_size).await?;

            if found_target {
                break;
            } else if n < target_ver {
                if !has_right { break; }
                curr = right_child;
            } else { 
                if log_math::is_leaf(curr) { break; }
                curr = log_math::left_child(curr);
            }
        }

        // Step 6: Fallback to leftmost candidate if exact match not found in loop
        if session.found_value.is_none() {
            if let Some(cand) = candidate_node {
                // If candidate is expired, that's an error (Step 6.1)
                // We checked expiration in loop, but time is relative to rightmost.
                // Assuming candidate visited in loop was not expired back then.
                // We re-visit to extract.
                // We need to prove `target_ver` existence here if it wasn't in the ladder.
                session.visit(cand, &[target_ver], Some(target_ver), tree_size).await?;
            } else {
                return Err(anyhow::Error::new(KtError::Unavailable));
            }
        }

        if session.found_value.is_none() {
             return Err(anyhow::Error::new(KtError::Unavailable));
        }

        let (proof, ladder, val, op) = session.finalize(tree_size, consistency_last)?;

        Ok(SearchResultData {
            combined_proof: proof,
            binary_ladder: ladder,
            value: val,
            opening: op,
        })
    }

    pub async fn traverse_greatest_search(
        &self,
        tree_size: u64,
        label: &[u8],
        consistency_last: u64
    ) -> Result<SearchResultData> {
        let mut session = TraversalSession::new(self, label);
        let label_history = self.store.get_label_history(label)?;
        
        let mut known_max = 0; 
        let frontier = self.get_frontier_nodes(tree_size, 0);

        for &node in &frontier {
            let n = self.get_max_version_at(&label_history, node);
            if n > known_max { known_max = n; }

            let extract = if node == *frontier.last().unwrap() { Some(known_max) } else { None };
            let versions = greatest_version_binary_ladder(known_max, n, false, &[], &[], &[]);
            
            session.visit(node, &versions, extract, tree_size).await?;
        }

        let (proof, ladder, val, op) = session.finalize(tree_size, consistency_last)?;
        Ok(SearchResultData {
            combined_proof: proof,
            binary_ladder: ladder,
            value: val,
            opening: op,
        })
    }

    pub async fn traverse_monitoring(
        &self,
        tree_size: u64,
        req: &crate::proto::transparency::MonitorRequest
    ) -> Result<(CombinedTreeProof, Vec<MonitorLabelVersions>)> {
        
        let mut session = TraversalSession::new(self, b""); 
        let mut label_versions_list = Vec::new();

        session.visit_frontier(tree_size).await?;

        let distinguished_nodes = self.find_distinguished_nodes(tree_size).await?;
        let distinguished_set: HashSet<u64> = distinguished_nodes.into_iter().collect();

        for label_req in &req.labels {
            session.set_label(&label_req.label);

            for entry in &label_req.entries {
                let mut path = vec![entry.position];
                path.extend(log_math::ibst_direct_path(entry.position, tree_size));
                path.retain(|&idx| idx >= entry.position);
                path.sort();

                for &log_id in &path {
                    let ladder = monitor_binary_ladder(entry.version, &[]);
                    session.visit(log_id, &ladder, None, tree_size).await?;
                    if distinguished_set.contains(&log_id) { break; }
                }
            }

            if let Some(rightmost) = label_req.rightmost {
                let mut versions_out = MonitorLabelVersions { versions: vec![] };
                let history = self.store.get_label_history(&label_req.label)?;
                let root_idx = log_math::root(tree_size);
                let rightmost_ts = self.log.get_timestamp(tree_size - 1)?;
                let limit = self.config.max_response_entries;

                let (nodes, _) = self.owner_monitoring_traversal_collect(
                    root_idx, 0, rightmost_ts, tree_size, rightmost, &history, limit
                ).await?;

                for (node_idx, ver) in nodes {
                    versions_out.versions.push(ver);
                    let ladder = greatest_version_binary_ladder(ver, ver, true, &[], &[], &[]);
                    session.visit(node_idx, &ladder, None, tree_size).await?;
                }
                label_versions_list.push(versions_out);
            } else {
                label_versions_list.push(MonitorLabelVersions { versions: vec![] });
            }
        }

        let last = req.last.unwrap_or(0);
        Ok((session.finalize(tree_size, last)?.0, label_versions_list))
    }
}