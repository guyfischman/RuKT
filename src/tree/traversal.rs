use super::Tree;
use crate::proto::transparency::{CombinedTreeProof, MonitorMapEntry, BinaryLadderStep, UpdateValue};
use crate::tree::walker::TraversalSession;
use crate::tree::log_math;
use crate::tree::binary_ladder::{search_binary_ladder, monitoring_binary_ladder};
use crate::tree::errors::KtError;
use anyhow::{Result, anyhow};
use std::collections::HashSet;

pub struct SearchResultData {
    pub combined_proof: CombinedTreeProof,
    pub binary_ladder: Vec<BinaryLadderStep>,
    pub value: Option<UpdateValue>,
    pub opening: Vec<u8>,
    pub greatest_version: u32,
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

    // §7.2
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
        let distinguished = self.find_distinguished_nodes(tree_size).await?;

        let is_expired = |ts: u64| max_life.map_or(false, |ml| rightmost_ts.saturating_sub(ts) >= ml);
        let is_unexpired_distinguished = |node: u64, ts: u64| {
            distinguished.binary_search(&node).is_ok() && !is_expired(ts)
        };

        session.visit_frontier(tree_size).await?;

        let mut curr = log_math::root(tree_size);
        let mut expired_on_path = false;
        let mut encountered_expired = false;
        let mut left_path: Vec<(u64, u64)> = Vec::new();
        let mut inspected: Vec<(u64, u32)> = Vec::new();
        let mut success = false;

        loop {
            let ts = self.log.get_timestamp(curr)?;

            let right_child = if log_math::is_leaf(curr) { None } else { log_math::ibst_right_child(curr, tree_size) };

            // step 1
            if is_expired(ts) {
                encountered_expired = true;
                expired_on_path = true;
                session.visit_timestamp_only(curr)?;
                match right_child {
                    Some(rc) => { left_path.push((curr, ts)); curr = rc; continue; }
                    None => break,
                }
            }

            // step 2
            let n = self.get_max_version_at(&label_history, curr);
            let versions = search_binary_ladder(target_ver, n, &[], &[]);
            let extract = if n == target_ver { Some(target_ver) } else { None };
            session.visit(curr, &versions, extract, tree_size).await?;
            inspected.push((curr, n));

            if n < target_ver {
                // step 3
                match right_child {
                    Some(rc) => { left_path.push((curr, ts)); curr = rc; }
                    None => break,
                }
            } else if n > target_ver {
                // step 4
                if log_math::is_leaf(curr) { break; }
                curr = log_math::left_child(curr);
            } else {
                // step 5
                if !expired_on_path
                    || is_unexpired_distinguished(curr, ts)
                    || left_path.iter().any(|&(node, node_ts)| is_unexpired_distinguished(node, node_ts))
                {
                    success = true;
                    break;
                }
                return Err(anyhow::Error::new(KtError::Expired));
            }
        }

        // step 6
        if !success {
            let identified = inspected.iter()
                .filter(|&&(_, n)| n > target_ver)
                .map(|&(node, _)| node)
                .min();
            let identified = match identified {
                Some(node) => node,
                None => return Err(anyhow::Error::new(KtError::Unavailable)),
            };

            if encountered_expired {
                let mut has_unexpired_dist_left = false;
                for &d in &distinguished {
                    if d >= identified { break; }
                    if !is_expired(self.log.get_timestamp(d)?) {
                        has_unexpired_dist_left = true;
                        break;
                    }
                }
                if !has_unexpired_dist_left {
                    return Err(anyhow::Error::new(KtError::Expired));
                }
            }

            session.visit(identified, &[target_ver], Some(target_ver), tree_size).await?;
            if session.found_value.is_none() {
                return Err(anyhow::Error::new(KtError::Unavailable));
            }
        }

        let (proof, ladder, val, op) = session.finalize(tree_size, consistency_last)?;

        Ok(SearchResultData {
            combined_proof: proof,
            binary_ladder: ladder,
            value: val,
            opening: op,
            greatest_version: target_ver,
        })
    }

    // §6.3; TODO: start at the rightmost distinguished log entry instead of the root
    pub async fn traverse_greatest_search(
        &self,
        tree_size: u64,
        label: &[u8],
        consistency_last: u64
    ) -> Result<SearchResultData> {
        let mut session = TraversalSession::new(self, label);
        let label_history = self.store.get_label_history(label)?;

        session.visit_frontier(tree_size).await?;

        let frontier = self.get_frontier_nodes(tree_size, 0);
        let rightmost = *frontier.last().unwrap();
        // every entry's ladder targets the claimed greatest version
        let target = self.get_max_version_at(&label_history, rightmost);

        for &node in &frontier {
            let n = self.get_max_version_at(&label_history, node);
            let extract = if node == rightmost { Some(target) } else { None };
            let versions = search_binary_ladder(target, n, &[], &[]);

            session.visit(node, &versions, extract, tree_size).await?;
        }

        let (proof, ladder, val, op) = session.finalize(tree_size, consistency_last)?;
        Ok(SearchResultData {
            combined_proof: proof,
            binary_ladder: ladder,
            value: val,
            opening: op,
            greatest_version: target,
        })
    }

    // §8.2
    async fn visit_contact_entries(
        &self,
        session: &mut TraversalSession<'_>,
        entries: &[MonitorMapEntry],
        distinguished_set: &HashSet<u64>,
        tree_size: u64,
    ) -> Result<()> {
        for entry in entries {
            let mut path = vec![entry.position];
            path.extend(log_math::ibst_direct_path(entry.position, tree_size));
            path.retain(|&idx| idx >= entry.position);
            path.sort();

            for &log_id in &path {
                let ladder = monitoring_binary_ladder(entry.version, &[]);
                session.visit(log_id, &ladder, None, tree_size).await?;
                if distinguished_set.contains(&log_id) { break; }
            }
        }
        Ok(())
    }

    // §8.3 second algorithm
    async fn visit_owner_updates(
        &self,
        session: &mut TraversalSession<'_>,
        label: &[u8],
        start: u64,
        tree_size: u64,
    ) -> Result<Vec<u32>> {
        let history = self.store.get_label_history(label)?;
        let root_idx = log_math::root(tree_size);
        let rightmost_ts = self.log.get_timestamp(tree_size - 1)?;
        let limit = self.config.max_response_entries;

        let (nodes, _) = self.owner_monitoring_traversal_collect(
            root_idx, 0, rightmost_ts, tree_size, start, &history, limit
        ).await?;

        let mut versions = Vec::new();
        for (node_idx, ver) in nodes {
            versions.push(ver);
            let ladder = search_binary_ladder(ver, ver, &[], &[]);
            session.visit(node_idx, &ladder, None, tree_size).await?;
        }
        Ok(versions)
    }

    pub async fn traverse_contact_monitoring(
        &self,
        tree_size: u64,
        label: &[u8],
        entries: &[MonitorMapEntry],
        last: u64,
    ) -> Result<CombinedTreeProof> {
        let mut session = TraversalSession::new(self, label);
        session.visit_frontier(tree_size).await?;

        let distinguished_set: HashSet<u64> =
            self.find_distinguished_nodes(tree_size).await?.into_iter().collect();
        self.visit_contact_entries(&mut session, entries, &distinguished_set, tree_size).await?;

        Ok(session.finalize(tree_size, last)?.0)
    }

    pub async fn traverse_owner_init(
        &self,
        tree_size: u64,
        label: &[u8],
        start: u64,
        last: u64,
    ) -> Result<(CombinedTreeProof, Vec<BinaryLadderStep>, Vec<u32>)> {
        let mut session = TraversalSession::new(self, label);
        session.visit_frontier(tree_size).await?;

        let mut versions = self.visit_owner_updates(&mut session, label, start, tree_size).await?;
        // §13.3: greatest_versions are reported in descending order
        versions.reverse();

        let (proof, ladder, _, _) = session.finalize(tree_size, last)?;
        Ok((proof, ladder, versions))
    }

    // §10.1; "recent" = one of the max_response_entries rightmost distinguished entries
    pub async fn traverse_distinguished(
        &self,
        tree_size: u64,
        stop: Option<u64>,
        last: u64,
    ) -> Result<CombinedTreeProof> {
        let mut session = TraversalSession::new(self, b"");
        session.visit_frontier(tree_size).await?;

        let distinguished = self.find_distinguished_nodes(tree_size).await?;
        let dset: HashSet<u64> = distinguished.iter().copied().collect();
        let recent: HashSet<u64> = distinguished.iter().rev()
            .take(self.config.max_response_entries as usize)
            .copied()
            .collect();

        let mut stack = vec![log_math::root(tree_size)];
        while let Some(curr) = stack.pop() {
            // step 1
            if !dset.contains(&curr) { continue; }
            // §12.3.8
            session.visit_timestamp_only(curr)?;
            // step 2
            if !log_math::is_leaf(curr) {
                if let Some(rc) = log_math::ibst_right_child(curr, tree_size) {
                    stack.push(rc);
                }
            }
            // step 3
            if stop.map_or(false, |s| curr <= s) { continue; }
            // step 4
            if !recent.contains(&curr) { continue; }
            // step 5
            if !log_math::is_leaf(curr) {
                stack.push(log_math::left_child(curr));
            }
        }

        Ok(session.finalize(tree_size, last)?.0)
    }

    pub async fn traverse_owner_monitor(
        &self,
        tree_size: u64,
        label: &[u8],
        entries: &[MonitorMapEntry],
        start: u64,
        last: u64,
    ) -> Result<CombinedTreeProof> {
        let mut session = TraversalSession::new(self, label);
        session.visit_frontier(tree_size).await?;

        let distinguished_set: HashSet<u64> =
            self.find_distinguished_nodes(tree_size).await?.into_iter().collect();
        self.visit_contact_entries(&mut session, entries, &distinguished_set, tree_size).await?;
        self.visit_owner_updates(&mut session, label, start, tree_size).await?;

        Ok(session.finalize(tree_size, last)?.0)
    }
}