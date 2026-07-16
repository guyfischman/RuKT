use super::Tree;
use crate::proto::transparency::{
    AuditorTreeHead as PbAuditorTreeHead, Consistency, FullTreeHead, FullTreeHeadType,
    SearchResponse, UpdateValue,
};
use crate::tree::errors::KtError;
use anyhow::Result;

impl Tree {
    // §11.4
    pub fn get_full_tree_head(&self, consistency: Option<Consistency>) -> Result<FullTreeHead> {
        let (tree_head, current_size) = if let Some(th) = &self.latest {
            (Some(th.clone()), th.tree_size)
        } else {
            (None, 0)
        };

        let last_seen = consistency.as_ref().and_then(|c| c.last).unwrap_or(0);

        if last_seen == current_size && current_size > 0 {
            return Ok(FullTreeHead {
                head_type: FullTreeHeadType::Same as i32,
                tree_head: None,
                auditor_tree_head: None,
            });
        }

        // freshest verified auditor head
        let auditor_tree_head = self
            .auditors
            .values()
            .max_by_key(|ath| ath.tree_size)
            .map(|ath| PbAuditorTreeHead {
                tree_size: ath.tree_size,
                timestamp: ath.timestamp,
                signature: ath.signature.clone(),
            });

        Ok(FullTreeHead {
            head_type: FullTreeHeadType::Updated as i32,
            tree_head,
            auditor_tree_head,
        })
    }

    pub fn prove_consistency(&self, m: u64, n: u64) -> Result<Vec<Vec<u8>>> {
        self.log.get_consistency_proof(m, n)
    }

    /// None when no version of the label existed in the entry's prefix tree.
    pub(crate) fn get_max_version_at(
        &self,
        label_history: &[(u32, u64)],
        log_pos: u64,
    ) -> Option<u32> {
        let log_prefix_ptr = self.log.get_prefix_ptr(log_pos).unwrap_or(0);

        label_history
            .iter()
            .filter(|(_, ptr)| *ptr <= log_prefix_ptr)
            .map(|(ver, _)| *ver)
            .max()
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
        open_out: &mut Vec<u8>,
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

    pub async fn search(
        &self,
        req: &crate::proto::transparency::SearchRequest,
    ) -> Result<SearchResponse> {
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
            self.traverse_fixed_search(tree_size, &req.label, target_ver, last)
                .await?
        } else {
            self.traverse_greatest_search(tree_size, &req.label, last)
                .await?
        };

        let consistency = Consistency {
            last: req.last,
            distinguished: None,
        };
        let fth = self.get_full_tree_head(Some(consistency))?;

        Ok(SearchResponse {
            full_tree_head: Some(fth),
            binary_ladder: result_data.binary_ladder,
            search: Some(result_data.combined_proof),
            opening: result_data.opening,
            value: result_data.value,
            version: if is_greatest {
                Some(result_data.greatest_version)
            } else {
                None
            },
        })
    }

    /// Returns the PrefixProof for the requested versions plus, per version, the
    /// commitment when the version is included.
    pub(crate) async fn generate_ladder_proof(
        &self,
        prefix_ptr: u64,
        _tree_size: u64,
        label: &[u8],
        versions: &[u32],
    ) -> Result<(
        crate::proto::transparency::PrefixProof,
        Vec<(u32, Option<Vec<u8>>)>,
    )> {
        let overlay = std::collections::HashMap::new();
        let mut proof_results = Vec::new();
        let mut elements = Vec::new();
        let mut ladder_tuples = Vec::new();

        for &v in versions {
            let (idx, _) = self.config.vrf_prove(label, v)?;
            let res = self
                .prefix
                .search_for_proof(prefix_ptr, &idx, &overlay)
                .await?;

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

        Ok((
            crate::proto::transparency::PrefixProof {
                results: proof_results,
                elements,
            },
            ladder_tuples,
        ))
    }
}
