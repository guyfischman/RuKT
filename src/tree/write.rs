// Start src/tree/write.rs
use super::{PostUpdateData, PreUpdateData, Tree};
use crate::crypto::{construct_tree_head_tbs, sign_data};
use crate::proto::transparency::{
    AuditorUpdate, BinaryLadderStep, CombinedTreeProof, InclusionProof, PrefixLeaf, PrefixProof,
    PrefixSearchResult, Signature as PbSignature, TreeHead, UpdateInfo, UpdateResponse,
};
use anyhow::{Result, anyhow};
use prost::Message;
use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

impl Tree {
    pub async fn apply_batch(
        &mut self,
        updates: Vec<PreUpdateData>,
    ) -> Result<(Vec<Result<PostUpdateData>>, TreeHead)> {
        if updates.is_empty() {
            return Err(anyhow!("Empty batch"));
        }

        let start_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        let mut valid_updates = Vec::new();
        let mut results_map: Vec<Option<Result<PostUpdateData>>> =
            (0..updates.len()).map(|_| None).collect();

        let mut version_overlay: HashMap<Vec<u8>, u32> = HashMap::new();

        for (i, update) in updates.iter().enumerate() {
            let history = self.store.get_label_history(&update.label)?;
            let mut current_ver = history.last().map(|(v, _)| *v).unwrap_or(0);
            if let Some(v) = version_overlay.get(&update.label) {
                current_ver = *v;
            }
            let next_ver = if history.is_empty() && !version_overlay.contains_key(&update.label) {
                0
            } else {
                current_ver + 1
            };

            // vrf index and commitment were derived from update.version; a raced batch must not repair them silently
            if update.version != next_ver {
                results_map[i] = Some(Err(anyhow!(
                    "Version assignment raced: precomputed {} but batch assigns {}",
                    update.version,
                    next_ver
                )));
                continue;
            }
            version_overlay.insert(update.label.clone(), next_ver);

            valid_updates.push((i, update.clone(), next_ver));
        }

        if valid_updates.is_empty() {
            let th = self
                .latest
                .clone()
                .ok_or_else(|| anyhow!("No tree head available"))?;
            let final_results = results_map
                .into_iter()
                .map(|r| r.unwrap_or_else(|| Err(anyhow!("Error"))))
                .collect();
            return Ok((final_results, th));
        }

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let start_prefix_version = self.log.get_next_prefix_version()?;
        let current_log_ptr = if start_size > 0 {
            Some(self.log.get_prefix_ptr(start_size - 1)?)
        } else {
            None
        };

        let mut removed_leaves = Vec::new();
        let mut added_leaves = Vec::new();
        let mut combined_audit_proof_elements = Vec::new();
        let mut audit_search_results = Vec::new();
        let overlay: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut prefix_entries = Vec::new();

        // ==========================================
        // MICRO-TIMER 1: Generating Audit Proofs (Reads)
        // ==========================================
        let t_search = Instant::now();

        // §15.2: added is sorted ascending by vrf_output, with one search result
        // per added key (in order) followed by one per removed key
        let mut audit_keys: Vec<(Vec<u8>, Vec<u8>)> = valid_updates
            .iter()
            .map(|(_, update, _)| (update.index.to_vec(), update.commitment.clone()))
            .collect();
        audit_keys.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, update, _) in &valid_updates {
            prefix_entries.push((update.index.to_vec(), update.commitment.clone()));
        }

        let mut audit_futures = Vec::new();
        let prefix_arc = self.prefix.clone();

        for (idx, comm) in &audit_keys {
            if let Some(ptr) = current_log_ptr {
                let p_tree = prefix_arc.clone();
                let idx = idx.clone();
                let comm = comm.clone();
                audit_futures.push(tokio::spawn(async move {
                    let overlay = HashMap::new();
                    let proof_res = p_tree.search_for_proof(ptr, &idx, &overlay).await?;
                    Ok::<_, anyhow::Error>((proof_res, idx, comm))
                }));
            } else {
                // genesis: every search in the empty previous tree is a non-inclusion
                audit_search_results.push(PrefixSearchResult {
                    result_type: 3,
                    leaf: None,
                    depth: 0,
                });
                added_leaves.push(PrefixLeaf {
                    vrf_output: idx.clone(),
                    commitment: comm.clone(),
                });
            }
        }

        let results = futures::future::join_all(audit_futures).await;
        let mut removed_results: Vec<(PrefixSearchResult, Vec<Vec<u8>>)> = Vec::new();

        for res in results {
            let (proof_res, idx_bytes, update_comm) = res??;

            let leaf = if proof_res.result_type == 2 {
                Some(PrefixLeaf {
                    vrf_output: proof_res.leaf_vrf_output.unwrap_or_default(),
                    commitment: proof_res.leaf_commitment.unwrap_or_default(),
                })
            } else {
                None
            };
            let result = PrefixSearchResult {
                result_type: proof_res.result_type,
                leaf,
                depth: proof_res.depth,
            };

            if let Some(old_c) = &proof_res.commitment {
                removed_leaves.push(PrefixLeaf {
                    vrf_output: idx_bytes.clone(),
                    commitment: old_c.clone(),
                });
                removed_results.push((result.clone(), proof_res.inclusion_proof.clone()));
            }

            audit_search_results.push(result);
            combined_audit_proof_elements.extend(proof_res.inclusion_proof);

            added_leaves.push(PrefixLeaf {
                vrf_output: idx_bytes,
                commitment: update_comm,
            });
        }

        for (result, elements) in removed_results {
            audit_search_results.push(result);
            combined_audit_proof_elements.extend(elements);
        }

        let dur_search = t_search.elapsed();

        // ==========================================
        // MICRO-TIMER 2: Prefix Tree Merkle Appends (Reads/Writes)
        // ==========================================
        let t_insert = Instant::now();
        let (_roots, search_results, final_prefix_ptr) = self
            .prefix
            .batch_insert(start_prefix_version, current_log_ptr, &prefix_entries)
            .await?;
        let dur_insert = t_insert.elapsed();

        // ==========================================
        // MICRO-TIMER 3: Log Tree Appends (Reads/Writes)
        // ==========================================
        let t_log = Instant::now();
        let new_log_index = start_size;
        self.log.put_prefix_ptr(new_log_index, final_prefix_ptr)?;
        self.log.set_next_prefix_version(final_prefix_ptr + 1)?;

        let final_root_hash = _roots.last().unwrap().clone();
        let new_log_root = self
            .log
            .batch_append(start_size, vec![(timestamp, final_root_hash)])?;
        let dur_log = t_log.elapsed();

        // ==========================================
        // MICRO-TIMER 4: Metadata DB Writes
        // ==========================================
        let t_meta = Instant::now();
        let audit_update = AuditorUpdate {
            timestamp,
            added: added_leaves,
            removed: removed_leaves,
            proof: Some(PrefixProof {
                results: audit_search_results,
                elements: combined_audit_proof_elements,
            }),
        };
        let mut blob = Vec::new();
        audit_update.encode(&mut blob)?;
        self.store.put_audit_blob(new_log_index, blob)?;

        let mut value_batch = Vec::with_capacity(valid_updates.len());
        let mut opening_batch = Vec::with_capacity(valid_updates.len());
        let mut history_batch = Vec::with_capacity(valid_updates.len());

        for (k, (_, update, ver)) in valid_updates.iter().enumerate() {
            let ptr = search_results[k].log_position;
            value_batch.push((ptr, update.value.clone()));
            opening_batch.push((ptr, update.opening.clone()));
            history_batch.push((update.label.clone(), *ver, ptr));
        }

        self.store.put_value_batch(value_batch)?;
        self.store.put_opening_batch(opening_batch)?;
        self.store.put_history_batch(history_batch)?;
        let dur_meta = t_meta.elapsed();

        let new_size = start_size + 1;
        let auditor_pk_bytes =
            if self.config.mode == crate::crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING {
                self.config.auditor_keys.keys().next().map(|k| k.as_slice())
            } else {
                None
            };

        let tbs_data =
            construct_tree_head_tbs(&self.config, auditor_pk_bytes, new_size, &new_log_root)?;
        let signature = sign_data(&self.config.sig_key, &tbs_data);

        let th = TreeHead {
            tree_size: new_size,
            timestamp: timestamp as i64,
            signatures: vec![PbSignature {
                auditor_public_key: self.config.sig_key.verifying_key().to_bytes(),
                signature,
            }],
        };

        let mut head_buf = Vec::new();
        th.encode(&mut head_buf)?;
        self.store.set_head(head_buf)?;
        self.latest = Some(th.clone());

        let fth = self.get_full_tree_head(None)?;

        for (k, (original_idx, _, _)) in valid_updates.into_iter().enumerate() {
            let post = PostUpdateData {
                tree_head: fth.clone(),
                search_result: search_results[k].clone(),
            };
            results_map[original_idx] = Some(Ok(post));
        }

        Ok((
            results_map
                .into_iter()
                .map(|r| r.unwrap_or_else(|| Err(anyhow!("Internal error"))))
                .collect(),
            th,
        ))
    }

    pub(crate) fn find_log_entry_for_prefix_pos(&self, pos: u64, tree_size: u64) -> Result<u64> {
        let (mut lo, mut hi) = (0u64, tree_size - 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.log.get_prefix_ptr(mid)? >= pos {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Ok(lo)
    }

    // §13.5: the advertised greatest_version is behind; report the versions created
    // in the log entry immediately following it instead of inserting anything
    pub async fn catch_up_update(
        &self,
        req: &crate::proto::transparency::UpdateRequest,
    ) -> Result<UpdateResponse> {
        let tree_size = self
            .latest
            .as_ref()
            .map(|th| th.tree_size)
            .ok_or_else(|| anyhow!("Empty tree"))?;
        let history = self.store.get_label_history(&req.label)?;

        let first_missing = req.greatest_version.map(|g| g + 1).unwrap_or(0);
        let first_pos = history
            .iter()
            .find(|(v, _)| *v == first_missing)
            .map(|(_, p)| *p)
            .ok_or_else(|| anyhow!("Version {} missing from label history", first_missing))?;

        let position = self.find_log_entry_for_prefix_pos(first_pos, tree_size)?;
        let entry_hi = self.log.get_prefix_ptr(position)?;

        let mut values = Vec::new();
        let mut info = Vec::new();
        let mut binary_ladder = Vec::new();
        let mut new_greatest = first_missing;

        for &(v, p) in history
            .iter()
            .filter(|(v, p)| *v >= first_missing && *p <= entry_hi)
        {
            let value = self
                .store
                .get_value(p)?
                .ok_or_else(|| anyhow!("Value for v={} was pruned", v))?;
            let opening = self
                .store
                .get_opening(p)?
                .ok_or_else(|| anyhow!("Opening for v={} was pruned", v))?;
            let (_, vrf_proof) = self.config.vrf_prove(&req.label, v)?;

            values.push(crate::proto::transparency::LabelValue { value });
            info.push(UpdateInfo {
                opening,
                suffix_signature: None,
            });
            binary_ladder.push(BinaryLadderStep {
                proof: vrf_proof,
                commitment: None,
            });
            new_greatest = v;
        }

        let combined_proof = self
            .traverse_update_verification(
                tree_size,
                position,
                &req.label,
                new_greatest,
                req.last.unwrap_or(0),
            )
            .await?;
        let fth = self.get_full_tree_head(None)?;

        Ok(UpdateResponse {
            full_tree_head: Some(fth),
            position,
            values,
            info,
            binary_ladder,
            update: Some(combined_proof),
        })
    }

    /// pres: all versions created for one label by one request, ascending, same log entry.
    pub async fn post_update(
        &self,
        pres: &[PreUpdateData],
        post: PostUpdateData,
    ) -> Result<UpdateResponse> {
        let newest = pres.last().ok_or_else(|| anyhow!("Empty update group"))?;
        let tree_size = post.tree_head.tree_head.as_ref().unwrap().tree_size;
        let insertion_log_index = tree_size - 1;

        let combined_proof = self
            .traverse_update_verification(
                tree_size,
                insertion_log_index,
                &newest.label,
                newest.version,
                newest.last,
            )
            .await?;

        // §13.5: commitments are only sent for versions <= the user's advertised
        // greatest_version; every version here is newer than that
        let binary_ladder = pres
            .iter()
            .map(|p| BinaryLadderStep {
                proof: p.vrf_proof.clone(),
                commitment: None,
            })
            .collect();

        let info = pres
            .iter()
            .map(|p| UpdateInfo {
                opening: p.opening.clone(),
                suffix_signature: None,
            })
            .collect();

        Ok(UpdateResponse {
            full_tree_head: Some(post.tree_head),
            position: insertion_log_index,
            values: vec![],
            info,
            binary_ladder,
            update: Some(combined_proof),
        })
    }
}
// End src/tree/write.rs
