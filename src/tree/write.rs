use super::{Tree, PreUpdateData, PostUpdateData};
use crate::proto::transparency::{
    SignedUpdateRequest, UpdateResponse, CombinedTreeProof,
    TreeHead, Signature as PbSignature,
    InclusionProof, BinaryLadderStep, PrefixProof, PrefixSearchResult,
    AuditorUpdate, PrefixLeaf
};
use crate::crypto::{
    generate_random_opening, commit, construct_tree_head_tbs, construct_update_tbs, sign_data, verify_data,
    DEPLOYMENT_MODE_THIRD_PARTY_MANAGEMENT, ServiceVerifyingKey
};
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};
use prost::Message;
use std::collections::HashMap;

impl Tree {
    pub fn pre_update(&self, req: SignedUpdateRequest, _current_tree_size: u64) -> Result<PreUpdateData> {
        let inner_req = req.request.ok_or_else(|| anyhow!("Missing inner UpdateRequest"))?;
        
        let history = self.store.get_label_history(&inner_req.search_key)?;
        let next_version = history.last().map(|(v, _)| v + 1).unwrap_or(0);

        let (index, vrf_proof) = self.config.vrf_prove(&inner_req.search_key, next_version)?;
        
        let opening = generate_random_opening();
        let commitment = commit(&inner_req.search_key, &inner_req.value, &opening)?;

        Ok(PreUpdateData {
            req: inner_req,
            signature: req.signature,
            index,
            vrf_proof,
            commitment,
            opening,
        })
    }

    pub async fn apply_batch(&mut self, updates: Vec<PreUpdateData>) -> Result<(Vec<Result<PostUpdateData>>, TreeHead)> {
        if updates.is_empty() {
            return Err(anyhow!("Empty batch"));
        }

        let start_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        
        let mut valid_updates = Vec::new();
        let mut results_map: Vec<Option<Result<PostUpdateData>>> = (0..updates.len()).map(|_| None).collect();
        let mut tpm_verifier: Option<ServiceVerifyingKey> = None;
        if self.config.mode == DEPLOYMENT_MODE_THIRD_PARTY_MANAGEMENT {
             if let Some(pk_bytes) = &self.config.leaf_public_key {
                tpm_verifier = Some(ServiceVerifyingKey::from_bytes(pk_bytes)?);
            } else {
                return Err(anyhow!("Server configured for ThirdPartyManagement but no Leaf Public Key provided"));
            }
        }
        let mut version_overlay: HashMap<Vec<u8>, u32> = HashMap::new();

        for (i, update) in updates.iter().enumerate() {
            let history = self.store.get_label_history(&update.req.search_key)?;
            let mut current_ver = history.last().map(|(v, _)| *v).unwrap_or(0);
            if let Some(v) = version_overlay.get(&update.req.search_key) { current_ver = *v; }
            let next_ver = if history.is_empty() && !version_overlay.contains_key(&update.req.search_key) { 0 } else { current_ver + 1 };
            
            if !update.req.expected_pre_update_value.is_empty() {
                let last_pos = history.last().map(|(_, p)| *p);
                let actual = if let Some(p) = last_pos { self.store.get_value(p)?.unwrap_or_default() } else { vec![] };
                if actual != update.req.expected_pre_update_value {
                    results_map[i] = Some(Err(anyhow!("Tombstone update failed: expected value mismatch")));
                    continue;
                }
            }
            if let Some(verifier) = &tpm_verifier {
                let tbs = construct_update_tbs(&update.req.search_key, next_ver, &update.req.value)?;
                if let Err(e) = verify_data(verifier, &tbs, &update.signature) {
                    results_map[i] = Some(Err(anyhow!("TPM Signature verification failed: {}", e)));
                    continue;
                }
            }
            version_overlay.insert(update.req.search_key.clone(), next_ver);
            let (new_index, new_proof) = self.config.vrf_prove(&update.req.search_key, next_ver)?;
            let mut mod_update = update.clone();
            mod_update.index = new_index;
            mod_update.vrf_proof = new_proof;
            valid_updates.push((i, mod_update, next_ver));
        }

        if valid_updates.is_empty() {
             let th = self.latest.clone().ok_or_else(|| anyhow!("No tree head available"))?;
             let final_results = results_map.into_iter().map(|r| r.unwrap_or_else(|| Err(anyhow!("Error")))).collect();
             return Ok((final_results, th));
        }

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let start_prefix_version = self.log.get_next_prefix_version()?;
        let current_log_ptr = if start_size > 0 { Some(self.log.get_prefix_ptr(start_size - 1)?) } else { None };

        let mut removed_leaves = Vec::new();
        let mut added_leaves = Vec::new();
        let mut combined_audit_proof_elements = Vec::new();
        let mut audit_search_results = Vec::new();
        
        let overlay: HashMap<u64, Vec<u8>> = HashMap::new(); 
        
        let mut prefix_entries = Vec::new();
        for (_, update, _) in &valid_updates {
             prefix_entries.push((update.index.to_vec(), update.commitment.clone()));
             added_leaves.push(PrefixLeaf { vrf_output: update.index.to_vec(), commitment: update.commitment.clone() });
             
             if let Some(ptr) = current_log_ptr {
                 let proof_res = self.prefix.search_for_proof(ptr, &update.index, &overlay).await?;
                 
                 // Collect removed leaf if it existed
                 if let Some(old_c) = &proof_res.commitment {
                     removed_leaves.push(PrefixLeaf { vrf_output: update.index.to_vec(), commitment: old_c.clone() });
                 }
                 
                 // Construct PrefixSearchResult for Auditor
                 let leaf = if proof_res.result_type == 2 { // NonInclusionLeaf
                     Some(PrefixLeaf {
                         vrf_output: proof_res.leaf_vrf_output.unwrap_or_default(),
                         commitment: proof_res.leaf_commitment.unwrap_or_default(),
                     })
                 } else {
                     None
                 };
                 
                 audit_search_results.push(PrefixSearchResult {
                     result_type: proof_res.result_type,
                     leaf,
                     depth: proof_res.depth,
                 });

                 if combined_audit_proof_elements.is_empty() {
                     combined_audit_proof_elements = proof_res.inclusion_proof;
                 }
             }
        }
        
        let (_roots, search_results, final_prefix_ptr) = self.prefix.batch_insert(
            start_prefix_version, 
            current_log_ptr, 
            &prefix_entries
        ).await?;

        let new_log_index = start_size;
        self.log.put_prefix_ptr(new_log_index, final_prefix_ptr)?;
        self.log.set_next_prefix_version(final_prefix_ptr + 1)?;

        let final_root_hash = _roots.last().unwrap().clone();
        let new_log_root = self.log.batch_append(start_size, vec![(timestamp, final_root_hash)])?;

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

        for (k, (_, update, ver)) in valid_updates.iter().enumerate() {
            let ptr = search_results[k].log_position;
            self.store.put_value(ptr, update.req.value.clone())?;
            self.store.put_opening(ptr, update.opening.clone())?;
            self.store.append_label_history(&update.req.search_key, *ver, ptr)?;
        }

        let new_size = start_size + 1;
        let auditor_pk_bytes = if self.config.mode == crate::crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING {
            self.config.auditor_keys.keys().next().map(|k| k.as_slice())
        } else { None };

        let tbs_data = construct_tree_head_tbs(
            &self.config, auditor_pk_bytes, new_size, &new_log_root
        )?;
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
        
        Ok((results_map.into_iter().map(|r| r.unwrap_or_else(|| Err(anyhow!("Internal error")))).collect(), th))
    }

    pub async fn post_update(&self, pre: PreUpdateData, post: PostUpdateData) -> Result<UpdateResponse> {
        let tree_size = post.tree_head.tree_head.as_ref().unwrap().tree_size;
        let insertion_log_index = tree_size - 1;
        let last = pre.req.consistency.as_ref().and_then(|c| c.last).unwrap_or(0);
        
        // The new version was returned in the SearchResult counter from apply_batch
        let new_version = post.search_result.counter;

        // Perform rigorous traversal according to Draft Section 9.1
        let combined_proof = self.traverse_update_verification(
            tree_size,
            insertion_log_index,
            &pre.req.search_key,
            new_version,
            last
        ).await?;

        let binary_ladder = vec![BinaryLadderStep {
            proof: pre.vrf_proof.clone(),
            commitment: Some(post.search_result.commitment),
        }];

        Ok(UpdateResponse {
            tree_head: Some(post.tree_head),
            binary_ladder,
            search: Some(combined_proof),
            opening: pre.opening,
        })
    }
}