use tonic::transport::Channel;
use crate::proto::kt::key_transparency_service_client::KeyTransparencyServiceClient;
use crate::proto::transparency::{
    TreeSearchRequest, UpdateRequest, SignedUpdateRequest,
    MonitorRequest, MonitorLabel, Consistency,
    UpdateResponse, TreeSearchResponse, MonitorResponse,
    FullTreeHead, FullTreeHeadType, PrefixProof,
};
use crate::crypto::{self, PublicConfig, ServiceVerifyingKey, construct_tree_head_tbs_public, verify_data, construct_vrf_input};
use crate::client::verifier::{LogVerifier, PrefixVerifier, CommitmentVerifier};
use crate::tree::log_math;
use crate::tree::binary_ladder::base_binary_ladder;
use anyhow::{Result, anyhow, Context};

#[derive(Clone, Debug)]
pub struct TrustedState {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub timestamp: u64,
}

pub struct KtClient {
    client: KeyTransparencyServiceClient<Channel>,
    sig_pk: ServiceVerifyingKey,
    vrf_pk: Vec<u8>,
    pub state: Option<TrustedState>,
    config: PublicConfig,
}

impl KtClient {
    pub async fn connect(dst: String, config: PublicConfig) -> Result<Self> {
        let client = KeyTransparencyServiceClient::connect(dst).await?;
        let sig_pk = ServiceVerifyingKey::from_bytes(&config.server_sig_pk)
            .context("Invalid server signing public key in PublicConfig")?;
        let vrf_pk = config.vrf_public_key.clone();

        Ok(Self {
            client,
            sig_pk,
            vrf_pk,
            state: None,
            config,
        })
    }

    pub async fn update(&mut self, user: Vec<u8>, value: Vec<u8>) -> Result<UpdateResponse> {
        let req = UpdateRequest {
            search_key: user.clone(),
            value: value.clone(),
            consistency: self.get_consistency_req(),
            expected_pre_update_value: vec![],
            return_update_response: true,
        };

        let signed_req = SignedUpdateRequest {
            request: Some(req),
            signature: vec![],
        };

        let resp = self.client.clone().update(signed_req).await?.into_inner();

        self.verify_update_response(&user, &value, &resp).await?;

        Ok(resp)
    }

    pub async fn search(&mut self, user: Vec<u8>, version: Option<u32>) -> Result<TreeSearchResponse> {
        let req = TreeSearchRequest {
            search_key: user.clone(),
            consistency: self.get_consistency_req(),
            version,
        };

        let resp = self.client.clone().search(req).await?.into_inner();

        self.verify_search_response(&user, version, &resp).await?;

        Ok(resp)
    }

    pub async fn monitor(&mut self, user: Vec<u8>, position: u64, version: u32) -> Result<MonitorResponse> {
        let req = MonitorRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            labels: vec![MonitorLabel {
                label: user.clone(),
                entries: vec![crate::proto::transparency::MonitorMapEntry {
                    position,
                    version,
                }],
                rightmost: None,
            }],
            consistency: self.get_consistency_req(),
        };

        let resp = self.client.clone().monitor(req).await?.into_inner();

        self.verify_monitor_response(&resp).await?;

        Ok(resp)
    }

    // --- Helpers ---

    fn get_consistency_req(&self) -> Option<Consistency> {
        // TODO: advertise `last` (§12) once retained subtree roots are cached client-side
        None
    }

    async fn verify_update_response(&mut self, label: &[u8], value: &[u8], resp: &UpdateResponse) -> Result<()> {
        let proof = resp.search.as_ref().ok_or(anyhow!("Missing search proof"))?;

        let ladder = &resp.binary_ladder;
        if ladder.is_empty() { return Err(anyhow!("Empty binary ladder")); }

        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        let th = fth.tree_head.as_ref().ok_or(anyhow!("Missing TreeHead"))?;

        if th.tree_size == 0 {
            return Err(anyhow!("Tree size is 0"));
        }

        let vrf_output = crypto::ecvrf_verify(
            self.config.cipher_suite,
            &self.vrf_pk,
            &construct_vrf_input(label, th.tree_size as u32 - 1).unwrap_or(vec![]),
            &ladder[0].proof
        ).context("VRF verification failed")?;
        let _ = vrf_output;

        let comm = ladder[0].commitment.as_ref().ok_or(anyhow!("Missing commitment"))?;
        CommitmentVerifier::verify(label, resp.version, value, &resp.opening, comm)?;

        if proof.prefix_proofs.is_empty() { return Err(anyhow!("Missing prefix proof")); }

        self.state = Some(TrustedState {
            tree_size: th.tree_size,
            root_hash: vec![0u8; 32],
            timestamp: th.timestamp as u64,
        });

        Ok(())
    }

    async fn verify_search_response(
        &mut self,
        label: &[u8],
        requested_version: Option<u32>,
        resp: &TreeSearchResponse,
    ) -> Result<()> {
        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        let proof = resp.search.as_ref().ok_or(anyhow!("Missing CombinedTreeProof"))?;

        let (tree_size, timestamp_opt, fth_is_updated) = self.tree_size_for_fth(fth)?;
        if tree_size == 0 {
            return Err(anyhow!("Server returned empty tree for search"));
        }

        // §10.5
        let value = resp.value.as_ref().ok_or(anyhow!("Missing UpdateValue"))?;

        let target_version: u32 = match requested_version {
            Some(v) => v,
            None => resp.version.ok_or_else(|| {
                anyhow!("Greatest-version search response missing TreeSearchResponse.version")
            })?,
        };

        let expected_versions = base_binary_ladder(target_version);
        if resp.binary_ladder.len() != expected_versions.len() {
            return Err(anyhow!(
                "Binary ladder length mismatch: got {}, expected {} for target v={}",
                resp.binary_ladder.len(), expected_versions.len(), target_version
            ));
        }

        let mut vrf_outputs: Vec<Vec<u8>> = Vec::with_capacity(expected_versions.len());
        for (i, ver) in expected_versions.iter().enumerate() {
            let vrf_input = construct_vrf_input(label, *ver)
                .context("VRF input construction failed")?;
            let out = crypto::ecvrf_verify(
                self.config.cipher_suite,
                &self.vrf_pk,
                &vrf_input,
                &resp.binary_ladder[i].proof,
            ).with_context(|| format!("Binary ladder VRF verify failed at v={}", ver))?;
            vrf_outputs.push(out.to_vec());
        }

        let target_idx = expected_versions.iter().position(|&v| v == target_version)
            .ok_or_else(|| anyhow!("Target version {} not in binary ladder", target_version))?;
        // §12.1: the target-version commitment is normally omitted; a server-sent one must match
        let target_commitment = crate::crypto::hash::commit(label, target_version, &value.value, &resp.opening)
            .context("Commitment computation failed")?;
        if let Some(server_comm) = &resp.binary_ladder[target_idx].commitment {
            if server_comm != &target_commitment {
                return Err(anyhow!(
                    "Target-version commitment mismatch: server-supplied does not open to provided value"
                ));
            }
        }

        // §11.3
        let mut prev_ts = 0u64;
        for &ts in &proof.timestamps {
            if ts < prev_ts {
                return Err(anyhow!("CombinedTreeProof: timestamps are not monotonic"));
            }
            prev_ts = ts;
        }
        // §11.3.1
        if let Some(&rightmost_ts) = proof.timestamps.last() {
            self.check_timestamp_bounds(rightmost_ts)
                .context("CombinedTreeProof: rightmost timestamp out of bounds")?;
        }

        let mut per_proof_roots: Vec<Vec<u8>> = Vec::with_capacity(proof.prefix_proofs.len());
        for (proof_idx, prefix_proof) in proof.prefix_proofs.iter().enumerate() {
            let root = verify_prefix_proof_consistent(
                prefix_proof,
                &expected_versions,
                &vrf_outputs,
                &resp.binary_ladder,
                target_idx,
                &target_commitment,
            ).with_context(|| format!("Prefix proof #{} verification failed", proof_idx))?;
            per_proof_roots.push(root);
        }

        // TODO: fixed-version log-root reconstruction requires simulating the IBST walk
        if fth_is_updated && requested_version.is_none() {
            let frontier = log_math::get_frontier(tree_size);
            if frontier.len() != per_proof_roots.len() {
                return Err(anyhow!(
                    "Greatest-version search: prefix_proofs count {} != frontier size {} for tree_size={}",
                    per_proof_roots.len(), frontier.len(), tree_size
                ));
            }
            if proof.timestamps.len() != frontier.len() {
                return Err(anyhow!(
                    "Greatest-version search: timestamps count {} != frontier size {} for tree_size={}",
                    proof.timestamps.len(), frontier.len(), tree_size
                ));
            }
            if !proof.prefix_roots.is_empty() {
                return Err(anyhow!(
                    "Greatest-version search: unexpected prefix_roots entries (expected 0)"
                ));
            }

            let mut visited = frontier.clone();
            visited.sort();

            let leaf_hashes: Vec<Vec<u8>> = visited.iter().enumerate().map(|(i, _)| {
                crate::crypto::hash::log_leaf_value(proof.timestamps[i], &per_proof_roots[i])
            }).collect();

            let inclusion = proof.inclusion.as_ref()
                .ok_or_else(|| anyhow!("Missing inclusion proof"))?;

            let candidate_root = LogVerifier::calculate_root(
                &visited,
                &leaf_hashes,
                tree_size,
                &inclusion.elements,
            ).context("Log tree root reconstruction failed")?;

            let th = fth.tree_head.as_ref()
                .ok_or_else(|| anyhow!("FullTreeHead.head_type=updated but TreeHead is missing"))?;
            self.verify_tree_head_signature(th, tree_size, &candidate_root)
                .context("TreeHead signature verification failed")?;

            self.state = Some(TrustedState {
                tree_size,
                root_hash: candidate_root,
                timestamp: timestamp_opt.unwrap_or(0),
            });
        }

        Ok(())
    }

    async fn verify_monitor_response(&mut self, resp: &MonitorResponse) -> Result<()> {
        let fth = resp.tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;

        // 1. Verify Tree Head State
        if let Some(th) = &fth.tree_head {
            if let Some(state) = &self.state {
                if th.tree_size < state.tree_size {
                    return Err(anyhow!("Server rolled back tree size in Monitor response"));
                }
            }
             // Update state if newer
             if self.state.is_none() || th.tree_size > self.state.as_ref().unwrap().tree_size {
                 self.state = Some(TrustedState {
                    tree_size: th.tree_size,
                    root_hash: vec![0u8; 32],
                    timestamp: th.timestamp as u64,
                });
            }
        }

        // 2. Verify CombinedTreeProof structure (Draft Section 11.3)
        if let Some(monitor_proof) = &resp.monitor {
            // Verify timestamps monotonicity
            let mut prev_ts = 0;
            for &ts in &monitor_proof.timestamps {
                if ts < prev_ts {
                    return Err(anyhow!("Monitor timestamps are not monotonic"));
                }
                prev_ts = ts;
            }

            // Must have inclusion proof for consistency
            if monitor_proof.inclusion.is_none() {
                return Err(anyhow!("Missing inclusion proof in monitor response"));
            }
        } else {
             return Err(anyhow!("Missing monitor proof"));
        }

        Ok(())
    }

    // --- FullTreeHead helpers ---

    // §10.4
    fn tree_size_for_fth(&self, fth: &FullTreeHead) -> Result<(u64, Option<u64>, bool)> {
        if fth.head_type == FullTreeHeadType::Same as i32 {
            let prev = self.state.as_ref().ok_or_else(|| {
                anyhow!("Server returned head_type=SAME but client has no previous tree head")
            })?;
            return Ok((prev.tree_size, Some(prev.timestamp), false));
        }
        if fth.head_type == FullTreeHeadType::Updated as i32 {
            let th = fth.tree_head.as_ref().ok_or_else(|| {
                anyhow!("FullTreeHead.head_type=updated but TreeHead is missing")
            })?;
            if let Some(prev) = &self.state {
                if th.tree_size < prev.tree_size {
                    return Err(anyhow!("Server rolled back tree size: {} < {}", th.tree_size, prev.tree_size));
                }
            }
            return Ok((th.tree_size, Some(th.timestamp as u64), true));
        }
        Err(anyhow!("Unknown FullTreeHeadType: {}", fth.head_type))
    }

    fn check_timestamp_bounds(&self, ts: u64) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(ts);
        if ts > now.saturating_add(self.config.max_ahead) {
            return Err(anyhow!("Tree head timestamp is too far ahead of local clock"));
        }
        if now > ts.saturating_add(self.config.max_behind) {
            return Err(anyhow!("Tree head timestamp is too far behind local clock"));
        }
        Ok(())
    }

    fn verify_tree_head_signature(
        &self,
        th: &crate::proto::transparency::TreeHead,
        tree_size: u64,
        root_hash: &[u8],
    ) -> Result<()> {
        if th.tree_size != tree_size {
            return Err(anyhow!("TreeHead.tree_size mismatch"));
        }
        if th.signatures.is_empty() {
            return Err(anyhow!("TreeHead has no signatures"));
        }
        let tbs = construct_tree_head_tbs_public(&self.config, None, tree_size, root_hash)
            .context("TreeHeadTBS construction failed")?;
        // signatures carries one entry per auditor plus the operator; any match under our pinned key suffices
        let mut last_err: Option<anyhow::Error> = None;
        for sig in &th.signatures {
            match verify_data(&self.sig_pk, &tbs, &sig.signature) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("No matching TreeHead signature")))
    }
}

fn verify_prefix_proof_consistent(
    prefix_proof: &PrefixProof,
    versions: &[u32],
    vrf_outputs: &[Vec<u8>],
    binary_ladder: &[crate::proto::transparency::BinaryLadderStep],
    target_idx: usize,
    target_commitment: &[u8],
) -> Result<Vec<u8>> {
    if prefix_proof.results.len() != versions.len() {
        return Err(anyhow!(
            "PrefixProof results count {} != binary ladder length {}",
            prefix_proof.results.len(), versions.len()
        ));
    }

    let mut elements_offset = 0usize;
    let mut computed_root: Option<Vec<u8>> = None;

    for (i, _) in versions.iter().enumerate() {
        let result = &prefix_proof.results[i];
        let result_type = result.result_type;

        // TODO: stop skipping once generate_ladder_proof emits real non-inclusion proofs
        if result_type != 1 && result.depth == 0 && result.leaf.is_none() {
            continue;
        }

        let commitment_bytes: Option<Vec<u8>> = if result_type == 1 {
            if i == target_idx {
                Some(target_commitment.to_vec())
            } else {
                Some(
                    binary_ladder[i].commitment.clone()
                        .ok_or_else(|| anyhow!(
                            "Inclusion result for v={} but binary ladder has no commitment",
                            versions[i]
                        ))?
                )
            }
        } else {
            None
        };

        let (root, consumed) = PrefixVerifier::compute_root_from_result(
            prefix_proof,
            i,
            &vrf_outputs[i],
            commitment_bytes.as_deref(),
            elements_offset,
        )?;
        elements_offset += consumed;

        match &computed_root {
            None => computed_root = Some(root),
            Some(prev) if prev == &root => {}
            Some(prev) => {
                return Err(anyhow!(
                    "PrefixProof results disagree on prefix-tree root (result {} vs prior): {} vs {}",
                    i, hex::encode(&root), hex::encode(prev)
                ));
            }
        }
    }

    if elements_offset != prefix_proof.elements.len() {
        return Err(anyhow!(
            "PrefixProof: {} unused proof elements", prefix_proof.elements.len() - elements_offset
        ));
    }

    computed_root.ok_or_else(|| anyhow!(
        "PrefixProof produced no verifiable root — server provided no inclusion or real non-inclusion entries"
    ))
}
