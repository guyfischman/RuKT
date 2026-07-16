use tonic::transport::Channel;
use crate::proto::kt::key_transparency_service_client::KeyTransparencyServiceClient;
use crate::proto::transparency::{
    SearchRequest, UpdateRequest, LabelValue,
    ContactMonitorRequest, ContactMonitorResponse,
    OwnerInitRequest, OwnerInitResponse,
    OwnerMonitorRequest, OwnerMonitorResponse,
    DistinguishedRequest, DistinguishedResponse,
    MonitorMapEntry, Consistency, CombinedTreeProof,
    UpdateResponse, SearchResponse,
    FullTreeHead, FullTreeHeadType, PrefixProof,
};
use std::collections::HashMap;
use crate::crypto::{self, PublicConfig, ServiceVerifyingKey, construct_tree_head_tbs_public, verify_data, construct_vrf_input};
use crate::client::verifier::{LogVerifier, PrefixVerifier};
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
    pub label_versions: HashMap<Vec<u8>, u32>,
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
            label_versions: HashMap::new(),
            config,
        })
    }

    pub async fn update(&mut self, user: Vec<u8>, value: Vec<u8>) -> Result<UpdateResponse> {
        // §13.5: a response with non-empty values means our request was disregarded;
        // absorb the reported versions and retry with the advanced greatest_version
        for _ in 0..32 {
            let greatest_version = self.label_versions.get(&user).copied();
            let req = UpdateRequest {
                last: self.get_consistency_req().and_then(|c| c.last),
                label: user.clone(),
                greatest_version,
                values: vec![LabelValue { value: value.clone() }],
            };

            let resp = self.client.clone().update(req).await?.into_inner();

            self.verify_update_response(&user, greatest_version, &[value.clone()], &resp).await?;

            let start = greatest_version.map(|v| v + 1).unwrap_or(0);
            if resp.values.is_empty() {
                self.label_versions.insert(user, start);
                return Ok(resp);
            }
            self.label_versions.insert(user.clone(), start + resp.values.len() as u32 - 1);
        }
        Err(anyhow!("Update did not converge while catching up on existing versions"))
    }

    pub async fn search(&mut self, user: Vec<u8>, version: Option<u32>) -> Result<SearchResponse> {
        let req = SearchRequest {
            last: self.get_consistency_req().and_then(|c| c.last),
            label: user.clone(),
            version,
        };

        let resp = self.client.clone().search(req).await?.into_inner();

        self.verify_search_response(&user, version, &resp).await?;

        if let (None, Some(greatest)) = (version, resp.version) {
            self.label_versions.insert(user, greatest);
        }

        Ok(resp)
    }

    pub async fn contact_monitor(&mut self, user: Vec<u8>, entries: Vec<(u64, u32)>) -> Result<ContactMonitorResponse> {
        let req = ContactMonitorRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            label: user,
            entries: entries.into_iter()
                .map(|(position, version)| MonitorMapEntry { position, version })
                .collect(),
        };

        let resp = self.client.clone().contact_monitor(req).await?.into_inner();

        self.verify_monitor_proof(resp.full_tree_head.as_ref(), resp.monitor.as_ref())?;

        Ok(resp)
    }

    pub async fn owner_init(&mut self, user: Vec<u8>, start: u64) -> Result<OwnerInitResponse> {
        let req = OwnerInitRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            label: user,
            start,
        };

        let resp = self.client.clone().owner_init(req).await?.into_inner();

        self.verify_monitor_proof(resp.full_tree_head.as_ref(), resp.init.as_ref())?;

        Ok(resp)
    }

    pub async fn distinguished(&mut self, stop: Option<u64>) -> Result<DistinguishedResponse> {
        let req = DistinguishedRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            stop,
        };

        let resp = self.client.clone().distinguished(req).await?.into_inner();

        self.verify_monitor_proof(resp.full_tree_head.as_ref(), resp.distinguished.as_ref())?;

        Ok(resp)
    }

    pub async fn owner_monitor(
        &mut self,
        user: Vec<u8>,
        entries: Vec<(u64, u32)>,
        start: u64,
        greatest_version: Option<u32>,
    ) -> Result<OwnerMonitorResponse> {
        let req = OwnerMonitorRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            label: user,
            entries: entries.into_iter()
                .map(|(position, version)| MonitorMapEntry { position, version })
                .collect(),
            start,
            greatest_version,
        };

        let resp = self.client.clone().owner_monitor(req).await?.into_inner();

        self.verify_monitor_proof(resp.full_tree_head.as_ref(), resp.monitor.as_ref())?;

        Ok(resp)
    }

    // --- Helpers ---

    fn get_consistency_req(&self) -> Option<Consistency> {
        // TODO: advertise `last` (§12) once retained subtree roots are cached client-side
        None
    }

    async fn verify_update_response(
        &mut self,
        label: &[u8],
        advertised_greatest: Option<u32>,
        sent_values: &[Vec<u8>],
        resp: &UpdateResponse,
    ) -> Result<()> {
        let proof = resp.update.as_ref().ok_or(anyhow!("Missing update proof"))?;
        let fth = resp.full_tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        let th = fth.tree_head.as_ref().ok_or(anyhow!("Missing TreeHead"))?;

        if th.tree_size == 0 {
            return Err(anyhow!("Tree size is 0"));
        }
        if resp.position >= th.tree_size {
            return Err(anyhow!("Insertion position {} outside tree of size {}", resp.position, th.tree_size));
        }

        // §13.5 step 2: non-empty response values mean the request was disregarded
        // and info describes those versions instead of ours
        let effective_values: Vec<&[u8]> = if resp.values.is_empty() {
            sent_values.iter().map(|v| v.as_slice()).collect()
        } else {
            resp.values.iter().map(|lv| lv.value.as_slice()).collect()
        };
        if resp.info.is_empty() {
            return Err(anyhow!("Empty UpdateResponse.info"));
        }
        if resp.info.len() != effective_values.len() {
            return Err(anyhow!("info length {} != covered values {}", resp.info.len(), effective_values.len()));
        }

        // §13.5 step 4
        if resp.binary_ladder.len() != effective_values.len() {
            return Err(anyhow!("Binary ladder length {} != covered versions {}", resp.binary_ladder.len(), effective_values.len()));
        }
        let start_ver = advertised_greatest.map(|v| v + 1).unwrap_or(0);
        for (k, step) in resp.binary_ladder.iter().enumerate() {
            let ver = start_ver + k as u32;
            let vrf_input = construct_vrf_input(label, ver)
                .context("VRF input construction failed")?;
            crypto::ecvrf_verify(self.config.cipher_suite, &self.vrf_pk, &vrf_input, &step.proof)
                .with_context(|| format!("Update ladder VRF verify failed at v={}", ver))?;
            if step.commitment.is_some() {
                return Err(anyhow!("Commitment provided for v={} greater than advertised greatest_version", ver));
            }
        }

        for (k, info) in resp.info.iter().enumerate() {
            let ver = start_ver + k as u32;
            crate::crypto::hash::commit(label, ver, effective_values[k], &info.opening)
                .with_context(|| format!("Commitment recompute failed at v={}", ver))?;
        }

        if proof.prefix_proofs.is_empty() { return Err(anyhow!("Missing prefix proof")); }

        // TODO: §9.1 proof verification, candidate-root reconstruction, head signature
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
        resp: &SearchResponse,
    ) -> Result<()> {
        let fth = resp.full_tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
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
        let proof_count = proof.prefix_proofs.len();
        for (proof_idx, prefix_proof) in proof.prefix_proofs.iter().enumerate() {
            // §6.3 step 2 applies per entry for greatest-version searches; the full
            // check (every v <= target included) applies at the rightmost entry only
            let greatest = requested_version.is_none();
            let root = verify_prefix_proof_consistent(
                prefix_proof,
                &expected_versions,
                &vrf_outputs,
                &resp.binary_ladder,
                target_idx,
                &target_commitment,
                greatest,
                greatest && proof_idx == proof_count - 1,
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

    fn verify_monitor_proof(
        &mut self,
        fth: Option<&FullTreeHead>,
        proof: Option<&CombinedTreeProof>,
    ) -> Result<()> {
        let fth = fth.ok_or(anyhow!("Missing FullTreeHead"))?;

        if let Some(th) = &fth.tree_head {
            if let Some(state) = &self.state {
                if th.tree_size < state.tree_size {
                    return Err(anyhow!("Server rolled back tree size in monitor response"));
                }
            }
            if self.state.is_none() || th.tree_size > self.state.as_ref().unwrap().tree_size {
                self.state = Some(TrustedState {
                    tree_size: th.tree_size,
                    root_hash: vec![0u8; 32],
                    timestamp: th.timestamp as u64,
                });
            }
        }

        let proof = proof.ok_or(anyhow!("Missing monitor proof"))?;
        // §12.3
        let mut prev_ts = 0;
        for &ts in &proof.timestamps {
            if ts < prev_ts {
                return Err(anyhow!("Monitor timestamps are not monotonic"));
            }
            prev_ts = ts;
        }
        if proof.inclusion.is_none() {
            return Err(anyhow!("Missing inclusion proof in monitor response"));
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
    require_upper_non_inclusion: bool,
    require_lower_inclusion: bool,
) -> Result<Vec<u8>> {
    if prefix_proof.results.len() != versions.len() {
        return Err(anyhow!(
            "PrefixProof results count {} != binary ladder length {}",
            prefix_proof.results.len(), versions.len()
        ));
    }

    let target_version = versions[target_idx];
    let mut elements_offset = 0usize;
    let mut computed_root: Option<Vec<u8>> = None;

    for (i, &v) in versions.iter().enumerate() {
        let result = &prefix_proof.results[i];
        let is_inclusion = result.result_type == 1;

        // §6.3 step 2
        if require_upper_non_inclusion && v > target_version && is_inclusion {
            return Err(anyhow!("Inclusion proof for v={} contradicts claimed greatest version {}", v, target_version));
        }
        if require_lower_inclusion && v <= target_version && !is_inclusion {
            return Err(anyhow!("Non-inclusion proof for v={} at the rightmost entry contradicts claimed greatest version {}", v, target_version));
        }

        let commitment_bytes: Option<Vec<u8>> = if is_inclusion {
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

    computed_root.ok_or_else(|| anyhow!("PrefixProof contained no results"))
}
