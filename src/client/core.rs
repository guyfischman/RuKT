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
use std::collections::{BTreeMap, HashMap};
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

// §13: users retain the most recent verified TreeHead and AuditorTreeHead
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PersistedState {
    tree_size: u64,
    root_hash: String,
    timestamp: u64,
    auditor_head: Option<(u64, u64)>,
    label_versions: Vec<(String, u32)>,
    retained_subtrees: Vec<(u64, String)>,
    #[serde(default)]
    monitoring_map: Vec<(String, Vec<(u64, u32)>)>,
    #[serde(default)]
    version_material: Vec<(String, Vec<(u32, String, Option<String>)>)>,
}

pub struct KtClient {
    client: KeyTransparencyServiceClient<Channel>,
    sig_pk: ServiceVerifyingKey,
    vrf_pk: Vec<u8>,
    pub state: Option<TrustedState>,
    pub label_versions: HashMap<Vec<u8>, u32>,
    pub retained_subtrees: BTreeMap<u64, Vec<u8>>,
    pub auditor_head: Option<(u64, u64)>,
    // §8.2 monitoring map plus the vrf outputs and commitments needed to re-verify
    pub monitoring_map: HashMap<Vec<u8>, BTreeMap<u64, u32>>,
    version_material: HashMap<Vec<u8>, HashMap<u32, (Vec<u8>, Option<Vec<u8>>)>>,
    state_path: Option<std::path::PathBuf>,
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
            retained_subtrees: BTreeMap::new(),
            auditor_head: None,
            monitoring_map: HashMap::new(),
            version_material: HashMap::new(),
            state_path: None,
            config,
        })
    }

    /// Loads any previously persisted state from `path` and saves verified state
    /// changes back to it from then on.
    pub fn persist_to(&mut self, path: impl Into<std::path::PathBuf>) -> Result<()> {
        let path = path.into();
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let p: PersistedState = serde_json::from_str(&data)?;
            if p.tree_size > 0 {
                self.state = Some(TrustedState {
                    tree_size: p.tree_size,
                    root_hash: hex::decode(&p.root_hash)?,
                    timestamp: p.timestamp,
                });
            }
            self.auditor_head = p.auditor_head;
            self.label_versions = p.label_versions.into_iter()
                .map(|(l, v)| Ok((hex::decode(&l)?, v)))
                .collect::<Result<_>>()?;
            self.retained_subtrees = p.retained_subtrees.into_iter()
                .map(|(n, h)| Ok((n, hex::decode(&h)?)))
                .collect::<Result<_>>()?;
            self.monitoring_map = p.monitoring_map.into_iter()
                .map(|(l, m)| Ok((hex::decode(&l)?, m.into_iter().collect())))
                .collect::<Result<_>>()?;
            self.version_material = p.version_material.into_iter()
                .map(|(l, vs)| {
                    let inner = vs.into_iter()
                        .map(|(v, vrf, comm)| Ok((v, (hex::decode(&vrf)?, comm.map(|c| hex::decode(&c)).transpose()?))))
                        .collect::<Result<_>>()?;
                    Ok((hex::decode(&l)?, inner))
                })
                .collect::<Result<_>>()?;
        }
        self.state_path = Some(path);
        Ok(())
    }

    fn save_state(&self) -> Result<()> {
        let Some(path) = &self.state_path else { return Ok(()) };
        let p = PersistedState {
            tree_size: self.state.as_ref().map(|s| s.tree_size).unwrap_or(0),
            root_hash: self.state.as_ref().map(|s| hex::encode(&s.root_hash)).unwrap_or_default(),
            timestamp: self.state.as_ref().map(|s| s.timestamp).unwrap_or(0),
            auditor_head: self.auditor_head,
            label_versions: self.label_versions.iter().map(|(l, v)| (hex::encode(l), *v)).collect(),
            retained_subtrees: self.retained_subtrees.iter().map(|(n, h)| (*n, hex::encode(h))).collect(),
            monitoring_map: self.monitoring_map.iter()
                .map(|(l, m)| (hex::encode(l), m.iter().map(|(&p, &v)| (p, v)).collect()))
                .collect(),
            version_material: self.version_material.iter()
                .map(|(l, vs)| (
                    hex::encode(l),
                    vs.iter().map(|(&v, (vrf, comm))| (v, hex::encode(vrf), comm.as_ref().map(hex::encode))).collect(),
                ))
                .collect(),
        };
        std::fs::write(path, serde_json::to_string(&p)?)?;
        Ok(())
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
                self.save_state()?;
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
            self.save_state()?;
        }

        Ok(resp)
    }

    // §13.2: monitors every obligation in the label's monitoring map
    pub async fn contact_monitor(&mut self, user: Vec<u8>) -> Result<ContactMonitorResponse> {
        let map = self.monitoring_map.get(&user).cloned().unwrap_or_default();
        if map.is_empty() {
            return Err(anyhow!("No monitoring obligations recorded for this label"));
        }

        let req = ContactMonitorRequest {
            last: self.state.as_ref().map(|s| s.tree_size),
            label: user.clone(),
            entries: map.iter()
                .map(|(&position, &version)| MonitorMapEntry { position, version })
                .collect(),
        };

        let resp = self.client.clone().contact_monitor(req).await?.into_inner();

        self.verify_contact_monitor(&user, &map, &resp)?;
        self.save_state()?;

        Ok(resp)
    }

    // §8.2 replay
    fn verify_contact_monitor(
        &mut self,
        label: &[u8],
        map: &BTreeMap<u64, u32>,
        resp: &ContactMonitorResponse,
    ) -> Result<()> {
        let fth = resp.full_tree_head.as_ref().ok_or(anyhow!("Missing FullTreeHead"))?;
        let proof = resp.monitor.as_ref().ok_or(anyhow!("Missing monitor proof"))?;

        let (tree_size, timestamp_opt, fth_is_updated) = self.tree_size_for_fth(fth)?;
        if tree_size == 0 {
            return Err(anyhow!("Cannot monitor an empty tree"));
        }
        if fth_is_updated {
            if let Some(head_ts) = timestamp_opt {
                self.check_timestamp_bounds(head_ts)
                    .context("TreeHead timestamp out of bounds")?;
            }
        }

        let material = self.version_material.get(label).cloned().unwrap_or_default();
        let rmw = self.config.reasonable_monitoring_window;

        let mut reader = ProofReader::new(proof);
        let frontier = log_math::get_frontier(tree_size);
        for &f in &frontier {
            reader.timestamp(f)?;
        }
        let rightmost_ts = reader.timestamp(tree_size - 1)?;

        let mut entry_roots: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut new_map = map.clone();
        let mut ladder_targets: HashMap<u64, u32> = HashMap::new();

        for (&pos, &ver) in map.iter().rev() {
            let mut bounds = (0u64, rightmost_ts);
            let mut parent_dist = true;
            let mut ancestor_dist: HashMap<u64, bool> = HashMap::new();
            let mut curr = log_math::root(tree_size);
            while curr != pos {
                let ts = reader.timestamp(curr)?;
                let dist = parent_dist && bounds.1.saturating_sub(bounds.0) >= rmw;
                ancestor_dist.insert(curr, dist);
                if !dist {
                    parent_dist = false;
                    break;
                }
                if pos < curr {
                    bounds.1 = ts;
                    curr = log_math::left_child(curr);
                } else {
                    bounds.0 = ts;
                    curr = match log_math::ibst_right_child(curr, tree_size) {
                        Some(rc) => rc,
                        None => break,
                    };
                }
            }
            let pos_dist = parent_dist && curr == pos
                && bounds.1.saturating_sub(bounds.0) >= rmw;

            // step 1 + final map cleanup: a distinguished entry needs no monitoring
            if pos_dist {
                new_map.remove(&pos);
                continue;
            }

            // step 2
            let mut list: Vec<u64> = log_math::ibst_direct_path(pos, tree_size)
                .into_iter()
                .filter(|&a| a > pos)
                .collect();
            list.sort();
            if let Some(cut) = list.iter().position(|a| *ancestor_dist.get(a).unwrap_or(&false)) {
                list.truncate(cut + 1);
            }

            // step 3
            let mut moved_to: Option<u64> = None;
            for &e in &list {
                if let Some(&t) = ladder_targets.get(&e) {
                    if t > ver {
                        new_map.remove(&pos);
                        moved_to = None;
                    } else {
                        return Err(anyhow!(
                            "Entry {} already covered by a ladder with non-greater target {}", e, t
                        ));
                    }
                    break;
                }
                let pp = reader.prefix_proof(e)?;
                let root = self.verify_monitoring_ladder(&material, pp, ver)
                    .with_context(|| format!("Monitoring ladder failed at entry {}", e))?;
                record_entry_root(&mut entry_roots, e, root)?;
                ladder_targets.insert(e, ver);
                moved_to = Some(e);
            }

            if let Some(newpos) = moved_to {
                new_map.remove(&pos);
                if !*ancestor_dist.get(&newpos).unwrap_or(&false) {
                    new_map.insert(newpos, ver);
                }
            }
        }

        let leaf_data = reader.finish(&entry_roots)?;
        let positions: Vec<u64> = leaf_data.iter().map(|(p, _, _)| *p).collect();
        let leaf_hashes: Vec<Vec<u8>> = leaf_data.iter()
            .map(|(_, ts, root)| crate::crypto::hash::log_leaf_value(*ts, root))
            .collect();
        let inclusion = proof.inclusion.as_ref()
            .ok_or_else(|| anyhow!("Missing inclusion proof"))?;

        let (candidate_root, new_peaks) = LogVerifier::calculate_root_with_retained(
            &positions, &leaf_hashes, tree_size, &inclusion.elements, &self.retained_subtrees,
        ).context("Log tree root reconstruction failed")?;

        if fth_is_updated {
            let th = fth.tree_head.as_ref()
                .ok_or_else(|| anyhow!("FullTreeHead.head_type=updated but TreeHead is missing"))?;
            self.verify_tree_head_signature(th, tree_size, &candidate_root)
                .context("TreeHead signature verification failed")?;
            if self.config.mode == crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING {
                self.verify_auditor_tree_head(fth, th, tree_size, &candidate_root)
                    .context("AuditorTreeHead verification failed")?;
            }
            self.state = Some(TrustedState {
                tree_size,
                root_hash: candidate_root,
                timestamp: timestamp_opt.unwrap_or(0),
            });
            self.retained_subtrees = new_peaks;
        } else {
            let prev = self.state.as_ref()
                .ok_or_else(|| anyhow!("SAME head without previous state"))?;
            if candidate_root != prev.root_hash {
                return Err(anyhow!("SAME head but proofs do not reconstruct the retained root"));
            }
        }

        self.monitoring_map.insert(label.to_vec(), new_map);
        Ok(())
    }

    // §8.2 step 3.2: every monitoring-ladder lookup must show inclusion, folded
    // with the vrf outputs and commitments retained from earlier searches
    fn verify_monitoring_ladder(
        &self,
        material: &HashMap<u32, (Vec<u8>, Option<Vec<u8>>)>,
        prefix_proof: &PrefixProof,
        target: u32,
    ) -> Result<Vec<u8>> {
        let versions = crate::tree::binary_ladder::monitoring_binary_ladder(target, &[]);
        if prefix_proof.results.len() != versions.len() {
            return Err(anyhow!(
                "Monitoring ladder has {} results, expected {}",
                prefix_proof.results.len(), versions.len()
            ));
        }

        let mut elements_offset = 0usize;
        let mut computed_root: Option<Vec<u8>> = None;

        for (j, &v) in versions.iter().enumerate() {
            if prefix_proof.results[j].result_type != 1 {
                return Err(anyhow!("Monitoring lookup for v={} is not an inclusion proof", v));
            }
            let (vrf_output, commitment) = material.get(&v)
                .ok_or_else(|| anyhow!("No retained material for v={}", v))?;
            let commitment = commitment.as_ref()
                .ok_or_else(|| anyhow!("No retained commitment for v={}", v))?;

            let (root, consumed) = PrefixVerifier::compute_root_from_result(
                prefix_proof, j, vrf_output, Some(commitment), elements_offset,
            )?;
            elements_offset += consumed;

            match &computed_root {
                None => computed_root = Some(root),
                Some(prev) if prev == &root => {}
                Some(_) => return Err(anyhow!("Monitoring ladder results disagree on prefix-tree root")),
            }
        }

        if elements_offset != prefix_proof.elements.len() {
            return Err(anyhow!("Monitoring ladder has unused proof elements"));
        }
        computed_root.ok_or_else(|| anyhow!("Monitoring ladder contained no results"))
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
        self.state.as_ref().map(|s| Consistency { last: Some(s.tree_size), distinguished: None })
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

        // TODO: §9.1 proof verification and candidate-root reconstruction; until then
        // updates leave the trusted state alone rather than storing an unverified head
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

        let greatest = requested_version.is_none();

        // §13.1: the wire ladder lists versions in §5 output order for the target
        let mut wire_index: HashMap<u32, usize> = HashMap::new();
        if greatest {
            let base = base_binary_ladder(target_version);
            if resp.binary_ladder.len() != base.len() {
                return Err(anyhow!(
                    "Binary ladder length mismatch: got {}, expected {} for target v={}",
                    resp.binary_ladder.len(), base.len(), target_version
                ));
            }
            for (i, &v) in base.iter().enumerate() {
                wire_index.insert(v, i);
            }
        }

        // §12.1: the target-version commitment is omitted; a server-sent one must match
        let target_commitment = crate::crypto::hash::commit(label, target_version, &value.value, &resp.opening)
            .context("Commitment computation failed")?;

        // §11.4
        if fth_is_updated {
            if let Some(head_ts) = timestamp_opt {
                self.check_timestamp_bounds(head_ts)
                    .context("TreeHead timestamp out of bounds")?;
            }
        }

        let mut vrf_cache: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut reader = ProofReader::new(proof);
        let frontier = log_math::get_frontier(tree_size);

        // §12.3.1
        for &f in &frontier {
            reader.timestamp(f)?;
        }

        let mut entry_roots: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut material: HashMap<u32, Option<Vec<u8>>> = HashMap::new();
        let terminal: u64;

        if greatest {
            // §6.3
            let rightmost = *frontier.last().unwrap();
            let mut first_equal: Option<u64> = None;
            for &entry in &frontier {
                let pp = reader.prefix_proof(entry)?;
                let (root, relation) = self.verify_ladder_proof(
                    label, pp, target_version, &mut wire_index, &mut vrf_cache,
                    &resp.binary_ladder, &target_commitment, true, entry == rightmost,
                    &mut material,
                ).with_context(|| format!("Ladder verification failed at entry {}", entry))?;
                record_entry_root(&mut entry_roots, entry, root)?;
                if relation == std::cmp::Ordering::Equal && first_equal.is_none() {
                    first_equal = Some(entry);
                }
            }
            terminal = first_equal.unwrap_or(rightmost);
        } else {
            terminal = self.simulate_fixed_search(
                label, tree_size, target_version, &mut reader,
                &mut wire_index, &mut vrf_cache, resp, &target_commitment, &mut entry_roots,
                &mut material,
            )?;
        }

        if resp.binary_ladder.len() != wire_index.len() {
            return Err(anyhow!(
                "Binary ladder has {} steps but only {} versions were looked up",
                resp.binary_ladder.len(), wire_index.len()
            ));
        }

        // §12.3: exact queue consumption; proof-less entries surface prefix roots
        let leaf_data = reader.finish(&entry_roots)?;

        let positions: Vec<u64> = leaf_data.iter().map(|(p, _, _)| *p).collect();
        let leaf_hashes: Vec<Vec<u8>> = leaf_data.iter()
            .map(|(_, ts, root)| crate::crypto::hash::log_leaf_value(*ts, root))
            .collect();

        let inclusion = proof.inclusion.as_ref()
            .ok_or_else(|| anyhow!("Missing inclusion proof"))?;

        let (candidate_root, new_peaks) = LogVerifier::calculate_root_with_retained(
            &positions, &leaf_hashes, tree_size, &inclusion.elements, &self.retained_subtrees,
        ).context("Log tree root reconstruction failed")?;

        if fth_is_updated {
            let th = fth.tree_head.as_ref()
                .ok_or_else(|| anyhow!("FullTreeHead.head_type=updated but TreeHead is missing"))?;
            self.verify_tree_head_signature(th, tree_size, &candidate_root)
                .context("TreeHead signature verification failed")?;

            if self.config.mode == crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING {
                self.verify_auditor_tree_head(fth, th, tree_size, &candidate_root)
                    .context("AuditorTreeHead verification failed")?;
            }

            self.state = Some(TrustedState {
                tree_size,
                root_hash: candidate_root,
                timestamp: timestamp_opt.unwrap_or(0),
            });
            self.retained_subtrees = new_peaks;
            self.save_state()?;
        } else {
            // SAME: the reconstruction must land exactly on the retained root
            let prev = self.state.as_ref()
                .ok_or_else(|| anyhow!("SAME head without previous state"))?;
            if candidate_root != prev.root_hash {
                return Err(anyhow!("SAME head but proofs do not reconstruct the retained root"));
            }
        }

        // §8.2: the terminal entry enters the monitoring map, with the material
        // needed to re-verify monitoring ladders later
        let stash = self.version_material.entry(label.to_vec()).or_default();
        for (v, comm) in material {
            if let Some(out) = vrf_cache.get(&v) {
                stash.insert(v, (out.clone(), comm));
            }
        }
        self.monitoring_map.entry(label.to_vec()).or_default()
            .insert(terminal, target_version);

        Ok(())
    }

    /// Verifies one search binary ladder PrefixProof: VRF per lookup, commitment
    /// rules, per-entry root consistency. Returns the prefix root and how the
    /// entry's greatest version relates to the target.
    fn verify_ladder_proof(
        &self,
        label: &[u8],
        prefix_proof: &PrefixProof,
        target_version: u32,
        wire_index: &mut HashMap<u32, usize>,
        vrf_cache: &mut HashMap<u32, Vec<u8>>,
        binary_ladder: &[crate::proto::transparency::BinaryLadderStep],
        target_commitment: &[u8],
        greatest: bool,
        is_rightmost: bool,
        material: &mut HashMap<u32, Option<Vec<u8>>>,
    ) -> Result<(Vec<u8>, std::cmp::Ordering)> {
        let decoded = decode_search_ladder(&prefix_proof.results, target_version)
            .context("Ladder decode failed")?;

        let mut relation = std::cmp::Ordering::Equal;
        let mut elements_offset = 0usize;
        let mut computed_root: Option<Vec<u8>> = None;

        for (j, lk) in decoded.iter().enumerate() {
            if lk.inclusion && lk.version > target_version {
                // §6.3 step 2
                if greatest {
                    return Err(anyhow!(
                        "Inclusion proof for v={} contradicts claimed greatest version {}",
                        lk.version, target_version
                    ));
                }
                relation = std::cmp::Ordering::Greater;
            }
            if !lk.inclusion && lk.version <= target_version {
                if greatest && is_rightmost {
                    return Err(anyhow!(
                        "Non-inclusion proof for v={} at the rightmost entry contradicts claimed greatest version {}",
                        lk.version, target_version
                    ));
                }
                relation = std::cmp::Ordering::Less;
            }

            let next_slot = wire_index.len();
            let wi = *wire_index.entry(lk.version).or_insert(next_slot);
            let step = binary_ladder.get(wi)
                .ok_or_else(|| anyhow!("Ladder step missing for v={}", lk.version))?;

            if !vrf_cache.contains_key(&lk.version) {
                let vrf_input = construct_vrf_input(label, lk.version)
                    .context("VRF input construction failed")?;
                let out = crypto::ecvrf_verify(
                    self.config.cipher_suite,
                    &self.vrf_pk,
                    &vrf_input,
                    &step.proof,
                ).with_context(|| format!("Binary ladder VRF verify failed at v={}", lk.version))?;
                vrf_cache.insert(lk.version, out.to_vec());
            }

            let commitment: Option<Vec<u8>> = if lk.inclusion {
                if lk.version == target_version {
                    if let Some(server_comm) = &step.commitment {
                        if server_comm != target_commitment {
                            return Err(anyhow!(
                                "Target-version commitment mismatch: server-supplied does not open to provided value"
                            ));
                        }
                    }
                    Some(target_commitment.to_vec())
                } else {
                    Some(step.commitment.clone().ok_or_else(|| anyhow!(
                        "Inclusion result for v={} but binary ladder has no commitment", lk.version
                    ))?)
                }
            } else {
                // only a greatest-version claim makes versions above the target globally absent
                if greatest && step.commitment.is_some() && lk.version > target_version {
                    return Err(anyhow!("Commitment provided for non-existent v={}", lk.version));
                }
                None
            };

            if lk.inclusion {
                material.insert(lk.version, commitment.clone());
            }

            let (root, consumed) = PrefixVerifier::compute_root_from_result(
                prefix_proof,
                j,
                &vrf_cache[&lk.version],
                commitment.as_deref(),
                elements_offset,
            )?;
            elements_offset += consumed;

            match &computed_root {
                None => computed_root = Some(root),
                Some(prev) if prev == &root => {}
                Some(prev) => {
                    return Err(anyhow!(
                        "PrefixProof results disagree on prefix-tree root: {} vs {}",
                        hex::encode(&root), hex::encode(prev)
                    ));
                }
            }
        }

        if elements_offset != prefix_proof.elements.len() {
            return Err(anyhow!(
                "PrefixProof: {} unused proof elements",
                prefix_proof.elements.len() - elements_offset
            ));
        }

        if greatest && is_rightmost {
            let base = base_binary_ladder(target_version);
            let seen: Vec<u32> = decoded.iter().map(|lk| lk.version).collect();
            if seen != base {
                return Err(anyhow!(
                    "Rightmost entry ladder incomplete: expected full base ladder for v={}",
                    target_version
                ));
            }
        }

        let root = computed_root.ok_or_else(|| anyhow!("PrefixProof contained no results"))?;
        Ok((root, relation))
    }

    // §7.2 step 6.3
    fn verify_single_lookup(
        &self,
        label: &[u8],
        prefix_proof: &PrefixProof,
        version: u32,
        wire_index: &mut HashMap<u32, usize>,
        vrf_cache: &mut HashMap<u32, Vec<u8>>,
        binary_ladder: &[crate::proto::transparency::BinaryLadderStep],
        target_commitment: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        if prefix_proof.results.len() != 1 {
            return Err(anyhow!("Expected a single-lookup PrefixProof, got {} results", prefix_proof.results.len()));
        }
        let inclusion = prefix_proof.results[0].result_type == 1;

        let next_slot = wire_index.len();
        let wi = *wire_index.entry(version).or_insert(next_slot);
        let step = binary_ladder.get(wi)
            .ok_or_else(|| anyhow!("Ladder step missing for v={}", version))?;
        if !vrf_cache.contains_key(&version) {
            let vrf_input = construct_vrf_input(label, version)?;
            let out = crypto::ecvrf_verify(self.config.cipher_suite, &self.vrf_pk, &vrf_input, &step.proof)
                .with_context(|| format!("VRF verify failed at v={}", version))?;
            vrf_cache.insert(version, out.to_vec());
        }

        let commitment = inclusion.then(|| target_commitment.to_vec());
        let (root, consumed) = PrefixVerifier::compute_root_from_result(
            prefix_proof, 0, &vrf_cache[&version], commitment.as_deref(), 0,
        )?;
        if consumed != prefix_proof.elements.len() {
            return Err(anyhow!("Single-lookup PrefixProof has unused elements"));
        }
        Ok((root, inclusion))
    }

    // §7.2
    fn simulate_fixed_search(
        &self,
        label: &[u8],
        tree_size: u64,
        target_version: u32,
        reader: &mut ProofReader,
        wire_index: &mut HashMap<u32, usize>,
        vrf_cache: &mut HashMap<u32, Vec<u8>>,
        resp: &SearchResponse,
        target_commitment: &[u8],
        entry_roots: &mut BTreeMap<u64, Vec<u8>>,
        material: &mut HashMap<u32, Option<Vec<u8>>>,
    ) -> Result<u64> {
        let rightmost_ts = reader.timestamp(tree_size - 1)?;
        let max_life = self.config.maximum_lifetime;
        let rmw = self.config.reasonable_monitoring_window;
        let is_expired = |ts: u64| max_life.map_or(false, |ml| rightmost_ts.saturating_sub(ts) >= ml);

        let mut curr = log_math::root(tree_size);
        // §6.1 selection interval, tracked along the walk
        let mut bounds = (0u64, rightmost_ts);
        let mut parent_dist = true;
        let mut expired_on_path = false;
        let mut encountered_expired = false;
        // walked entries left of the current path: (position, unexpired-and-distinguished)
        let mut left_path: Vec<(u64, bool)> = Vec::new();
        let mut inspected: Vec<(u64, std::cmp::Ordering)> = Vec::new();
        let mut terminal: Option<u64> = None;

        loop {
            let ts = reader.timestamp(curr)?;
            let is_dist = parent_dist && bounds.1.saturating_sub(bounds.0) >= rmw;
            let right_child = if log_math::is_leaf(curr) { None } else { log_math::ibst_right_child(curr, tree_size) };

            // step 1
            if is_expired(ts) {
                encountered_expired = true;
                expired_on_path = true;
                match right_child {
                    Some(rc) => {
                        left_path.push((curr, false));
                        bounds.0 = ts;
                        parent_dist = is_dist;
                        curr = rc;
                        continue;
                    }
                    None => break,
                }
            }

            // step 2
            let pp = reader.prefix_proof(curr)?;
            let (root, relation) = self.verify_ladder_proof(
                label, pp, target_version, wire_index, vrf_cache,
                &resp.binary_ladder, target_commitment, false, false, material,
            ).with_context(|| format!("Ladder verification failed at entry {}", curr))?;
            record_entry_root(entry_roots, curr, root)?;
            inspected.push((curr, relation));

            match relation {
                // step 3
                std::cmp::Ordering::Less => match right_child {
                    Some(rc) => {
                        left_path.push((curr, is_dist && !is_expired(ts)));
                        bounds.0 = ts;
                        parent_dist = is_dist;
                        curr = rc;
                    }
                    None => break,
                },
                // step 4
                std::cmp::Ordering::Greater => {
                    if log_math::is_leaf(curr) { break; }
                    bounds.1 = ts;
                    parent_dist = is_dist;
                    curr = log_math::left_child(curr);
                }
                // step 5
                std::cmp::Ordering::Equal => {
                    if !expired_on_path
                        || is_dist
                        || left_path.iter().any(|&(_, d)| d)
                    {
                        terminal = Some(curr);
                        break;
                    }
                    return Err(anyhow!("Requested version of the label is expired"));
                }
            }
        }

        // step 6
        if terminal.is_none() {
            let identified = inspected.iter()
                .filter(|&&(_, r)| r == std::cmp::Ordering::Greater)
                .map(|&(p, _)| p)
                .min()
                .ok_or_else(|| anyhow!("Requested version of the label does not exist"))?;

            if encountered_expired {
                // conservative: only entries on the walked path are decidable
                let covered = left_path.iter().any(|&(p, d)| p < identified && d);
                if !covered {
                    return Err(anyhow!("Requested version of the label is expired"));
                }
            }

            let pp = reader.prefix_proof(identified)?;
            let (root, included) = self.verify_single_lookup(
                label, pp, target_version, wire_index, vrf_cache,
                &resp.binary_ladder, target_commitment,
            ).with_context(|| format!("Target-version lookup failed at entry {}", identified))?;
            record_entry_root(entry_roots, identified, root)?;

            if !included {
                return Err(anyhow!("Requested version of the label does not exist"));
            }
            terminal = Some(identified);
        }

        Ok(terminal.unwrap())
    }

    // §11.3
    fn verify_auditor_tree_head(
        &mut self,
        fth: &FullTreeHead,
        th: &crate::proto::transparency::TreeHead,
        tree_size: u64,
        candidate_root: &[u8],
    ) -> Result<()> {
        let ath = fth.auditor_tree_head.as_ref()
            .ok_or_else(|| anyhow!("Missing AuditorTreeHead in third-party-auditing mode"))?;

        // step 1
        if let Some((prev_auditor_size, _)) = self.auditor_head {
            if prev_auditor_size < self.config.auditor_start_pos {
                return Err(anyhow!("Auditor started after the previously verified auditor position"));
            }
        }
        // step 2
        let rightmost_ts = th.timestamp as u64;
        let auditor_ts = ath.timestamp as u64;
        if auditor_ts > rightmost_ts {
            return Err(anyhow!("Auditor timestamp is ahead of the rightmost log entry"));
        }
        if rightmost_ts - auditor_ts > self.config.max_auditor_lag {
            return Err(anyhow!("Auditor tree head exceeds max_auditor_lag"));
        }
        // step 3
        if ath.tree_size > th.tree_size {
            return Err(anyhow!("Auditor tree size exceeds the log's tree size"));
        }

        // step 4
        if ath.tree_size == tree_size {
            let tbs = crypto::construct_auditor_tree_head_tbs_public(
                &self.config, ath.tree_size, auditor_ts, candidate_root,
            ).context("AuditorTreeHeadTBS construction failed")?;
            let apk_bytes = self.config.auditor_public_key.as_deref()
                .ok_or_else(|| anyhow!("No auditor public key configured"))?;
            let apk = ServiceVerifyingKey::from_bytes(apk_bytes)
                .context("Invalid auditor public key")?;
            verify_data(&apk, &tbs, &ath.signature)
                .context("Auditor signature verification failed")?;
        }
        // TODO: reconstruct the root at ath.tree_size from retained subtrees when it lags

        self.auditor_head = Some((ath.tree_size, auditor_ts));
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
        }

        let proof = proof.ok_or(anyhow!("Missing monitor proof"))?;
        // TODO: position-aware timestamp monotonicity via algorithm simulation (§12.3, Appendix C)
        if proof.inclusion.is_none() {
            return Err(anyhow!("Missing inclusion proof in monitor response"));
        }

        Ok(())
    }

    // --- FullTreeHead helpers ---

    // §11.4
    fn tree_size_for_fth(&self, fth: &FullTreeHead) -> Result<(u64, Option<u64>, bool)> {
        if fth.head_type == FullTreeHeadType::Same as i32 {
            let prev = self.state.as_ref().ok_or_else(|| {
                anyhow!("Server returned head_type=SAME but client has no previous tree head")
            })?;
            self.check_timestamp_bounds(prev.timestamp)
                .context("Retained tree head is stale (head_type=SAME)")?;
            return Ok((prev.tree_size, Some(prev.timestamp), false));
        }
        if fth.head_type == FullTreeHeadType::Updated as i32 {
            let th = fth.tree_head.as_ref().ok_or_else(|| {
                anyhow!("FullTreeHead.head_type=updated but TreeHead is missing")
            })?;
            // §11.4 step 2.1: an updated head must be strictly newer than the advertised size
            if let Some(prev) = &self.state {
                if th.tree_size <= prev.tree_size {
                    return Err(anyhow!("Updated head does not advance the tree: {} <= {}", th.tree_size, prev.tree_size));
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
        let tbs = construct_tree_head_tbs_public(&self.config, tree_size, root_hash)
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

/// Consumes a CombinedTreeProof's fields as queues in the order the executed
/// algorithm requests them (Appendix C), enforcing position-wise timestamp
/// monotonicity and exact consumption.
struct ProofReader<'a> {
    proof: &'a CombinedTreeProof,
    ts_idx: usize,
    proof_idx: usize,
    assigned_ts: BTreeMap<u64, u64>,
}

impl<'a> ProofReader<'a> {
    fn new(proof: &'a CombinedTreeProof) -> Self {
        Self { proof, ts_idx: 0, proof_idx: 0, assigned_ts: BTreeMap::new() }
    }

    fn timestamp(&mut self, pos: u64) -> Result<u64> {
        if let Some(&ts) = self.assigned_ts.get(&pos) {
            return Ok(ts);
        }
        let ts = *self.proof.timestamps.get(self.ts_idx)
            .ok_or_else(|| anyhow!("Timestamp queue exhausted at entry {}", pos))?;
        self.ts_idx += 1;

        // §12.3: monotonic by log position
        if let Some((_, &left_ts)) = self.assigned_ts.range(..pos).next_back() {
            if ts < left_ts {
                return Err(anyhow!("Timestamp for entry {} is older than an entry to its left", pos));
            }
        }
        if let Some((_, &right_ts)) = self.assigned_ts.range(pos + 1..).next() {
            if ts > right_ts {
                return Err(anyhow!("Timestamp for entry {} is newer than an entry to its right", pos));
            }
        }
        self.assigned_ts.insert(pos, ts);
        Ok(ts)
    }

    fn prefix_proof(&mut self, _pos: u64) -> Result<&'a PrefixProof> {
        let pp = self.proof.prefix_proofs.get(self.proof_idx)
            .ok_or_else(|| anyhow!("PrefixProof queue exhausted"))?;
        self.proof_idx += 1;
        Ok(pp)
    }

    /// Enforces exact consumption of all three queues and returns, per touched
    /// entry in position order, its timestamp and prefix root (from the entry's
    /// verified proof, or popped from prefix_roots for proof-less entries).
    fn finish(self, entry_roots: &BTreeMap<u64, Vec<u8>>) -> Result<Vec<(u64, u64, Vec<u8>)>> {
        if self.ts_idx != self.proof.timestamps.len() {
            return Err(anyhow!("{} unused timestamps in proof", self.proof.timestamps.len() - self.ts_idx));
        }
        if self.proof_idx != self.proof.prefix_proofs.len() {
            return Err(anyhow!("{} unused PrefixProofs in proof", self.proof.prefix_proofs.len() - self.proof_idx));
        }

        let mut roots_idx = 0usize;
        let mut out = Vec::with_capacity(self.assigned_ts.len());
        for (&pos, &ts) in &self.assigned_ts {
            let root = if let Some(root) = entry_roots.get(&pos) {
                root.clone()
            } else {
                let root = self.proof.prefix_roots.get(roots_idx)
                    .ok_or_else(|| anyhow!("Missing prefix root for entry {}", pos))?;
                roots_idx += 1;
                root.clone()
            };
            out.push((pos, ts, root));
        }
        if roots_idx != self.proof.prefix_roots.len() {
            return Err(anyhow!("{} unused prefix roots in proof", self.proof.prefix_roots.len() - roots_idx));
        }
        Ok(out)
    }
}

fn record_entry_root(map: &mut BTreeMap<u64, Vec<u8>>, entry: u64, root: Vec<u8>) -> Result<()> {
    match map.get(&entry) {
        Some(prev) if prev != &root => Err(anyhow!(
            "PrefixProofs for entry {} disagree on the prefix-tree root", entry
        )),
        _ => {
            map.insert(entry, root);
            Ok(())
        }
    }
}

struct DecodedLookup {
    version: u32,
    inclusion: bool,
}

// §6.2/Appendix B: replay the ladder generation, reading each probe's outcome
// from the next result's type, to recover which version every result covers
fn decode_search_ladder(
    results: &[crate::proto::transparency::PrefixSearchResult],
    target: u32,
) -> Result<Vec<DecodedLookup>> {
    let mut out: Vec<DecodedLookup> = Vec::new();
    let mut idx = 0usize;

    let finish = |out: Vec<DecodedLookup>, idx: usize| -> Result<Vec<DecodedLookup>> {
        if idx != results.len() {
            return Err(anyhow!(
                "PrefixProof has {} results but the ladder only requires {}",
                results.len(), idx
            ));
        }
        Ok(out)
    };

    macro_rules! probe {
        ($v:expr) => {{
            let r = results.get(idx).ok_or_else(|| anyhow!(
                "PrefixProof has fewer results than its ladder requires"
            ))?;
            idx += 1;
            let inc = r.result_type == 1;
            out.push(DecodedLookup { version: $v, inclusion: inc });
            inc
        }};
    }

    let mut k = 0u32;
    let mut last_included: Option<u32> = None;
    let (mut lower, mut upper) = loop {
        let v64 = (1u64 << k) - 1;
        let v = if v64 > u32::MAX as u64 { u32::MAX } else { v64 as u32 };

        if probe!(v) {
            if v > target || v == u32::MAX {
                return finish(out, idx);
            }
            last_included = Some(v);
            k += 1;
        } else {
            if v <= target {
                return finish(out, idx);
            }
            match last_included {
                Some(l) => break (l, v),
                // v = 0 non-included always has v <= target
                None => unreachable!(),
            }
        }
    };

    while lower + 1 < upper {
        let v = lower + (upper - lower) / 2;
        if probe!(v) {
            if v > target {
                return finish(out, idx);
            }
            lower = v;
        } else {
            if v <= target {
                return finish(out, idx);
            }
            upper = v;
        }
    }

    finish(out, idx)
}
