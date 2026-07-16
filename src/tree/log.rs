use crate::crypto::hash::{log_leaf_value, log_parent_value};
use crate::db::TransparencyStore;
use crate::tree::log_math;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

struct NodeChunk {
    chunk_root_id: u64,
    nodes: [Option<Vec<u8>>; 15],
    id_map: HashMap<u64, usize>,
    dirty: bool,
}

impl NodeChunk {
    fn new(chunk_root: u64, data: Option<Vec<u8>>) -> Result<Self> {
        let mut nodes: [Option<Vec<u8>>; 15] = Default::default();
        let ids = log_math::chunk_layout(chunk_root);
        let mut id_map = HashMap::new();
        for (i, &id) in ids.iter().enumerate() {
            id_map.insert(id, i);
        }

        if let Some(bytes) = data {
            let mut cursor = 0;
            for i in (0..15).step_by(2) {
                if cursor + 32 > bytes.len() {
                    break;
                }
                nodes[i] = Some(bytes[cursor..cursor + 32].to_vec());
                cursor += 32;
            }
            recompute_intermediates(&mut nodes, &ids);
        }
        Ok(Self {
            chunk_root_id: chunk_root,
            nodes,
            id_map,
            dirty: false,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for i in (0..15).step_by(2) {
            if let Some(val) = &self.nodes[i] {
                out.extend_from_slice(val);
            } else {
                break;
            }
        }
        out
    }

    fn set_value(&mut self, node_id: u64, val: Vec<u8>) -> Result<()> {
        let idx = *self
            .id_map
            .get(&node_id)
            .ok_or_else(|| anyhow!("Node ID not in chunk"))?;
        if idx % 2 != 0 {
            return Err(anyhow!("Cannot set intermediate node directly"));
        }
        self.nodes[idx] = Some(val);
        self.dirty = true;
        Ok(())
    }

    fn get_value(&self, node_id: u64) -> Option<Vec<u8>> {
        let idx = *self.id_map.get(&node_id)?;
        self.nodes[idx].clone()
    }

    fn recompute(&mut self) {
        let ids = log_math::chunk_layout(self.chunk_root_id);
        recompute_intermediates(&mut self.nodes, &ids);
    }
}

fn recompute_intermediates(nodes: &mut [Option<Vec<u8>>; 15], ids: &[u64; 15]) {
    for i in [1, 5, 9, 13] {
        if let (Some(l), Some(r)) = (&nodes[i - 1], &nodes[i + 1]) {
            let l_is_leaf = log_math::is_leaf(ids[i - 1]);
            let r_is_leaf = log_math::is_leaf(ids[i + 1]);
            nodes[i] = Some(log_parent_value(l, l_is_leaf, r, r_is_leaf));
        }
    }
    for i in [3, 11] {
        if let (Some(l), Some(r)) = (&nodes[i - 2], &nodes[i + 2]) {
            let l_is_leaf = log_math::is_leaf(ids[i - 2]);
            let r_is_leaf = log_math::is_leaf(ids[i + 2]);
            nodes[i] = Some(log_parent_value(l, l_is_leaf, r, r_is_leaf));
        }
    }
    if let (Some(l), Some(r)) = (&nodes[3], &nodes[11]) {
        let l_is_leaf = log_math::is_leaf(ids[3]);
        let r_is_leaf = log_math::is_leaf(ids[11]);
        nodes[7] = Some(log_parent_value(l, l_is_leaf, r, r_is_leaf));
    }
}

pub struct LogTree {
    store: Arc<dyn TransparencyStore>,
}

impl LogTree {
    pub fn new(store: Arc<dyn TransparencyStore>) -> Self {
        Self { store }
    }

    pub fn get_root(&self, tree_size: u64) -> Result<Vec<u8>> {
        if tree_size == 0 {
            return Ok(vec![0u8; 32]);
        }
        let root_id = log_math::merkle_root(tree_size);
        self.resolve_node(root_id, tree_size)
    }

    fn resolve_node(&self, node_id: u64, tree_size: u64) -> Result<Vec<u8>> {
        self.resolve_node_simple(node_id, tree_size)
    }

    pub fn resolve_node_simple(&self, node_id: u64, tree_size: u64) -> Result<Vec<u8>> {
        let cid = log_math::chunk_id(node_id);

        let chunk_data = self.store.get_log(cid)?;
        if let Some(data) = chunk_data {
            let chunk = NodeChunk::new(cid, Some(data))?;
            if let Some(val) = chunk.get_value(node_id) {
                return Ok(val);
            }
        }

        if log_math::is_leaf(node_id) {
            return Err(anyhow!("Missing leaf node {}", node_id));
        }

        let left = log_math::left_child(node_id);
        let right = log_math::right_child(node_id, tree_size);

        if left == right {
            return self.resolve_node(left, tree_size);
        }

        let l_val = self.resolve_node(left, tree_size)?;
        let r_val = self.resolve_node(right, tree_size)?;

        Ok(log_parent_value(
            &l_val,
            log_math::is_leaf(left),
            &r_val,
            log_math::is_leaf(right),
        ))
    }

    pub fn batch_append(
        &self,
        start_tree_size: u64,
        entries: Vec<(u64, Vec<u8>)>,
    ) -> Result<Vec<u8>> {
        let mut chunk_cache: HashMap<u64, NodeChunk> = HashMap::new();

        for (i, (ts, root)) in entries.iter().enumerate() {
            let log_index = start_tree_size + i as u64;
            let node_id = log_index * 2;

            let leaf_hash = log_leaf_value(*ts, root);

            let cid = log_math::chunk_id(node_id);

            let chunk = if let Some(c) = chunk_cache.remove(&cid) {
                c
            } else {
                let data = self.store.get_log(cid)?;
                NodeChunk::new(cid, data)?
            };

            let mut mutable_chunk = chunk;
            mutable_chunk.set_value(node_id, leaf_hash)?;
            chunk_cache.insert(cid, mutable_chunk);

            // 1. Timestamp: Key = log_index | (1 << 63)
            let ts_key = log_index | (1u64 << 63);
            self.store.put_value(ts_key, ts.to_be_bytes().to_vec())?;

            // 2. Prefix Root Hash: Key = log_index | (1 << 62)
            let root_key = log_index | (1u64 << 62);
            self.store.put_value(root_key, root.clone())?;
        }

        let mut batch = Vec::new();
        for (_, mut chunk) in chunk_cache {
            chunk.recompute();
            batch.push((chunk.chunk_root_id, chunk.serialize()));
        }
        self.store.put_log_batch(batch)?;

        self.get_root(start_tree_size + entries.len() as u64)
    }

    pub fn get_timestamp(&self, log_index: u64) -> Result<u64> {
        let ts_key = log_index | (1u64 << 63);
        let bytes = self
            .store
            .get_value(ts_key)?
            .ok_or_else(|| anyhow!("Timestamp not found for log index {}", log_index))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(u64::from_be_bytes(arr))
    }

    pub fn get_prefix_root(&self, log_index: u64) -> Result<Vec<u8>> {
        let root_key = log_index | (1u64 << 62);
        let bytes = self
            .store
            .get_value(root_key)?
            .ok_or_else(|| anyhow!("Prefix Root not found for log index {}", log_index))?;
        Ok(bytes)
    }

    // Mapping: LogIndex -> PrefixVersion (u64)
    pub fn put_prefix_ptr(&self, log_index: u64, version: u64) -> Result<()> {
        let key = log_index | (1u64 << 61);
        self.store.put_value(key, version.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn get_prefix_ptr(&self, log_index: u64) -> Result<u64> {
        let key = log_index | (1u64 << 61);
        let bytes = self
            .store
            .get_value(key)?
            .ok_or_else(|| anyhow!("Prefix Ptr not found for log index {}", log_index))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(u64::from_be_bytes(arr))
    }

    pub fn get_next_prefix_version(&self) -> Result<u64> {
        // Implementation note: Ideally use `CF_META`, but `store` only exposes specific gets.
        // We will assume `get_head` returns `TreeHead`, we need another method?
        // Let's use `u64::MAX` in `CF_VALUE` as a hack for now since we are modifying files.
        // Key: u64::MAX
        match self.store.get_value(u64::MAX)? {
            Some(v) => Ok(u64::from_be_bytes(v.try_into().unwrap())),
            None => Ok(0),
        }
    }

    pub fn set_next_prefix_version(&self, ver: u64) -> Result<()> {
        self.store.put_value(u64::MAX, ver.to_be_bytes().to_vec())?;
        Ok(())
    }

    pub fn get_consistency_proof(&self, m: u64, n: u64) -> Result<Vec<Vec<u8>>> {
        if m == 0 || m >= n {
            return Err(anyhow!(
                "Invalid consistency proof parameters: m={}, n={}",
                m,
                n
            ));
        }
        let node_ids = log_math::consistency_proof(m, n);
        let mut proof = Vec::new();
        for id in node_ids {
            let val = self.resolve_node(id, n)?;
            proof.push(val);
        }
        Ok(proof)
    }

    pub fn get_batch_proof_for_nodes(
        &self,
        leaf_indices: Vec<u64>,
        tree_size: u64,
        last_size: u64,
        boundaries: &[u64],
    ) -> Result<Vec<Vec<u8>>> {
        let root_id = log_math::merkle_root(tree_size);
        let mut skeleton = HashSet::new();
        for &idx in &leaf_indices {
            let node_id = idx * 2;
            skeleton.insert(node_id);
            let mut curr = node_id;
            for _ in 0..64 {
                if curr == root_id {
                    break;
                }
                curr = log_math::parent(curr, tree_size);
                skeleton.insert(curr);
            }
        }
        // descend along boundary paths without providing their leaves, so the
        // proof carries what a client needs to derive historical sub-roots
        for &boundary in boundaries {
            if boundary == 0 || boundary > tree_size {
                continue;
            }
            let mut curr = (boundary - 1) * 2;
            for _ in 0..64 {
                if curr == root_id {
                    break;
                }
                curr = log_math::parent(curr, tree_size);
                skeleton.insert(curr);
            }
        }

        // Client State Optimization:
        // If the client has cached roots for 'last_size', we can omit them
        // unless we need to traverse through them to reach a target leaf.
        let retained: HashSet<u64> = if last_size > 0 && last_size <= tree_size {
            log_math::get_roots(last_size).into_iter().collect()
        } else {
            HashSet::new()
        };

        let root_id = log_math::merkle_root(tree_size);
        let needed_ids = self.recursive_needed(root_id, tree_size, &skeleton, &retained)?;

        let mut proof = Vec::new();
        for id in needed_ids {
            proof.push(self.resolve_node(id, tree_size)?);
        }
        Ok(proof)
    }

    fn recursive_needed(
        &self,
        node_id: u64,
        tree_size: u64,
        skeleton: &HashSet<u64>,
        retained: &HashSet<u64>,
    ) -> Result<Vec<u64>> {
        // Optimization: If client has this node cached
        if retained.contains(&node_id) {
            // And we don't need to traverse into it (not in skeleton)
            if !skeleton.contains(&node_id) {
                return Ok(vec![]); // Omit from proof
            }
            // If in skeleton, we must recurse (effectively ignoring the cache for this path)
        }

        if !skeleton.contains(&node_id) {
            return Ok(vec![node_id]);
        }
        if log_math::is_leaf(node_id) {
            return Ok(vec![]);
        }
        let l = log_math::left_child(node_id);
        let r = log_math::right_child(node_id, tree_size);
        if l == r {
            return self.recursive_needed(l, tree_size, skeleton, retained);
        }
        let mut left_res = self.recursive_needed(l, tree_size, skeleton, retained)?;
        let mut right_res = self.recursive_needed(r, tree_size, skeleton, retained)?;
        left_res.append(&mut right_res);
        Ok(left_res)
    }
}
