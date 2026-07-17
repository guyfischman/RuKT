//! Bulk population utilities for building large trees efficiently.
//!
//! Two strategies for fast benchmark setup:
//!
//! 1. **Checkpoint**: Build a tree once via `bulk_populate`, then use
//!    `RocksDbStore::checkpoint()` to snapshot it. Restore by copying
//!    the checkpoint directory and opening a new `RocksDbStore`.
//!
//! 2. **SST Ingestion**: Auxiliary data (values, openings, history) is
//!    written via SST file ingestion, bypassing the WAL and memtable.
//!    The prefix tree is still built sequentially (inherent dependency)
//!    but all crypto is parallelized and batcher overhead is eliminated.

use crate::crypto::{self, PrivateConfig, commit, generate_random_opening};
use crate::db::RocksDbStore;
use crate::proto::prefix_tree::{LogEntry, ParentNode};
use crate::proto::transparency::{Signature as PbSignature, TreeHead};
use crate::tree::Tree;
use crate::tree::prefix::entry::CachedLogEntry;
use crate::tree::prefix::hasher::{ZERO_VALUE, get_bit, parent_hash};
use anyhow::Result;
use prost::Message;
use rayon::prelude::*;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Pre-computed cryptographic data for a single entry.
struct BulkEntry {
    search_key: Vec<u8>,
    value: Vec<u8>,
    index: [u8; 32],
    commitment: Vec<u8>,
    opening: Vec<u8>,
}

/// Bulk-populate a tree with `n` unique users, bypassing the batcher.
///
/// This is significantly faster than submitting updates through the service
/// because it:
/// - Parallelizes all VRF + commitment computation via rayon
/// - Calls prefix tree batch_insert directly (no batcher channel/phases)
/// - Writes auxiliary data (values, openings, history) via SST ingestion
/// - Skips audit proof generation and individual response proofs
///
/// The tree is populated in chunks to bound memory usage. Each chunk
/// processes up to `chunk_size` entries.
pub async fn bulk_populate(
    tree: &mut Tree,
    db: &RocksDbStore,
    config: &PrivateConfig,
    labels: Vec<(Vec<u8>, Vec<u8>)>,
    chunk_size: usize,
) -> Result<()> {
    let total = labels.len();
    if total == 0 {
        return Ok(());
    }

    let t_total = Instant::now();
    let mut processed = 0usize;

    for chunk in labels.chunks(chunk_size) {
        let t_chunk = Instant::now();

        // Phase 1: Parallel crypto (VRF prove + commitment)
        let t_crypto = Instant::now();
        let entries: Vec<BulkEntry> = chunk
            .par_iter()
            .map(|(search_key, value)| {
                let (index, _vrf_proof) = config.vrf_prove(search_key, 0)?;
                let opening = generate_random_opening();
                let commitment = commit(search_key, 0, value, &opening)?;
                Ok(BulkEntry {
                    search_key: search_key.clone(),
                    value: value.clone(),
                    index,
                    commitment,
                    opening,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let dur_crypto = t_crypto.elapsed();

        // Phase 2: Prefix tree insertion (sequential, inherent dependency)
        let t_prefix = Instant::now();
        let start_size = tree.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        let start_prefix_version = tree.log.get_next_prefix_version()?;
        let current_log_ptr = if start_size > 0 {
            Some(tree.log.get_prefix_ptr(start_size - 1)?)
        } else {
            None
        };

        let prefix_entries: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|e| (e.index.to_vec(), e.commitment.clone()))
            .collect();

        let (roots, _search_results, final_prefix_ptr) = tree
            .prefix
            .batch_insert(start_prefix_version, current_log_ptr, &prefix_entries)
            .await?;
        let dur_prefix = t_prefix.elapsed();

        // Phase 3: Log tree append
        let t_log = Instant::now();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        tree.log.put_prefix_ptr(start_size, final_prefix_ptr)?;
        tree.log.set_next_prefix_version(final_prefix_ptr + 1)?;

        let final_root_hash = roots.last().unwrap().clone();
        let new_log_root = tree
            .log
            .batch_append(start_size, vec![(timestamp, final_root_hash)])?;
        let dur_log = t_log.elapsed();

        // Phase 4: Auxiliary data via SST ingestion
        let t_aux = Instant::now();
        let log_pos_base = start_prefix_version;

        // Values: sorted by position key (big-endian u64)
        let mut value_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
        let mut opening_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
        let mut history_map: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());

        for (i, entry) in entries.iter().enumerate() {
            let pos = log_pos_base + i as u64;
            let pos_key = pos.to_be_bytes().to_vec();

            value_entries.push((pos_key.clone(), entry.value.clone()));
            opening_entries.push((pos_key, entry.opening.clone()));

            // History: key is the search_key, value is (version=0, pos)
            let mut hist_val = Vec::with_capacity(12);
            hist_val.extend_from_slice(&0u32.to_be_bytes());
            hist_val.extend_from_slice(&pos.to_be_bytes());
            history_map.push((entry.search_key.clone(), hist_val));
        }

        // Sort all by key for SST ingestion
        value_entries.sort_by(|a, b| a.0.cmp(&b.0));
        opening_entries.sort_by(|a, b| a.0.cmp(&b.0));
        history_map.sort_by(|a, b| a.0.cmp(&b.0));

        db.ingest_sst(RocksDbStore::cf_value(), value_entries)?;
        db.ingest_sst(RocksDbStore::cf_openings(), opening_entries)?;
        db.ingest_sst(RocksDbStore::cf_history(), history_map)?;
        let dur_aux = t_aux.elapsed();

        // Phase 5: Tree head
        let new_size = start_size + 1;
        let tbs_data = crypto::construct_tree_head_tbs(config, None, new_size, &new_log_root)?;
        let signature = crypto::sign_data(&config.sig_key, &tbs_data);

        let th = TreeHead {
            tree_size: new_size,
            timestamp: timestamp as i64,
            signatures: vec![PbSignature {
                auditor_public_key: config.sig_key.verifying_key().to_bytes(),
                signature,
            }],
        };

        let mut head_buf = Vec::new();
        th.encode(&mut head_buf)?;
        tree.store.set_head(head_buf)?;
        tree.latest = Some(th);

        processed += chunk.len();
        println!(
            "   📦 Bulk chunk [{}/{}] | Crypto: {:.2?} | Prefix: {:.2?} | Log: {:.2?} | SST: {:.2?} | Chunk: {:.2?}",
            processed,
            total,
            dur_crypto,
            dur_prefix,
            dur_log,
            dur_aux,
            t_chunk.elapsed()
        );
    }

    println!(
        "   ✅ Bulk populate complete: {} entries in {:.2?}",
        total,
        t_total.elapsed()
    );
    Ok(())
}

/// Bulk-populate a tree with one log entry per label (all at version 0),
/// timestamps spaced `ts_step_ms` apart. A fresh tree's timestamps end at the
/// current time; a non-empty tree continues from its rightmost timestamp.
///
/// Unlike `bulk_populate` (one log entry per chunk), this produces a log tree
/// whose size equals the number of labels, so frontier/ladder-shaped client
/// work scales realistically with the population.
pub async fn bulk_populate_per_entry(
    tree: &mut Tree,
    db: &RocksDbStore,
    config: &PrivateConfig,
    labels: Vec<(Vec<u8>, Vec<u8>)>,
    ts_step_ms: u64,
) -> Result<()> {
    let total = labels.len() as u64;
    if total == 0 {
        return Ok(());
    }

    let entries: Vec<BulkEntry> = labels
        .par_iter()
        .map(|(search_key, value)| {
            let (index, _vrf_proof) = config.vrf_prove(search_key, 0)?;
            let opening = generate_random_opening();
            let commitment = commit(search_key, 0, value, &opening)?;
            Ok(BulkEntry {
                search_key: search_key.clone(),
                value: value.clone(),
                index,
                commitment,
                opening,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let start_size = tree.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
    let start_prefix_version = tree.log.get_next_prefix_version()?;
    let mut current_ptr = if start_size > 0 {
        Some(tree.log.get_prefix_ptr(start_size - 1)?)
    } else {
        None
    };
    let base_ts = if start_size > 0 {
        tree.log.get_timestamp(start_size - 1)? + ts_step_ms
    } else {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        now - ts_step_ms * (total - 1)
    };

    let mut roots: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for chunk in entries.chunks(8192) {
        let prefix_entries: Vec<(Vec<u8>, Vec<u8>)> = chunk
            .iter()
            .map(|e| (e.index.to_vec(), e.commitment.clone()))
            .collect();
        let (chunk_roots, _, final_ptr) = tree
            .prefix
            .batch_insert(
                start_prefix_version + roots.len() as u64,
                current_ptr,
                &prefix_entries,
            )
            .await?;
        roots.extend(chunk_roots);
        current_ptr = Some(final_ptr);
    }

    for i in 0..total {
        tree.log
            .put_prefix_ptr(start_size + i, start_prefix_version + i)?;
    }
    tree.log
        .set_next_prefix_version(start_prefix_version + total)?;

    let log_entries: Vec<(u64, Vec<u8>)> = roots
        .iter()
        .enumerate()
        .map(|(i, root)| (base_ts + i as u64 * ts_step_ms, root.clone()))
        .collect();
    let last_ts = log_entries.last().unwrap().0;
    let new_log_root = tree.log.batch_append(start_size, log_entries)?;

    let mut value_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
    let mut opening_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
    let mut history_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let pos = start_prefix_version + i as u64;
        let pos_key = pos.to_be_bytes().to_vec();

        value_entries.push((pos_key.clone(), entry.value.clone()));
        opening_entries.push((pos_key, entry.opening.clone()));

        let mut hist_val = Vec::with_capacity(12);
        hist_val.extend_from_slice(&0u32.to_be_bytes());
        hist_val.extend_from_slice(&pos.to_be_bytes());
        history_entries.push((entry.search_key.clone(), hist_val));
    }
    value_entries.sort_by(|a, b| a.0.cmp(&b.0));
    opening_entries.sort_by(|a, b| a.0.cmp(&b.0));
    history_entries.sort_by(|a, b| a.0.cmp(&b.0));

    db.ingest_sst(RocksDbStore::cf_value(), value_entries)?;
    db.ingest_sst(RocksDbStore::cf_openings(), opening_entries)?;
    db.ingest_sst(RocksDbStore::cf_history(), history_entries)?;

    let new_size = start_size + total;
    let tbs_data = crypto::construct_tree_head_tbs(config, None, new_size, &new_log_root)?;
    let signature = crypto::sign_data(&config.sig_key, &tbs_data);
    let th = TreeHead {
        tree_size: new_size,
        timestamp: last_ts as i64,
        signatures: vec![PbSignature {
            auditor_public_key: config.sig_key.verifying_key().to_bytes(),
            signature,
        }],
    };
    let mut head_buf = Vec::new();
    th.encode(&mut head_buf)?;
    tree.store.set_head(head_buf)?;
    tree.latest = Some(th);

    Ok(())
}

// ============================================================================
// Parallel Bulk Populate (Option 5: Sub-tree partitioning)
// ============================================================================

/// Extract the first `k` bits of a VRF index as a partition ID.
fn partition_id(index: &[u8], k: usize) -> usize {
    let mut pid = 0usize;
    for d in 0..k {
        pid = (pid << 1) | (get_bit(index, d) as usize);
    }
    pid
}

/// For partition `p` at depth `d`, compute the partition ID of the sibling
/// sub-tree's "rightmost" (representative) partition.
fn sibling_root_pid(p: usize, d: usize, k: usize) -> usize {
    let bit_pos = k - 1 - d;
    (p ^ (1 << bit_pos)) | ((1 << bit_pos) - 1)
}

/// Build a binary hash tree over partition root hashes.
/// Returns `hash_tree[level][index]` where level 0 = global root, level k = partition leaves.
fn build_hash_tree(partition_hashes: Vec<Vec<u8>>, k: usize) -> Vec<Vec<Vec<u8>>> {
    let mut tree = vec![vec![]; k + 1];
    tree[k] = partition_hashes;
    for level in (0..k).rev() {
        let n = 1 << level;
        let mut hashes = Vec::with_capacity(n);
        for j in 0..n {
            let left = &tree[level + 1][2 * j];
            let right = &tree[level + 1][2 * j + 1];
            hashes.push(parent_hash(left, right));
        }
        tree[level] = hashes;
    }
    tree
}

/// Compute the K merge ParentNode entries for partition `p` at depths 0..K-1.
fn merge_copath_for_partition(
    p: usize,
    k: usize,
    hash_tree: &[Vec<Vec<u8>>],
    root_positions: &[Option<u64>],
) -> Vec<ParentNode> {
    (0..k)
        .map(|d| {
            let node_idx = p >> (k - 1 - d);
            let sibling_idx = node_idx ^ 1;
            let sibling_hash = hash_tree[d + 1][sibling_idx].clone();
            let sibling_pid = sibling_root_pid(p, d, k);
            let sibling_pos = root_positions[sibling_pid];
            ParentNode {
                hash: sibling_hash,
                ptr: sibling_pos,
                first_update_position: sibling_pos,
            }
        })
        .collect()
}

/// Bulk-populate a tree using parallel sub-tree construction.
///
/// Partitions entries by the first `k` bits of their VRF index (2^k partitions),
/// builds each partition's sub-tree independently in parallel, then merges by
/// patching copath entries at depths 0..k-1 with the correct cross-partition
/// sibling hashes and pointers.
///
/// For N entries on C cores, this gives ~C× speedup on the prefix tree walk
/// (the dominant cost), at the expense of an O(N) merge pass.
pub async fn parallel_bulk_populate(
    tree: &mut Tree,
    db: &RocksDbStore,
    config: &PrivateConfig,
    labels: Vec<(Vec<u8>, Vec<u8>)>,
    k: usize,
) -> Result<()> {
    let total = labels.len();
    if total == 0 {
        return Ok(());
    }
    let n_partitions = 1usize << k;
    let t_total = Instant::now();

    // Phase 1: Parallel crypto
    let t1 = Instant::now();
    let entries: Vec<BulkEntry> = labels
        .par_iter()
        .map(|(search_key, value)| {
            let (index, _) = config.vrf_prove(search_key, 0)?;
            let opening = generate_random_opening();
            let commitment = commit(search_key, 0, value, &opening)?;
            Ok(BulkEntry {
                search_key: search_key.clone(),
                value: value.clone(),
                index,
                commitment,
                opening,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    println!("   [parallel] Phase 1 (crypto): {:.2?}", t1.elapsed());

    // Phase 2: Partition by first k bits
    let t2 = Instant::now();
    let mut partitions: Vec<Vec<usize>> = vec![Vec::new(); n_partitions];
    for (i, entry) in entries.iter().enumerate() {
        let pid = partition_id(&entry.index, k);
        partitions[pid].push(i);
    }

    // Compute position offsets (disjoint ranges per partition)
    let start_prefix_version = tree.log.get_next_prefix_version()?;
    let mut pos_offsets = vec![0u64; n_partitions + 1];
    for p in 0..n_partitions {
        pos_offsets[p + 1] = pos_offsets[p] + partitions[p].len() as u64;
    }
    let total_positions = pos_offsets[n_partitions];
    println!(
        "   [parallel] Phase 2 (partition): {:.2?} ({} partitions, {} total entries)",
        t2.elapsed(),
        n_partitions,
        total_positions
    );

    // Phase 3: Build sub-trees in parallel
    let t3 = Instant::now();
    let mut handles = Vec::with_capacity(n_partitions);
    for p in 0..n_partitions {
        if partitions[p].is_empty() {
            continue;
        }
        let prefix_tree = tree.prefix.clone();
        let start_pos = start_prefix_version + pos_offsets[p];
        let prefix_entries: Vec<(Vec<u8>, Vec<u8>)> = partitions[p]
            .iter()
            .map(|&i| (entries[i].index.to_vec(), entries[i].commitment.clone()))
            .collect();

        handles.push(tokio::spawn(async move {
            let (_roots, _search_results, final_ptr) = prefix_tree
                .batch_insert(start_pos, None, &prefix_entries)
                .await?;
            Ok::<_, anyhow::Error>((p, final_ptr))
        }));
    }

    let mut root_positions: Vec<Option<u64>> = vec![None; n_partitions];
    for handle in handles {
        let (pid, final_ptr) = handle.await??;
        root_positions[pid] = Some(final_ptr);
    }
    println!(
        "   [parallel] Phase 3 (sub-tree build): {:.2?}",
        t3.elapsed()
    );

    // Phase 4: Compute partition hash tree
    let t4 = Instant::now();
    let mut partition_hashes: Vec<Vec<u8>> = Vec::with_capacity(n_partitions);
    for &partition_root in root_positions.iter().take(n_partitions) {
        if let Some(root_pos) = partition_root {
            let root_bytes = tree.store.get_prefix(root_pos)?.unwrap();
            let root_entry = Arc::new(LogEntry::decode(&root_bytes[..])?);
            let cached = CachedLogEntry::new(root_entry, &config.prefix_aes_key);
            partition_hashes.push(cached.rollup(k, None));
        } else {
            partition_hashes.push(ZERO_VALUE.to_vec());
        }
    }
    let hash_tree = build_hash_tree(partition_hashes, k);
    let global_root_hash = hash_tree[0][0].clone();
    println!("   [parallel] Phase 4 (hash tree): {:.2?}", t4.elapsed());

    // Phase 5: Merge — patch copath[0..k-1] for all entries
    let t5 = Instant::now();
    let mut merge_batch: Vec<(u64, Vec<u8>)> = Vec::with_capacity(total_positions as usize);

    for p in 0..n_partitions {
        let psize = partitions[p].len() as u64;
        if psize == 0 {
            continue;
        }
        let pstart = start_prefix_version + pos_offsets[p];
        let merge_prefix = merge_copath_for_partition(p, k, &hash_tree, &root_positions);

        // Batch-read all entries in this partition
        let keys: Vec<u64> = (pstart..pstart + psize).collect();
        let raw_entries = tree.store.batch_get_prefix(&keys)?;

        for (pos, bytes) in raw_entries {
            let mut entry = LogEntry::decode(&bytes[..])?;

            // Build merged copath: merge_prefix[0..k] + original[k..]
            let mut new_copath = merge_prefix.clone();
            if entry.copath.len() > k {
                new_copath.extend_from_slice(&entry.copath[k..]);
            }
            entry.copath = new_copath;

            let mut buf = Vec::new();
            entry.encode(&mut buf)?;
            merge_batch.push((pos, buf));
        }
    }

    tree.store.put_prefix_batch(merge_batch)?;
    tree.prefix.node_cache.invalidate_all();
    println!(
        "   [parallel] Phase 5 (merge {} entries): {:.2?}",
        total_positions,
        t5.elapsed()
    );

    // Phase 6: Log tree + aux data + tree head
    let t6 = Instant::now();
    let start_size = tree.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

    // Find the global root position (last entry of last non-empty partition)
    let global_root_pos = root_positions.iter().rev().find_map(|&p| p).unwrap();

    tree.log.put_prefix_ptr(start_size, global_root_pos)?;
    tree.log
        .set_next_prefix_version(start_prefix_version + total_positions)?;

    let new_log_root = tree
        .log
        .batch_append(start_size, vec![(timestamp, global_root_hash)])?;

    // Auxiliary data via SST
    let mut value_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(total);
    let mut opening_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(total);
    let mut history_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(total);

    for p in 0..n_partitions {
        for (local_i, &global_i) in partitions[p].iter().enumerate() {
            let pos = start_prefix_version + pos_offsets[p] + local_i as u64;
            let pos_key = pos.to_be_bytes().to_vec();
            let e = &entries[global_i];

            value_entries.push((pos_key.clone(), e.value.clone()));
            opening_entries.push((pos_key, e.opening.clone()));

            let mut hist_val = Vec::with_capacity(12);
            hist_val.extend_from_slice(&0u32.to_be_bytes());
            hist_val.extend_from_slice(&pos.to_be_bytes());
            history_entries.push((e.search_key.clone(), hist_val));
        }
    }

    value_entries.sort_by(|a, b| a.0.cmp(&b.0));
    opening_entries.sort_by(|a, b| a.0.cmp(&b.0));
    history_entries.sort_by(|a, b| a.0.cmp(&b.0));

    db.ingest_sst(RocksDbStore::cf_value(), value_entries)?;
    db.ingest_sst(RocksDbStore::cf_openings(), opening_entries)?;
    db.ingest_sst(RocksDbStore::cf_history(), history_entries)?;

    // Tree head
    let new_size = start_size + 1;
    let tbs_data = crypto::construct_tree_head_tbs(config, None, new_size, &new_log_root)?;
    let signature = crypto::sign_data(&config.sig_key, &tbs_data);

    let th = TreeHead {
        tree_size: new_size,
        timestamp: timestamp as i64,
        signatures: vec![PbSignature {
            auditor_public_key: config.sig_key.verifying_key().to_bytes(),
            signature,
        }],
    };

    let mut head_buf = Vec::new();
    th.encode(&mut head_buf)?;
    tree.store.set_head(head_buf)?;
    tree.latest = Some(th);

    println!(
        "   [parallel] Phase 6 (log + aux + head): {:.2?}",
        t6.elapsed()
    );
    println!(
        "   ✅ Parallel bulk populate complete: {} entries in {:.2?}",
        total,
        t_total.elapsed()
    );
    Ok(())
}
