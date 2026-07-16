// Key Transparency Protocol (draft-ietf-keytrans-protocol-03) Benchmarks
// For IETF KEYTRANS Working Group Presentation
//
// REPRODUCIBILITY:
//   - Pinned to BENCH_WORKER_THREADS tokio worker threads (default 4)
//   - All tree setups use deterministic labels/values
//   - Sample sizes tuned per group for fast runs (~2-5 min total)
//
// Categories:
//   1. Cryptographic Primitives (VRF, Signing, Commitments, Hashing)
//   2. Binary Ladder & Tree Math (pure computation, no I/O)
//   3. End-to-End Protocol Operations (Update, Search, Monitor, Audit, Credential)
//   4. Scale Scenarios (Enterprise Rotation, Git Forge, Batch Throughput)
//   5. Scalability Analysis (how latency grows with tree size)
//   6. Proof Size Analysis (response payload sizes)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rukt::bulk;
use rukt::crypto::{
    self, CIPHER_SUITE_KT_128_SHA256_ED25519, CIPHER_SUITE_KT_128_SHA256_P256, PrivateConfig,
    commit, generate_random_opening, generate_sig_keypair, generate_vrf_keypair, sign_data,
    verify_data,
};
use rukt::db::{RocksDbStore, TransparencyStore};
use rukt::proto::kt::AuditRequest;
use rukt::proto::kt::key_transparency_service_server::KeyTransparencyService;
use rukt::proto::transparency::{
    Consistency, ContactMonitorRequest, GetCredentialRequest, LabelValue, MonitorMapEntry,
    OwnerInitRequest, SearchRequest, UpdateRequest,
};
use rukt::service::KeyTransparencyImpl;
use rukt::tree::Tree;
use rukt::tree::binary_ladder::{base_binary_ladder, search_binary_ladder};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::runtime::Runtime;

/// Worker thread count for benchmark measurements (kept at 4 for consistency
/// with all existing data). Golden DB builds use a separate higher-parallelism runtime.
const BENCH_WORKER_THREADS: usize = 4;

/// Worker threads for golden DB builds only (saturate all cores).
const BUILD_WORKER_THREADS: usize = 14;

// ============================================================================
// Helpers
// ============================================================================

fn make_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(BENCH_WORKER_THREADS)
        .enable_all()
        .build()
        .unwrap()
}

fn make_label(i: usize) -> Vec<u8> {
    format!("user_{}@example.com", i).into_bytes()
}

fn make_value(i: usize) -> Vec<u8> {
    format!("pubkey_v{}", i).into_bytes()
}

fn make_large_value(size_bytes: usize) -> Vec<u8> {
    vec![0xAB; size_bytes]
}

fn update_req(label: Vec<u8>, greatest_version: Option<u32>, value: Vec<u8>) -> UpdateRequest {
    UpdateRequest {
        last: None,
        label,
        greatest_version,
        values: vec![LabelValue { value }],
    }
}

/// Deterministic pseudo-random version in [1, max_exclusive) for benchmarks.
/// Avoids v0 (always cheapest — earliest entry, ladder terminates immediately)
/// while remaining reproducible across runs.
fn rand_version(max_exclusive: usize) -> u32 {
    if max_exclusive <= 1 {
        return 0;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    max_exclusive.hash(&mut h);
    ((h.finish() % (max_exclusive as u64 - 1)) + 1) as u32
}

/// Sets up a KT service and bulk-inserts `n` unique users.
/// Uses concurrent submissions to the batcher for speed.
/// Returns (service, runtime). The TempDir is leaked to keep DB alive.
fn setup_service_with_users(n: usize) -> (KeyTransparencyImpl, Runtime) {
    let rt = make_runtime();
    let service = rt.block_on(async {
        let dir = tempdir().unwrap();
        let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
        let (signer, _) = generate_sig_keypair();
        let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
        let svc = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
            .await
            .unwrap();
        // Leak dir so RocksDB stays open
        std::mem::forget(dir);

        // Fire all updates concurrently; the batcher will group them
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let svc_clone = svc.clone();
            handles.push(tokio::spawn(async move {
                let req = tonic::Request::new(update_req(make_label(i), None, make_value(0)));
                let _ = svc_clone.update(req).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        // Let final batch flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        svc
    });
    (service, rt)
}

/// Pre-populates a tree with 1 user that has `n` key versions (sequential rotations).
fn setup_service_with_versions(n: usize) -> (KeyTransparencyImpl, Runtime) {
    let rt = make_runtime();
    let service = rt.block_on(async {
        let dir = tempdir().unwrap();
        let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
        let (signer, _) = generate_sig_keypair();
        let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
        let svc = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
            .await
            .unwrap();
        std::mem::forget(dir);

        let label = make_label(0);
        for v in 0..n {
            let gv = if v == 0 { None } else { Some(v as u32 - 1) };
            let req = tonic::Request::new(update_req(label.clone(), gv, make_value(v)));
            let _ = svc.update(req).await;
            // Wait for batcher to flush each individually (separate log entries)
            tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
        }
        svc
    });
    (service, rt)
}

// ============================================================================
// FAST SETUP: Bulk Loader + Checkpoint/Snapshot
// ============================================================================

/// Number of prefix bits for parallel partitioning (2^K partitions).
/// K=4 → 16 partitions is fine for ≤32K entries. For 1M+ we use K=6
/// → 64 partitions so all 14 cores stay busy during sub-tree construction.
const PARALLEL_PARTITION_BITS: usize = 4;
const PARALLEL_PARTITION_BITS_LARGE: usize = 6;

/// Directory for cached golden databases.
const GOLDEN_DB_DIR: &str = "/tmp/kt_golden";

/// Key material file stored alongside the golden DB so checkpoints use the same VRF key.
const KEYS_FILENAME: &str = "bench_keys.bin";

/// Serialize signing key + VRF key to a file.
fn save_keys(dir: &str, signer: &rukt::crypto::ServiceSigningKey, vrf_key: &[u8]) {
    let sig_bytes = match signer {
        rukt::crypto::ServiceSigningKey::Ed25519(k) => k.to_bytes().to_vec(),
        _ => panic!("Only Ed25519 signing keys supported in bench"),
    };
    let path = format!("{}/{}", dir, KEYS_FILENAME);
    let mut data = Vec::new();
    data.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(&sig_bytes);
    data.extend_from_slice(&(vrf_key.len() as u32).to_be_bytes());
    data.extend_from_slice(vrf_key);
    std::fs::write(path, data).unwrap();
}

/// Load signing key + VRF key from a file.
fn load_keys(dir: &str) -> (rukt::crypto::ServiceSigningKey, Vec<u8>) {
    let path = format!("{}/{}", dir, KEYS_FILENAME);
    let data = std::fs::read(path).unwrap();
    let mut cursor = 0;
    let sig_len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    let sig_bytes = &data[cursor..cursor + sig_len];
    cursor += sig_len;
    let vrf_len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    let vrf_key = data[cursor..cursor + vrf_len].to_vec();

    let sig_arr: [u8; 32] = sig_bytes.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sig_arr);
    (
        rukt::crypto::ServiceSigningKey::Ed25519(signing_key),
        vrf_key,
    )
}

/// Build a golden database with `n` users using parallel bulk population.
/// The result is cached at `{GOLDEN_DB_DIR}/golden_{n}`. Subsequent calls reuse the cache.
/// Keys are persisted alongside the DB so checkpoints produce correct VRF proofs.
fn build_or_load_golden(n: usize) -> String {
    let golden_path = format!("{}/golden_{}", GOLDEN_DB_DIR, n);
    if Path::new(&golden_path).exists()
        && Path::new(&format!("{}/{}", golden_path, KEYS_FILENAME)).exists()
    {
        println!("   ♻️  Reusing golden DB at {}", golden_path);
        return golden_path;
    }

    // Clean stale partial builds
    let _ = std::fs::remove_dir_all(&golden_path);
    std::fs::create_dir_all(GOLDEN_DB_DIR).unwrap();
    println!("   🔨 Building golden DB with {} users...", n);

    let (signer, _) = generate_sig_keypair();
    let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let build_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(BUILD_WORKER_THREADS)
        .enable_all()
        .build()
        .unwrap();
    build_rt.block_on(async {
        let db = Arc::new(RocksDbStore::new(&golden_path).unwrap());
        let config = make_bench_config(signer.clone(), vrf_key.clone());
        let mut tree = Tree::new(db.clone(), &config).await.unwrap();

        let labels: Vec<(Vec<u8>, Vec<u8>)> =
            (0..n).map(|i| (make_label(i), make_value(0))).collect();

        // Use parallel sub-tree construction for all sizes.
        // Larger trees get more partitions (2^6 = 64) to saturate all cores.
        // Memory: ~130 bytes/entry × 1M ≈ 130MB — well within bounds.
        let k = if n > 32_768 {
            PARALLEL_PARTITION_BITS_LARGE
        } else {
            PARALLEL_PARTITION_BITS
        };
        bulk::parallel_bulk_populate(&mut tree, &db, &config, labels, k)
            .await
            .unwrap();
    });

    save_keys(&golden_path, &signer, &vrf_key);
    golden_path
}

/// Open a service from a golden DB checkpoint (fast copy via hard links).
/// Uses the same VRF key that was used to build the golden DB, so VRF proofs
/// in search/monitor responses are correct and verifiable.
fn setup_from_checkpoint(golden_path: &str) -> (KeyTransparencyImpl, Runtime) {
    let (signer, vrf_key) = load_keys(golden_path);

    let rt = make_runtime();
    let service = rt.block_on(async {
        let dir = tempdir().unwrap();
        let checkpoint_dest = dir.path().join("db");
        let checkpoint_str = checkpoint_dest.to_str().unwrap();

        // Use RocksDB checkpoint (hard-link based, very fast)
        let source_db = RocksDbStore::new(golden_path).unwrap();
        source_db.checkpoint(checkpoint_str).unwrap();
        drop(source_db);

        let db = Arc::new(RocksDbStore::new(checkpoint_str).unwrap());
        let svc = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
            .await
            .unwrap();
        std::mem::forget(dir);
        svc
    });
    (service, rt)
}

/// Construct a PrivateConfig for benchmark use (no auditors, contact monitoring mode).
fn make_bench_config(signer: rukt::crypto::ServiceSigningKey, vrf_key: Vec<u8>) -> PrivateConfig {
    PrivateConfig::new(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        rukt::crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        signer,
        vrf_key,
        HashMap::new(),
        5000,
        5000,
        86400000,
        None,
        None,
        100,
    )
    .unwrap()
}

/// Fast setup using bulk population + checkpoint. For large tree sizes,
/// this is much faster than `setup_service_with_users` because:
/// - Crypto is parallelized via rayon (not sequential through batcher)
/// - Auxiliary data written via SST ingestion
/// - Golden DB is cached and reused across benchmark runs
fn setup_service_bulk(n: usize) -> (KeyTransparencyImpl, Runtime) {
    let golden = build_or_load_golden(n);
    setup_from_checkpoint(&golden)
}

/// Pre-build golden databases for all sizes used across benchmark groups.
/// Call this once before running benchmarks to avoid build delays mid-run.
/// Sizes are deduped and sorted so larger builds (which take longer) go last.
fn preload_golden_dbs(sizes: &[usize]) {
    let mut unique: Vec<usize> = sizes.to_vec();
    unique.sort();
    unique.dedup();
    println!("Preloading {} golden DBs: {:?}", unique.len(), unique);
    for &n in &unique {
        build_or_load_golden(n);
    }
    println!("All golden DBs ready.\n");
}

/// All tree sizes used across benchmark groups.
const BENCH_TREE_SIZES: &[usize] = &[10, 100, 500, 1_000, 2_000];

/// Large-scale tree sizes: 2^5, 2^10, 2^15, 2^20 (32 to ~1M users).
/// Models WhatsApp-scale deployments where each user has 1-3 key versions.
const LARGE_TREE_SIZES: &[usize] = &[32, 1_024, 32_768, 1_048_576];

/// Version counts for binary ladder efficiency benchmarks.
const BENCH_VERSION_COUNTS: &[usize] = &[1, 5, 10, 25, 50, 100];

// ============================================================================
// 1. CRYPTOGRAPHIC PRIMITIVES
// ============================================================================

fn bench_crypto_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("1_crypto");
    group.sample_size(100);

    // --- VRF Prove / Verify (Ed25519) ---
    let (vrf_key_ed, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let vrf_ctx_ed =
        crypto::expand_vrf_secret(CIPHER_SUITE_KT_128_SHA256_ED25519, &vrf_key_ed).unwrap();
    let vrf_input = crypto::construct_vrf_input(b"alice@example.com", 42).unwrap();
    let vrf_pk_ed =
        crypto::get_public_key(CIPHER_SUITE_KT_128_SHA256_ED25519, &vrf_key_ed).unwrap();
    let (_, proof_ed) = crypto::ecvrf_prove(&vrf_ctx_ed, &vrf_input).unwrap();

    group.bench_function("vrf_prove_ed25519", |b| {
        b.iter(|| crypto::ecvrf_prove(&vrf_ctx_ed, &vrf_input).unwrap())
    });
    group.bench_function("vrf_verify_ed25519", |b| {
        b.iter(|| {
            crypto::ecvrf_verify(
                CIPHER_SUITE_KT_128_SHA256_ED25519,
                &vrf_pk_ed,
                &vrf_input,
                &proof_ed,
            )
            .unwrap()
        })
    });

    // --- VRF Prove / Verify (P-256) ---
    let (vrf_key_p256, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_P256);
    let vrf_ctx_p256 =
        crypto::expand_vrf_secret(CIPHER_SUITE_KT_128_SHA256_P256, &vrf_key_p256).unwrap();
    let vrf_pk_p256 =
        crypto::get_public_key(CIPHER_SUITE_KT_128_SHA256_P256, &vrf_key_p256).unwrap();
    let (_, proof_p256) = crypto::ecvrf_prove(&vrf_ctx_p256, &vrf_input).unwrap();

    group.bench_function("vrf_prove_p256", |b| {
        b.iter(|| crypto::ecvrf_prove(&vrf_ctx_p256, &vrf_input).unwrap())
    });
    group.bench_function("vrf_verify_p256", |b| {
        b.iter(|| {
            crypto::ecvrf_verify(
                CIPHER_SUITE_KT_128_SHA256_P256,
                &vrf_pk_p256,
                &vrf_input,
                &proof_p256,
            )
            .unwrap()
        })
    });

    // --- Ed25519 Sign / Verify ---
    let (signer, _) = generate_sig_keypair();
    let tbs_data = vec![0u8; 128];
    let sig = sign_data(&signer, &tbs_data);
    let verifier =
        crypto::ServiceVerifyingKey::from_bytes(&signer.verifying_key().to_bytes()).unwrap();

    group.bench_function("ed25519_sign", |b| b.iter(|| sign_data(&signer, &tbs_data)));
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| verify_data(&verifier, &tbs_data, &sig).unwrap())
    });

    // --- HMAC Commitment ---
    let value = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...".to_vec();
    group.bench_function("hmac_commitment", |b| {
        b.iter(|| {
            let opening = generate_random_opening();
            commit(b"alice@example.com", 0, &value, &opening).unwrap()
        })
    });

    // --- SHA-256 (log tree leaf & parent) ---
    let root = vec![0u8; 32];
    group.bench_function("sha256_log_leaf", |b| {
        b.iter(|| crypto::hash::log_leaf_value(1_700_000_000_000, &root))
    });
    let left = vec![0u8; 32];
    let right = vec![0u8; 32];
    group.bench_function("sha256_log_parent", |b| {
        b.iter(|| crypto::hash::log_parent_value(&left, true, &right, true))
    });

    group.finish();
}

// ============================================================================
// 2. BINARY LADDER & TREE MATH (pure computation, no I/O)
// ============================================================================

fn bench_binary_ladder(c: &mut Criterion) {
    let mut group = c.benchmark_group("2_binary_ladder");
    group.sample_size(200);

    for &v in &[0u32, 1, 6, 100, 1_000, 10_000, 100_000, 1_000_000] {
        group.bench_with_input(BenchmarkId::new("base", v), &v, |b, &v| {
            b.iter(|| base_binary_ladder(v))
        });
    }

    for &(t, n) in &[(0u32, 6u32), (3, 100), (50, 1_000), (500, 10_000)] {
        group.bench_with_input(
            BenchmarkId::new("fixed_version", format!("t{}_n{}", t, n)),
            &(t, n),
            |b, &(t, n)| b.iter(|| search_binary_ladder(t, n, &[], &[])),
        );
    }

    group.finish();
}

// ============================================================================
// 3. END-TO-END PROTOCOL OPERATIONS
// ============================================================================

fn bench_protocol_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_update");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    let (service, rt) = setup_service_with_users(100);
    let counter = std::sync::atomic::AtomicUsize::new(10_000);

    // New user registration
    group.bench_function("new_user_registration", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            rt.block_on(async {
                let req = tonic::Request::new(update_req(make_label(i), None, make_value(0)));
                service.update(req).await.unwrap()
            })
        })
    });

    // Key rotation (existing label)
    let rotation_ctr = std::sync::atomic::AtomicUsize::new(1);
    group.bench_function("key_rotation", |b| {
        b.iter(|| {
            let v = rotation_ctr.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            rt.block_on(async {
                let req = tonic::Request::new(update_req(
                    make_label(0),
                    Some(v as u32 - 1),
                    make_value(v),
                ));
                service.update(req).await.unwrap()
            })
        })
    });

    group.finish();
}

fn bench_protocol_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_search");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Search at two representative tree sizes
    for &n in &[100usize, 1_000] {
        let (service, rt) = setup_service_with_users(n);

        group.bench_with_input(BenchmarkId::new("greatest_version", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        group.bench_with_input(BenchmarkId::new("fixed_version_0", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: Some(0),
                    });
                    service.search(req).await.unwrap()
                })
            })
        });
    }

    group.finish();
}

fn bench_protocol_search_versioned(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_search_versioned");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    for &nv in &[10usize, 50] {
        let (service, rt) = setup_service_with_versions(nv);

        group.bench_with_input(BenchmarkId::new("latest_of_n", nv), &nv, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        // Fixed-version search with a pseudo-random version (avoids v0 bias)
        let rv = rand_version(nv);
        group.bench_with_input(BenchmarkId::new("fixed_vrand_of_n", nv), &nv, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: Some(rv),
                    });
                    service.search(req).await.unwrap()
                })
            })
        });
    }

    group.finish();
}

fn bench_protocol_monitor(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_monitor");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let (service, rt) = setup_service_with_users(500);

    // Contact monitoring: 1 label
    group.bench_function("contact_1_label", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(ContactMonitorRequest {
                    last: None,
                    label: make_label(0),
                    entries: vec![MonitorMapEntry {
                        position: 0,
                        version: 0,
                    }],
                });
                service.contact_monitor(req).await.unwrap()
            })
        })
    });

    // Contact monitoring: 10 labels
    group.bench_function("contact_10_labels", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..10 {
                    let req = tonic::Request::new(ContactMonitorRequest {
                        last: None,
                        label: make_label(i),
                        entries: vec![MonitorMapEntry {
                            position: 0,
                            version: 0,
                        }],
                    });
                    service.contact_monitor(req).await.unwrap();
                }
            })
        })
    });

    // Owner monitoring
    group.bench_function("owner_monitoring", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(OwnerInitRequest {
                    last: None,
                    label: make_label(0),
                    start: 0,
                });
                service.owner_init(req).await.unwrap()
            })
        })
    });

    group.finish();
}

fn bench_protocol_audit(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_audit");
    group.sample_size(20);

    let (service, rt) = setup_service_with_users(500);

    for &limit in &[10u64, 100] {
        group.bench_with_input(
            BenchmarkId::new("fetch_entries", limit),
            &limit,
            |b, &lim| {
                b.iter(|| {
                    rt.block_on(async {
                        let req = tonic::Request::new(AuditRequest {
                            start: 0,
                            limit: lim,
                        });
                        service.audit(req).await.unwrap()
                    })
                })
            },
        );
    }

    group.finish();
}

fn bench_protocol_credential(c: &mut Criterion) {
    let mut group = c.benchmark_group("3_credential");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let (service, rt) = setup_service_with_users(500);

    group.bench_function("get_credential", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(GetCredentialRequest {
                    label: make_label(0),
                });
                service.get_credential(req).await.unwrap()
            })
        })
    });

    group.finish();
}

// ============================================================================
// 4. SCALE SCENARIOS
// ============================================================================

fn bench_batch_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("4_batch_throughput");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    for &batch_size in &[1usize, 10, 50, 100, 500, 1000] {
        let rt = make_runtime();
        let dir = tempdir().unwrap();
        let service = rt.block_on(async {
            let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
            let (signer, _) = generate_sig_keypair();
            let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
            KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
                .await
                .unwrap()
        });

        let counter = std::sync::atomic::AtomicUsize::new(0);
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_updates", batch_size),
            &batch_size,
            |b, &bs| {
                b.iter(|| {
                    let base = counter.fetch_add(bs, std::sync::atomic::Ordering::SeqCst);
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(bs);
                        for i in 0..bs {
                            let svc = service.clone();
                            let idx = base + i;
                            handles.push(tokio::spawn(async move {
                                let req = tonic::Request::new(update_req(
                                    make_label(idx),
                                    None,
                                    make_value(0),
                                ));
                                let _ = svc.update(req).await;
                            }));
                        }
                        for h in handles {
                            let _ = h.await;
                        }
                    })
                })
            },
        );
        std::mem::forget(dir);
    }

    group.finish();
}

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("4_concurrent_reads");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let (service, rt) = setup_service_with_users(500);

    for &n in &[1usize, 10, 50, 100] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("parallel_searches", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::with_capacity(n);
                    for i in 0..n {
                        let svc = service.clone();
                        handles.push(tokio::spawn(async move {
                            let req = tonic::Request::new(SearchRequest {
                                label: make_label(i % 500),
                                last: None,
                                version: None,
                            });
                            let _ = svc.search(req).await;
                        }));
                    }
                    for h in handles {
                        let _ = h.await;
                    }
                })
            })
        });
    }

    group.finish();
}

fn bench_git_forge_scenario(c: &mut Criterion) {
    let mut group = c.benchmark_group("4_git_forge");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    let (service, rt) = setup_service_with_users(500);

    // Verify a developer's signing key
    group.bench_function("verify_developer_key", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(42),
                    last: None,
                    version: None,
                });
                service.search(req).await.unwrap()
            })
        })
    });

    // Get credential for offline verification
    group.bench_function("get_developer_credential", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(GetCredentialRequest {
                    label: make_label(42),
                });
                service.get_credential(req).await.unwrap()
            })
        })
    });

    // New developer onboarding
    let counter = std::sync::atomic::AtomicUsize::new(50_000);
    group.bench_function("onboard_new_developer", |b| {
        b.iter(|| {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            rt.block_on(async {
                let req = tonic::Request::new(update_req(
                    make_label(i),
                    None,
                    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample...".to_vec(),
                ));
                service.update(req).await.unwrap()
            })
        })
    });

    // CI/CD pipeline: verify 10 developers concurrently
    group.bench_function("ci_verify_10_devs", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::with_capacity(10);
                for i in 0..10 {
                    let svc = service.clone();
                    handles.push(tokio::spawn(async move {
                        let req = tonic::Request::new(SearchRequest {
                            label: make_label(i * 50),
                            last: None,
                            version: None,
                        });
                        let _ = svc.search(req).await;
                    }));
                }
                for h in handles {
                    let _ = h.await;
                }
            })
        })
    });

    group.finish();
}

fn bench_enterprise_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("4_enterprise_rotation");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    // 50 users, 10 rotations each = 500 log entries + 50 initial = 550
    let rt = make_runtime();
    let dir = tempdir().unwrap();
    let service = rt.block_on(async {
        let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
        let (signer, _) = generate_sig_keypair();
        let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
        let svc = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
            .await
            .unwrap();
        std::mem::forget(dir);

        // Register 50 users
        let mut handles = Vec::new();
        for i in 0..50 {
            let s = svc.clone();
            handles.push(tokio::spawn(async move {
                let req = tonic::Request::new(update_req(make_label(i), None, make_value(0)));
                let _ = s.update(req).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Each user rotates 10 times
        for rotation in 1..=10 {
            let mut handles = Vec::new();
            for i in 0..50 {
                let s = svc.clone();
                handles.push(tokio::spawn(async move {
                    let req = tonic::Request::new(update_req(
                        make_label(i),
                        Some(rotation as u32 - 1),
                        make_value(rotation),
                    ));
                    let _ = s.update(req).await;
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        svc
    });

    group.bench_function("search_after_rotations", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(25),
                    last: None,
                    version: None,
                });
                service.search(req).await.unwrap()
            })
        })
    });

    // Fixed-version search with random version (avoids v0 best-case bias;
    // each user has 10 rotations so versions 0..10 exist).
    let ent_rv = rand_version(11);
    group.bench_function("search_fixed_vrand", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(25),
                    last: None,
                    version: Some(ent_rv),
                });
                service.search(req).await.unwrap()
            })
        })
    });

    group.bench_function("audit_100_entries", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(AuditRequest {
                    start: 0,
                    limit: 100,
                });
                service.audit(req).await.unwrap()
            })
        })
    });

    group.finish();
}

// ============================================================================
// 5. SCALABILITY ANALYSIS
// ============================================================================

fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("5_scalability");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(8));

    // How search & update latency grow with tree size
    for &n in &[10usize, 100, 500, 1_000, 2_000] {
        let (service, rt) = setup_service_with_users(n);

        group.bench_with_input(BenchmarkId::new("search_at_size", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(n / 2),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        let counter = std::sync::atomic::AtomicUsize::new(n + 100_000);
        group.bench_with_input(BenchmarkId::new("update_at_size", n), &n, |b, _| {
            b.iter(|| {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                rt.block_on(async {
                    let req = tonic::Request::new(update_req(make_label(i), None, make_value(0)));
                    service.update(req).await.unwrap()
                })
            })
        });
    }

    group.finish();
}

// ============================================================================
// 6. PROOF SIZE & VALUE SIZE ANALYSIS
// ============================================================================

fn bench_proof_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("6_proof_sizes");
    group.sample_size(10);

    for &n in &[10usize, 100, 1_000] {
        let (service, rt) = setup_service_with_users(n);

        group.bench_with_input(BenchmarkId::new("search_response_bytes", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    let resp = service.search(req).await.unwrap().into_inner();
                    let mut size = 0usize;
                    if let Some(th) = &resp.full_tree_head {
                        size += prost::Message::encoded_len(th);
                    }
                    if let Some(s) = &resp.search {
                        size += prost::Message::encoded_len(s);
                    }
                    size += resp.opening.len();
                    for step in &resp.binary_ladder {
                        size += prost::Message::encoded_len(step);
                    }
                    size
                })
            })
        });
    }

    group.finish();
}

fn bench_value_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("6_value_sizes");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    for &sz in &[32usize, 256, 1024, 4096] {
        let rt = make_runtime();
        let dir = tempdir().unwrap();
        let service = rt.block_on(async {
            let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
            let (signer, _) = generate_sig_keypair();
            let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
            KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None)
                .await
                .unwrap()
        });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_with_input(BenchmarkId::new("update_value_bytes", sz), &sz, |b, &sz| {
            b.iter(|| {
                let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                rt.block_on(async {
                    let req =
                        tonic::Request::new(update_req(make_label(i), None, make_large_value(sz)));
                    service.update(req).await.unwrap()
                })
            })
        });
        std::mem::forget(dir);
    }

    group.finish();
}

fn bench_tree_head(c: &mut Criterion) {
    let mut group = c.benchmark_group("6_tree_head");
    group.sample_size(20);

    let (service, rt) = setup_service_with_users(500);

    group.bench_function("tree_size_rpc", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(());
                service.tree_size(req).await.unwrap()
            })
        })
    });

    group.bench_function("full_tree_head_fresh", |b| {
        b.iter(|| {
            rt.block_on(async {
                let guard = service.tree.read().await;
                guard.get_full_tree_head(None).unwrap()
            })
        })
    });

    group.bench_function("full_tree_head_consistency", |b| {
        b.iter(|| {
            rt.block_on(async {
                let guard = service.tree.read().await;
                guard
                    .get_full_tree_head(Some(Consistency {
                        last: Some(250),
                        distinguished: None,
                    }))
                    .unwrap()
            })
        })
    });

    group.finish();
}

// ============================================================================
// 7. COMPARATIVE ANALYSIS (protocol design choices vs alternatives)
// ============================================================================

fn bench_comparative_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("7_comparative");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    // --- Greatest-version vs fixed-version search across tree sizes ---
    // Uses LARGE_TREE_SIZES (32 to 1M users) to show O(log n) scaling at
    // WhatsApp-like magnitudes. Each user has 1 key version (bulk populated).
    for &n in LARGE_TREE_SIZES {
        let (service, rt) = setup_service_bulk(n);

        group.bench_with_input(BenchmarkId::new("greatest_version", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        group.bench_with_input(BenchmarkId::new("fixed_v0", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: Some(0),
                    });
                    service.search(req).await.unwrap()
                })
            })
        });
    }

    // --- Binary ladder efficiency: how search cost grows with version count ---
    // Each setup creates 1 user with `nv` versions via sequential rotations.
    // We benchmark greatest-version, fixed-v0, and fixed-vmid to show:
    //   - Greatest scales with frontier × ladder size (expensive)
    //   - Fixed-v0 is unrealistically cheap (terminates early)
    //   - Fixed-vmid is the realistic fixed-version cost
    for &nv in BENCH_VERSION_COUNTS {
        let (service, rt) = setup_service_with_versions(nv);

        group.bench_with_input(BenchmarkId::new("ladder_greatest", nv), &nv, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        // Fixed-version with pseudo-random version (avoids v0 best-case bias)
        let rv = rand_version(nv);
        group.bench_with_input(BenchmarkId::new("ladder_fixed_vrand", nv), &nv, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: Some(rv),
                    });
                    service.search(req).await.unwrap()
                })
            })
        });
    }

    // --- Proof payload size: combined proof bytes by tree size ---
    // Shows O(log n) growth of the combined proof (inclusion + correctness
    // share copath elements, deduplicating vs separate proofs).
    // Uses LARGE_TREE_SIZES to show scaling across orders of magnitude.
    for &n in LARGE_TREE_SIZES {
        let (service, rt) = setup_service_bulk(n);

        // One-time measurement: print actual byte count
        let one_shot_bytes = rt.block_on(async {
            let req = tonic::Request::new(SearchRequest {
                label: make_label(0),
                last: None,
                version: None,
            });
            let resp = service.search(req).await.unwrap().into_inner();
            let mut size = 0usize;
            if let Some(th) = &resp.full_tree_head {
                size += prost::Message::encoded_len(th);
            }
            if let Some(s) = &resp.search {
                size += prost::Message::encoded_len(s);
            }
            size += resp.opening.len();
            for step in &resp.binary_ladder {
                size += prost::Message::encoded_len(step);
            }
            size
        });
        eprintln!("📐 proof_bytes_by_users/{} = {} bytes", n, one_shot_bytes);

        group.bench_with_input(BenchmarkId::new("proof_bytes_by_users", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(0),
                        last: None,
                        version: None,
                    });
                    let resp = service.search(req).await.unwrap().into_inner();
                    let mut size = 0usize;
                    if let Some(th) = &resp.full_tree_head {
                        size += prost::Message::encoded_len(th);
                    }
                    if let Some(s) = &resp.search {
                        size += prost::Message::encoded_len(s);
                    }
                    size += resp.opening.len();
                    for step in &resp.binary_ladder {
                        size += prost::Message::encoded_len(step);
                    }
                    size
                })
            })
        });
    }

    // --- Proof payload size: bytes by version count ---
    // Shows how greatest-version proof grows with more versions
    // (more binary ladder steps).
    for &nv in BENCH_VERSION_COUNTS {
        let (service, rt) = setup_service_with_versions(nv);

        // One-time measurement: print actual byte count
        let one_shot_bytes = rt.block_on(async {
            let req = tonic::Request::new(SearchRequest {
                label: make_label(0),
                last: None,
                version: None,
            });
            let resp = service.search(req).await.unwrap().into_inner();
            let mut size = 0usize;
            if let Some(th) = &resp.full_tree_head {
                size += prost::Message::encoded_len(th);
            }
            if let Some(s) = &resp.search {
                size += prost::Message::encoded_len(s);
            }
            size += resp.opening.len();
            for step in &resp.binary_ladder {
                size += prost::Message::encoded_len(step);
            }
            size
        });
        eprintln!(
            "📐 proof_bytes_by_versions/{} = {} bytes",
            nv, one_shot_bytes
        );

        group.bench_with_input(
            BenchmarkId::new("proof_bytes_by_versions", nv),
            &nv,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        let req = tonic::Request::new(SearchRequest {
                            label: make_label(0),
                            last: None,
                            version: None,
                        });
                        let resp = service.search(req).await.unwrap().into_inner();
                        let mut size = 0usize;
                        if let Some(th) = &resp.full_tree_head {
                            size += prost::Message::encoded_len(th);
                        }
                        if let Some(s) = &resp.search {
                            size += prost::Message::encoded_len(s);
                        }
                        size += resp.opening.len();
                        for step in &resp.binary_ladder {
                            size += prost::Message::encoded_len(step);
                        }
                        size
                    })
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 8. LARGE-SCALE USER SCALABILITY (WhatsApp-scale: 32 to 1M+ users)
// ============================================================================

fn bench_large_scale_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("8_large_scale");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    for &n in LARGE_TREE_SIZES {
        let (service, rt) = setup_service_bulk(n);

        // Search latency (greatest-version, 1 key version per user)
        group.bench_with_input(BenchmarkId::new("search_latency", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(n / 2),
                        last: None,
                        version: None,
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        // Fixed-version search (mid-range label, version 0 — realistic since
        // most WhatsApp users have 1-3 versions)
        group.bench_with_input(BenchmarkId::new("fixed_v0_latency", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(n / 2),
                        last: None,
                        version: Some(0),
                    });
                    service.search(req).await.unwrap()
                })
            })
        });

        // Contact monitoring latency (1 label)
        group.bench_with_input(BenchmarkId::new("monitor_latency", n), &n, |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(ContactMonitorRequest {
                        last: None,
                        label: make_label(0),
                        entries: vec![MonitorMapEntry {
                            position: 0,
                            version: 0,
                        }],
                    });
                    service.contact_monitor(req).await.unwrap()
                })
            })
        });

        // Search response payload size (bytes on the wire)
        let one_shot_bytes = rt.block_on(async {
            let req = tonic::Request::new(SearchRequest {
                label: make_label(n / 2),
                last: None,
                version: None,
            });
            let resp = service.search(req).await.unwrap().into_inner();
            let mut size = 0usize;
            if let Some(th) = &resp.full_tree_head {
                size += prost::Message::encoded_len(th);
            }
            if let Some(s) = &resp.search {
                size += prost::Message::encoded_len(s);
            }
            size += resp.opening.len();
            for step in &resp.binary_ladder {
                size += prost::Message::encoded_len(step);
            }
            size
        });
        eprintln!("📐 search_payload_bytes/{} = {} bytes", n, one_shot_bytes);

        group.bench_with_input(BenchmarkId::new("search_payload_bytes", n), &n, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let req = tonic::Request::new(SearchRequest {
                        label: make_label(n / 2),
                        last: None,
                        version: None,
                    });
                    let resp = service.search(req).await.unwrap().into_inner();
                    let mut size = 0usize;
                    if let Some(th) = &resp.full_tree_head {
                        size += prost::Message::encoded_len(th);
                    }
                    if let Some(s) = &resp.search {
                        size += prost::Message::encoded_len(s);
                    }
                    size += resp.opening.len();
                    for step in &resp.binary_ladder {
                        size += prost::Message::encoded_len(step);
                    }
                    size
                })
            })
        });
    }

    group.finish();
}

// ============================================================================
// 9. GDPR / PRIVACY (pruning, right-to-be-forgotten)
// ============================================================================

fn bench_gdpr(c: &mut Criterion) {
    let mut group = c.benchmark_group("9_gdpr");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    // --- Setup: service with maximum_lifetime enabled ---
    let rt = make_runtime();
    let dir = tempdir().unwrap();
    let db_for_bench = rt.block_on(async {
        let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap()).unwrap());
        let (signer, _) = generate_sig_keypair();
        let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
        let svc = KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None)
            .await
            .unwrap();

        // Enable maximum_lifetime (10s)
        {
            let mut tree = svc.tree.write().await;
            tree.config.maximum_lifetime = Some(10_000);
        }

        // Insert 100 users
        let mut handles = Vec::with_capacity(100);
        for i in 0..100 {
            let s = svc.clone();
            handles.push(tokio::spawn(async move {
                let req = tonic::Request::new(update_req(make_label(i), None, make_value(0)));
                let _ = s.update(req).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        (svc, db)
    });
    let (service, db) = db_for_bench;
    std::mem::forget(dir);

    // --- Benchmark: search with maximum_lifetime enabled (non-expired) ---
    // Measures whether having maximum_lifetime enabled adds overhead to normal searches.
    // Must run BEFORE destructive benchmarks that delete openings / age timestamps.
    group.bench_function("search_with_lifetime_enabled", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(1),
                    last: None,
                    version: None,
                });
                service.search(req).await.unwrap()
            })
        })
    });

    // --- Benchmark: delete_opening latency (right-to-be-forgotten) ---
    // Measures how fast we can erase a user's opening from the DB.
    // Uses high key range to avoid colliding with labels used by other benchmarks.
    let delete_counter = std::sync::atomic::AtomicUsize::new(10_000);
    group.bench_function("delete_opening", |b| {
        b.iter(|| {
            let i = delete_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            db.delete_opening(i as u64).unwrap()
        })
    });

    // --- Benchmark: search after opening deletion (should fail fast) ---
    // Delete user 50's opening, then measure how fast the "unavailable" error returns.
    rt.block_on(async {
        let history = db.get_label_history(&make_label(50)).unwrap();
        let (_, ptr) = history[0];
        db.delete_opening(ptr).unwrap();
    });
    group.bench_function("search_after_forget", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(50),
                    last: None,
                    version: Some(0),
                });
                let _ = service.search(req).await;
            })
        })
    });

    // --- Benchmark: search expired entry (after artificial aging) ---
    // Age entry 0's timestamp past the maximum_lifetime, then measure error path.
    rt.block_on(async {
        let tree = service.tree.read().await;
        let tree_size = tree.latest.as_ref().unwrap().tree_size;
        let current_ts_bytes = db
            .get_value((tree_size - 1) | (1u64 << 63))
            .unwrap()
            .unwrap();
        let current_ts = u64::from_be_bytes(current_ts_bytes.try_into().unwrap());
        let old_ts = current_ts - 20_000;
        db.put_value(1u64 << 63, old_ts.to_be_bytes().to_vec())
            .unwrap();
    });
    group.bench_function("search_expired_entry", |b| {
        b.iter(|| {
            rt.block_on(async {
                let req = tonic::Request::new(SearchRequest {
                    label: make_label(0),
                    last: None,
                    version: Some(0),
                });
                let _ = service.search(req).await;
            })
        })
    });

    group.finish();
}

// ============================================================================
// CRITERION GROUPS
// ============================================================================

/// Preload all golden databases before any benchmarks run.
fn bench_preload(_c: &mut Criterion) {
    let mut all_sizes = BENCH_TREE_SIZES.to_vec();
    all_sizes.extend_from_slice(LARGE_TREE_SIZES);
    preload_golden_dbs(&all_sizes);
}

criterion_group! {
    name = warmup;
    config = Criterion::default();
    targets = bench_preload
}

criterion_group! {
    name = crypto;
    config = Criterion::default();
    targets = bench_crypto_primitives
}

criterion_group! {
    name = tree_math;
    config = Criterion::default();
    targets = bench_binary_ladder
}

criterion_group! {
    name = protocol;
    config = Criterion::default();
    targets =
        bench_protocol_update,
        bench_protocol_search,
        bench_protocol_search_versioned,
        bench_protocol_monitor,
        bench_protocol_audit,
        bench_protocol_credential
}

criterion_group! {
    name = scale;
    config = Criterion::default();
    targets =
        bench_batch_throughput,
        bench_concurrent_reads,
        bench_git_forge_scenario,
        bench_enterprise_rotation
}

criterion_group! {
    name = analysis;
    config = Criterion::default();
    targets =
        bench_scalability,
        bench_proof_sizes,
        bench_value_sizes,
        bench_tree_head
}

criterion_group! {
    name = comparative;
    config = Criterion::default();
    targets = bench_comparative_analysis
}

criterion_group! {
    name = large_scale;
    config = Criterion::default();
    targets = bench_large_scale_scalability
}

criterion_group! {
    name = gdpr;
    config = Criterion::default();
    targets = bench_gdpr
}

criterion_main!(
    warmup,
    crypto,
    tree_math,
    protocol,
    scale,
    analysis,
    comparative,
    large_scale,
    gdpr
);
