// Proof verification cost (draft-05), for both verifying parties:
//   8_client_verification — what an end user pays per verified response
//   8_auditor_verification — what a third-party auditor pays per log entry
//
// Measures only the verify routine. Excluded from the timed region:
// network/gRPC, the tokio runtime, server-side proof generation, and state
// persistence I/O.
//
// Requires the `bench-internals` feature:
//   cargo bench --features bench-internals --bench verification
//
// Setup builds golden DBs with ONE log entry per label (timestamps spaced
// TS_STEP_MS apart) so frontier and ladder work scales with tree size, then
// captures each operation's response by calling the Tree handlers directly.
// Clock windows and auditor lag are set effectively unbounded in the (signed)
// config so captured heads stay verifiable across runs; the monitoring window
// scales with tree size so the distinguished structure is size-invariant
// (~2×DIST_HEADS heads per tree).

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rukt::bulk;
use rukt::client::KtClient;
use rukt::client::verifier::{LogAccumulator, PrefixTransitioner};
use rukt::crypto::{
    self, CIPHER_SUITE_KT_128_SHA256_ED25519, DEPLOYMENT_MODE_CONTACT_MONITORING,
    DEPLOYMENT_MODE_THIRD_PARTY_AUDITING, PrivateConfig, PublicConfig, ServiceSigningKey,
    ServiceVerifyingKey, generate_sig_keypair, generate_vrf_keypair,
};
use rukt::db::RocksDbStore;
use rukt::proto::transparency::{
    AuditorTreeHead, AuditorUpdate, ContactMonitorRequest, ContactMonitorResponse, Credential,
    CredentialType, CredentialUpdate, DistinguishedRequest, DistinguishedResponse,
    GetCredentialRequest, GetCredentialUpdateRequest, MonitorMapEntry, OwnerInitRequest,
    OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse, SearchRequest, SearchResponse,
};
use rukt::tree::{PreUpdateData, Tree};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::runtime::Runtime;

const SIZES: &[u64] = &[1_000, 10_000, 100_000];
const TS_STEP_MS: u64 = 1_000;
/// Target number of top-level distinguished intervals per tree.
const DIST_HEADS: u64 = 32;
/// Effectively-unbounded clock window so golden DBs stay verifiable across runs.
const MAX_SKEW_MS: u64 = u64::MAX / 4;
const GOLDEN_DB_DIR: &str = "/tmp/kt_golden";
const KEYS_FILENAME: &str = "bench_keys.bin";

fn rmw_for(n: u64) -> u64 {
    n * TS_STEP_MS / DIST_HEADS
}

fn make_label(i: u64) -> Vec<u8> {
    format!("user_{}@example.com", i).into_bytes()
}

fn make_value() -> Vec<u8> {
    b"pubkey_v0".to_vec()
}

fn make_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

// ============================================================================
// Golden DB construction (per-entry log trees, cached across runs)
// ============================================================================

fn save_keys(dir: &str, signer: &ServiceSigningKey, vrf_key: &[u8], auditor: Option<&[u8]>) {
    let sig_bytes = match signer {
        ServiceSigningKey::Ed25519(k) => k.to_bytes().to_vec(),
        _ => panic!("Only Ed25519 signing keys supported in bench"),
    };
    let mut data = Vec::new();
    for part in [&sig_bytes[..], vrf_key, auditor.unwrap_or(&[])] {
        data.extend_from_slice(&(part.len() as u32).to_be_bytes());
        data.extend_from_slice(part);
    }
    std::fs::write(format!("{}/{}", dir, KEYS_FILENAME), data).unwrap();
}

fn load_keys(dir: &str) -> (ServiceSigningKey, Vec<u8>, Option<ServiceSigningKey>) {
    let data = std::fs::read(format!("{}/{}", dir, KEYS_FILENAME)).unwrap();
    let mut cursor = 0usize;
    let mut next = || {
        let len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let part = data[cursor..cursor + len].to_vec();
        cursor += len;
        part
    };
    let sig_bytes = next();
    let vrf_key = next();
    let auditor_bytes = next();

    let to_signer = |bytes: &[u8]| {
        let arr: [u8; 32] = bytes.try_into().unwrap();
        ServiceSigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&arr))
    };
    let auditor = if auditor_bytes.is_empty() {
        None
    } else {
        Some(to_signer(&auditor_bytes))
    };
    (to_signer(&sig_bytes), vrf_key, auditor)
}

fn bench_private_config(
    signer: ServiceSigningKey,
    vrf_key: Vec<u8>,
    auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
    n: u64,
) -> PrivateConfig {
    let mode = if auditor_keys.is_empty() {
        DEPLOYMENT_MODE_CONTACT_MONITORING
    } else {
        DEPLOYMENT_MODE_THIRD_PARTY_AUDITING
    };
    let mut config = PrivateConfig::new(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode,
        signer,
        vrf_key,
        auditor_keys,
        MAX_SKEW_MS,
        MAX_SKEW_MS,
        rmw_for(n),
        None,
        None,
        100,
    )
    .unwrap();
    config.max_auditor_lag = MAX_SKEW_MS;
    config
}

fn public_config(config: &PrivateConfig) -> PublicConfig {
    PublicConfig {
        cipher_suite: config.cipher_suite,
        mode: config.mode,
        server_sig_pk: config.sig_key.verifying_key().to_bytes(),
        vrf_public_key: config.vrf_public_key.clone(),
        leaf_public_key: config.leaf_public_key.clone(),
        auditor_public_key: config.auditor_public_key.clone(),
        auditor_start_pos: config.auditor_start_pos,
        max_auditor_lag: config.max_auditor_lag,
        max_ahead: config.max_ahead,
        max_behind: config.max_behind,
        reasonable_monitoring_window: config.reasonable_monitoring_window,
        maximum_lifetime: config.maximum_lifetime,
    }
}

fn auditor_keys_map(auditor: &ServiceSigningKey) -> HashMap<Vec<u8>, ServiceVerifyingKey> {
    let vk = auditor.verifying_key();
    HashMap::from([(vk.to_bytes(), vk)])
}

fn build_or_load_golden(n: u64, auditing: bool, rt: &Runtime) -> String {
    let mode = if auditing { "auditing" } else { "contact" };
    let golden_path = format!("{}/verify_{}_{}", GOLDEN_DB_DIR, mode, n);
    if Path::new(&format!("{}/{}", golden_path, KEYS_FILENAME)).exists() {
        println!("   ♻️  Reusing golden DB at {}", golden_path);
        return golden_path;
    }

    let _ = std::fs::remove_dir_all(&golden_path);
    std::fs::create_dir_all(GOLDEN_DB_DIR).unwrap();
    println!("   🔨 Building per-entry golden DB ({} {})...", mode, n);

    let (signer, _) = generate_sig_keypair();
    let (vrf_key, _) = generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let (auditor, auditor_keys) = if auditing {
        let (ask, _) = generate_sig_keypair();
        let keys = auditor_keys_map(&ask);
        (Some(ask), keys)
    } else {
        (None, HashMap::new())
    };
    let config = bench_private_config(signer.clone(), vrf_key.clone(), auditor_keys, n);

    rt.block_on(async {
        let db = Arc::new(RocksDbStore::new(&golden_path).unwrap());
        let mut tree = Tree::new(db.clone(), &config).await.unwrap();
        let labels: Vec<(Vec<u8>, Vec<u8>)> =
            (0..n).map(|i| (make_label(i), make_value())).collect();
        bulk::bulk_populate_per_entry(&mut tree, &db, &config, labels, TS_STEP_MS)
            .await
            .unwrap();
    });

    let auditor_sk = auditor.as_ref().map(|a| match a {
        ServiceSigningKey::Ed25519(k) => k.to_bytes().to_vec(),
        _ => unreachable!(),
    });
    save_keys(&golden_path, &signer, &vrf_key, auditor_sk.as_deref());
    golden_path
}

/// Opens a fast hard-link checkpoint of the golden DB; the TempDir keeps it
/// alive for the fixture's lifetime and cleans it up on drop.
fn open_checkpoint(
    golden: &str,
    config: &PrivateConfig,
    rt: &Runtime,
) -> (Arc<RocksDbStore>, Tree, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint = dir.path().join("db");
    let checkpoint = checkpoint.to_str().unwrap();

    let source = RocksDbStore::new(golden).unwrap();
    source.checkpoint(checkpoint).unwrap();
    drop(source);

    let db = Arc::new(RocksDbStore::new(checkpoint).unwrap());
    let tree = rt.block_on(Tree::new(db.clone(), config)).unwrap();
    (db, tree, dir)
}

// ============================================================================
// Fixtures: captured responses + primed clients, all off the clock
// ============================================================================

struct ContactFixture {
    fresh: KtClient,
    sg_label: Vec<u8>,
    sg_resp: SearchResponse,
    sf_label: Vec<u8>,
    sf_resp: SearchResponse,
    cm_client: KtClient,
    cm_label: Vec<u8>,
    cm_map: BTreeMap<u64, u32>,
    cm_resp: ContactMonitorResponse,
    oi_label: Vec<u8>,
    oi_start: u64,
    oi_resp: OwnerInitResponse,
    om_client: KtClient,
    om_label: Vec<u8>,
    om_map: BTreeMap<u64, u32>,
    om_start: u64,
    om_resp: OwnerMonitorResponse,
    dist_resp: DistinguishedResponse,
    cred_client: KtClient,
    cred_std: Credential,
    cred_prov: Credential,
    cu_client: KtClient,
    cu_update: CredentialUpdate,
    _dir: TempDir,
}

/// Runs a greatest-version search and verifies it, seeding the client's
/// trusted state, monitoring map, and retained version material.
fn prime_with_search(client: &mut KtClient, tree: &Tree, label: &[u8], rt: &Runtime) {
    let resp = rt
        .block_on(tree.search(&SearchRequest {
            last: None,
            label: label.to_vec(),
            version: None,
        }))
        .unwrap();
    client
        .bench_verify_search_response(label, None, &resp)
        .expect("priming search must verify");
}

fn monitor_entries(map: &BTreeMap<u64, u32>) -> Vec<MonitorMapEntry> {
    map.iter()
        .map(|(&position, &version)| MonitorMapEntry { position, version })
        .collect()
}

// the lazy tonic channel can only be constructed inside a runtime context
fn unconnected_client(config: PublicConfig, rt: &Runtime) -> KtClient {
    let _guard = rt.enter();
    KtClient::bench_unconnected(config).unwrap()
}

fn build_contact_fixture(n: u64, rt: &Runtime) -> ContactFixture {
    let golden = build_or_load_golden(n, false, rt);
    let (signer, vrf_key, _) = load_keys(&golden);
    let config = bench_private_config(signer, vrf_key, HashMap::new(), n);
    let (db, mut tree, dir) = open_checkpoint(&golden, &config, rt);
    let fresh = unconnected_client(public_config(&config), rt);

    // search_greatest / search_fixed: a recent label makes the fixed-version
    // walk descend the full right path instead of terminating at the root
    let sg_label = make_label(n / 2);
    let sg_resp = rt
        .block_on(tree.search(&SearchRequest {
            last: None,
            label: sg_label.clone(),
            version: None,
        }))
        .unwrap();
    fresh
        .clone()
        .bench_verify_search_response(&sg_label, None, &sg_resp)
        .expect("search_greatest capture must verify");

    let sf_label = make_label(n - 3);
    let sf_resp = rt
        .block_on(tree.search(&SearchRequest {
            last: None,
            label: sf_label.clone(),
            version: Some(0),
        }))
        .unwrap();
    fresh
        .clone()
        .bench_verify_search_response(&sf_label, Some(0), &sf_resp)
        .expect("search_fixed capture must verify");

    // owner_init: a label registered at entry 0 exists at every entry of the
    // init list, which climbs the ancestors below `start`
    let oi_label = make_label(0);
    let oi_start = n / 2;
    let oi_resp = rt
        .block_on(tree.owner_init(&OwnerInitRequest {
            last: None,
            label: oi_label.clone(),
            start: oi_start,
        }))
        .unwrap();
    fresh
        .clone()
        .bench_verify_owner_init(&oi_label, oi_start, &oi_resp)
        .expect("owner_init capture must verify");

    // distinguished walk, also priming the credential verifier's client
    let dist_resp = rt
        .block_on(tree.distinguished(&DistinguishedRequest {
            last: None,
            stop: None,
        }))
        .unwrap();
    let mut cred_client = fresh.clone();
    cred_client
        .bench_verify_distinguished(None, &dist_resp)
        .expect("distinguished capture must verify");

    // credentials: an old label is covered by a distinguished entry
    // (standard); the newest label is not (provisional)
    let cred_std = rt
        .block_on(tree.get_credential(&GetCredentialRequest {
            label: make_label(n / 4),
        }))
        .unwrap();
    assert_eq!(cred_std.credential_type, CredentialType::Standard as i32);
    cred_client
        .verify_credential(&cred_std)
        .expect("standard credential must verify");

    let cred_prov = rt
        .block_on(tree.get_credential(&GetCredentialRequest {
            label: make_label(n - 1),
        }))
        .unwrap();
    assert_eq!(
        cred_prov.credential_type,
        CredentialType::Provisional as i32
    );
    cred_client
        .verify_credential(&cred_prov)
        .expect("provisional credential must verify");

    // monitoring obligations are seeded at size n and monitored after the log
    // grows: a fresh obligation sits on the frontier where the replay is a
    // no-op, so growth is what makes the monitor rows do real ladder work
    let cm_label = make_label(n - 2);
    let mut cm_client = fresh.clone();
    prime_with_search(&mut cm_client, &tree, &cm_label, rt);
    let cm_map = cm_client.monitoring_map.get(&cm_label).cloned().unwrap();

    let om_label = make_label(n / 2 + 1);
    let om_start = n / 2 + 1;
    let mut om_client = fresh.clone();
    prime_with_search(&mut om_client, &tree, &om_label, rt);
    let om_map = om_client.monitoring_map.get(&om_label).cloned().unwrap();

    // grow the log; this also puts a distinguished entry right of the
    // provisional credential's terminal, which credential_update requires
    let growth: Vec<(Vec<u8>, Vec<u8>)> = (n..n + n / 8)
        .map(|i| (make_label(i), make_value()))
        .collect();
    rt.block_on(bulk::bulk_populate_per_entry(
        &mut tree, &db, &config, growth, TS_STEP_MS,
    ))
    .unwrap();

    let cm_resp = rt
        .block_on(tree.contact_monitor(&ContactMonitorRequest {
            last: cm_client.state.as_ref().map(|s| s.tree_size),
            label: cm_label.clone(),
            entries: monitor_entries(&cm_map),
        }))
        .unwrap();
    cm_client
        .clone()
        .bench_verify_contact_monitor(&cm_label, &cm_map, &cm_resp)
        .expect("contact_monitor capture must verify");

    let om_resp = rt
        .block_on(tree.owner_monitor(&OwnerMonitorRequest {
            last: om_client.state.as_ref().map(|s| s.tree_size),
            label: om_label.clone(),
            entries: monitor_entries(&om_map),
            start: om_start,
            greatest_version: Some(0),
        }))
        .unwrap();
    om_client
        .clone()
        .bench_verify_owner_monitor(&om_label, &om_map, om_start, Some(0), &om_resp)
        .expect("owner_monitor capture must verify");

    let mut cu_client = cred_client.clone();
    let dist2 = rt
        .block_on(tree.distinguished(&DistinguishedRequest {
            last: cu_client.state.as_ref().map(|s| s.tree_size),
            stop: None,
        }))
        .unwrap();
    cu_client
        .bench_verify_distinguished(None, &dist2)
        .expect("post-growth distinguished walk must verify");
    let terminal = cu_client.credential_terminal(&cred_prov).unwrap();
    let cu_update = rt
        .block_on(tree.get_credential_update(&GetCredentialUpdateRequest {
            label: make_label(n - 1),
            terminal_position: terminal,
            terminal_version: cred_prov.version,
        }))
        .unwrap();
    cu_client
        .verify_credential_update(&cred_prov, &cu_update)
        .expect("credential update must verify");

    ContactFixture {
        fresh,
        sg_label,
        sg_resp,
        sf_label,
        sf_resp,
        cm_client,
        cm_label,
        cm_map,
        cm_resp,
        oi_label,
        oi_start,
        oi_resp,
        om_client,
        om_label,
        om_map,
        om_start,
        om_resp,
        dist_resp,
        cred_client,
        cred_std,
        cred_prov,
        cu_client,
        cu_update,
        _dir: dir,
    }
}

struct AuditingFixture {
    fresh: KtClient,
    label: Vec<u8>,
    lagging_resp: SearchResponse,
    fresh_resp: SearchResponse,
    _dir: TempDir,
}

fn sign_auditor_head(
    tree: &Tree,
    config: &PublicConfig,
    auditor: &ServiceSigningKey,
    tree_size: u64,
) -> AuditorTreeHead {
    let root = tree.log.get_root(tree_size).unwrap();
    let ts = tree.log.get_timestamp(tree_size - 1).unwrap();
    let tbs = crypto::construct_auditor_tree_head_tbs_public(config, tree_size, ts, &root).unwrap();
    AuditorTreeHead {
        tree_size,
        timestamp: ts as i64,
        signature: crypto::sign_data(auditor, &tbs),
    }
}

fn build_auditing_fixture(n: u64, rt: &Runtime) -> AuditingFixture {
    let golden = build_or_load_golden(n, true, rt);
    let (signer, vrf_key, auditor) = load_keys(&golden);
    let auditor = auditor.expect("auditing golden DB must persist the auditor key");
    let auditor_keys = auditor_keys_map(&auditor);
    let config = bench_private_config(signer, vrf_key, auditor_keys.clone(), n);
    let (_db, mut tree, dir) = open_checkpoint(&golden, &config, rt);
    let pub_config = public_config(&config);
    let fresh = unconnected_client(pub_config.clone(), rt);
    let label = make_label(n / 2);

    // lagging head first (the same-auditor head can only advance), so both
    // captures see the auditor state they are meant to exercise; the signed
    // size must end at a frontier leaf — the client can only derive the
    // auditor sub-root when the boundary leaf is provided by the search proof
    let target = n - n / 8;
    let lag_size = rukt::tree::log_math::get_frontier(n)
        .into_iter()
        .map(|f| f + 1)
        .filter(|&m| m < n)
        .min_by_key(|&m| m.abs_diff(target))
        .unwrap();
    let ath = sign_auditor_head(&tree, &pub_config, &auditor, lag_size);
    rt.block_on(tree.set_auditor_head(ath, &auditor_keys))
        .unwrap();
    let lagging_resp = rt
        .block_on(tree.search(&SearchRequest {
            last: None,
            label: label.clone(),
            version: None,
        }))
        .unwrap();
    fresh
        .clone()
        .bench_verify_search_response(&label, None, &lagging_resp)
        .expect("lagging-auditor capture must verify");

    let ath = sign_auditor_head(&tree, &pub_config, &auditor, n);
    rt.block_on(tree.set_auditor_head(ath, &auditor_keys))
        .unwrap();
    let fresh_resp = rt
        .block_on(tree.search(&SearchRequest {
            last: None,
            label: label.clone(),
            version: None,
        }))
        .unwrap();
    fresh
        .clone()
        .bench_verify_search_response(&label, None, &fresh_resp)
        .expect("fresh-auditor capture must verify");

    AuditingFixture {
        fresh,
        label,
        lagging_resp,
        fresh_resp,
        _dir: dir,
    }
}

// ============================================================================
// 8. CLIENT-SIDE VERIFICATION
// ============================================================================

fn bench_client_verification(c: &mut Criterion) {
    let rt = make_runtime();
    let mut group = c.benchmark_group("8_client_verification");
    group.sample_size(30);
    // pure CPU verification is very low-variance; the default 3s+5s per row
    // would dominate the run's wall time
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    for &n in SIZES {
        let fx = build_contact_fixture(n, &rt);

        group.bench_with_input(BenchmarkId::new("search_greatest", n), &n, |b, _| {
            b.iter_batched(
                || fx.fresh.clone(),
                |mut client| {
                    client
                        .bench_verify_search_response(&fx.sg_label, None, &fx.sg_resp)
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("search_fixed", n), &n, |b, _| {
            b.iter_batched(
                || fx.fresh.clone(),
                |mut client| {
                    client
                        .bench_verify_search_response(&fx.sf_label, Some(0), &fx.sf_resp)
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("contact_monitor", n), &n, |b, _| {
            b.iter_batched(
                || fx.cm_client.clone(),
                |mut client| {
                    client
                        .bench_verify_contact_monitor(&fx.cm_label, &fx.cm_map, &fx.cm_resp)
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("owner_init", n), &n, |b, _| {
            b.iter_batched(
                || fx.fresh.clone(),
                |mut client| {
                    client
                        .bench_verify_owner_init(&fx.oi_label, fx.oi_start, &fx.oi_resp)
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("owner_monitor", n), &n, |b, _| {
            b.iter_batched(
                || fx.om_client.clone(),
                |mut client| {
                    client
                        .bench_verify_owner_monitor(
                            &fx.om_label,
                            &fx.om_map,
                            fx.om_start,
                            Some(0),
                            &fx.om_resp,
                        )
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("distinguished", n), &n, |b, _| {
            b.iter_batched(
                || fx.fresh.clone(),
                |mut client| {
                    client
                        .bench_verify_distinguished(None, &fx.dist_resp)
                        .unwrap();
                    client
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_with_input(BenchmarkId::new("credential_standard", n), &n, |b, _| {
            b.iter(|| fx.cred_client.verify_credential(&fx.cred_std).unwrap())
        });

        group.bench_with_input(BenchmarkId::new("credential_provisional", n), &n, |b, _| {
            b.iter(|| fx.cred_client.verify_credential(&fx.cred_prov).unwrap())
        });

        group.bench_with_input(BenchmarkId::new("credential_update", n), &n, |b, _| {
            b.iter(|| {
                fx.cu_client
                    .verify_credential_update(&fx.cred_prov, &fx.cu_update)
                    .unwrap()
            })
        });

        drop(fx);
        let ax = build_auditing_fixture(n, &rt);

        group.bench_with_input(
            BenchmarkId::new("search_greatest_auditing", n),
            &n,
            |b, _| {
                b.iter_batched(
                    || ax.fresh.clone(),
                    |mut client| {
                        client
                            .bench_verify_search_response(&ax.label, None, &ax.fresh_resp)
                            .unwrap();
                        client
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("search_greatest_lagging_auditor", n),
            &n,
            |b, _| {
                b.iter_batched(
                    || ax.fresh.clone(),
                    |mut client| {
                        client
                            .bench_verify_search_response(&ax.label, None, &ax.lagging_resp)
                            .unwrap();
                        client
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// ============================================================================
// Auditor fixtures: AuditorUpdates captured from the real write path
// ============================================================================

fn pre_update(config: &PrivateConfig, label: Vec<u8>) -> PreUpdateData {
    let value = make_value();
    let (index, vrf_proof) = config.vrf_prove(&label, 0).unwrap();
    let opening = crypto::generate_random_opening();
    let commitment = crypto::commit(&label, 0, &value, &opening).unwrap();
    PreUpdateData {
        label,
        value,
        last: 0,
        version: 0,
        index,
        vrf_proof,
        commitment,
        opening,
    }
}

/// The auditor state an operator hands to a late-starting auditor
/// (`audit_bootstrap`): accumulator peaks, prefix root, and last timestamp.
fn bootstrap_auditor(tree: &Tree, tree_size: u64) -> (LogAccumulator, Vec<u8>, u64) {
    let peaks = rukt::tree::log_math::get_roots(tree_size)
        .into_iter()
        .map(|node| tree.log.resolve_node_simple(node, tree_size).unwrap())
        .collect();
    let acc = LogAccumulator::from_peaks(tree_size, peaks).unwrap();
    let prefix_root = tree.log.get_prefix_root(tree_size - 1).unwrap();
    let last_ts = tree.log.get_timestamp(tree_size - 1).unwrap();
    (acc, prefix_root, last_ts)
}

/// §15.2 per-update verification, exactly the `KtAuditor::process_and_sign`
/// loop body: structural checks, prefix transition, log accumulator append.
fn ingest_update(
    update: &AuditorUpdate,
    prefix_root: &mut Vec<u8>,
    last_ts: &mut u64,
    acc: &mut LogAccumulator,
) {
    assert!(update.timestamp >= *last_ts, "time regression");
    for list in [&update.added, &update.removed] {
        for pair in list.windows(2) {
            assert!(pair[0].vrf_output < pair[1].vrf_output, "unsorted leaves");
        }
    }
    let proof = update.proof.as_ref().unwrap();
    assert_eq!(
        proof.results.len(),
        update.added.len() + update.removed.len()
    );

    let new_root = PrefixTransitioner::verify_and_transition(
        prefix_root,
        &update.added,
        &update.removed,
        proof,
    )
    .unwrap();
    acc.append_leaf(rukt::crypto::hash::log_leaf_value(
        update.timestamp,
        &new_root,
    ));
    *prefix_root = new_root;
    *last_ts = update.timestamp;
}

/// Applies `batch_size` fresh-label updates as one log entry through the real
/// write path and returns the auditor's view of it: the previous prefix root
/// and the entry's `AuditorUpdate`.
fn capture_transition(
    tree: &mut Tree,
    config: &PrivateConfig,
    batch_size: usize,
    label_seq: &mut u64,
    rt: &Runtime,
) -> (Vec<u8>, AuditorUpdate) {
    let entry = tree.latest.as_ref().unwrap().tree_size;
    let old_root = tree.log.get_prefix_root(entry - 1).unwrap();

    let updates: Vec<PreUpdateData> = (0..batch_size)
        .map(|_| {
            *label_seq += 1;
            pre_update(config, make_label(*label_seq))
        })
        .collect();
    rt.block_on(tree.apply_batch(updates)).unwrap();

    let (mut captured, _) = rt.block_on(tree.audit(entry, 1)).unwrap();
    let update = captured.pop().unwrap();

    let new_root = PrefixTransitioner::verify_and_transition(
        &old_root,
        &update.added,
        &update.removed,
        update.proof.as_ref().unwrap(),
    )
    .expect("captured transition must verify");
    assert_eq!(
        new_root,
        tree.log.get_prefix_root(entry).unwrap(),
        "transition must reproduce the entry's prefix root"
    );

    (old_root, update)
}

const TRANSITION_BATCH_SIZES: &[usize] = &[1, 8, 64, 512];
const DEPTH_SIZES: &[u64] = &[1_000, 100_000];
const INGEST_STREAM_LEN: usize = 64;

struct AuditorFixture {
    transitions: Vec<(usize, Vec<u8>, AuditorUpdate)>,
    depth_transitions: Vec<(u64, Vec<u8>, AuditorUpdate)>,
    stream_state: (LogAccumulator, Vec<u8>, u64),
    stream: Vec<AuditorUpdate>,
    acc_large: LogAccumulator,
    _dirs: Vec<TempDir>,
}

fn build_auditor_fixture(rt: &Runtime) -> AuditorFixture {
    let mut dirs = Vec::new();

    // batch-size sweep and the ingest stream, on top of the smallest tree
    let base = DEPTH_SIZES[0];
    let golden = build_or_load_golden(base, false, rt);
    let (signer, vrf_key, _) = load_keys(&golden);
    let config = bench_private_config(signer, vrf_key, HashMap::new(), base);
    let (_db, mut tree, dir) = open_checkpoint(&golden, &config, rt);
    dirs.push(dir);

    let mut label_seq = base * 2;
    let transitions: Vec<(usize, Vec<u8>, AuditorUpdate)> = TRANSITION_BATCH_SIZES
        .iter()
        .map(|&b| {
            let (old_root, update) = capture_transition(&mut tree, &config, b, &mut label_seq, rt);
            (b, old_root, update)
        })
        .collect();

    let stream_start = tree.latest.as_ref().unwrap().tree_size;
    let stream_state = bootstrap_auditor(&tree, stream_start);
    for _ in 0..INGEST_STREAM_LEN {
        capture_transition(&mut tree, &config, 1, &mut label_seq, rt);
    }
    let (stream, _) = rt
        .block_on(tree.audit(stream_start, INGEST_STREAM_LEN as u64))
        .unwrap();
    {
        let (mut acc, mut root, mut ts) = stream_state.clone();
        for update in &stream {
            ingest_update(update, &mut root, &mut ts, &mut acc);
        }
        let final_size = stream_start + INGEST_STREAM_LEN as u64;
        assert_eq!(
            acc.calculate_root().unwrap(),
            tree.log.get_root(final_size).unwrap(),
            "ingested stream must reproduce the log root"
        );
    }

    // copath-depth sweep: single-leaf transitions at each tree size; the
    // largest tree also provides the accumulator-append baseline state
    let mut acc_large = None;
    let depth_transitions: Vec<(u64, Vec<u8>, AuditorUpdate)> = DEPTH_SIZES
        .iter()
        .map(|&n| {
            let golden = build_or_load_golden(n, false, rt);
            let (signer, vrf_key, _) = load_keys(&golden);
            let config = bench_private_config(signer, vrf_key, HashMap::new(), n);
            let (_db, mut tree, dir) = open_checkpoint(&golden, &config, rt);
            let mut label_seq = n * 2;
            let (old_root, update) = capture_transition(&mut tree, &config, 1, &mut label_seq, rt);
            if n == *DEPTH_SIZES.last().unwrap() {
                acc_large = Some(bootstrap_auditor(&tree, n).0);
            }
            dirs.push(dir);
            (n, old_root, update)
        })
        .collect();
    let acc_large = acc_large.unwrap();

    AuditorFixture {
        transitions,
        depth_transitions,
        stream_state,
        stream,
        acc_large,
        _dirs: dirs,
    }
}

// ============================================================================
// 8b. AUDITOR VERIFICATION (§15.2)
// ============================================================================

fn bench_auditor_verification(c: &mut Criterion) {
    let rt = make_runtime();
    let mut group = c.benchmark_group("8_auditor_verification");
    group.sample_size(30);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    let fx = build_auditor_fixture(&rt);

    for (b, old_root, update) in &fx.transitions {
        group.bench_with_input(BenchmarkId::new("verify_transition", b), b, |bench, _| {
            bench.iter(|| {
                PrefixTransitioner::verify_and_transition(
                    old_root,
                    &update.added,
                    &update.removed,
                    update.proof.as_ref().unwrap(),
                )
                .unwrap()
            })
        });
    }

    for (n, old_root, update) in &fx.depth_transitions {
        group.bench_with_input(
            BenchmarkId::new("verify_transition_at_depth", n),
            n,
            |bench, _| {
                bench.iter(|| {
                    PrefixTransitioner::verify_and_transition(
                        old_root,
                        &update.added,
                        &update.removed,
                        update.proof.as_ref().unwrap(),
                    )
                    .unwrap()
                })
            },
        );
    }

    let leaf = rukt::crypto::hash::log_leaf_value(1_700_000_000_000, &[0u8; 32]);
    group.bench_with_input(
        BenchmarkId::new("accumulator_append", DEPTH_SIZES.last().unwrap()),
        &(),
        |bench, _| {
            bench.iter_batched(
                || fx.acc_large.clone(),
                |mut acc| {
                    acc.append_leaf(leaf.clone());
                    acc
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.throughput(Throughput::Elements(INGEST_STREAM_LEN as u64));
    group.bench_with_input(
        BenchmarkId::new("ingest_throughput", INGEST_STREAM_LEN),
        &(),
        |bench, _| {
            bench.iter_batched(
                || fx.stream_state.clone(),
                |(mut acc, mut root, mut ts)| {
                    for update in &fx.stream {
                        ingest_update(update, &mut root, &mut ts, &mut acc);
                    }
                    (acc, root, ts)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.finish();
}

criterion_group! {
    name = verification;
    config = Criterion::default();
    targets = bench_auditor_verification, bench_client_verification
}

criterion_main!(verification);
