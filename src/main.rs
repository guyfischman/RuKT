pub mod batcher;
pub mod client;
pub mod crypto;
pub mod db;
pub mod service;
pub mod tree; // Added this line

pub mod proto {
    pub mod transparency {
        tonic::include_proto!("transparency");
    }
    pub mod kt {
        tonic::include_proto!("kt");
    }
    pub mod prefix_tree {
        tonic::include_proto!("prefix_tree");
    }
}

#[cfg(test)]
mod integration;

const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kt_descriptor.bin"));

use crate::crypto::{
    CIPHER_SUITE_KT_128_SHA256_ED25519, CIPHER_SUITE_KT_128_SHA256_P256,
    DEPLOYMENT_MODE_CONTACT_MONITORING, DEPLOYMENT_MODE_THIRD_PARTY_AUDITING, PrivateConfig,
    PublicConfig, ServiceSigningKey, ServiceVerifyingKey,
};
use crate::db::RocksDbStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyServiceServer;
use crate::proto::transparency::{LabelValue, UpdateRequest};
use crate::service::{KeyTransparencyImpl, ServerParams};
use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tonic::transport::Server;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SuiteArg {
    Ed25519,
    P256,
}

impl SuiteArg {
    fn code(self) -> u16 {
        match self {
            SuiteArg::Ed25519 => CIPHER_SUITE_KT_128_SHA256_ED25519,
            SuiteArg::P256 => CIPHER_SUITE_KT_128_SHA256_P256,
        }
    }
}

/// RuKT Key Transparency log server. Keys and log state are persisted under
/// `--data-dir` and reused across restarts; the public config clients must be
/// handed out of band is written to `config.json` there on every start.
#[derive(Parser, Debug)]
#[command(name = "rukt-server", version, about)]
struct Args {
    #[arg(long, env = "KT_LISTEN", default_value = "0.0.0.0:8081")]
    listen: SocketAddr,

    #[arg(long, env = "KT_DATA_DIR", default_value = "./kt_data")]
    data_dir: PathBuf,

    /// Signing private key (hex). Defaults to `<data-dir>/sig_key.hex`; generated on first start.
    #[arg(long, env = "KT_SIG_KEY_FILE")]
    sig_key_file: Option<PathBuf>,

    /// VRF private key (hex). Defaults to `<data-dir>/vrf_key.hex`; generated on first start.
    #[arg(long, env = "KT_VRF_KEY_FILE")]
    vrf_key_file: Option<PathBuf>,

    /// Where to write the public config JSON. Defaults to `<data-dir>/config.json`.
    #[arg(long, env = "KT_CONFIG_OUT")]
    config_out: Option<PathBuf>,

    #[arg(long, value_enum, env = "KT_CIPHER_SUITE", default_value = "ed25519")]
    cipher_suite: SuiteArg,

    /// Trusted auditor public key(s) (hex). Any value selects third-party-auditing mode.
    #[arg(
        long = "auditor-pubkey",
        env = "KT_AUDITOR_PUBKEY",
        value_delimiter = ','
    )]
    auditor_pubkeys: Vec<String>,

    #[arg(long, env = "KT_MAX_AHEAD", default_value_t = 10_000)]
    max_ahead: u64,

    #[arg(long, env = "KT_MAX_BEHIND", default_value_t = 60_000)]
    max_behind: u64,

    /// Re-publish the tree head at a fresh timestamp every N seconds so an idle
    /// log stays within clients' freshness window. 0 disables. Keep well below
    /// --max-behind.
    #[arg(long, env = "KT_EPOCH_INTERVAL_SECS", default_value_t = 10)]
    epoch_interval_secs: u64,

    #[arg(long, env = "KT_MONITORING_WINDOW", default_value_t = 86_400_000)]
    monitoring_window: u64,

    #[arg(long, env = "KT_MAXIMUM_LIFETIME")]
    maximum_lifetime: Option<u64>,

    #[arg(long, env = "KT_MAX_RESPONSE_ENTRIES", default_value_t = 100)]
    max_response_entries: usize,

    /// PEM certificate path for in-process TLS. Must be set with --tls-key.
    #[arg(long, env = "KT_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// PEM private key path for in-process TLS. Must be set with --tls-cert.
    #[arg(long, env = "KT_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Seed demo labels if the tree is empty, then serve.
    #[arg(long)]
    seed: bool,

    /// Write the public config and exit without opening the log or serving.
    #[arg(long)]
    dump_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let suite = args.cipher_suite.code();

    fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating data dir {}", args.data_dir.display()))?;
    let sig_path = args
        .sig_key_file
        .clone()
        .unwrap_or_else(|| args.data_dir.join("sig_key.hex"));
    let vrf_path = args
        .vrf_key_file
        .clone()
        .unwrap_or_else(|| args.data_dir.join("vrf_key.hex"));
    let config_path = args
        .config_out
        .clone()
        .unwrap_or_else(|| args.data_dir.join("config.json"));

    let sig_key = load_or_generate_sig(&sig_path, suite)?;
    let vrf_secret = load_or_generate_vrf(&vrf_path, suite)?;

    let mut auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey> = HashMap::new();
    for hexk in &args.auditor_pubkeys {
        let bytes = hex::decode(hexk.trim()).context("decoding --auditor-pubkey hex")?;
        let vk = ServiceVerifyingKey::from_bytes(&bytes)?;
        auditor_keys.insert(vk.to_bytes(), vk);
    }
    let mode = if auditor_keys.is_empty() {
        DEPLOYMENT_MODE_CONTACT_MONITORING
    } else {
        DEPLOYMENT_MODE_THIRD_PARTY_AUDITING
    };

    let params = ServerParams {
        max_ahead: args.max_ahead,
        max_behind: args.max_behind,
        reasonable_monitoring_window: args.monitoring_window,
        maximum_lifetime: args.maximum_lifetime,
        max_response_entries: args.max_response_entries,
    };

    // Derive the VRF public key and validate the suite without opening the DB.
    let priv_cfg = PrivateConfig::new(
        suite,
        mode,
        sig_key.clone(),
        vrf_secret.clone(),
        auditor_keys.clone(),
        params.max_ahead,
        params.max_behind,
        params.reasonable_monitoring_window,
        params.maximum_lifetime,
        None,
        params.max_response_entries,
    )
    .context("building configuration")?;

    let public = PublicConfig {
        cipher_suite: suite,
        mode,
        server_sig_pk: sig_key.verifying_key().to_bytes(),
        vrf_public_key: priv_cfg.vrf_public_key.clone(),
        leaf_public_key: None,
        auditor_public_key: priv_cfg.auditor_public_key.clone(),
        auditor_start_pos: priv_cfg.auditor_start_pos,
        max_auditor_lag: priv_cfg.max_auditor_lag,
        max_ahead: params.max_ahead,
        max_behind: params.max_behind,
        reasonable_monitoring_window: params.reasonable_monitoring_window,
        maximum_lifetime: params.maximum_lifetime,
    };
    let config_json = public.to_json()?;
    fs::write(&config_path, &config_json)
        .with_context(|| format!("writing config to {}", config_path.display()))?;

    println!("\n=== SERVER PUBLIC CONFIG (distribute to clients out of band) ===");
    println!("SIG_KEY: {}", hex::encode(&public.server_sig_pk));
    println!("VRF_KEY: {}", hex::encode(&public.vrf_public_key));
    println!("cipher_suite: {suite:#06x}  mode: {}", mode_name(mode));
    println!("config: {}", config_path.display());
    println!("================================================================\n");

    if args.dump_config {
        return Ok(());
    }

    let db_dir = args.data_dir.join("db");
    fs::create_dir_all(&db_dir)?;
    let db = Arc::new(RocksDbStore::new(
        db_dir.to_str().context("db dir path must be UTF-8")?,
    )?);
    let service =
        KeyTransparencyImpl::with_params(db, sig_key, vrf_secret, auditor_keys, None, params)
            .await?;

    if args.seed {
        seed_demo_data(&service).await?;
    }

    if args.epoch_interval_secs > 0 {
        let tree = service.tree.clone();
        let interval = std::time::Duration::from_secs(args.epoch_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // the first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                if let Err(e) = tree.write().await.refresh_head_timestamp() {
                    tracing::warn!("epoch tick failed: {e}");
                }
            }
        });
    }

    // §16: users SHOULD reach the log over transport-layer encryption
    let mut builder = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let identity = tonic::transport::Identity::from_pem(fs::read(cert)?, fs::read(key)?);
            tracing::info!("TLS enabled with certificate {}", cert.display());
            Server::builder()
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))?
        }
        (None, None) => {
            tracing::warn!(
                "Serving plaintext gRPC; set --tls-cert/--tls-key or terminate TLS in a fronting proxy"
            );
            Server::builder()
        }
        _ => anyhow::bail!("--tls-cert and --tls-key must be set together"),
    };

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()?;

    tracing::info!(
        "Key Transparency Server ({}) listening on {}",
        mode_name(mode),
        args.listen
    );

    builder
        .add_service(KeyTransparencyServiceServer::new(service))
        .add_service(reflection)
        .serve_with_shutdown(args.listen, shutdown_signal())
        .await?;

    Ok(())
}

fn mode_name(mode: u8) -> &'static str {
    if mode == DEPLOYMENT_MODE_THIRD_PARTY_AUDITING {
        "third-party-auditing"
    } else {
        "contact-monitoring"
    }
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing key to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_or_generate_sig(path: &Path, suite: u16) -> Result<ServiceSigningKey> {
    if path.exists() {
        let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let bytes = hex::decode(s.trim()).context("decoding signing key hex")?;
        ServiceSigningKey::from_seed_bytes(suite, &bytes)
    } else {
        let sk = if suite == CIPHER_SUITE_KT_128_SHA256_P256 {
            crypto::generate_p256_keypair().0
        } else {
            crypto::generate_sig_keypair().0
        };
        write_secret(path, &hex::encode(sk.to_seed_bytes()))?;
        tracing::info!("generated new signing key at {}", path.display());
        Ok(sk)
    }
}

fn load_or_generate_vrf(path: &Path, suite: u16) -> Result<Vec<u8>> {
    if path.exists() {
        let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        hex::decode(s.trim()).context("decoding VRF key hex")
    } else {
        let (secret, _public) = crypto::generate_vrf_keypair(suite);
        write_secret(path, &hex::encode(&secret))?;
        tracing::info!("generated new VRF key at {}", path.display());
        Ok(secret)
    }
}

async fn seed_demo_data(service: &KeyTransparencyImpl) -> Result<()> {
    let existing = {
        let tree = service.tree.read().await;
        tree.latest.as_ref().map(|th| th.tree_size).unwrap_or(0)
    };
    if existing > 0 {
        tracing::info!("tree already has {existing} entries; skipping --seed");
        return Ok(());
    }
    let entries: &[(&[u8], &[&[u8]])] = &[
        (b"alice", &[b"alice_pk_v1"]),
        (b"bob", &[b"bob_pk_v1", b"bob_pk_v2"]),
        (b"carol", &[b"carol_pk_v1"]),
    ];
    for (label, values) in entries {
        for (i, value) in values.iter().enumerate() {
            let greatest_version = (i as u32).checked_sub(1);
            let req = UpdateRequest {
                last: None,
                label: label.to_vec(),
                greatest_version,
                values: vec![LabelValue {
                    value: value.to_vec(),
                }],
            };
            service.batcher.submit(req).await?;
        }
    }
    tracing::info!("seeded {} demo labels", entries.len());
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received, draining");
}
