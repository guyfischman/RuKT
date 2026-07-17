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

use crate::crypto::CIPHER_SUITE_KT_128_SHA256_ED25519;
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "0.0.0.0:8081".parse()?;

    // Wipe DB for this demo so keys match data
    let db_path = "./kt_data";
    if std::path::Path::new(db_path).exists() {
        std::fs::remove_dir_all(db_path)?;
    }

    let db = Arc::new(RocksDbStore::new(db_path)?);

    // 1. Generate Keys
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_secret, vrf_public) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    // --- ADDED: PRINT KEYS ---
    let sig_hex = hex::encode(signer.verifying_key().to_bytes());
    let vrf_hex = hex::encode(&vrf_public);

    println!("\n=== SERVER KEYS (COPY THESE TO CLIENT) ===");
    println!("SIG_KEY: {}", sig_hex);
    println!("VRF_KEY: {}", vrf_hex);
    println!("==========================================\n");
    // -------------------------

    let auditor_keys = HashMap::new();

    // Pass the keys we just printed to the service
    let service = KeyTransparencyImpl::new(db, signer, vrf_secret, auditor_keys, None).await?;

    // §16: users SHOULD reach the log over transport-layer encryption
    let mut builder = match (
        std::env::var_os("KT_TLS_CERT"),
        std::env::var_os("KT_TLS_KEY"),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let identity = tonic::transport::Identity::from_pem(
                std::fs::read(&cert_path)?,
                std::fs::read(&key_path)?,
            );
            tracing::info!("TLS enabled with certificate {:?}", cert_path);
            Server::builder()
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))?
        }
        (None, None) => {
            tracing::warn!(
                "Serving plaintext gRPC; set KT_TLS_CERT/KT_TLS_KEY or terminate TLS in a fronting proxy"
            );
            Server::builder()
        }
        _ => anyhow::bail!("KT_TLS_CERT and KT_TLS_KEY must be set together"),
    };

    tracing::info!("Key Transparency Server listening on {}", addr);

    builder
        .add_service(
            proto::kt::key_transparency_service_server::KeyTransparencyServiceServer::new(
                service.clone(),
            ),
        )
        .serve(addr)
        .await?;

    Ok(())
}
