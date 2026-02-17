pub mod db;
pub mod tree;
pub mod service;
pub mod crypto;
pub mod batcher;
pub mod client; // Added this line

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

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tonic::transport::Server;
use crate::service::KeyTransparencyImpl;
use crate::db::RocksDbStore;
use crate::crypto::CIPHER_SUITE_KT_128_SHA256_ED25519;

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

    tracing::info!("Key Transparency Server listening on {}", addr);

    Server::builder()
        .add_service(proto::kt::key_transparency_service_server::KeyTransparencyServiceServer::new(service.clone()))
        .serve(addr)
        .await?;

    Ok(())
}