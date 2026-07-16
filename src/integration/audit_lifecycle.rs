use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::client::{KtClient, KtAuditor};
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tonic::transport::Server;

#[tokio::test]
async fn test_full_auditor_lifecycle() -> Result<()> {
    // 1. Keys
    let (server_sk, server_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let (auditor_sk, auditor_vk) = crypto::generate_sig_keypair();
    let auditor_vk_bytes = auditor_vk.to_bytes();

    // 2. Setup Server with Auditing Mode
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    
    let mut auditor_keys = HashMap::new();
    auditor_keys.insert(auditor_vk_bytes.clone(), auditor_vk.clone());

    let service = KeyTransparencyImpl::new(
        db, 
        server_sk, 
        vrf_priv, 
        auditor_keys, 
        None
    ).await?;

    // Fix: Explicit type annotation
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    
    tokio::spawn(async move {
        // Create a stream manually using futures::stream::unfold
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let res = listener.accept().await.map(|(s, _)| s);
            Some((res, listener))
        });

        let result: Result<(), tonic::transport::Error> = Server::builder()
            .add_service(crate::proto::kt::key_transparency_service_server::KeyTransparencyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await;

        if let Err(e) = result {
            eprintln!("Server error: {}", e);
        }
    });

    let uri = format!("http://{}", local_addr);

    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING,
        server_sig_pk: server_vk.to_bytes(),
        vrf_public_key: vrf_pub.clone(),
        leaf_public_key: None,
        auditor_public_key: Some(auditor_vk_bytes.clone()),
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: 5000,
        max_behind: 5000,
        reasonable_monitoring_window: 86400000,
        maximum_lifetime: None,
    };

    // 3. User Updates
    let mut user_client: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;

    println!("--- User Update 1 ---");
    let _ = user_client.update(b"user1".to_vec(), b"val1".to_vec()).await?;

    println!("--- Auditor Processing ---");
    let mut auditor: KtAuditor = KtAuditor::connect(uri.clone(), auditor_sk, public_config).await?;
    
    // Process update 1
    auditor.process_and_sign().await?;
    
    assert_eq!(auditor.log_accumulator.tree_size, 1);
    
    // 5. Check Server State
    // User client performs search. The response should now contain the AuditorTreeHead.
    println!("--- User Checks for Signed Head ---");
    let search_resp = user_client.search(b"user1".to_vec(), None).await?;
    let fth = search_resp.full_tree_head.unwrap();
    
    let returned_ath = fth.auditor_tree_head.expect("Server should return auditor tree head");
    assert_eq!(returned_ath.tree_size, 1);

    println!("Auditor Lifecycle Test Passed");
    Ok(())
}