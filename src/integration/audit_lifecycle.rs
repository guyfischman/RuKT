use crate::client::{KtAuditor, KtClient};
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

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

    let service = KeyTransparencyImpl::new(db, server_sk, vrf_priv, auditor_keys, None).await?;

    // Fix: Explicit type annotation
    let channel = crate::integration::harness::serve_in_memory(service).await?;

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
    let mut user_client: KtClient = KtClient::with_channel(channel.clone(), public_config.clone())?;

    println!("--- User Update 1 ---");
    let _ = user_client
        .update(b"user1".to_vec(), b"val1".to_vec())
        .await?;

    println!("--- Auditor Processing ---");
    let mut auditor: KtAuditor =
        KtAuditor::with_channel(channel.clone(), auditor_sk.clone(), public_config.clone())?;

    // Process update 1
    auditor.process_and_sign().await?;

    assert_eq!(auditor.log_accumulator.tree_size, 1);

    // 5. Check Server State
    // User client performs search. The response should now contain the AuditorTreeHead.
    println!("--- User Checks for Signed Head ---");
    let search_resp = user_client.search(b"user1".to_vec(), None).await?;
    let fth = search_resp.full_tree_head.unwrap();

    let returned_ath = fth
        .auditor_tree_head
        .expect("Server should return auditor tree head");
    assert_eq!(returned_ath.tree_size, 1);

    // 6. The auditor restarts with no local history and bootstraps from the
    // operator's current signed head, then audits forward
    let _ = user_client
        .update(b"user2".to_vec(), b"val2".to_vec())
        .await?;
    let _ = user_client
        .update(b"user3".to_vec(), b"val3".to_vec())
        .await?;

    let mut restarted: KtAuditor =
        KtAuditor::with_channel(channel.clone(), auditor_sk, public_config)?;
    let started_at = restarted.bootstrap().await?;
    assert_eq!(started_at, 3);

    let _ = user_client
        .update(b"user4".to_vec(), b"val4".to_vec())
        .await?;
    restarted.process_and_sign().await?;
    assert_eq!(restarted.log_accumulator.tree_size, 4);

    // 7. The log advances past the auditor; the client verifies the lagging
    // auditor signature against the derived root at the auditor's tree size
    let _ = user_client
        .update(b"user5".to_vec(), b"val5".to_vec())
        .await?;
    let resp = user_client.search(b"user5".to_vec(), None).await?;
    let lagging_ath = resp.full_tree_head.unwrap().auditor_tree_head.unwrap();
    assert_eq!(lagging_ath.tree_size, 4);
    assert_eq!(user_client.state.as_ref().unwrap().tree_size, 5);

    println!("Auditor Lifecycle Test Passed");
    Ok(())
}
