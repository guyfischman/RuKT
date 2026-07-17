use crate::client::KtClient;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::transparency::FullTreeHeadType;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_client_lifecycle() -> Result<()> {
    // 1. Setup Server
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, HashMap::new(), None).await?;

    // Fix: Explicit type annotation
    let channel = crate::integration::harness::serve_in_memory(service).await?;
    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: sig_vk.to_bytes(),
        vrf_public_key: vrf_pub,
        leaf_public_key: None,
        auditor_public_key: None,
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: 5000,
        max_behind: 5000,
        reasonable_monitoring_window: 86400000,
        maximum_lifetime: None,
    };
    let mut client: KtClient = KtClient::with_channel(channel.clone(), public_config)?;

    // 3. Update (Register User)
    let user_id = b"client_user".to_vec();
    let value_v0 = b"key_material_v0".to_vec();

    println!("--- Client Update v0 ---");
    let update_resp = client.update(user_id.clone(), value_v0.clone()).await?;
    assert_eq!(
        update_resp
            .full_tree_head
            .unwrap()
            .tree_head
            .unwrap()
            .tree_size,
        1
    );

    // 4. Search (Verify)
    println!("--- Client Search v0 ---");
    let search_resp = client.search(user_id.clone(), None).await?;
    let val = search_resp.value.unwrap();
    assert_eq!(val.value, value_v0);

    // 5. Update v1
    let value_v1 = b"key_material_v1".to_vec();
    println!("--- Client Update v1 ---");
    let update_resp_2 = client.update(user_id.clone(), value_v1.clone()).await?;
    assert_eq!(
        update_resp_2
            .full_tree_head
            .unwrap()
            .tree_head
            .unwrap()
            .tree_size,
        2
    );

    // 6. Monitor
    println!("--- Client Monitor ---");
    // Monitor position 0 (v0)
    let mon_resp = client.contact_monitor(user_id.clone()).await?;

    // Check FullTreeHead
    let fth = mon_resp.full_tree_head.unwrap();
    match fth.head_type {
        x if x == FullTreeHeadType::Updated as i32 => {
            assert_eq!(fth.tree_head.unwrap().tree_size, 2);
        }
        x if x == FullTreeHeadType::Same as i32 => {
            // Client state is already at 2, so server returned SAME.
            // TreeHead field is None in this case.
            assert!(fth.tree_head.is_none());
            // Since we know the client was at 2, this is correct behavior.
        }
        _ => panic!("Unexpected head type"),
    }

    println!("Client Lifecycle Test Passed");
    Ok(())
}
