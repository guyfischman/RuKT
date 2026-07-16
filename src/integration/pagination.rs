use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, MonitorRequest, MonitorLabel, SearchRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_pagination_full_lifecycle() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    // 1. Configure Server for Test
    // - Strict pagination: 2 entries per response.
    // - RMW = 0: Every log entry is "Distinguished", forcing maximum recursion.
    {
        let mut tree = service.tree.write().await;
        tree.config.max_response_entries = 2;
        tree.config.reasonable_monitoring_window = 0;
    }

    let user_id = b"lifecycle_user".to_vec();

    // 2. Initial Setup: User creates label (Log Index 0)
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: b"v0".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: false,
        }),
        signature: vec![],
    })).await?;

    // 3. User verifies initial state via Search (TOFU - Trust On First Use)
    // This gives the user their "Anchor" at Log Index 0.
    let search_resp = service.search(tonic::Request::new(SearchRequest {
        label: user_id.clone(),
        last: None,
        version: None,
    })).await?.into_inner();

    let initial_tree_size = search_resp.full_tree_head.as_ref().unwrap().tree_head.as_ref().unwrap().tree_size;
    assert_eq!(initial_tree_size, 1);
    
    // User's local state: verified up to index 0.
    let mut local_rightmost = 0u64;

    // 4. Activity happens while user is offline (Indices 1..5)
    for i in 1..=5 {
        service.update(tonic::Request::new(SignedUpdateRequest {
            request: Some(UpdateRequest {
                search_key: user_id.clone(),
                value: format!("v{}", i).as_bytes().to_vec(),
                consistency: None,
                expected_pre_update_value: vec![],
                return_update_response: false,
            }),
            signature: vec![],
        })).await?;
    }

    // 5. User comes online. Wants to catch up from Index 0 to Index 5.
    // Loop until we catch up to the server's head.
    loop {
        let req = MonitorRequest {
            last: None,
            labels: vec![MonitorLabel {
                label: user_id.clone(),
                entries: vec![],
                rightmost: Some(local_rightmost),
            }],
            consistency: None,
        };
        
        let resp = service.monitor(tonic::Request::new(req)).await?.into_inner();
        
        let global_tree_size = resp.tree_head.as_ref().unwrap().tree_head.as_ref().unwrap().tree_size;
        let global_rightmost = global_tree_size - 1;
        
        let new_versions = &resp.label_versions[0].versions;
        let proof = resp.monitor.unwrap();
        
        println!("Client at {}. Global at {}. Received {} items.", local_rightmost, global_rightmost, new_versions.len());

        // Assert Server respected pagination limit
        assert!(new_versions.len() <= 2);

        if new_versions.is_empty() {
            // No new updates, we are synced.
            assert_eq!(local_rightmost, global_rightmost);
            break;
        }

        local_rightmost += new_versions.len() as u64;
    }

    assert_eq!(local_rightmost, 5);
    println!("Successfully synced to head via pagination.");

    Ok(())
}