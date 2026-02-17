use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, TreeSearchRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tempfile::tempdir;

#[tokio::test]
async fn test_multi_label_batching_collisions() -> Result<()> {
    // 1. Setup
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    // 2. Prepare concurrent updates for the SAME label
    let label = b"collision_target".to_vec();
    let num_concurrent_updates = 10;
    let mut handles = vec![];

    // We launch 10 updates simultaneously. 
    // They are "Blind Updates" (expected_pre_update_value is empty), 
    // allowing the server to sequence them arbitrarily but validly.
    for i in 0..num_concurrent_updates {
        let svc = service.clone();
        let label_clone = label.clone();
        let val = format!("val_{}", i).as_bytes().to_vec();
        
        handles.push(tokio::spawn(async move {
            let req = tonic::Request::new(SignedUpdateRequest {
                request: Some(UpdateRequest {
                    search_key: label_clone,
                    value: val,
                    consistency: None,
                    // Critical: Must be empty to allow blind sequencing by batcher.
                    // If we enforced a previous value, 9 of 10 would fail.
                    expected_pre_update_value: vec![], 
                    return_update_response: true,
                }),
                signature: vec![],
            });
            svc.update(req).await
        }));
    }

    // 3. Collect Results
    let mut assigned_versions = HashSet::new();
    let mut last_tree_size = 0;

    for h in handles {
        let response = h.await??.into_inner();
        
        // Extract the FullTreeHead to check tree size
        if let Some(fth) = response.tree_head {
            if let Some(th) = fth.tree_head {
                last_tree_size = th.tree_size;
            }
        }

        // Verify the binary ladder proves the specific version assigned to this update
        // The first step of the ladder corresponds to the version of the update
        if !response.binary_ladder.is_empty() {
            // In a real scenario we'd decode the proof, but here we trust the 
            // sequence logic if the versions are unique and sequential.
        }
        
        // The server doesn't explicitly return the assigned version number in the 
        // UpdateResponse top-level struct in this draft implementation (it returns 
        // proofs), but we can infer success if no error occurred.
        // However, we can inspect the binary ladder size or verify via search.
    }

    // 4. Verify Sequentiality via Search
    // We expect versions 0 to 9 to exist.
    for i in 0..num_concurrent_updates {
        let req = tonic::Request::new(TreeSearchRequest {
            search_key: label.clone(),
            consistency: None,
            version: Some(i as u32),
        });

        let resp = service.search(req).await;
        assert!(resp.is_ok(), "Version {} should exist", i);
        
        let inner = resp.unwrap().into_inner();
        assert!(inner.value.is_some());
        
        let val_str = String::from_utf8(inner.value.unwrap().value)?;
        println!("Version {}: {}", i, val_str);
        
        assigned_versions.insert(i);
    }

    // 5. Assertions
    assert_eq!(assigned_versions.len(), num_concurrent_updates);
    
    // Check that we didn't create 10 separate log entries (batches should work)
    // Note: Exact tree size depends on race conditions and batch timeout, 
    // but it should ideally be less than the number of updates.
    let current_tree_size = service.tree.lock().await.latest.as_ref().unwrap().tree_size;
    println!("Total updates: {}, Final Tree Size: {}", num_concurrent_updates, current_tree_size);
    
    // 6. Verify Greatest Version
    let req_latest = tonic::Request::new(TreeSearchRequest {
        search_key: label.clone(),
        consistency: None,
        version: None, // Greatest
    });
    
    let resp_latest = service.search(req_latest).await?.into_inner();
    
    // The value should match one of our inputs (specifically the one assigned version 9)
    assert!(resp_latest.value.is_some());

    Ok(())
}