use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{
    UpdateRequest, SignedUpdateRequest, 
    MonitorRequest, MonitorLabel, MonitorMapEntry
};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_contact_monitoring_conformant() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    // Init service
    let mut service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    // Set RMW to 0 to make every node distinguished (maximum verification path)
    {
        let mut tree = service.tree.lock().await;
        tree.config.reasonable_monitoring_window = 0;
    }

    let user_a = b"user_a".to_vec();

    // 1. Initial Update (Log Index 0)
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_a.clone(),
            value: b"v1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    // 2. Other updates to advance tree (Log Indices 1, 2)
    for i in 1..=2 {
        service.update(tonic::Request::new(SignedUpdateRequest {
            request: Some(UpdateRequest {
                search_key: format!("user_dummy_{}", i).as_bytes().to_vec(),
                value: b"data".to_vec(),
                consistency: None,
                expected_pre_update_value: vec![],
                return_update_response: false,
            }),
            signature: vec![],
        })).await?;
    }

    // 3. Contact Monitoring Request
    // User last saw 'user_a' at position 0. Current head is 3.
    // Logic should trace path from 0 -> Head.
    let req = MonitorRequest {
        last: Some(1), // Client thinks tree size is 1
        labels: vec![MonitorLabel {
            label: user_a.clone(),
            entries: vec![MonitorMapEntry {
                position: 0,
                version: 0,
            }],
            rightmost: None, // Contact mode
        }],
        consistency: None,
    };

    let resp = service.monitor(tonic::Request::new(req)).await?.into_inner();

    // Verify Response Structure (Draft Section 11.3)
    let proof = resp.monitor.expect("Missing monitor proof");
    
    // With RMW=0, we expect timestamps for intermediate nodes
    assert!(!proof.timestamps.is_empty(), "Should contain timestamps");
    
    // Verify monotonicity locally
    let mut prev = 0;
    for t in &proof.timestamps {
        assert!(*t >= prev, "Timestamps must be monotonic");
        prev = *t;
    }

    // Ensure we have prefix proofs for the label
    // Since RMW=0, we hit distinguished nodes quickly, so we expect proofs.
    assert!(!proof.prefix_proofs.is_empty(), "Should contain prefix proofs for monitoring");

    Ok(())
}

#[tokio::test]
async fn test_owner_monitoring_conformant() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let mut service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    // Normal RMW to test skipping
    {
        let mut tree = service.tree.lock().await;
        tree.config.reasonable_monitoring_window = 1000 * 60; // 1 minute
    }

    let user_me = b"owner_user".to_vec();

    // 1. Initial Update (Index 0)
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_me.clone(),
            value: b"v1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    // 2. Second Update (Index 1)
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_me.clone(),
            value: b"v2".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    // 3. Owner Monitoring Request
    // User verifies up to index 0. Wants to know what happened since.
    let req = MonitorRequest {
        last: Some(1), 
        labels: vec![MonitorLabel {
            label: user_me.clone(),
            entries: vec![],
            rightmost: Some(0), // Owner mode: last verified distinguished node
        }],
        consistency: None,
    };

    let resp = service.monitor(tonic::Request::new(req)).await?.into_inner();

    // Verify
    assert!(!resp.label_versions.is_empty());
    let vers = &resp.label_versions[0];
    
    // Should find version '1' (which is v2, 0-indexed was v1) at index 1
    assert!(vers.versions.contains(&1), "Should detect new version 1");
    
    let proof = resp.monitor.unwrap();
    assert!(proof.inclusion.is_some());
    assert!(!proof.prefix_proofs.is_empty());

    Ok(())
}