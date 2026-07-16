use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{
    UpdateRequest, LabelValue,
    ContactMonitorRequest, OwnerInitRequest, MonitorMapEntry
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
        let mut tree = service.tree.write().await;
        tree.config.reasonable_monitoring_window = 0;
    }

    let user_a = b"user_a".to_vec();

    // 1. Initial Update (Log Index 0)
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user_a.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"v1".to_vec() }],
    })).await?;

    // 2. Other updates to advance tree (Log Indices 1, 2)
    for i in 1..=2 {
        service.update(tonic::Request::new(UpdateRequest {
            last: None,
            label: format!("user_dummy_{}", i).as_bytes().to_vec(),
            greatest_version: None,
            values: vec![LabelValue { value: b"data".to_vec() }],
        })).await?;
    }

    // 3. Contact Monitoring Request
    // User last saw 'user_a' at position 0. Current head is 3.
    // Logic should trace path from 0 -> Head.
    let req = ContactMonitorRequest {
        last: Some(1), // Client thinks tree size is 1
        label: user_a.clone(),
        entries: vec![MonitorMapEntry {
            position: 0,
            version: 0,
        }],
    };

    let resp = service.contact_monitor(tonic::Request::new(req)).await?.into_inner();

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
        let mut tree = service.tree.write().await;
        tree.config.reasonable_monitoring_window = 1000 * 60; // 1 minute
    }

    let user_me = b"owner_user".to_vec();

    // 1. Initial Update (Index 0)
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user_me.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"v1".to_vec() }],
    })).await?;

    // 2. Second Update (Index 1)
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user_me.clone(),
        greatest_version: Some(0),
        values: vec![LabelValue { value: b"v2".to_vec() }],
    })).await?;

    // 3. Owner Initialization Request
    // User verifies up to index 0. Wants to know what happened since.
    let req = OwnerInitRequest {
        last: Some(1),
        label: user_me.clone(),
        start: 0,
    };

    let resp = service.owner_init(tonic::Request::new(req)).await?.into_inner();

    // Should find version '1' (which is v2, 0-indexed was v1) at index 1
    assert!(resp.greatest_versions.contains(&1), "Should detect new version 1");

    let proof = resp.init.unwrap();
    assert!(proof.inclusion.is_some());
    assert!(!proof.prefix_proofs.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_contact_monitoring_ibst_path_fix() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    // We intentionally leave Reasonable Monitoring Window at default (86400000 ms) 
    // to force the traversal loop to climb the IBST tree.

    // 1. Build a tree of 50 updates (mimicking the benchmark environment)
    let target_user = b"bug_test_user".to_vec();
    
    for i in 0..50 {
        let user = if i == 25 { target_user.clone() } else { format!("user_{}", i).into_bytes() };
        
        service.update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user,
            greatest_version: None,
            values: vec![LabelValue { value: format!("val_{}", i).into_bytes() }],
        })).await?;
    }

    // 2. Perform Contact Monitoring for the user inserted at position 25
    let req = ContactMonitorRequest {
        last: Some(50),
        label: target_user.clone(),
        entries: vec![MonitorMapEntry {
            position: 25,
            version: 0,
        }],
    };

    // Before the fix, this panicked with "Timestamp not found for log index XXX".
    // After the fix, it should succeed.
    let resp = service.contact_monitor(tonic::Request::new(req)).await;

    assert!(resp.is_ok(), "Monitor request failed: {:?}", resp.err());
    
    let inner_resp = resp.unwrap().into_inner();
    assert!(inner_resp.monitor.is_some());
    assert!(!inner_resp.monitor.unwrap().timestamps.is_empty());

    Ok(())
}