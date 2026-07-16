use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{
    ContactMonitorRequest, LabelValue, MonitorMapEntry, OwnerInitRequest, UpdateRequest,
};
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_contact_monitoring_conformant() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_a = b"user_a".to_vec();

    // Two dummies first so 'user_a' lands at position 2 — a position off the
    // 0-anchored left spine, hence not distinguished and in need of monitoring
    for i in 0..2 {
        service
            .update(tonic::Request::new(UpdateRequest {
                last: None,
                label: format!("user_dummy_{}", i).as_bytes().to_vec(),
                greatest_version: None,
                values: vec![LabelValue {
                    value: b"data".to_vec(),
                }],
            }))
            .await?;
    }
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user_a.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"v1".to_vec(),
            }],
        }))
        .await?;
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: b"user_dummy_2".to_vec(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"data".to_vec(),
            }],
        }))
        .await?;

    let req = ContactMonitorRequest {
        last: Some(3),
        label: user_a.clone(),
        entries: vec![MonitorMapEntry {
            position: 2,
            version: 0,
        }],
    };

    let resp = service
        .contact_monitor(tonic::Request::new(req))
        .await?
        .into_inner();

    let proof = resp.monitor.expect("Missing monitor proof");
    assert!(!proof.timestamps.is_empty(), "Should contain timestamps");
    // §8.2: ladders along the ancestors of position 2 up to the first distinguished entry
    assert!(
        !proof.prefix_proofs.is_empty(),
        "Should contain prefix proofs for monitoring"
    );

    Ok(())
}

#[tokio::test]
async fn test_owner_monitoring_conformant() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    // Normal RMW to test skipping
    {
        let mut tree = service.tree.write().await;
        tree.config.reasonable_monitoring_window = 1000 * 60; // 1 minute
    }

    let user_me = b"owner_user".to_vec();

    // 1. Initial Update (Index 0)
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user_me.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"v1".to_vec(),
            }],
        }))
        .await?;

    // 2. Second Update (Index 1)
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user_me.clone(),
            greatest_version: Some(0),
            values: vec![LabelValue {
                value: b"v2".to_vec(),
            }],
        }))
        .await?;

    // 3. Owner Initialization from the distinguished entry at index 1
    // §8.3 reports the greatest version at the start entry (v2 = version 1)
    let req = OwnerInitRequest {
        last: None,
        label: user_me.clone(),
        start: 1,
    };

    let resp = service
        .owner_init(tonic::Request::new(req))
        .await?
        .into_inner();

    assert_eq!(
        resp.greatest_versions,
        vec![1],
        "greatest version at index 1 is 1"
    );

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
        let user = if i == 25 {
            target_user.clone()
        } else {
            format!("user_{}", i).into_bytes()
        };

        service
            .update(tonic::Request::new(UpdateRequest {
                last: None,
                label: user,
                greatest_version: None,
                values: vec![LabelValue {
                    value: format!("val_{}", i).into_bytes(),
                }],
            }))
            .await?;
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

// §12.3.6: the verifier requests each walked entry's timestamp on entry to the
// recursion, before descending into the left child. A tree large enough that a
// left-subtree internal node is neither on the frontier nor a contact-walk
// ancestor exposes any server-side emission-order divergence.
#[tokio::test]
async fn test_owner_monitor_walk_requests_timestamps_in_entry_order() -> Result<()> {
    let server = super::harness::TestServer::contact_monitoring_all_distinguished().await?;
    let mut client = server.client().await?;

    client.update(b"filler_0".to_vec(), b"v".to_vec()).await?;
    client.update(b"owner".to_vec(), b"v".to_vec()).await?;
    for i in 2..12 {
        client
            .update(format!("filler_{}", i).into_bytes(), b"v".to_vec())
            .await?;
    }

    let resp = client
        .owner_monitor(b"owner".to_vec(), vec![], 1, Some(0))
        .await?;
    assert!(resp.monitor.is_some());

    Ok(())
}

// §8.2 step 3: each monitoring-ladder entry must contribute its timestamp so
// its verified prefix root is bound into the log reconstruction. An obligation
// seeded before the log grows acquires ladder ancestors that are neither on
// the frontier nor on the distinguished walk down from the root.
#[tokio::test]
async fn test_contact_monitor_binds_ladder_entries_after_growth() -> Result<()> {
    let server = super::harness::TestServer::contact_monitoring().await?;
    let mut client = server.client().await?;

    for i in 0..28 {
        client
            .update(format!("filler_{}", i).into_bytes(), b"v".to_vec())
            .await?;
    }
    client.update(b"watched".to_vec(), b"v".to_vec()).await?;
    client.search(b"watched".to_vec(), None).await?;

    for i in 28..60 {
        client
            .update(format!("filler_{}", i).into_bytes(), b"v".to_vec())
            .await?;
    }

    let resp = client.contact_monitor(b"watched".to_vec()).await?;
    assert!(resp.monitor.is_some());

    Ok(())
}
