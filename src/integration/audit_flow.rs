use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, LabelValue};
use crate::proto::kt::{AuditRequest, key_transparency_service_server::KeyTransparencyService};
use crate::crypto;
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use ed25519_dalek::Signer;
use tempfile::tempdir;

#[tokio::test]
async fn test_audit_flow_with_signatures() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    
    let (server_signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(crypto::CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let (auditor_signer, auditor_vk) = crypto::generate_sig_keypair();
    let mut auditor_map = HashMap::new();
    
    let auditor_raw_signer = if let crypto::ServiceSigningKey::Ed25519(s) = auditor_signer { s } else { panic!() };
    let auditor_raw_vk = if let crypto::ServiceVerifyingKey::Ed25519(v) = auditor_vk { v } else { panic!() };
    let auditor_pk_bytes = auditor_raw_vk.to_bytes().to_vec();
    
    auditor_map.insert(auditor_pk_bytes.clone(), crypto::ServiceVerifyingKey::Ed25519(auditor_raw_vk));

    let service = KeyTransparencyImpl::new(db, server_signer, vrf_key, auditor_map.clone(), None).await?;

    // 1. Submit multiple updates
    let user = b"user".to_vec();
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"val1".to_vec() }],
    })).await?;

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: Some(0),
        values: vec![LabelValue { value: b"val2".to_vec() }],
    })).await?;

    // 2. Audit the log
    let resp = service.audit(tonic::Request::new(AuditRequest {
        start: 0,
        limit: 10,
    })).await?;
    let updates = resp.into_inner().updates;
    assert_eq!(updates.len(), 2);

    // 3. Auditor Signs the Head
    let tree_size = 2;
    let root_hash = {
        let guard = service.tree.write().await;
        guard.log.get_root(tree_size)?
    };
    let timestamp = {
        let guard = service.tree.write().await;
        guard.latest.as_ref().unwrap().timestamp as u64
    };

    let tbs = crypto::construct_auditor_tree_head_tbs(
        &service.config,
        &auditor_pk_bytes, 
        tree_size,
        timestamp,
        &root_hash,
    )?;

    let signature = auditor_raw_signer.sign(&tbs).to_vec();

    let auditor_head = crate::proto::transparency::AuditorTreeHead {
        tree_size,
        timestamp: timestamp as i64,
        signature,
    };

    service.set_auditor_head(tonic::Request::new(auditor_head)).await?;

    Ok(())
}

#[tokio::test]
async fn test_auditor_verifies_multi_leaf_batches() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);

    let (server_signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(crypto::CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, server_signer, vrf_key, HashMap::new(), None).await?;

    // one log entry with many added leaves, then another
    let values: Vec<LabelValue> = (0..8)
        .map(|i| LabelValue { value: format!("v{}", i).into_bytes() })
        .collect();
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: b"batch_label".to_vec(),
        greatest_version: None,
        values,
    })).await?;
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: b"solo_label".to_vec(),
        greatest_version: None,
        values: vec![LabelValue { value: b"x".to_vec() }],
    })).await?;

    let updates = service.audit(tonic::Request::new(AuditRequest { start: 0, limit: 10 }))
        .await?.into_inner().updates;
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].added.len(), 8);
    assert!(updates[0].added.windows(2).all(|w| w[0].vrf_output < w[1].vrf_output));

    // §15.2 steps 6-7 across both entries, checked against the operator's roots
    use crate::client::verifier::PrefixTransitioner;
    let mut prefix_root = vec![0u8; 32];
    for update in &updates {
        prefix_root = PrefixTransitioner::verify_and_transition(
            &prefix_root,
            &update.added,
            &update.removed,
            update.proof.as_ref().unwrap(),
        )?;
    }

    let guard = service.tree.read().await;
    let served_root = guard.log.get_prefix_root(1)?;
    assert_eq!(prefix_root, served_root, "Auditor-computed prefix root must match the operator's");

    Ok(())
}