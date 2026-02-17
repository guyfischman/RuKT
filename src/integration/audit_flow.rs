use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SignedUpdateRequest};
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
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user.clone(),
            value: b"val1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: false,
        }),
        signature: vec![],
    })).await?;

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user.clone(),
            value: b"val2".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: false,
        }),
        signature: vec![],
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
        let guard = service.tree.lock().await;
        guard.log.get_root(tree_size)?
    };
    let timestamp = {
        let guard = service.tree.lock().await;
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