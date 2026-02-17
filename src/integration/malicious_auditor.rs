use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SignedUpdateRequest, AuditorTreeHead};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;
use ed25519_dalek::Signer;

#[tokio::test]
async fn test_malicious_auditor_logic() -> Result<()> {
    // 1. Setup Keys
    let (server_signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    // Auditor Keys
    let (auditor_signer, auditor_vk) = crypto::generate_sig_keypair();
    let auditor_raw_signer = if let crypto::ServiceSigningKey::Ed25519(s) = auditor_signer { s } else { panic!() };
    let auditor_raw_vk = if let crypto::ServiceVerifyingKey::Ed25519(v) = auditor_vk { v } else { panic!() };
    let auditor_pk_bytes = auditor_raw_vk.to_bytes().to_vec();

    // 2. Init Server
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let mut auditor_map = HashMap::new();
    auditor_map.insert(auditor_pk_bytes.clone(), crypto::ServiceVerifyingKey::Ed25519(auditor_raw_vk));
    
    let service = KeyTransparencyImpl::new(db, server_signer, vrf_key, auditor_map, None).await?;

    // 3. Populate Tree (Size 0 -> 2)
    for i in 0..2 {
        service.update(tonic::Request::new(SignedUpdateRequest {
            request: Some(UpdateRequest {
                search_key: format!("user_{}", i).as_bytes().to_vec(),
                value: b"val".to_vec(),
                consistency: None,
                expected_pre_update_value: vec![],
                return_update_response: false,
            }),
            signature: vec![],
        })).await?;
    }

    // Current Server State: TreeSize = 2
    let tree_guard = service.tree.lock().await;
    let current_root = tree_guard.log.get_root(2)?;
    let current_ts = tree_guard.latest.as_ref().unwrap().timestamp as u64;
    drop(tree_guard); // Drop lock to allow service calls

    // =========================================================
    // Scenario A: Future State Attack (Auditor signs Size 100)
    // =========================================================
    // The server doesn't have 100 leaves. It must reject this even if the signature is valid.
    
    let fake_future_root = vec![0x99; 32];
    let tbs_future = crypto::construct_auditor_tree_head_tbs(
        &service.config, 
        &auditor_pk_bytes, 
        100, // Size 100
        current_ts + 1000, 
        &fake_future_root
    )?;
    
    let sig_future = auditor_raw_signer.sign(&tbs_future).to_vec();

    let req_future = tonic::Request::new(AuditorTreeHead {
        tree_size: 100,
        timestamp: (current_ts + 1000) as i64,
        signature: sig_future,
    });

    let res_future = service.set_auditor_head(req_future).await;
    
    // ASSERTION: Server must reject future states
    assert!(res_future.is_err(), "Server must reject TreeHead size > local tree size");
    assert!(res_future.unwrap_err().message().contains("ahead of service"));

    // =========================================================
    // Scenario B: Valid Update (Auditor signs Size 2)
    // =========================================================
    // Establish a baseline. Server accepts head at Size 2.
    
    let tbs_valid = crypto::construct_auditor_tree_head_tbs(
        &service.config, 
        &auditor_pk_bytes, 
        2, 
        current_ts, 
        &current_root
    )?;
    let sig_valid = auditor_raw_signer.sign(&tbs_valid).to_vec();

    let req_valid = tonic::Request::new(AuditorTreeHead {
        tree_size: 2,
        timestamp: current_ts as i64,
        signature: sig_valid,
    });

    let res_valid = service.set_auditor_head(req_valid).await;
    assert!(res_valid.is_ok(), "Server should accept valid current head");

    // =========================================================
    // Scenario C: Rewind Attack (Auditor tries to overwrite with Size 1)
    // =========================================================
    // The auditor key is compromised or malicious. They try to tell the server 
    // "Actually, the tree size is 1".
    
    let root_1 = {
        let guard = service.tree.lock().await;
        guard.log.get_root(1)?
    };

    let tbs_rewind = crypto::construct_auditor_tree_head_tbs(
        &service.config, 
        &auditor_pk_bytes, 
        1, 
        current_ts - 1000, 
        &root_1
    )?;
    let sig_rewind = auditor_raw_signer.sign(&tbs_rewind).to_vec();

    let req_rewind = tonic::Request::new(AuditorTreeHead {
        tree_size: 1,
        timestamp: (current_ts - 1000) as i64,
        signature: sig_rewind,
    });

    let res_rewind = service.set_auditor_head(req_rewind).await;
    
    // ASSERTION: Server must reject rewind
    assert!(res_rewind.is_err(), "Server must reject auditor rewind attempt");
    let err_msg = res_rewind.unwrap_err().message().to_string();
    assert!(err_msg.contains("regression"), "Error message should mention regression/rewind. Got: {}", err_msg);

    // Verify the state remains at 2
    let tree_guard = service.tree.lock().await;
    let stored_ath = tree_guard.auditors.get(&hex::encode(&auditor_pk_bytes)).unwrap();
    
    assert_eq!(stored_ath.tree_size, 2, "Auditor state should verify remain at 2");

    Ok(())
}