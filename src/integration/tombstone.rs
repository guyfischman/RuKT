use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, TreeSearchRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_tombstone_updates() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_id = b"user_tombstone".to_vec();
    let val_1 = b"value_1".to_vec();
    let val_2 = b"value_2".to_vec();

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: val_1.clone(),
            consistency: None,
            expected_pre_update_value: vec![], 
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    let wrong_val = b"wrong_value".to_vec();
    let req_fail = tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: val_2.clone(),
            consistency: None,
            expected_pre_update_value: wrong_val,
            return_update_response: true,
        }),
        signature: vec![],
    });

    let result = service.update(req_fail).await;
    assert!(result.is_err());

    let search_resp = service.search(tonic::Request::new(TreeSearchRequest {
        search_key: user_id.clone(),
        consistency: None,
        version: None,
    })).await?.into_inner();
    
    let current_val = search_resp.value.unwrap().value;
    assert_eq!(current_val, val_1);

    let req_success = tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: val_2.clone(),
            consistency: None,
            expected_pre_update_value: val_1.clone(),
            return_update_response: true,
        }),
        signature: vec![],
    });

    let _ = service.update(req_success).await?;

    let search_resp_2 = service.search(tonic::Request::new(TreeSearchRequest {
        search_key: user_id.clone(),
        consistency: None,
        version: None,
    })).await?.into_inner();

    let new_val = search_resp_2.value.unwrap().value;
    assert_eq!(new_val, val_2);

    Ok(())
}