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
async fn test_versioned_updates() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_a = b"alice@example.com".to_vec();
    
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

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_a.clone(),
            value: b"v2".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    let search_resp = service.search(tonic::Request::new(TreeSearchRequest {
        search_key: user_a.clone(),
        consistency: None,
        version: None,
    })).await?;

    let val = search_resp.into_inner().value.unwrap();
    assert_eq!(val.value, b"v2".to_vec());
    Ok(())
}