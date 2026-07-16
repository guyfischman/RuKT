use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SearchRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;
use crate::db::TransparencyStore;

#[tokio::test]
async fn test_pruning_expiration() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None).await?;
    
    {
        let mut tree = service.tree.write().await;
        tree.config.maximum_lifetime = Some(10_000);
    }

    let user_id = b"pruned_user".to_vec();

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: b"v0".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: b"v1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    })).await?;

    let ts_key_0 = 0 | (1u64 << 63);
    let ts_key_1 = 1 | (1u64 << 63);
    let current_ts_bytes = db.get_value(ts_key_1)?.unwrap();
    let current_ts = u64::from_be_bytes(current_ts_bytes.try_into().unwrap());
    
    let old_ts = current_ts - 20_000; 
    db.put_value(ts_key_0, old_ts.to_be_bytes().to_vec())?;

    let req_v0 = tonic::Request::new(SearchRequest {
        label: user_id.clone(),
        last: None,
        version: Some(0),
    });

    let result_v0 = service.search(req_v0).await;
    assert!(result_v0.is_err());
    let err = result_v0.err().unwrap();
    assert!(err.to_string().contains("expired"));

    let req_v1 = tonic::Request::new(SearchRequest {
        label: user_id.clone(),
        last: None,
        version: Some(1),
    });

    let result_v1 = service.search(req_v1).await;
    assert!(result_v1.is_ok());
    
    Ok(())
}