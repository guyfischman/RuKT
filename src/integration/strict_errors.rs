use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{LabelValue, SearchRequest, UpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;
use crate::db::TransparencyStore;

#[tokio::test]
async fn test_strict_errors() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None).await?;
    {
         let mut tree = service.tree.write().await;
         tree.config.maximum_lifetime = Some(10_000); 
    }

    let user = b"error_user".to_vec();

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"v0".to_vec() }],
    })).await?;

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: Some(0),
        values: vec![LabelValue { value: b"v1".to_vec() }],
    })).await?;

    let req_missing = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: None,
        version: Some(999),
    });
    
    let result_missing = service.search(req_missing).await;
    match result_missing {
        Ok(_) => panic!("Expected error for unavailable version"),
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::NotFound);
            assert!(e.message().contains("unavailable"));
        }
    }

    let ts_key_0 = 0 | (1u64 << 63);
    let current_ts_key = 1 | (1u64 << 63);
    let current_ts_bytes = db.get_value(current_ts_key)?.unwrap();
    let current_ts = u64::from_be_bytes(current_ts_bytes.try_into().unwrap());
    
    let old_ts = current_ts - 20_000; 
    db.put_value(ts_key_0, old_ts.to_be_bytes().to_vec())?;

    let req_expired = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: None,
        version: Some(0),
    });
    
    let result_expired = service.search(req_expired).await;
    match result_expired {
        Ok(_) => panic!("Expected error for expired version"),
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::NotFound);
            assert!(e.message().contains("expired"));
        }
    }

    Ok(())
}