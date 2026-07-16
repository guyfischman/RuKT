use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SearchRequest, Consistency, FullTreeHeadType, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_tree_head_same_optimization() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    let user = b"user_opt".to_vec();

    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user.clone(),
            value: b"v1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: false,
        }),
        signature: vec![],
    })).await?;

    let req_cold = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: None, 
        version: None,
    });
    let resp_cold = service.search(req_cold).await?.into_inner();
    let fth_cold = resp_cold.full_tree_head.unwrap();
    
    assert_eq!(fth_cold.head_type, FullTreeHeadType::Updated as i32);
    assert!(fth_cold.tree_head.is_some());

    let req_same = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: Some(1),
        version: None,
    });
    let resp_same = service.search(req_same).await?.into_inner();
    let fth_same = resp_same.full_tree_head.unwrap();
    
    assert_eq!(fth_same.head_type, FullTreeHeadType::Same as i32);
    assert!(fth_same.tree_head.is_none());
    
    service.update(tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user.clone(),
            value: b"v2".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: false,
        }),
        signature: vec![],
    })).await?;

    let req_behind = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: Some(1),
        version: None,
    });
    let resp_behind = service.search(req_behind).await?.into_inner();
    let fth_behind = resp_behind.full_tree_head.unwrap();
    
    assert_eq!(fth_behind.head_type, FullTreeHeadType::Updated as i32);
    assert!(fth_behind.tree_head.is_some());
    assert_eq!(fth_behind.tree_head.unwrap().tree_size, 2);
    
    Ok(())
}