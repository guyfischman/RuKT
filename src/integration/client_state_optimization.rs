use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SearchRequest, Consistency, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_inclusion_proof_optimization() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    for i in 0..4 {
        let user = format!("user_{}", i).as_bytes().to_vec();
        service.update(tonic::Request::new(SignedUpdateRequest {
            request: Some(UpdateRequest {
                search_key: user,
                value: b"val".to_vec(),
                consistency: None,
                expected_pre_update_value: vec![],
                return_update_response: false,
            }),
            signature: vec![],
        })).await?;
    }

    let target_user = b"user_2".to_vec();

    // Cold Client
    let req_cold = tonic::Request::new(SearchRequest {
        label: target_user.clone(),
        last: Some(0),
        version: None,
    });

    let resp_cold = service.search(req_cold).await?.into_inner();
    let proof_cold = resp_cold.search.unwrap().inclusion.unwrap();
    
    assert_eq!(proof_cold.elements.len(), 2);

    // Warm Client
    let req_warm = tonic::Request::new(SearchRequest {
        label: target_user.clone(),
        last: Some(2),
        version: None,
    });

    let resp_warm = service.search(req_warm).await?.into_inner();
    let proof_warm = resp_warm.search.unwrap().inclusion.unwrap();
    
    assert_eq!(proof_warm.elements.len(), 1);
    assert!(proof_warm.elements.len() < proof_cold.elements.len());

    Ok(())
}