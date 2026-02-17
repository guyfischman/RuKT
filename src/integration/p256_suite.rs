use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_P256};
use crate::proto::transparency::{UpdateRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_p256_cipher_suite() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    
    // Generate P-256 keys
    let (signer, _) = crypto::generate_p256_keypair();
    let (vrf_secret, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_P256);
    
    // Init service (detects suite from keys)
    let service = KeyTransparencyImpl::new(db, signer, vrf_secret, HashMap::new(), None).await?;
    
    assert_eq!(service.config.cipher_suite, CIPHER_SUITE_KT_128_SHA256_P256);

    let user = b"p256_user".to_vec();
    let val = b"p256_val".to_vec();

    // 1. Perform Update
    let req = tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user.clone(),
            value: val.clone(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    });

    let resp = service.update(req).await?.into_inner();
    
    // 2. Verify Output
    let tree_head = resp.tree_head.unwrap();
    let th = tree_head.tree_head.unwrap();
    
    // TreeHead signature should be P-256 (64 bytes)
    assert_eq!(th.signatures[0].signature.len(), 64);
    
    // VRF Proof in binary ladder should be P-256 (81 bytes)
    assert!(!resp.binary_ladder.is_empty());
    assert_eq!(resp.binary_ladder[0].proof.len(), 81);

    Ok(())
}