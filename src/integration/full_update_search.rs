use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, LabelValue};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use sha2::{Sha256, Digest};
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_update_search_and_consistency() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_a = b"alice@example.com".to_vec();
    let key_a = b"alice_key_v1".to_vec();
    let req_a = tonic::Request::new(UpdateRequest {
        last: None,
        label: user_a.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: key_a.clone() }],
    });
    
    let _ = service.update(req_a).await?;
    
    let root_1 = {
        let guard = service.tree.write().await;
        guard.log.get_root(1)?
    };

    let user_b = b"bob@example.com".to_vec();
    let key_b = b"bob_key_v1".to_vec();
    let req_b = tonic::Request::new(UpdateRequest {
        last: None,
        label: user_b.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: key_b.clone() }],
    });
    let _ = service.update(req_b).await?;
    
    let root_2 = {
        let guard = service.tree.write().await;
        guard.log.get_root(2)?
    };

    let proof = {
        let guard = service.tree.write().await;
        guard.prove_consistency(1, 2)?
    };
    
    assert_eq!(proof.len(), 1);
    let mut hasher = Sha256::new();
    
    hasher.update(&[0x00]); // Left is Leaf
    hasher.update(&root_1);
    
    hasher.update(&[0x00]); // Right is Leaf
    hasher.update(&proof[0]);
    
    let calculated_root_2 = hasher.finalize().to_vec();
    assert_eq!(calculated_root_2, root_2);

    Ok(())
}