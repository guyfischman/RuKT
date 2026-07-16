use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SearchRequest, LabelValue};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService; 
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_batcher_logic() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    let mut handles = vec![];
    for i in 0..10 {
        let svc = service.clone();
        handles.push(tokio::spawn(async move {
            let user = format!("user_{}", i).as_bytes().to_vec();
            let req = tonic::Request::new(UpdateRequest {
                last: None,
                label: user,
                greatest_version: None,
                values: vec![LabelValue { value: b"val".to_vec() }],
            });
            svc.update(req).await
        }));
    }

    for h in handles {
        let _ = h.await??;
    }

    let size = service.tree.write().await.latest.as_ref().unwrap().tree_size;
    
    assert!(size >= 1);
    assert!(size < 10);

    for i in 0..10 {
        let user = format!("user_{}", i).as_bytes().to_vec();
        let resp = service.search(tonic::Request::new(SearchRequest {
            label: user,
            last: None,
            version: None,
        })).await?.into_inner();
        
        assert_eq!(resp.value.unwrap().value, b"val");
    }

    Ok(())
}