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
async fn test_protocol_optimization_prefix_roots() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    let user = b"opt_user".to_vec();

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

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: Some(1),
        values: vec![LabelValue { value: b"v2".to_vec() }],
    })).await?;

    let req = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: None,
        version: Some(0),
    });

    let resp = service.search(req).await?.into_inner();
    let proof = resp.search.unwrap();

    assert_eq!(proof.timestamps.len(), 3);
    assert_eq!(proof.prefix_proofs.len(), 2);
    assert_eq!(proof.prefix_roots.len(), 1);
    assert_eq!(proof.prefix_roots[0].len(), 32);

    assert!(proof.inclusion.is_some());
    let inc = proof.inclusion.unwrap();
    assert_eq!(inc.elements.len(), 0);

    Ok(())
}