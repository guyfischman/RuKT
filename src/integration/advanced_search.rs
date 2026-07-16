use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{LabelValue, SearchRequest, UpdateRequest};
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_advanced_search() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    let user = b"adv_user".to_vec();

    // 1. Insert v0
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"v0".to_vec(),
            }],
        }))
        .await?;

    // 2. Insert v1
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user.clone(),
            greatest_version: Some(0),
            values: vec![LabelValue {
                value: b"v1".to_vec(),
            }],
        }))
        .await?;

    // 3. Greatest-Version Search (v1)
    let resp = service
        .search(tonic::Request::new(SearchRequest {
            label: user.clone(),
            last: None,
            version: None, // Greatest
        }))
        .await?
        .into_inner();

    assert_eq!(resp.value.unwrap().value, b"v1");

    // 4. Fixed-Version Search (v0)
    let resp_v0 = service
        .search(tonic::Request::new(SearchRequest {
            label: user.clone(),
            last: None,
            version: Some(0),
        }))
        .await?
        .into_inner();

    assert_eq!(resp_v0.value.unwrap().value, b"v0");

    Ok(())
}
