use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::db::TransparencyStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{LabelValue, SearchRequest, UpdateRequest};
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_deletable_openings() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service =
        KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None).await?;
    let user = b"forgotten_user".to_vec();

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

    // 2. Search Success (Opening Present)
    let resp_ok = service
        .search(tonic::Request::new(SearchRequest {
            label: user.clone(),
            last: None,
            version: Some(0),
        }))
        .await?
        .into_inner();

    assert!(!resp_ok.opening.is_empty());
    assert_eq!(resp_ok.value.unwrap().value, b"v0");

    // 3. Delete Opening (Right to Be Forgotten)
    let history = db.get_label_history(&user)?;
    let (_, ptr) = history[0];

    db.delete_opening(ptr)?;

    // 4. Search Failure (Opening Absent)
    let req_fail = tonic::Request::new(SearchRequest {
        label: user.clone(),
        last: None,
        version: Some(0),
    });

    let result = service.search(req_fail).await;
    match result {
        Ok(_) => panic!("Search should fail after opening deletion"),
        Err(e) => {
            if e.code() != tonic::Code::NotFound {
                println!(
                    "Unexpected error code: {:?} - Message: {}",
                    e.code(),
                    e.message()
                );
            }
            assert_eq!(e.code(), tonic::Code::NotFound);
            assert!(e.message().contains("unavailable"));
        }
    }

    Ok(())
}
