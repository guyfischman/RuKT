use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{LabelValue, SearchRequest, UpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_tombstone_updates() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_id = b"user_tombstone".to_vec();
    let val_1 = b"value_1".to_vec();
    let val_2 = b"value_2".to_vec();

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user_id.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: val_1.clone() }],
    })).await?;

    let req_stale = tonic::Request::new(UpdateRequest {
        last: None,
        label: user_id.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: val_2.clone() }],
    });

    // §13.5: a stale greatest_version is disregarded and answered with the
    // existing versions instead of creating anything
    let result = service.update(req_stale).await?.into_inner();
    assert_eq!(result.values.len(), 1, "Stale update is informed of the existing version");
    assert_eq!(result.values[0].value, val_1);
    assert_eq!(result.info.len(), 1);

    let req_wrong = tonic::Request::new(UpdateRequest {
        last: None,
        label: user_id.clone(),
        greatest_version: Some(5),
        values: vec![LabelValue { value: val_2.clone() }],
    });

    let result_wrong = service.update(req_wrong).await;
    assert!(result_wrong.is_err(), "Wrong greatest_version must be rejected");
    assert_eq!(result_wrong.unwrap_err().code(), tonic::Code::FailedPrecondition);

    let search_resp = service.search(tonic::Request::new(SearchRequest {
        label: user_id.clone(),
        last: None,
        version: None,
    })).await?.into_inner();

    let current_val = search_resp.value.unwrap().value;
    assert_eq!(current_val, val_1);

    let req_success = tonic::Request::new(UpdateRequest {
        last: None,
        label: user_id.clone(),
        greatest_version: Some(0),
        values: vec![LabelValue { value: val_2.clone() }],
    });

    let _ = service.update(req_success).await?;

    let search_resp_2 = service.search(tonic::Request::new(SearchRequest {
        label: user_id.clone(),
        last: None,
        version: None,
    })).await?.into_inner();

    let new_val = search_resp_2.value.unwrap().value;
    assert_eq!(new_val, val_2);

    Ok(())
}
