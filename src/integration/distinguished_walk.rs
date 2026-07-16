use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{DistinguishedRequest, LabelValue, UpdateRequest};
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_walk_distinguished_heads() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    {
        let mut tree = service.tree.write().await;
        tree.config.reasonable_monitoring_window = 0;
    }

    for i in 0..7 {
        service
            .update(tonic::Request::new(UpdateRequest {
                last: None,
                label: format!("user_{}", i).into_bytes(),
                greatest_version: None,
                values: vec![LabelValue {
                    value: b"v".to_vec(),
                }],
            }))
            .await?;
    }

    let resp = service
        .distinguished(tonic::Request::new(DistinguishedRequest {
            last: None,
            stop: None,
        }))
        .await?
        .into_inner();

    let proof = resp.distinguished.expect("Missing distinguished proof");
    assert_eq!(
        proof.timestamps.len(),
        7,
        "With RMW=0 every entry is distinguished and recent"
    );
    assert!(proof.inclusion.is_some());

    let resp_stopped = service
        .distinguished(tonic::Request::new(DistinguishedRequest {
            last: None,
            stop: Some(3),
        }))
        .await?
        .into_inner();

    let stopped_proof = resp_stopped.distinguished.unwrap();
    assert!(
        stopped_proof.timestamps.len() < 7,
        "Stopping position must truncate the walk"
    );

    Ok(())
}
