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
async fn test_multi_label_batching_collisions() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let label = b"collision_target".to_vec();
    let num_versions = 10usize;

    let values: Vec<LabelValue> = (0..num_versions)
        .map(|i| LabelValue {
            value: format!("val_{}", i).into_bytes(),
        })
        .collect();

    let resp = service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: label.clone(),
            greatest_version: None,
            values,
        }))
        .await?
        .into_inner();

    assert!(
        resp.values.is_empty(),
        "Successful update returns no values"
    );
    assert_eq!(
        resp.info.len(),
        num_versions,
        "One UpdateInfo per created version"
    );
    assert_eq!(resp.position, 0);

    for i in 0..num_versions {
        let req = tonic::Request::new(SearchRequest {
            label: label.clone(),
            last: None,
            version: Some(i as u32),
        });

        let resp = service.search(req).await;
        assert!(resp.is_ok(), "Version {} should exist", i);

        let inner = resp.unwrap().into_inner();
        let val = inner.value.expect("value present").value;
        assert_eq!(val, format!("val_{}", i).into_bytes());
    }

    let tree_size = service
        .tree
        .write()
        .await
        .latest
        .as_ref()
        .unwrap()
        .tree_size;
    assert_eq!(
        tree_size, 1,
        "All versions of one request share a single log entry"
    );

    let mut handles = vec![];
    for i in 0..2 {
        let svc = service.clone();
        let label_clone = label.clone();
        handles.push(tokio::spawn(async move {
            svc.update(tonic::Request::new(UpdateRequest {
                last: None,
                label: label_clone,
                greatest_version: Some(9),
                values: vec![LabelValue {
                    value: format!("racer_{}", i).into_bytes(),
                }],
            }))
            .await
        }));
    }

    let mut winners = 0;
    let mut caught_up = 0;
    for h in handles {
        let resp = h.await??.into_inner();
        if resp.values.is_empty() {
            winners += 1;
        } else {
            // §13.5: the loser is informed of the winner's version instead of failing
            assert_eq!(resp.values.len(), 1);
            assert!(resp.values[0].value.starts_with(b"racer_"));
            assert_eq!(resp.info.len(), 1);
            caught_up += 1;
        }
    }
    assert_eq!(winners, 1, "Exactly one racing update wins");
    assert_eq!(
        caught_up, 1,
        "The loser is caught up on the winner's version"
    );

    let resp_latest = service
        .search(tonic::Request::new(SearchRequest {
            label: label.clone(),
            last: None,
            version: None,
        }))
        .await?
        .into_inner();

    let latest = resp_latest.value.expect("value present").value;
    assert!(latest.starts_with(b"racer_"));

    Ok(())
}
