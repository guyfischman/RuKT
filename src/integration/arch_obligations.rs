use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::db::TransparencyStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{
    ContactMonitorRequest, LabelValue, MonitorMapEntry, SearchRequest, UpdateRequest,
};
use crate::service::{AccessPolicy, KeyTransparencyImpl};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

struct DenyLabel(Vec<u8>);
impl AccessPolicy for DenyLabel {
    fn allow_search(&self, label: &[u8]) -> bool {
        label != self.0.as_slice()
    }
    fn allow_update(&self, label: &[u8]) -> bool {
        label != self.0.as_slice()
    }
}

#[tokio::test]
async fn test_monitoring_bypasses_revoked_access() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let mut service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    let label = b"revoked_user".to_vec();

    // populated while access was still granted; label lands at position 2
    for i in 0..2 {
        service
            .update(tonic::Request::new(UpdateRequest {
                last: None,
                label: format!("f_{}", i).into_bytes(),
                greatest_version: None,
                values: vec![LabelValue {
                    value: b"x".to_vec(),
                }],
            }))
            .await?;
    }
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: label.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"v0".to_vec(),
            }],
        }))
        .await?;
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: b"f_2".to_vec(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"x".to_vec(),
            }],
        }))
        .await?;

    service.set_access_policy(Arc::new(DenyLabel(label.clone())));

    let denied = service
        .search(tonic::Request::new(SearchRequest {
            last: None,
            label: label.clone(),
            version: None,
        }))
        .await;
    assert_eq!(denied.unwrap_err().code(), tonic::Code::PermissionDenied);

    let denied = service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: label.clone(),
            greatest_version: Some(0),
            values: vec![LabelValue {
                value: b"v1".to_vec(),
            }],
        }))
        .await;
    assert_eq!(denied.unwrap_err().code(), tonic::Code::PermissionDenied);

    // protocol-obligated monitoring must still be served
    let monitored = service
        .contact_monitor(tonic::Request::new(ContactMonitorRequest {
            last: None,
            label: label.clone(),
            entries: vec![MonitorMapEntry {
                position: 2,
                version: 0,
            }],
        }))
        .await?;
    assert!(monitored.into_inner().monitor.is_some());

    Ok(())
}

#[tokio::test]
async fn test_erasure_and_lifetime_pruning() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service =
        KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None).await?;
    {
        let mut tree = service.tree.write().await;
        tree.config.maximum_lifetime = Some(10_000);
    }

    let label = b"erased_user".to_vec();
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: label.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"v0".to_vec(),
            }],
        }))
        .await?;
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: label.clone(),
            greatest_version: Some(0),
            values: vec![LabelValue {
                value: b"v1".to_vec(),
            }],
        }))
        .await?;

    // erasure removes the value and opening immediately
    {
        let tree = service.tree.read().await;
        tree.erase(&label, 0)?;
        let history = tree.store.get_label_history(&label)?;
        let pos = history.iter().find(|(v, _)| *v == 0).unwrap().1;
        assert!(db.get_value(pos)?.is_none());
        assert!(db.get_opening(pos)?.is_none());
    }

    let gone = service
        .search(tonic::Request::new(SearchRequest {
            last: None,
            label: label.clone(),
            version: Some(0),
        }))
        .await;
    assert!(gone.is_err(), "Erased version must not be servable");

    let latest = service
        .search(tonic::Request::new(SearchRequest {
            last: None,
            label: label.clone(),
            version: None,
        }))
        .await?;
    assert_eq!(latest.into_inner().value.unwrap().value, b"v1".to_vec());

    // lifetime pruning: backdate entry 0 past the maximum lifetime
    let ts_key_0 = 0 | (1u64 << 63);
    let ts_key_1 = 1 | (1u64 << 63);
    let current_ts_bytes = db.get_value(ts_key_1)?.unwrap();
    let current_ts = u64::from_be_bytes(current_ts_bytes.try_into().unwrap());
    db.put_value(ts_key_0, (current_ts - 20_000).to_be_bytes().to_vec())?;

    {
        let tree = service.tree.read().await;
        // v0 already erased; nothing left to prune besides it
        let pruned = tree.prune_expired_versions(&label)?;
        assert_eq!(pruned, 1, "The expired non-greatest version is pruned");
        // the greatest version never expires through the lifetime mechanism
        let history = tree.store.get_label_history(&label)?;
        let pos_v1 = history.iter().find(|(v, _)| *v == 1).unwrap().1;
        assert!(db.get_value(pos_v1)?.is_some());
    }

    Ok(())
}
