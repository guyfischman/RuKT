use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::transparency::{
    ContactMonitorRequest, LabelValue, MonitorMapEntry, OwnerInitRequest, UpdateRequest,
};
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_monitoring_flow() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;

    let user_id = b"monitor_user".to_vec();
    // 'monitor_user' lands at position 2: off the 0-anchored left spine, so its
    // map entry is not distinguished and must be walked up
    for i in 0..2 {
        service
            .update(tonic::Request::new(UpdateRequest {
                last: None,
                label: format!("user_b_{}", i).as_bytes().to_vec(),
                greatest_version: None,
                values: vec![LabelValue {
                    value: b"val_b".to_vec(),
                }],
            }))
            .await?;
    }
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: user_id.clone(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"monitored_value".to_vec(),
            }],
        }))
        .await?;
    service
        .update(tonic::Request::new(UpdateRequest {
            last: None,
            label: b"user_b_2".to_vec(),
            greatest_version: None,
            values: vec![LabelValue {
                value: b"val_b".to_vec(),
            }],
        }))
        .await?;

    // Contact Monitoring
    let req_contact = ContactMonitorRequest {
        last: None,
        label: user_id.clone(),
        entries: vec![MonitorMapEntry {
            position: 2,
            version: 0,
        }],
    };

    let resp_contact = service
        .contact_monitor(tonic::Request::new(req_contact))
        .await?
        .into_inner();
    assert!(resp_contact.monitor.is_some());
    let monitor_proof = resp_contact.monitor.unwrap();
    assert!(!monitor_proof.prefix_proofs.is_empty());
    assert!(monitor_proof.inclusion.is_some());

    // Owner Initialization from the entry where the label was created
    let req_owner = OwnerInitRequest {
        last: None,
        label: user_id.clone(),
        start: 2,
    };

    let resp_owner = service
        .owner_init(tonic::Request::new(req_owner))
        .await?
        .into_inner();
    assert!(resp_owner.init.is_some());
    assert_eq!(resp_owner.greatest_versions, vec![0]);

    Ok(())
}
