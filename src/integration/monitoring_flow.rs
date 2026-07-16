use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, LabelValue, MonitorRequest, MonitorLabel, MonitorMapEntry};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_monitoring_flow() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let mut service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    service.config.reasonable_monitoring_window = 0; 

    let user_id = b"monitor_user".to_vec();
    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user_id.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"monitored_value".to_vec() }],
    })).await?;

    for i in 0..3 {
        service.update(tonic::Request::new(UpdateRequest {
            last: None,
            label: format!("user_b_{}", i).as_bytes().to_vec(),
            greatest_version: None,
            values: vec![LabelValue { value: b"val_b".to_vec() }],
        })).await?;
    }

    // Contact Monitoring
    let req_contact = MonitorRequest {
        last: None,
        labels: vec![MonitorLabel {
            label: user_id.clone(),
            entries: vec![MonitorMapEntry {
                position: 0,
                version: 0,
            }],
            rightmost: None, 
        }],
        consistency: None,
    };

    let resp_contact = service.monitor(tonic::Request::new(req_contact)).await?.into_inner();
    assert!(resp_contact.monitor.is_some());
    let monitor_proof = resp_contact.monitor.unwrap();
    assert!(!monitor_proof.prefix_proofs.is_empty());
    assert!(monitor_proof.inclusion.is_some());

    // Owner Monitoring
    let req_owner = MonitorRequest {
        last: None,
        labels: vec![MonitorLabel {
            label: user_id.clone(),
            entries: vec![],
            rightmost: Some(0), 
        }],
        consistency: None,
    };

    let resp_owner = service.monitor(tonic::Request::new(req_owner)).await?.into_inner();
    assert!(resp_owner.monitor.is_some());
    assert_eq!(resp_owner.label_versions.len(), 1);
    let versions = &resp_owner.label_versions[0].versions;
    assert!(!versions.is_empty());
    
    Ok(())
}