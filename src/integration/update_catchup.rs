use crate::client::KtClient;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_stale_client_catches_up_on_update() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, HashMap::new(), None).await?;

    let channel = crate::integration::harness::serve_in_memory(service).await?;
    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: sig_vk.to_bytes(),
        vrf_public_key: vrf_pub,
        leaf_public_key: None,
        auditor_public_key: None,
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: 5000,
        max_behind: 5000,
        reasonable_monitoring_window: 86400000,
        maximum_lifetime: None,
    };

    let label = b"shared_label".to_vec();

    let mut client_a: KtClient = KtClient::with_channel(channel.clone(), public_config.clone())?;
    client_a.update(label.clone(), b"a_v0".to_vec()).await?;
    client_a.update(label.clone(), b"a_v1".to_vec()).await?;

    // Fresh client with no local version state: its first update must transparently
    // absorb versions 0..1 via catch-up responses, then land as version 2
    let mut client_b: KtClient = KtClient::with_channel(channel.clone(), public_config)?;
    client_b.update(label.clone(), b"b_v2".to_vec()).await?;
    assert_eq!(client_b.label_versions.get(&label), Some(&2));

    let latest = client_a.search(label.clone(), None).await?;
    assert_eq!(latest.version, Some(2));
    assert_eq!(latest.value.unwrap().value, b"b_v2".to_vec());

    // fixed-version searches ride the SAME head and replay the §7.2 walk
    let v1 = client_a.search(label.clone(), Some(1)).await?;
    assert_eq!(v1.value.unwrap().value, b"a_v1".to_vec());
    let v0 = client_a.search(label.clone(), Some(0)).await?;
    assert_eq!(v0.value.unwrap().value, b"a_v0".to_vec());

    Ok(())
}
