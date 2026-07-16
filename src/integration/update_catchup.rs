use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::client::KtClient;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tonic::transport::Server;

#[tokio::test]
async fn test_stale_client_catches_up_on_update() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, HashMap::new(), None).await?;

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    tokio::spawn(async move {
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let res = listener.accept().await.map(|(s, _)| s);
            Some((res, listener))
        });
        let _ = Server::builder()
            .add_service(crate::proto::kt::key_transparency_service_server::KeyTransparencyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await;
    });

    let uri = format!("http://{}", local_addr);
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

    let mut client_a: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;
    client_a.update(label.clone(), b"a_v0".to_vec()).await?;
    client_a.update(label.clone(), b"a_v1".to_vec()).await?;

    // Fresh client with no local version state: its first update must transparently
    // absorb versions 0..1 via catch-up responses, then land as version 2
    let mut client_b: KtClient = KtClient::connect(uri.clone(), public_config).await?;
    client_b.update(label.clone(), b"b_v2".to_vec()).await?;
    assert_eq!(client_b.label_versions.get(&label), Some(&2));

    let latest = client_a.search(label.clone(), None).await?;
    assert_eq!(latest.version, Some(2));
    assert_eq!(latest.value.unwrap().value, b"b_v2".to_vec());

    Ok(())
}
