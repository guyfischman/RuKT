use crate::client::KtClient;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tonic::transport::Server;

// §8.3 owner initialization, verified end-to-end by the client against a
// distinguished start entry.
#[tokio::test]
async fn test_owner_init_client_verified() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, HashMap::new(), None).await?;
    {
        // every entry distinguished, so the whole init list is exercised
        let mut tree = service.tree.write().await;
        tree.config.reasonable_monitoring_window = 0;
    }

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
        reasonable_monitoring_window: 0,
        maximum_lifetime: None,
    };

    let owner = b"owner_label".to_vec();
    let mut client: KtClient = KtClient::connect(uri, public_config).await?;

    // the label gains several versions, interleaved with unrelated activity
    client.update(owner.clone(), b"v0".to_vec()).await?;
    client.update(b"noise".to_vec(), b"x".to_vec()).await?;
    client.update(owner.clone(), b"v1".to_vec()).await?;
    client.update(owner.clone(), b"v2".to_vec()).await?;

    // initialize ownership from the rightmost entry holding the label
    let resp = client.owner_init(owner.clone(), 3).await?;
    assert_eq!(resp.greatest_versions.first(), Some(&2));
    // client verification updated the trusted head
    assert_eq!(client.state.as_ref().map(|s| s.tree_size), Some(4));

    // §8.3 second algorithm: the owner monitors that no version beyond 2 appeared
    // at any distinguished entry as the tree grows
    client.update(b"noise2".to_vec(), b"y".to_vec()).await?;
    client.update(b"noise3".to_vec(), b"z".to_vec()).await?;
    let owner_resp = client
        .owner_monitor(owner.clone(), vec![], 3, Some(2))
        .await?;
    assert!(owner_resp.monitor.is_some());
    assert_eq!(client.state.as_ref().map(|s| s.tree_size), Some(6));

    Ok(())
}
