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
async fn test_client_state_survives_restart() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().join("db").to_str().unwrap())?);
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
    let state_file = dir.path().join("client_state.json");
    let label = b"persisted_label".to_vec();

    {
        let mut client: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;
        client.persist_to(&state_file)?;

        client.update(label.clone(), b"v0".to_vec()).await?;
        client.search(label.clone(), None).await?;

        let state = client.state.as_ref().expect("verified state");
        assert_eq!(state.tree_size, 1);
        assert!(!client.retained_subtrees.is_empty());
    }

    // restart with persisted state; a repeat search must ride the SAME head and
    // reconstruct exactly the retained root
    {
        let mut client: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;
        client.persist_to(&state_file)?;
        assert_eq!(client.state.as_ref().map(|s| s.tree_size), Some(1));
        assert_eq!(client.label_versions.get(&label), Some(&0));

        client.search(label.clone(), None).await?;
        assert_eq!(client.state.as_ref().map(|s| s.tree_size), Some(1));
    }

    // grow the tree while the client is offline, then verify the updated head
    // against retained subtrees on reconnect
    {
        let mut writer: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;
        writer.update(b"other_label".to_vec(), b"x".to_vec()).await?;
        writer.update(label.clone(), b"v1".to_vec()).await?;

        let mut client: KtClient = KtClient::connect(uri, public_config).await?;
        client.persist_to(&state_file)?;

        let resp = client.search(label.clone(), None).await?;
        assert_eq!(resp.version, Some(1));
        assert_eq!(client.state.as_ref().map(|s| s.tree_size), Some(3));
        assert_eq!(client.label_versions.get(&label), Some(&1));
    }

    Ok(())
}
