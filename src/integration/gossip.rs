use crate::client::KtClient;
use crate::client::gossip::{GossipHead, GossipOutcome, verify_fork_evidence};
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tonic::transport::Server;

#[tokio::test]
async fn test_gossip_detects_split_view() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    let malicious_signer = sig_sk.clone();

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

    // the configuration artifact survives its distribution round-trip
    let json = public_config.to_json()?;
    let restored = crypto::PublicConfig::from_json(&json)?;
    assert_eq!(restored.server_sig_pk, public_config.server_sig_pk);
    assert_eq!(
        restored.reasonable_monitoring_window,
        public_config.reasonable_monitoring_window
    );

    let mut alice: KtClient = KtClient::connect(uri.clone(), public_config.clone()).await?;
    let mut bob: KtClient = KtClient::connect(uri, public_config.clone()).await?;

    alice.update(b"alice".to_vec(), b"pk_a".to_vec()).await?;
    alice.search(b"alice".to_vec(), None).await?;
    bob.search(b"alice".to_vec(), None).await?;

    // honest exchange: both saw the same head
    let from_bob = bob.export_head()?;
    match alice.check_gossiped_head(&from_bob)? {
        GossipOutcome::Consistent => {}
        _ => panic!("Honest peers must agree"),
    }

    // a compromised operator signs a second head over a different root at the
    // same size; the exchange yields self-contained fork evidence
    let fake_root = vec![0x42u8; 32];
    let tree_size = alice.state.as_ref().unwrap().tree_size;
    let tbs = crypto::construct_tree_head_tbs_public(&public_config, tree_size, &fake_root)?;
    let forged_sig = crypto::sign_data(&malicious_signer, &tbs);
    let forged_head = crate::proto::transparency::TreeHead {
        tree_size,
        timestamp: alice.state.as_ref().unwrap().timestamp as i64,
        signatures: vec![crate::proto::transparency::Signature {
            auditor_public_key: vec![],
            signature: forged_sig,
        }],
    };
    let forged = GossipHead::new(tree_size, &fake_root, &forged_head);

    match alice.check_gossiped_head(&forged)? {
        GossipOutcome::Fork(evidence) => {
            verify_fork_evidence(&public_config, &evidence)?;
            let serialized = serde_json::to_string(&evidence)?;
            let deserialized: crate::client::gossip::ForkEvidence =
                serde_json::from_str(&serialized)?;
            verify_fork_evidence(&public_config, &deserialized)?;
        }
        _ => panic!("Split view must be detected as a fork"),
    }

    // §10.2: historical root values at distinguished heads are derivable from
    // the walk and comparable across peers
    alice.update(b"more_1".to_vec(), b"x".to_vec()).await?;
    alice.update(b"more_2".to_vec(), b"y".to_vec()).await?;
    alice.distinguished(None).await?;
    bob.distinguished(None).await?;

    let alice_roots = alice.distinguished_roots()?;
    assert!(!alice_roots.is_empty());

    let their_roots = bob.export_distinguished_roots()?;
    alice.check_gossiped_roots(&their_roots)?;

    // a forged root list with a divergent recent entry must be rejected
    let mut forged_roots = their_roots.clone();
    let last = forged_roots.roots.len() - 1;
    forged_roots.roots[last].1 = hex::encode(vec![0x66u8; 32]);
    assert!(alice.check_gossiped_roots(&forged_roots).is_err());

    Ok(())
}
