use crate::client::{KtAuditor, KtClient};
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tonic::transport::{Channel, Server};

/// Serves the gRPC service over an in-memory duplex transport (no network
/// ports) and returns a `Channel` that opens a fresh duplex per connection.
pub async fn serve_in_memory(service: KeyTransparencyImpl) -> Result<Channel> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<tokio::io::DuplexStream>();
    let incoming = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|io| (Ok::<_, std::io::Error>(io), rx))
    });
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(
                crate::proto::kt::key_transparency_service_server::KeyTransparencyServiceServer::new(
                    service,
                ),
            )
            .serve_with_incoming(incoming)
            .await;
    });

    let channel = tonic::transport::Endpoint::try_from("http://in-memory")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let tx = tx.clone();
            async move {
                let (client_io, server_io) = tokio::io::duplex(1 << 20);
                tx.send(server_io).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "server task gone")
                })?;
                Ok::<_, std::io::Error>(client_io)
            }
        }))
        .await?;
    Ok(channel)
}

/// A running in-process server plus the public config clients need to verify it.
pub struct TestServer {
    pub channel: Channel,
    pub config: crypto::PublicConfig,
    pub auditor_signer: Option<crypto::ServiceSigningKey>,
    _dir: TempDir,
}

impl TestServer {
    pub async fn contact_monitoring() -> Result<Self> {
        Self::spawn(false, 86_400_000).await
    }

    /// RMW = 0 makes every log entry distinguished, exercising the full
    /// distinguished-walk and credential paths.
    pub async fn contact_monitoring_all_distinguished() -> Result<Self> {
        Self::spawn(false, 0).await
    }

    pub async fn auditing_all_distinguished() -> Result<Self> {
        Self::spawn(true, 0).await
    }

    async fn spawn(auditing: bool, rmw: u64) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
        let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
        let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

        let (auditor_keys, auditor_signer, auditor_pk) = if auditing {
            let (ask, avk) = crypto::generate_sig_keypair();
            let mut map = HashMap::new();
            map.insert(avk.to_bytes(), avk.clone());
            (map, Some(ask), Some(avk.to_bytes()))
        } else {
            (HashMap::new(), None, None)
        };

        let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, auditor_keys, None).await?;
        {
            let mut tree = service.tree.write().await;
            tree.config.reasonable_monitoring_window = rmw;
        }

        let channel = serve_in_memory(service).await?;

        let mode = if auditing {
            crypto::DEPLOYMENT_MODE_THIRD_PARTY_AUDITING
        } else {
            crypto::DEPLOYMENT_MODE_CONTACT_MONITORING
        };
        let config = crypto::PublicConfig {
            cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
            mode,
            server_sig_pk: sig_vk.to_bytes(),
            vrf_public_key: vrf_pub,
            leaf_public_key: None,
            auditor_public_key: auditor_pk,
            auditor_start_pos: 0,
            max_auditor_lag: 60_000,
            max_ahead: 5000,
            max_behind: 5000,
            reasonable_monitoring_window: rmw,
            maximum_lifetime: None,
        };

        Ok(Self {
            channel,
            config,
            auditor_signer,
            _dir: dir,
        })
    }

    pub async fn client(&self) -> Result<KtClient> {
        KtClient::with_channel(self.channel.clone(), self.config.clone())
    }

    /// Ingests all pending log entries and publishes a fresh auditor head.
    pub async fn run_auditor(&self) -> Result<()> {
        let signer = self
            .auditor_signer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not an auditing deployment"))?;
        let mut auditor =
            KtAuditor::with_channel(self.channel.clone(), signer, self.config.clone())?;
        auditor.process_and_sign().await?;
        Ok(())
    }
}
