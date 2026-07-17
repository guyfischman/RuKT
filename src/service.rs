// Start src/service.rs
use crate::batcher::Batcher;
use crate::crypto::{
    CIPHER_SUITE_KT_128_SHA256_ED25519, CIPHER_SUITE_KT_128_SHA256_P256,
    DEPLOYMENT_MODE_CONTACT_MONITORING, DEPLOYMENT_MODE_THIRD_PARTY_AUDITING, PrivateConfig,
    ServiceSigningKey, ServiceVerifyingKey,
};
use crate::db::TransparencyStore;
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::kt::{AuditBootstrapResponse, AuditRequest, AuditResponse, TreeSizeResponse};
use crate::proto::transparency::{
    AuditorTreeHead, ContactMonitorRequest, ContactMonitorResponse, Credential, CredentialUpdate,
    DistinguishedRequest, DistinguishedResponse, GetCredentialRequest, GetCredentialUpdateRequest,
    OwnerInitRequest, OwnerInitResponse, OwnerMonitorRequest, OwnerMonitorResponse, SearchRequest,
    SearchResponse, UpdateRequest, UpdateResponse,
};
use crate::tree::Tree;
use crate::tree::errors::map_anyhow_to_status;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock; // CHANGED: Replaced Mutex with RwLock
use tonic::{Request, Response, Status};

/// Application-defined access control for point-in-time operations. The
/// monitoring endpoints deliberately have no hook: protocol-obligated monitor
/// queries MUST be permitted regardless of current permissions.
pub trait AccessPolicy: Send + Sync {
    fn allow_search(&self, _label: &[u8]) -> bool {
        true
    }
    fn allow_update(&self, _label: &[u8]) -> bool {
        true
    }
}

pub struct AllowAll;
impl AccessPolicy for AllowAll {}

// `Default` reproduces the values the service previously hardcoded.
#[derive(Clone, Debug)]
pub struct ServerParams {
    pub max_ahead: u64,
    pub max_behind: u64,
    pub reasonable_monitoring_window: u64,
    pub maximum_lifetime: Option<u64>,
    pub max_response_entries: usize,
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            max_ahead: 5000,
            max_behind: 5000,
            reasonable_monitoring_window: 86_400_000,
            maximum_lifetime: None,
            max_response_entries: 100,
        }
    }
}

#[derive(Clone)]
pub struct KeyTransparencyImpl {
    pub db: Arc<dyn TransparencyStore>,
    pub config: PrivateConfig,
    pub auditor_keys: Arc<HashMap<Vec<u8>, ServiceVerifyingKey>>,
    pub batcher: Arc<Batcher>,
    pub tree: Arc<RwLock<Tree>>, // CHANGED: Now using RwLock for high-concurrency reads
    pub access_policy: Arc<dyn AccessPolicy>,
}

impl KeyTransparencyImpl {
    pub async fn new(
        db: Arc<dyn TransparencyStore>,
        sig_key: ServiceSigningKey,
        vrf_key: Vec<u8>,
        auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
        leaf_public_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        Self::with_params(
            db,
            sig_key,
            vrf_key,
            auditor_keys,
            leaf_public_key,
            ServerParams::default(),
        )
        .await
    }

    pub async fn with_params(
        db: Arc<dyn TransparencyStore>,
        sig_key: ServiceSigningKey,
        vrf_key: Vec<u8>,
        auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
        leaf_public_key: Option<Vec<u8>>,
        params: ServerParams,
    ) -> Result<Self> {
        let mode = if !auditor_keys.is_empty() {
            DEPLOYMENT_MODE_THIRD_PARTY_AUDITING
        } else {
            DEPLOYMENT_MODE_CONTACT_MONITORING
        };

        // Determine cipher suite from key type
        let suite = match &sig_key {
            ServiceSigningKey::Ed25519(_) => CIPHER_SUITE_KT_128_SHA256_ED25519,
            ServiceSigningKey::P256(_) => CIPHER_SUITE_KT_128_SHA256_P256,
        };

        let config = PrivateConfig::new(
            suite,
            mode,
            sig_key,
            vrf_key,
            auditor_keys.clone(),
            params.max_ahead,
            params.max_behind,
            params.reasonable_monitoring_window,
            params.maximum_lifetime,
            leaf_public_key,
            params.max_response_entries,
        )
        .context("Failed to initialize cryptographic configuration")?;

        let tree = Tree::new(db.clone(), &config).await?;
        let tree_arc = Arc::new(RwLock::new(tree)); // CHANGED: Instantiating RwLock

        let batcher = Arc::new(Batcher::new(tree_arc.clone()));

        Ok(Self {
            db,
            config,
            auditor_keys: Arc::new(auditor_keys),
            batcher,
            tree: tree_arc,
            access_policy: Arc::new(AllowAll),
        })
    }

    pub fn set_access_policy(&mut self, policy: Arc<dyn AccessPolicy>) {
        self.access_policy = policy;
    }
}

#[tonic::async_trait]
impl KeyTransparencyService for KeyTransparencyImpl {
    async fn tree_size(&self, _request: Request<()>) -> Result<Response<TreeSizeResponse>, Status> {
        let tree_guard = self.tree.read().await; // CHANGED: Read lock
        let size = tree_guard
            .latest
            .as_ref()
            .map(|th| th.tree_size)
            .unwrap_or(0);

        Ok(Response::new(TreeSizeResponse { tree_size: size }))
    }

    async fn audit(
        &self,
        request: Request<AuditRequest>,
    ) -> Result<Response<AuditResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await; // CHANGED: Read lock

        let (updates, more) = tree_guard
            .audit(req.start, req.limit)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(AuditResponse { updates, more }))
    }

    async fn audit_bootstrap(
        &self,
        _request: Request<()>,
    ) -> Result<Response<AuditBootstrapResponse>, Status> {
        let tree_guard = self.tree.read().await;

        let th = tree_guard
            .latest
            .clone()
            .ok_or_else(|| Status::failed_precondition("Empty tree"))?;
        let tree_size = th.tree_size;

        let mut log_peaks = Vec::new();
        for node in crate::tree::log_math::get_roots(tree_size) {
            log_peaks.push(
                tree_guard
                    .log
                    .resolve_node_simple(node, tree_size)
                    .map_err(map_anyhow_to_status)?,
            );
        }
        let prefix_root = tree_guard
            .log
            .get_prefix_root(tree_size - 1)
            .map_err(map_anyhow_to_status)?;
        let timestamp = tree_guard
            .log
            .get_timestamp(tree_size - 1)
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(AuditBootstrapResponse {
            tree_head: Some(th),
            log_peaks,
            prefix_root,
            timestamp,
        }))
    }

    async fn set_auditor_head(
        &self,
        request: Request<AuditorTreeHead>,
    ) -> Result<Response<()>, Status> {
        let head = request.into_inner();
        let mut tree_guard = self.tree.write().await; // CHANGED: Write lock (Requires exclusive access)

        tree_guard
            .set_auditor_head(head, &self.auditor_keys)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(()))
    }

    async fn search(
        &self,
        request: Request<SearchRequest>,
    ) -> Result<Response<SearchResponse>, Status> {
        let req = request.into_inner();
        if !self.access_policy.allow_search(&req.label) {
            return Err(Status::permission_denied(
                "Search not permitted for this label",
            ));
        }
        let tree_guard = self.tree.read().await; // CHANGED: Read lock

        let resp = tree_guard
            .search(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn update(
        &self,
        request: Request<UpdateRequest>,
    ) -> Result<Response<UpdateResponse>, Status> {
        let req = request.into_inner();
        if !self.access_policy.allow_update(&req.label) {
            return Err(Status::permission_denied(
                "Update not permitted for this label",
            ));
        }
        // The batcher handles taking the write lock internally when the batch is ready
        let resp = self
            .batcher
            .submit(req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn contact_monitor(
        &self,
        request: Request<ContactMonitorRequest>,
    ) -> Result<Response<ContactMonitorResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard
            .contact_monitor(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn owner_init(
        &self,
        request: Request<OwnerInitRequest>,
    ) -> Result<Response<OwnerInitResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard
            .owner_init(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn owner_monitor(
        &self,
        request: Request<OwnerMonitorRequest>,
    ) -> Result<Response<OwnerMonitorResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard
            .owner_monitor(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn distinguished(
        &self,
        request: Request<DistinguishedRequest>,
    ) -> Result<Response<DistinguishedResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard
            .distinguished(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn get_credential(
        &self,
        request: Request<GetCredentialRequest>,
    ) -> Result<Response<Credential>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await; // CHANGED: Read lock

        let cred = tree_guard
            .get_credential(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(cred))
    }

    async fn get_credential_update(
        &self,
        request: Request<GetCredentialUpdateRequest>,
    ) -> Result<Response<CredentialUpdate>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let update = tree_guard
            .get_credential_update(&req)
            .await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(update))
    }
}
// End src/service.rs
