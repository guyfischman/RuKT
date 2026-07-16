// Start src/service.rs
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::kt::{AuditRequest, AuditResponse, TreeSizeResponse};
use crate::proto::transparency::{
    SearchRequest, SearchResponse,
    UpdateRequest, UpdateResponse,
    ContactMonitorRequest, ContactMonitorResponse,
    OwnerInitRequest, OwnerInitResponse,
    OwnerMonitorRequest, OwnerMonitorResponse,
    DistinguishedRequest, DistinguishedResponse,
    AuditorTreeHead,
    GetCredentialRequest, Credential
};
use crate::db::TransparencyStore;
use crate::crypto::{
    PrivateConfig, ServiceSigningKey, ServiceVerifyingKey,
    DEPLOYMENT_MODE_CONTACT_MONITORING, 
    DEPLOYMENT_MODE_THIRD_PARTY_AUDITING,
    CIPHER_SUITE_KT_128_SHA256_ED25519,
    CIPHER_SUITE_KT_128_SHA256_P256
};
use crate::tree::Tree;
use crate::tree::errors::map_anyhow_to_status; 
use crate::batcher::Batcher;
use std::sync::Arc;
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use tokio::sync::RwLock; // CHANGED: Replaced Mutex with RwLock
use anyhow::{Result, Context};

#[derive(Clone)]
pub struct KeyTransparencyImpl {
    pub db: Arc<dyn TransparencyStore>,
    pub config: PrivateConfig,
    pub auditor_keys: Arc<HashMap<Vec<u8>, ServiceVerifyingKey>>,
    pub batcher: Arc<Batcher>,
    pub tree: Arc<RwLock<Tree>>, // CHANGED: Now using RwLock for high-concurrency reads
}

impl KeyTransparencyImpl {
    pub async fn new(
        db: Arc<dyn TransparencyStore>,
        sig_key: ServiceSigningKey,
        vrf_key: Vec<u8>,
        auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
        leaf_public_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let mode = if !auditor_keys.is_empty() {
            DEPLOYMENT_MODE_THIRD_PARTY_AUDITING
        } else {
            DEPLOYMENT_MODE_CONTACT_MONITORING
        };

        let max_ahead = 5000;
        let max_behind = 5000;
        let rmw = 86400000; 
        let maximum_lifetime = None; 
        let max_response_entries = 100; // Default limit for pagination

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
            max_ahead,
            max_behind,
            rmw,
            maximum_lifetime,
            leaf_public_key,
            max_response_entries
        ).context("Failed to initialize cryptographic configuration")?;

        let tree = Tree::new(db.clone(), &config).await?;
        let tree_arc = Arc::new(RwLock::new(tree)); // CHANGED: Instantiating RwLock
        
        let batcher = Arc::new(Batcher::new(tree_arc.clone()));

        Ok(Self {
            db,
            config,
            auditor_keys: Arc::new(auditor_keys),
            batcher,
            tree: tree_arc,
        })
    }
}

#[tonic::async_trait]
impl KeyTransparencyService for KeyTransparencyImpl {
    async fn tree_size(&self, _request: Request<()>) -> Result<Response<TreeSizeResponse>, Status> {
        let tree_guard = self.tree.read().await; // CHANGED: Read lock
        let size = tree_guard.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        
        Ok(Response::new(TreeSizeResponse { tree_size: size }))
    }

    async fn audit(&self, request: Request<AuditRequest>) -> Result<Response<AuditResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await; // CHANGED: Read lock

        let (updates, more) = tree_guard.audit(req.start, req.limit).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(AuditResponse { updates, more }))
    }

    async fn set_auditor_head(
        &self,
        request: Request<AuditorTreeHead>,
    ) -> Result<Response<()>, Status> {
        let head = request.into_inner();
        let mut tree_guard = self.tree.write().await; // CHANGED: Write lock (Requires exclusive access)

        tree_guard.set_auditor_head(head, &self.auditor_keys).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(()))
    }

    async fn search(&self, request: Request<SearchRequest>) -> Result<Response<SearchResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await; // CHANGED: Read lock
            
        let resp = tree_guard.search(&req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(resp))
    }

    async fn update(&self, request: Request<UpdateRequest>) -> Result<Response<UpdateResponse>, Status> {
        let req = request.into_inner();
        // The batcher handles taking the write lock internally when the batch is ready
        let resp = self.batcher.submit(req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(resp))
    }

    async fn contact_monitor(&self, request: Request<ContactMonitorRequest>) -> Result<Response<ContactMonitorResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard.contact_monitor(&req).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn owner_init(&self, request: Request<OwnerInitRequest>) -> Result<Response<OwnerInitResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard.owner_init(&req).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn owner_monitor(&self, request: Request<OwnerMonitorRequest>) -> Result<Response<OwnerMonitorResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard.owner_monitor(&req).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }

    async fn distinguished(&self, request: Request<DistinguishedRequest>) -> Result<Response<DistinguishedResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await;

        let resp = tree_guard.distinguished(&req).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(resp))
    }
    
    async fn get_credential(&self, request: Request<GetCredentialRequest>) -> Result<Response<Credential>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.read().await; // CHANGED: Read lock
        
        let cred = tree_guard.get_credential(&req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(cred))
    }
}
// End src/service.rs