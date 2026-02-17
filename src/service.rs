use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::proto::kt::{AuditRequest, AuditResponse, TreeSizeResponse};
use crate::proto::transparency::{
    TreeSearchRequest, TreeSearchResponse, 
    SignedUpdateRequest, UpdateResponse, 
    MonitorRequest, MonitorResponse,
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
use tokio::sync::Mutex;
use anyhow::{Result, Context};

#[derive(Clone)]
pub struct KeyTransparencyImpl {
    pub db: Arc<dyn TransparencyStore>,
    pub config: PrivateConfig,
    pub auditor_keys: Arc<HashMap<Vec<u8>, ServiceVerifyingKey>>,
    pub batcher: Arc<Batcher>,
    pub tree: Arc<Mutex<Tree>>,
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
        let tree_arc = Arc::new(Mutex::new(tree));
        
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
        let tree_guard = self.tree.lock().await;
        let size = tree_guard.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        
        Ok(Response::new(TreeSizeResponse { tree_size: size }))
    }

    async fn audit(&self, request: Request<AuditRequest>) -> Result<Response<AuditResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.lock().await;

        let (updates, more) = tree_guard.audit(req.start, req.limit).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(AuditResponse { updates, more }))
    }

    async fn set_auditor_head(
        &self,
        request: Request<AuditorTreeHead>,
    ) -> Result<Response<()>, Status> {
        let head = request.into_inner();
        let mut tree_guard = self.tree.lock().await;

        tree_guard.set_auditor_head(head, &self.auditor_keys).await
            .map_err(map_anyhow_to_status)?;

        Ok(Response::new(()))
    }

    async fn search(&self, request: Request<TreeSearchRequest>) -> Result<Response<TreeSearchResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.lock().await;
            
        let resp = tree_guard.search(&req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(resp))
    }

    async fn update(&self, request: Request<SignedUpdateRequest>) -> Result<Response<UpdateResponse>, Status> {
        let req = request.into_inner();
        let resp = self.batcher.submit(req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(resp))
    }

    async fn monitor(&self, request: Request<MonitorRequest>) -> Result<Response<MonitorResponse>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.lock().await;
            
        let resp = tree_guard.monitor(&req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(resp))
    }
    
    async fn get_credential(&self, request: Request<GetCredentialRequest>) -> Result<Response<Credential>, Status> {
        let req = request.into_inner();
        let tree_guard = self.tree.lock().await;
        
        let cred = tree_guard.get_credential(&req).await
            .map_err(map_anyhow_to_status)?;
            
        Ok(Response::new(cred))
    }
}