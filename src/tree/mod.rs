pub mod log;
pub mod prefix;
pub mod log_math;
pub mod read;
pub mod write;
pub mod monitor;
pub mod audit;
pub mod binary_ladder;
pub mod credential;
pub mod errors;
pub mod traversal;
pub mod walker;

use crate::db::{TransparencyStore, AuditorTreeHead};
use crate::proto::transparency::{
    FullTreeHead, TreeHead,
};
use crate::crypto::PrivateConfig;
use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use prost::Message;

pub struct Tree {
    pub store: Arc<dyn TransparencyStore>,
    pub log: log::LogTree, 
    pub prefix: prefix::PrefixTree,
    pub config: PrivateConfig,
    pub latest: Option<TreeHead>,
    pub auditors: HashMap<std::string::String, AuditorTreeHead>,
}

#[derive(Clone)]
pub struct PreUpdateData {
    pub label: Vec<u8>,
    pub value: Vec<u8>,
    pub last: u64,
    pub version: u32,
    pub index: [u8; 32],
    pub vrf_proof: Vec<u8>,
    pub commitment: Vec<u8>,
    pub opening: Vec<u8>,
}

#[derive(Clone)]
pub struct PostUpdateData {
    pub tree_head: FullTreeHead,
    pub search_result: prefix::SearchResult,
}

impl Tree {
    pub async fn new(store: Arc<dyn TransparencyStore>, config: &PrivateConfig) -> Result<Self> {
        let head_bytes = store.get_head()?;
        let latest = if let Some(b) = head_bytes {
            Some(TreeHead::decode(&b[..])?)
        } else {
            None
        };

        let auditors = HashMap::new();

        Ok(Self {
            log: log::LogTree::new(store.clone()),
            prefix: prefix::PrefixTree::new(store.clone(), config.prefix_aes_key.clone()),
            store,
            config: config.clone(),
            latest,
            auditors,
        })
    }
}