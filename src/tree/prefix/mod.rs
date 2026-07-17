// src/tree/prefix/mod.rs
pub mod entry;
pub mod hasher;
pub mod read;
pub mod write;

use self::entry::CachedLogEntry;
use crate::db::TransparencyStore;
use crate::proto::prefix_tree::ParentNode;
use moka::sync::Cache;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

pub use self::entry::combine_copaths;
pub use self::read::SearchResult;

const NODE_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum StepResult {
    Continue(u64),
    Found(Arc<CachedLogEntry>), // Now returns the Cached wrapper
    Failed(Vec<ParentNode>),
}

#[derive(Clone)]
pub struct PrefixTree {
    pub(crate) store: Arc<dyn TransparencyStore>,
    pub(crate) node_cache: Cache<u64, Arc<CachedLogEntry>>,
    pub(crate) hits: Arc<AtomicU64>,
    pub(crate) misses: Arc<AtomicU64>,
    pub(crate) debug_hash_ops: Arc<AtomicU64>,
    pub(crate) debug_steps: Arc<AtomicU64>,
}

impl PrefixTree {
    pub fn new(store: Arc<dyn TransparencyStore>) -> Self {
        Self {
            store,
            node_cache: Cache::builder()
                .max_capacity(NODE_CACHE_MAX_BYTES)
                .weigher(|_, v: &Arc<CachedLogEntry>| v.max_resident_bytes() as u32)
                .build(),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            debug_hash_ops: Arc::new(AtomicU64::new(0)),
            debug_steps: Arc::new(AtomicU64::new(0)),
        }
    }
}
