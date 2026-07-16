// src/tree/prefix/mod.rs
pub mod audit;
pub mod entry;
pub mod hasher;
pub mod read;
pub mod write;

use self::entry::CachedLogEntry;
use crate::db::TransparencyStore;
use crate::proto::prefix_tree::ParentNode;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64; // Import the struct

pub use self::entry::combine_copaths;
pub use self::read::SearchResult;

#[derive(Debug)]
pub(crate) enum StepResult {
    Continue(u64),
    Found(Arc<CachedLogEntry>), // Now returns the Cached wrapper
    Failed(Vec<ParentNode>, u64),
}

#[derive(Clone)]
pub struct PrefixTree {
    pub(crate) store: Arc<dyn TransparencyStore>,
    pub(crate) aes_key: Vec<u8>,
    // CHANGED: Store CachedLogEntry directly
    pub(crate) node_cache: Arc<DashMap<u64, Arc<CachedLogEntry>>>,
    pub(crate) hits: Arc<AtomicU64>,
    pub(crate) misses: Arc<AtomicU64>,
    pub(crate) debug_hash_ops: Arc<AtomicU64>,
    pub(crate) debug_steps: Arc<AtomicU64>,
}

impl PrefixTree {
    pub fn new(store: Arc<dyn TransparencyStore>, aes_key: Vec<u8>) -> Self {
        if aes_key.len() != 32 {
            panic!("Prefix Tree AES key must be 32 bytes");
        }
        Self {
            store,
            aes_key,
            node_cache: Arc::new(DashMap::new()),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            debug_hash_ops: Arc::new(AtomicU64::new(0)),
            debug_steps: Arc::new(AtomicU64::new(0)),
        }
    }
}
