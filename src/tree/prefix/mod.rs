// src/tree/prefix/mod.rs
pub mod hasher;
pub mod entry;
pub mod read;
pub mod write;
pub mod audit;

use crate::db::TransparencyStore;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use crate::proto::prefix_tree::{ParentNode, LogEntry};
use dashmap::DashMap;
use self::entry::CachedLogEntry; // Import the struct

pub use self::entry::combine_copaths;
pub use self::read::SearchResult;

#[derive(Debug)]
pub(crate) enum StepResult {
    Continue(u64),
    Found(Arc<CachedLogEntry>), // Now returns the Cached wrapper
    Failed(Vec<ParentNode>, u64) 
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