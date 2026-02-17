pub mod hasher;
pub mod entry;
pub mod read;
pub mod write;
pub mod audit;

use crate::db::TransparencyStore;
use std::sync::Arc;
use crate::proto::prefix_tree::ParentNode;

pub use self::entry::combine_copaths;
pub use self::read::SearchResult;

// Shared result type for traversal steps, used by read and write modules
#[derive(Debug)]
pub(crate) enum StepResult {
    Continue(u64),
    Found(self::entry::CachedLogEntry),
    Failed(Vec<ParentNode>, u64) 
}

pub struct PrefixTree {
    pub(crate) store: Arc<dyn TransparencyStore>,
    pub(crate) aes_key: Vec<u8>,
}

impl PrefixTree {
    pub fn new(store: Arc<dyn TransparencyStore>, aes_key: Vec<u8>) -> Self {
        if aes_key.len() != 32 {
            panic!("Prefix Tree AES key must be 32 bytes");
        }
        Self { store, aes_key }
    }
}