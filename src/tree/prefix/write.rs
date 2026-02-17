use crate::proto::prefix_tree::{LogEntry, LeafNode};
use crate::tree::prefix::{StepResult, PrefixTree, SearchResult};
use super::entry::CachedLogEntry;
use anyhow::Result;
use std::collections::HashMap;
use prost::Message;

impl PrefixTree {
    /// Applies a batch of updates, producing a sequence of new Prefix Tree versions.
    /// Returns:
    /// - List of Root Hashes for each update (intermediate + final)
    /// - List of SearchResults for each update
    /// - The final version pointer (u64)
    pub async fn batch_insert(
        &self, 
        start_version: u64, // The next available version ID for allocation
        current_root_ptr: Option<u64>, // Pointer to current Prefix Tree Root (None if empty)
        entries: &[(Vec<u8>, Vec<u8>)]
    ) -> Result<(Vec<Vec<u8>>, Vec<SearchResult>, u64)> {
        
        let mut current_ptr = current_root_ptr;
        let mut alloc_version = start_version;
        
        let mut db_batch = Vec::new();
        let mut roots = Vec::new();
        let mut search_results = Vec::new();
        
        // Overlay for uncommitted nodes in this batch
        let mut overlay: HashMap<u64, Vec<u8>> = HashMap::new();

        for (index, commitment) in entries {
            let (root, search_res, (pos, data)) = self.insert_internal(
                alloc_version, 
                current_ptr,
                index, 
                commitment, 
                &overlay
            ).await?;
            
            db_batch.push((pos, data.clone()));
            overlay.insert(pos, data);
            
            roots.push(root);
            search_results.push(search_res);
            
            current_ptr = Some(pos);
            alloc_version += 1;
        }

        self.store.put_prefix_batch(db_batch)?;

        // Return: roots, results, and the ID of the *final* root node
        Ok((roots, search_results, current_ptr.unwrap_or(0)))
    }

    pub(crate) async fn insert_internal(
        &self, 
        new_pos: u64, // Allocated ID for new node
        current_ptr: Option<u64>, // Pointer to previous root
        index: &[u8], 
        commitment: &[u8],
        overlay: &HashMap<u64, Vec<u8>>
    ) -> Result<(Vec<u8>, SearchResult, (u64, Vec<u8>))> {
        
        let mut copath = Vec::new();
        let mut current_ctr = 0;

        if let Some(ptr) = current_ptr {
            let mut curr = ptr;
            loop {
                let raw_entry = self.get_entry_bytes(curr, overlay)?;
                let entry = LogEntry::decode(&raw_entry[..])?;
                let cached = CachedLogEntry::new(entry, self.aes_key.clone());

                match self.step(index, curr, &mut copath, &cached) {
                    StepResult::Found(final_entry) => {
                        let leaf = final_entry.inner.leaf.as_ref().unwrap();
                        current_ctr = leaf.ctr + 1;
                        copath = final_entry.inner.copath;
                        break;
                    },
                    StepResult::Continue(next_ptr) => {
                        curr = next_ptr;
                    },
                    StepResult::Failed(failed_copath, _) => {
                        copath = failed_copath;
                        break;
                    }
                }
            }
        }

        let new_entry = LogEntry {
            index: index.to_vec(),
            copath: copath.clone(),
            first_update_position: new_pos,
            leaf: Some(LeafNode {
                ctr: current_ctr,
                commitment: commitment.to_vec(),
            }),
            precomputed32: vec![],
        };

        let mut buf = Vec::new();
        new_entry.encode(&mut buf)?;
        
        let cached_new = CachedLogEntry::new(new_entry, self.aes_key.clone());
        let root = cached_new.rollup(0);

        let search_result = SearchResult {
            log_position: new_pos, // Note: SearchResult still calls it log_position, but it is now the Prefix Ptr
            commitment: commitment.to_vec(),
            inclusion_proof: copath.iter().map(|n| n.hash.clone()).collect(),
            counter: current_ctr,
            depth: copath.len() as u32,
        };

        Ok((root, search_result, (new_pos, buf)))
    }
}