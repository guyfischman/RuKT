use super::Tree;
use crate::proto::transparency::{
    MonitorRequest, MonitorResponse
};
use anyhow::Result;

impl Tree {
    pub async fn monitor(&self, req: &MonitorRequest) -> Result<MonitorResponse> {
        let tree_size = if let Some(th) = &self.latest {
            th.tree_size
        } else {
            0
        };

        if tree_size == 0 {
             return Ok(MonitorResponse {
                 tree_head: Some(self.get_full_tree_head(None)?),
                 label_versions: vec![],
                 monitor: Some(crate::proto::transparency::CombinedTreeProof::default()),
             });
        }

        // Delegate to unified traversal
        let (combined_proof, label_versions) = self.traverse_monitoring(tree_size, req).await?;

        let fth = self.get_full_tree_head(req.consistency.clone())?;

        Ok(MonitorResponse {
            tree_head: Some(fth),
            label_versions,
            monitor: Some(combined_proof),
        })
    }
}