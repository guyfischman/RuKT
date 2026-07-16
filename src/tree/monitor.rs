use super::Tree;
use crate::proto::transparency::{
    ContactMonitorRequest, ContactMonitorResponse,
    OwnerInitRequest, OwnerInitResponse,
    OwnerMonitorRequest, OwnerMonitorResponse,
    Consistency, MonitorMapEntry,
};
use crate::tree::errors::KtError;
use anyhow::Result;

impl Tree {
    fn monitored_tree_size(&self) -> Result<u64> {
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        if tree_size == 0 {
            return Err(anyhow::Error::new(KtError::InvalidArgument(
                "Cannot monitor an empty tree".into(),
            )));
        }
        Ok(tree_size)
    }

    // §13.2
    fn validate_monitor_entries(entries: &[MonitorMapEntry], tree_size: u64) -> Result<()> {
        let mut prev: Option<u64> = None;
        for entry in entries {
            if entry.position >= tree_size {
                return Err(anyhow::Error::new(KtError::InvalidArgument(
                    format!("Entry position {} outside tree of size {}", entry.position, tree_size),
                )));
            }
            if let Some(p) = prev {
                if entry.position <= p {
                    return Err(anyhow::Error::new(KtError::InvalidArgument(
                        "Entries must be sorted ascending by position without duplicates".into(),
                    )));
                }
            }
            prev = Some(entry.position);
        }
        Ok(())
    }

    pub async fn contact_monitor(&self, req: &ContactMonitorRequest) -> Result<ContactMonitorResponse> {
        let tree_size = self.monitored_tree_size()?;
        Self::validate_monitor_entries(&req.entries, tree_size)?;

        let proof = self.traverse_contact_monitoring(
            tree_size, &req.label, &req.entries, req.last.unwrap_or(0),
        ).await?;
        let fth = self.get_full_tree_head(Some(Consistency { last: req.last, distinguished: None }))?;

        Ok(ContactMonitorResponse {
            full_tree_head: Some(fth),
            monitor: Some(proof),
        })
    }

    pub async fn owner_init(&self, req: &OwnerInitRequest) -> Result<OwnerInitResponse> {
        let tree_size = self.monitored_tree_size()?;
        if req.start >= tree_size {
            return Err(anyhow::Error::new(KtError::InvalidArgument(
                format!("Start position {} outside tree of size {}", req.start, tree_size),
            )));
        }
        // TODO: verify start is unexpired and distinguished (§13.3)

        let (proof, binary_ladder, greatest_versions) = self.traverse_owner_init(
            tree_size, &req.label, req.start, req.last.unwrap_or(0),
        ).await?;
        let fth = self.get_full_tree_head(Some(Consistency { last: req.last, distinguished: None }))?;

        Ok(OwnerInitResponse {
            full_tree_head: Some(fth),
            greatest_versions,
            binary_ladder,
            init: Some(proof),
        })
    }

    pub async fn owner_monitor(&self, req: &OwnerMonitorRequest) -> Result<OwnerMonitorResponse> {
        let tree_size = self.monitored_tree_size()?;
        Self::validate_monitor_entries(&req.entries, tree_size)?;
        if req.start >= tree_size {
            return Err(anyhow::Error::new(KtError::InvalidArgument(
                format!("Start position {} outside tree of size {}", req.start, tree_size),
            )));
        }
        // §13.4
        if let Some(claimed) = req.greatest_version {
            let actual = self.store.get_label_history(&req.label)?.last().map(|(v, _)| *v);
            if actual.map_or(true, |a| claimed > a) {
                return Err(anyhow::Error::new(KtError::InvalidArgument(
                    "greatest_version exceeds the label's actual greatest version".into(),
                )));
            }
        }

        let proof = self.traverse_owner_monitor(
            tree_size, &req.label, &req.entries, req.start, req.last.unwrap_or(0),
        ).await?;
        let fth = self.get_full_tree_head(Some(Consistency { last: req.last, distinguished: None }))?;

        Ok(OwnerMonitorResponse {
            full_tree_head: Some(fth),
            monitor: Some(proof),
        })
    }
}
