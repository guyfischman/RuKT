use super::Tree;
use anyhow::{Result, anyhow};

impl Tree {
    /// Right to erasure: the value and opening are unrecoverable immediately;
    /// the vrf output remains in historical prefix trees until expiry.
    pub fn erase(&self, label: &[u8], version: u32) -> Result<()> {
        let history = self.store.get_label_history(label)?;
        let pos = history.iter().find(|(v, _)| *v == version).map(|(_, p)| *p)
            .ok_or_else(|| anyhow!("Unknown label version"))?;
        self.store.delete_value(pos)?;
        self.store.delete_opening(pos)?;
        Ok(())
    }

    /// Drops the user data of non-greatest versions whose insertion log entry
    /// passed the maximum lifetime; their search proofs can no longer be served.
    pub fn prune_expired_versions(&self, label: &[u8]) -> Result<u64> {
        let Some(max_life) = self.config.maximum_lifetime else { return Ok(0) };
        let tree_size = self.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        if tree_size == 0 { return Ok(0); }
        let rightmost_ts = self.log.get_timestamp(tree_size - 1)?;

        let history = self.store.get_label_history(label)?;
        let Some(&(greatest, _)) = history.last() else { return Ok(0) };

        let mut pruned = 0u64;
        for &(version, pos) in &history {
            // the greatest version never expires through the lifetime mechanism
            if version == greatest { continue; }
            let entry = self.find_log_entry_for_prefix_pos(pos, tree_size)?;
            let ts = self.log.get_timestamp(entry)?;
            if rightmost_ts.saturating_sub(ts) >= max_life {
                self.store.delete_value(pos)?;
                self.store.delete_opening(pos)?;
                pruned += 1;
            }
        }
        Ok(pruned)
    }
}
