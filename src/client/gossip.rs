use crate::crypto::{PublicConfig, ServiceVerifyingKey, construct_tree_head_tbs_public, verify_data};
use crate::proto::transparency::TreeHead;
use anyhow::{Result, anyhow, Context};
use prost::Message;

/// A signed head bundled for exchange over an anonymous or peer-to-peer channel
/// (architecture §3.3): enough for anyone to re-verify the operator's signature.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct GossipHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub tree_head: String,
}

/// Two valid operator signatures over different roots for the same tree size:
/// self-contained, non-repudiable proof of a fork.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ForkEvidence {
    pub tree_size: u64,
    pub root_a: String,
    pub head_a: String,
    pub root_b: String,
    pub head_b: String,
}

pub enum GossipOutcome {
    Consistent,
    // TODO: comparable once historical roots at distinguished heads are retained (§10.2)
    Inconclusive,
    Fork(ForkEvidence),
}

impl GossipHead {
    pub fn new(tree_size: u64, root_hash: &[u8], head: &TreeHead) -> Self {
        let mut buf = Vec::new();
        head.encode(&mut buf).expect("prost encoding is infallible for TreeHead");
        Self {
            tree_size,
            root_hash: hex::encode(root_hash),
            tree_head: hex::encode(buf),
        }
    }

    pub fn decode_head(&self) -> Result<TreeHead> {
        let bytes = hex::decode(&self.tree_head)?;
        Ok(TreeHead::decode(&bytes[..])?)
    }
}

pub fn verify_gossip_head(config: &PublicConfig, gossip: &GossipHead) -> Result<()> {
    let head = gossip.decode_head()?;
    if head.tree_size != gossip.tree_size {
        return Err(anyhow!("Gossiped head tree size mismatch"));
    }
    let root = hex::decode(&gossip.root_hash)?;
    let tbs = construct_tree_head_tbs_public(config, gossip.tree_size, &root)?;
    let pk = ServiceVerifyingKey::from_bytes(&config.server_sig_pk)?;
    head.signatures.iter()
        .find(|sig| verify_data(&pk, &tbs, &sig.signature).is_ok())
        .map(|_| ())
        .ok_or_else(|| anyhow!("No valid operator signature on gossiped head"))
}

/// Verifiable by any third party from the configuration alone.
pub fn verify_fork_evidence(config: &PublicConfig, evidence: &ForkEvidence) -> Result<()> {
    if evidence.root_a == evidence.root_b {
        return Err(anyhow!("Evidence roots are identical: no fork"));
    }
    for (root, head) in [(&evidence.root_a, &evidence.head_a), (&evidence.root_b, &evidence.head_b)] {
        let gossip = GossipHead {
            tree_size: evidence.tree_size,
            root_hash: root.clone(),
            tree_head: head.clone(),
        };
        verify_gossip_head(config, &gossip)
            .context("Fork evidence signature verification failed")?;
    }
    Ok(())
}
