pub mod hash;
pub mod signing;
pub mod tls;
pub mod vrf;

use self::tls::{Opaqueu8, TlsEncode};
use anyhow::{Context, Result, anyhow};
use rand::rngs::OsRng;
use std::collections::HashMap;

// Re-export specific items from submodules to keep cleaner namespaces
pub use self::hash::{commit, generate_random_opening, log_leaf_value, log_parent_value};
pub use self::signing::{
    ServiceSigningKey, ServiceVerifyingKey, construct_auditor_tree_head_tbs,
    construct_auditor_tree_head_tbs_public, construct_tree_head_tbs,
    construct_tree_head_tbs_public, construct_update_tbs, generate_p256_keypair,
    generate_sig_keypair, sign_data, verify_data,
};
pub use self::vrf::{VrfContext, ecvrf_prove, ecvrf_verify, expand_vrf_secret, get_public_key};

pub const DEPLOYMENT_MODE_CONTACT_MONITORING: u8 = 1;
pub const DEPLOYMENT_MODE_THIRD_PARTY_MANAGEMENT: u8 = 2;
pub const DEPLOYMENT_MODE_THIRD_PARTY_AUDITING: u8 = 3;

// IANA Registry Values (Draft-03 Section 15.1)
pub const CIPHER_SUITE_KT_128_SHA256_P256: u16 = 0x0001;
pub const CIPHER_SUITE_KT_128_SHA256_ED25519: u16 = 0x0002;

#[derive(Clone)]
pub struct PrivateConfig {
    pub cipher_suite: u16,
    pub mode: u8,
    pub sig_key: ServiceSigningKey,
    pub vrf_key: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
    pub vrf_ctx: VrfContext,
    pub prefix_aes_key: Vec<u8>,
    pub auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
    pub auditor_public_key: Option<Vec<u8>>,
    pub auditor_start_pos: u64,
    pub max_auditor_lag: u64,

    pub max_ahead: u64,
    pub max_behind: u64,
    pub reasonable_monitoring_window: u64,
    pub maximum_lifetime: Option<u64>,

    pub leaf_public_key: Option<Vec<u8>>,

    // Pagination limit for Monitor responses
    pub max_response_entries: usize,
}

#[derive(Clone)]
pub struct PublicConfig {
    pub cipher_suite: u16,
    pub mode: u8,
    pub server_sig_pk: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
    pub leaf_public_key: Option<Vec<u8>>,
    pub auditor_public_key: Option<Vec<u8>>,
    pub auditor_start_pos: u64,
    pub max_auditor_lag: u64,
    pub max_ahead: u64,
    pub max_behind: u64,
    pub reasonable_monitoring_window: u64,
    pub maximum_lifetime: Option<u64>,
}

impl PrivateConfig {
    pub fn new(
        cipher_suite: u16,
        mode: u8,
        sig_key: ServiceSigningKey,
        vrf_key: Vec<u8>,
        auditor_keys: HashMap<Vec<u8>, ServiceVerifyingKey>,
        max_ahead: u64,
        max_behind: u64,
        reasonable_monitoring_window: u64,
        maximum_lifetime: Option<u64>,
        leaf_public_key: Option<Vec<u8>>,
        max_response_entries: usize,
    ) -> Result<Self> {
        match cipher_suite {
            CIPHER_SUITE_KT_128_SHA256_ED25519 => {
                if !matches!(sig_key, ServiceSigningKey::Ed25519(_)) {
                    return Err(anyhow!(
                        "Cipher suite mismatch: Expected Ed25519 signing key"
                    ));
                }
            }
            CIPHER_SUITE_KT_128_SHA256_P256 => {
                if !matches!(sig_key, ServiceSigningKey::P256(_)) {
                    return Err(anyhow!("Cipher suite mismatch: Expected P-256 signing key"));
                }
            }
            _ => return Err(anyhow!("Unsupported cipher suite")),
        }

        let vrf_ctx =
            expand_vrf_secret(cipher_suite, &vrf_key).context("Failed to expand VRF secret")?;

        let vrf_pk = match &vrf_ctx {
            VrfContext::Ed25519 { y_bytes, .. } => y_bytes.to_vec(),
            VrfContext::P256 { y_bytes, .. } => y_bytes.clone(),
        };

        // single-auditor deployments: pick the smallest key for a deterministic TBS
        let auditor_public_key = {
            let mut keys: Vec<&Vec<u8>> = auditor_keys.keys().collect();
            keys.sort();
            keys.first().map(|k| (*k).clone())
        };

        Ok(Self {
            cipher_suite,
            mode,
            sig_key,
            vrf_key,
            vrf_public_key: vrf_pk,
            vrf_ctx,
            prefix_aes_key: vec![0u8; 32],
            auditor_keys,
            auditor_public_key,
            auditor_start_pos: 0,
            max_auditor_lag: 60_000,
            max_ahead,
            max_behind,
            reasonable_monitoring_window,
            maximum_lifetime,
            leaf_public_key,
            max_response_entries,
        })
    }

    pub fn vrf_prove(&self, label: &[u8], version: u32) -> Result<([u8; 32], Vec<u8>)> {
        let input = construct_vrf_input(label, version)?;
        vrf::ecvrf_prove(&self.vrf_ctx, &input)
    }
}

// pre-distributed over a trustworthy channel (architecture §2)
#[derive(serde::Serialize, serde::Deserialize)]
struct PublicConfigArtifact {
    cipher_suite: u16,
    mode: u8,
    server_sig_pk: String,
    vrf_public_key: String,
    leaf_public_key: Option<String>,
    auditor_public_key: Option<String>,
    auditor_start_pos: u64,
    max_auditor_lag: u64,
    max_ahead: u64,
    max_behind: u64,
    reasonable_monitoring_window: u64,
    maximum_lifetime: Option<u64>,
}

impl PublicConfig {
    pub fn to_json(&self) -> Result<String> {
        let artifact = PublicConfigArtifact {
            cipher_suite: self.cipher_suite,
            mode: self.mode,
            server_sig_pk: hex::encode(&self.server_sig_pk),
            vrf_public_key: hex::encode(&self.vrf_public_key),
            leaf_public_key: self.leaf_public_key.as_ref().map(hex::encode),
            auditor_public_key: self.auditor_public_key.as_ref().map(hex::encode),
            auditor_start_pos: self.auditor_start_pos,
            max_auditor_lag: self.max_auditor_lag,
            max_ahead: self.max_ahead,
            max_behind: self.max_behind,
            reasonable_monitoring_window: self.reasonable_monitoring_window,
            maximum_lifetime: self.maximum_lifetime,
        };
        Ok(serde_json::to_string_pretty(&artifact)?)
    }

    pub fn from_json(data: &str) -> Result<Self> {
        let a: PublicConfigArtifact = serde_json::from_str(data)?;
        Ok(Self {
            cipher_suite: a.cipher_suite,
            mode: a.mode,
            server_sig_pk: hex::decode(&a.server_sig_pk)?,
            vrf_public_key: hex::decode(&a.vrf_public_key)?,
            leaf_public_key: a.leaf_public_key.map(|k| hex::decode(&k)).transpose()?,
            auditor_public_key: a.auditor_public_key.map(|k| hex::decode(&k)).transpose()?,
            auditor_start_pos: a.auditor_start_pos,
            max_auditor_lag: a.max_auditor_lag,
            max_ahead: a.max_ahead,
            max_behind: a.max_behind,
            reasonable_monitoring_window: a.reasonable_monitoring_window,
            maximum_lifetime: a.maximum_lifetime,
        })
    }
}

pub fn generate_vrf_keypair(suite: u16) -> (Vec<u8>, Vec<u8>) {
    match suite {
        CIPHER_SUITE_KT_128_SHA256_P256 => {
            let sk = p256::SecretKey::random(&mut OsRng);
            let pk = sk.public_key();
            let sec_bytes = sk.to_bytes().to_vec();
            let pk_bytes = pk.to_sec1_bytes().to_vec();
            (sec_bytes, pk_bytes)
        }
        _ => {
            let mut csprng = OsRng;
            let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
            let seed = sk.to_bytes().to_vec();
            let pk = sk.verifying_key().to_bytes().to_vec();
            (seed, pk)
        }
    }
}

pub fn construct_vrf_input(label: &[u8], version: u32) -> Result<Vec<u8>> {
    if label.len() >= 256 {
        return Err(anyhow!("Label too long for VRF Input"));
    }
    let mut buf = Vec::new();
    Opaqueu8(label).tls_encode(&mut buf);
    version.tls_encode(&mut buf);
    Ok(buf)
}
