pub mod vrf;
pub mod hash;
pub mod signing;
pub mod tls;

use anyhow::{Result, Context, anyhow};
use std::collections::HashMap;
use rand::rngs::OsRng;
use self::tls::{TlsEncode, Opaqueu8};

// Re-export specific items from submodules to keep cleaner namespaces
pub use self::vrf::{ecvrf_prove, ecvrf_verify, get_public_key, expand_vrf_secret, VrfContext};
pub use self::hash::{generate_random_opening, commit, log_leaf_value, log_parent_value}; 
pub use self::signing::{
    generate_sig_keypair, generate_p256_keypair, 
    construct_tree_head_tbs, construct_tree_head_tbs_public, construct_auditor_tree_head_tbs, construct_auditor_tree_head_tbs_public, construct_update_tbs,
    sign_data, verify_data,
    ServiceSigningKey, ServiceVerifyingKey 
};

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
                    return Err(anyhow!("Cipher suite mismatch: Expected Ed25519 signing key"));
                }
            },
            CIPHER_SUITE_KT_128_SHA256_P256 => {
                if !matches!(sig_key, ServiceSigningKey::P256(_)) {
                    return Err(anyhow!("Cipher suite mismatch: Expected P-256 signing key"));
                }
            },
            _ => return Err(anyhow!("Unsupported cipher suite")),
        }

        let vrf_ctx = expand_vrf_secret(cipher_suite, &vrf_key).context("Failed to expand VRF secret")?;
        
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

pub fn generate_vrf_keypair(suite: u16) -> (Vec<u8>, Vec<u8>) {
    match suite {
        CIPHER_SUITE_KT_128_SHA256_P256 => {
            let sk = p256::SecretKey::random(&mut OsRng);
            let pk = sk.public_key();
            let sec_bytes = sk.to_bytes().to_vec();
            let pk_bytes = pk.to_sec1_bytes().to_vec();
            (sec_bytes, pk_bytes)
        },
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