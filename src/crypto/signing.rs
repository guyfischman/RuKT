use ed25519_dalek::{Signer, Verifier, Signature as EdSignature};
use p256::ecdsa::{
    SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey, 
    signature::Signer as P256Signer, signature::Verifier as P256Verifier, 
    Signature as P256Signature
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use anyhow::{Result, anyhow};
use super::{PrivateConfig, PublicConfig};
use super::tls::{TlsEncode, Opaqueu16, Opaqueu32, Opaqueu8, FixedOpaque};

#[derive(Clone)]
pub enum ServiceSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(P256SigningKey),
}

#[derive(Clone)]
pub enum ServiceVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(P256VerifyingKey),
}

impl ServiceSigningKey {
    pub fn verifying_key(&self) -> ServiceVerifyingKey {
        match self {
            ServiceSigningKey::Ed25519(k) => ServiceVerifyingKey::Ed25519(k.verifying_key()),
            ServiceSigningKey::P256(k) => ServiceVerifyingKey::P256(*k.verifying_key()),
        }
    }
}

impl ServiceVerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ServiceVerifyingKey::Ed25519(k) => k.to_bytes().to_vec(),
            ServiceVerifyingKey::P256(k) => k.to_encoded_point(true).as_bytes().to_vec(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == 32 {
            let k = ed25519_dalek::VerifyingKey::from_bytes(bytes.try_into()?)
                .map_err(|_| anyhow!("Invalid Ed25519 key bytes"))?;
            Ok(ServiceVerifyingKey::Ed25519(k))
        } else if bytes.len() == 33 {
            let k = P256VerifyingKey::from_sec1_bytes(bytes)
                .map_err(|_| anyhow!("Invalid P-256 key bytes"))?;
            Ok(ServiceVerifyingKey::P256(k))
        } else {
             Err(anyhow!("Unknown key format length: {}", bytes.len()))
        }
    }
}

pub fn generate_sig_keypair() -> (ServiceSigningKey, ServiceVerifyingKey) {
    let mut csprng = OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
    let vk = sk.verifying_key();
    (ServiceSigningKey::Ed25519(sk), ServiceVerifyingKey::Ed25519(vk))
}

pub fn generate_p256_keypair() -> (ServiceSigningKey, ServiceVerifyingKey) {
    let sk = P256SigningKey::random(&mut OsRng);
    let vk = *sk.verifying_key();
    (ServiceSigningKey::P256(sk), ServiceVerifyingKey::P256(vk))
}

// Section 10.2: Configuration Structure
fn serialize_configuration(
    config: &PrivateConfig,
    auditor_pk: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let server_sig_pk = config.sig_key.verifying_key().to_bytes();

    config.cipher_suite.tls_encode(&mut buf);
    config.mode.tls_encode(&mut buf);
    Opaqueu16(&server_sig_pk).tls_encode(&mut buf);
    Opaqueu16(&config.vrf_public_key).tls_encode(&mut buf);

    if config.mode == 3 { 
        0u64.tls_encode(&mut buf);
        0u64.tls_encode(&mut buf);
        if let Some(apk) = auditor_pk {
            Opaqueu16(apk).tls_encode(&mut buf);
        } else {
             return Err(anyhow!("Auditor public key required for ThirdPartyAuditing mode"));
        }
    } else {
        if let Some(lpk) = &config.leaf_public_key {
            Opaqueu16(lpk).tls_encode(&mut buf);
        } else {
             Opaqueu16(&[]).tls_encode(&mut buf);
        }
    }

    config.max_ahead.tls_encode(&mut buf);
    config.max_behind.tls_encode(&mut buf);
    config.reasonable_monitoring_window.tls_encode(&mut buf);
    
    if let Some(life) = config.maximum_lifetime {
        1u8.tls_encode(&mut buf); 
        life.tls_encode(&mut buf);
    } else {
        0u8.tls_encode(&mut buf); 
    }

    Ok(buf)
}

fn serialize_configuration_public(
    config: &PublicConfig,
    auditor_pk: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    config.cipher_suite.tls_encode(&mut buf);
    config.mode.tls_encode(&mut buf);
    Opaqueu16(&config.server_sig_pk).tls_encode(&mut buf);
    Opaqueu16(&config.vrf_public_key).tls_encode(&mut buf);

    if config.mode == 3 { // Auditing
         0u64.tls_encode(&mut buf);
         0u64.tls_encode(&mut buf);
         if let Some(apk) = auditor_pk {
             Opaqueu16(apk).tls_encode(&mut buf);
         } else {
              return Err(anyhow!("Auditor public key required for ThirdPartyAuditing mode"));
         }
    } else {
        if let Some(lpk) = &config.leaf_public_key {
            Opaqueu16(lpk).tls_encode(&mut buf);
        } else {
             Opaqueu16(&[]).tls_encode(&mut buf);
        }
    }

    config.max_ahead.tls_encode(&mut buf);
    config.max_behind.tls_encode(&mut buf);
    config.reasonable_monitoring_window.tls_encode(&mut buf);
    
    if let Some(life) = config.maximum_lifetime {
        1u8.tls_encode(&mut buf); 
        life.tls_encode(&mut buf);
    } else {
        0u8.tls_encode(&mut buf); 
    }
    Ok(buf)
}

pub fn construct_tree_head_tbs(
    config: &PrivateConfig,
    auditor_pk: Option<&[u8]>,
    tree_size: u64,
    root_hash: &[u8]
) -> Result<Vec<u8>> {
    let mut buf = serialize_configuration(config, auditor_pk)?;
    tree_size.tls_encode(&mut buf);
    if root_hash.len() != 32 { return Err(anyhow!("Root hash must be 32 bytes")); }
    FixedOpaque(root_hash).tls_encode(&mut buf);
    Ok(buf)
}

pub fn construct_auditor_tree_head_tbs(
    config: &PrivateConfig,
    auditor_pk: &[u8],
    tree_size: u64,
    timestamp: u64,
    root_hash: &[u8]
) -> Result<Vec<u8>> {
    let mut buf = serialize_configuration(config, Some(auditor_pk))?;
    timestamp.tls_encode(&mut buf);
    tree_size.tls_encode(&mut buf);
    if root_hash.len() != 32 { return Err(anyhow!("Root hash must be 32 bytes")); }
    FixedOpaque(root_hash).tls_encode(&mut buf);
    Ok(buf)
}

pub fn construct_auditor_tree_head_tbs_public(
    config: &PublicConfig,
    auditor_pk: &[u8],
    tree_size: u64,
    timestamp: u64,
    root_hash: &[u8]
) -> Result<Vec<u8>> {
    let mut buf = serialize_configuration_public(config, Some(auditor_pk))?;
    timestamp.tls_encode(&mut buf);
    tree_size.tls_encode(&mut buf);
    if root_hash.len() != 32 { return Err(anyhow!("Root hash must be 32 bytes")); }
    FixedOpaque(root_hash).tls_encode(&mut buf);
    Ok(buf)
}

pub fn construct_tree_head_tbs_public(
    config: &PublicConfig,
    auditor_pk: Option<&[u8]>,
    tree_size: u64,
    root_hash: &[u8]
) -> Result<Vec<u8>> {
    let mut buf = serialize_configuration_public(config, auditor_pk)?;
    tree_size.tls_encode(&mut buf);
    if root_hash.len() != 32 { return Err(anyhow!("Root hash must be 32 bytes")); }
    FixedOpaque(root_hash).tls_encode(&mut buf);
    Ok(buf)
}

pub fn construct_update_tbs(
    label: &[u8],
    version: u32,
    value: &[u8]
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if label.len() >= 1 << 8 { return Err(anyhow!("Label too long")); }
    Opaqueu8(label).tls_encode(&mut buf);
    version.tls_encode(&mut buf);
    if value.len() >= 1 << 32 { return Err(anyhow!("Value too long")); }
    Opaqueu32(value).tls_encode(&mut buf);
    Ok(buf)
}

pub fn sign_data(sk: &ServiceSigningKey, data: &[u8]) -> Vec<u8> {
    match sk {
        ServiceSigningKey::Ed25519(k) => k.sign(data).to_vec(),
        ServiceSigningKey::P256(k) => {
            let signature: P256Signature = k.sign(data);
            signature.to_bytes().to_vec()
        }
    }
}

pub fn verify_data(pk: &ServiceVerifyingKey, data: &[u8], signature_bytes: &[u8]) -> Result<()> {
    match pk {
        ServiceVerifyingKey::Ed25519(k) => {
            let sig = EdSignature::from_slice(signature_bytes)
                .map_err(|_| anyhow!("Invalid Ed25519 signature format"))?;
            k.verify(data, &sig).map_err(|_| anyhow!("Ed25519 Verification failed"))
        },
        ServiceVerifyingKey::P256(k) => {
            let sig = P256Signature::from_bytes(signature_bytes.into())
                .map_err(|_| anyhow!("Invalid P-256 signature format"))?;
            k.verify(data, &sig).map_err(|_| anyhow!("P-256 Verification failed"))
        }
    }
}