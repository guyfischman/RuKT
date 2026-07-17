use super::tls::{FixedOpaque, Opaqueu8, Opaqueu16, Opaqueu32, TlsEncode};
use anyhow::Result;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

// §11.6
const KC: [u8; 16] = [
    0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97, 0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
];

// §11.6
pub fn generate_random_opening() -> Vec<u8> {
    let mut buf = vec![0u8; 16]; // Nc = 16
    OsRng.fill_bytes(&mut buf);
    buf
}

// §11.6
pub fn commit(
    label: &[u8],
    version: u32,
    update_value: &[u8],
    suffix_signature: Option<&[u8]>,
    opening: &[u8],
) -> Result<Vec<u8>> {
    if opening.len() != 16 {
        return Err(anyhow::anyhow!("Invalid opening length"));
    }

    let mut commitment_value = Vec::new();
    FixedOpaque(opening).tls_encode(&mut commitment_value);
    Opaqueu8::new(label)?.tls_encode(&mut commitment_value);
    version.tls_encode(&mut commitment_value);
    Opaqueu32::new(update_value)?.tls_encode(&mut commitment_value);
    // §11.5: UpdateSuffix carries the operator signature in third-party-management
    // mode and serializes to zero bytes in every other mode
    if let Some(sig) = suffix_signature {
        Opaqueu16::new(sig)?.tls_encode(&mut commitment_value);
    }

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&KC)?;
    mac.update(&commitment_value);
    Ok(mac.finalize().into_bytes().to_vec())
}

// Section 10.8: Log Tree Leaf
// Hash(timestamp || prefix_tree_root)
// timestamp: uint64 (8 bytes big endian)
// prefix_tree_root: 32 bytes
pub fn log_leaf_value(timestamp: u64, prefix_root: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(timestamp.to_be_bytes());
    h.update(prefix_root);
    h.finalize().to_vec()
}

// Section 10.8: Log Tree Parent
// Hash(hashContent(left) || hashContent(right))
// hashContent(leaf) = 0x00 || value
// hashContent(parent) = 0x01 || value
pub fn log_parent_value(
    left: &[u8],
    left_is_leaf: bool,
    right: &[u8],
    right_is_leaf: bool,
) -> Vec<u8> {
    let mut h = Sha256::new();

    if left_is_leaf {
        h.update([0x00]);
    } else {
        h.update([0x01]);
    }
    h.update(left);

    if right_is_leaf {
        h.update([0x00]);
    } else {
        h.update([0x01]);
    }
    h.update(right);

    h.finalize().to_vec()
}
