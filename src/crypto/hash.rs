use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use anyhow::Result;
use rand::{RngCore, rngs::OsRng};

// Draft 15.1: Kc = hex("d821f8790d97709796b4d7903357c3f5")
const KC: [u8; 16] = [
    0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
    0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5
];

// Section 10.6: Commitment Opening
// "The application generates a random Nc-byte value called opening"
pub fn generate_random_opening() -> Vec<u8> {
    let mut buf = vec![0u8; 16]; // Nc = 16
    OsRng.fill_bytes(&mut buf);
    buf
}

// Section 10.6: Commitment
// commitment = HMAC(Kc, CommitmentValue)
// CommitmentValue = opening || label || UpdateValue
pub fn commit(label: &[u8], update_value: &[u8], opening: &[u8]) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&KC)?;
    
    // 1. Opening (Nc=16)
    if opening.len() != 16 {
        return Err(anyhow::anyhow!("Invalid opening length"));
    }
    mac.update(opening);

    // 2. Label (opaque <0..2^8-1>)
    // TLS presentation: 1 byte length prefix
    if label.len() > 255 {
        return Err(anyhow::anyhow!("Label too long"));
    }
    mac.update(&(label.len() as u8).to_be_bytes());
    mac.update(label);

    // 3. UpdateValue
    // struct { UpdatePrefix prefix; opaque value<0..2^32-1>; }
    // Assuming ContactMonitoring (empty prefix).
    // TLS presentation for opaque value<0..2^32-1> is 4 byte length prefix.
    mac.update(&(update_value.len() as u32).to_be_bytes());
    mac.update(update_value);

    Ok(mac.finalize().into_bytes().to_vec())
}

// Section 10.8: Log Tree Leaf
// Hash(timestamp || prefix_tree_root)
// timestamp: uint64 (8 bytes big endian)
// prefix_tree_root: 32 bytes
pub fn log_leaf_value(timestamp: u64, prefix_root: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&timestamp.to_be_bytes());
    h.update(prefix_root);
    h.finalize().to_vec()
}

// Section 10.8: Log Tree Parent
// Hash(hashContent(left) || hashContent(right))
// hashContent(leaf) = 0x00 || value
// hashContent(parent) = 0x01 || value
pub fn log_parent_value(left: &[u8], left_is_leaf: bool, right: &[u8], right_is_leaf: bool) -> Vec<u8> {
    let mut h = Sha256::new();
    
    if left_is_leaf {
        h.update(&[0x00]);
    } else {
        h.update(&[0x01]);
    }
    h.update(left);

    if right_is_leaf {
        h.update(&[0x00]);
    } else {
        h.update(&[0x01]);
    }
    h.update(right);

    h.finalize().to_vec()
}