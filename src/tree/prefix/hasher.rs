use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};

pub const INDEX_LENGTH: usize = 32;
pub const ZERO_VALUE: [u8; 32] = [0u8; 32];

pub fn get_bit(data: &[u8], n: usize) -> u8 {
    (data[n / 8] >> (7 - (n % 8))) & 1
}

// §11.9
pub fn leaf_hash(vrf_output: &[u8], commitment: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&[0x02]);
    h.update(vrf_output);
    h.update(commitment);
    h.finalize().to_vec()
}

// §11.9
pub fn parent_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&[0x03]);
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}

pub fn compute_seed(aes_key: &[u8], ctr: u64) -> Vec<u8> {
    let key = GenericArray::from_slice(aes_key);
    let cipher = Aes256::new(key);
    
    let mut block = [0u8; 16]; 
    let ctr_bytes = ctr.to_be_bytes();
    block[8..16].copy_from_slice(&ctr_bytes);
    
    let mut block_arr = GenericArray::from(block);
    cipher.encrypt_block(&mut block_arr);
    block_arr.as_slice().to_vec()
}