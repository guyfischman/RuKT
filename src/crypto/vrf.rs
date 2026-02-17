use sha2::{Sha512, Sha256, Digest};
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::IsIdentity;
use anyhow::{Result, anyhow};
use rand::{RngCore, rngs::OsRng};
use p256::{
    ProjectivePoint, Scalar as P256Scalar, 
    elliptic_curve::{
        group::{Group, GroupEncoding}, 
        sec1::{ToEncodedPoint, FromEncodedPoint},
        PrimeField,
        Field,
    }
};

use super::{CIPHER_SUITE_KT_128_SHA256_ED25519, CIPHER_SUITE_KT_128_SHA256_P256};

pub struct VrfConfig<'a> {
    pub suite_id: u16,
    pub secret_key: &'a [u8],
}

pub fn get_public_key(suite_id: u16, secret: &[u8]) -> Result<Vec<u8>> {
    match suite_id {
        CIPHER_SUITE_KT_128_SHA256_ED25519 => get_public_key_ed25519(secret),
        CIPHER_SUITE_KT_128_SHA256_P256 => get_public_key_p256(secret),
        _ => Err(anyhow!("Unsupported cipher suite")),
    }
}

pub fn ecvrf_prove(config: &VrfConfig, alpha: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    match config.suite_id {
        CIPHER_SUITE_KT_128_SHA256_ED25519 => ecvrf_prove_ed25519(config.secret_key, alpha),
        CIPHER_SUITE_KT_128_SHA256_P256 => ecvrf_prove_p256(config.secret_key, alpha),
        _ => Err(anyhow!("Unsupported cipher suite")),
    }
}

pub fn ecvrf_verify(suite_id: u16, pub_key: &[u8], alpha: &[u8], proof: &[u8]) -> Result<[u8; 32]> {
    match suite_id {
        CIPHER_SUITE_KT_128_SHA256_ED25519 => ecvrf_verify_ed25519(pub_key, alpha, proof),
        CIPHER_SUITE_KT_128_SHA256_P256 => ecvrf_verify_p256(pub_key, alpha, proof),
        _ => Err(anyhow!("Unsupported cipher suite")),
    }
}

// --- ED25519 Implementation ---

fn get_public_key_ed25519(seed: &[u8]) -> Result<Vec<u8>> {
    if seed.len() != 32 { return Err(anyhow!("Invalid Ed25519 seed length")); }
    
    let mut h = Sha512::new();
    h.update(seed);
    let hashed_sk = h.finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hashed_sk[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    
    let mut wide_scalar = [0u8; 64];
    wide_scalar[0..32].copy_from_slice(&scalar_bytes);
    let x = Scalar::from_bytes_mod_order_wide(&wide_scalar);

    let y_point: EdwardsPoint = &x * ED25519_BASEPOINT_TABLE;
    Ok(y_point.compress().to_bytes().to_vec())
}

fn ecvrf_prove_ed25519(seed: &[u8], alpha: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let mut h = Sha512::new();
    h.update(seed);
    let hashed_sk = h.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hashed_sk[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let mut wide_scalar = [0u8; 64];
    wide_scalar[0..32].copy_from_slice(&scalar_bytes);
    let x = Scalar::from_bytes_mod_order_wide(&wide_scalar);
    let y_point: EdwardsPoint = &x * ED25519_BASEPOINT_TABLE;
    let y_bytes = y_point.compress().to_bytes();

    let h_point = encode_to_curve_ed25519(&y_bytes, alpha);
    let h_bytes = h_point.compress().to_bytes();

    let gamma = x * h_point;
    let gamma_bytes = gamma.compress().to_bytes();

    let mut k_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut k_bytes);
    let nonce_scalar = Scalar::from_bytes_mod_order_wide(&k_bytes);

    let u_point: EdwardsPoint = &nonce_scalar * ED25519_BASEPOINT_TABLE;
    let u_bytes = u_point.compress().to_bytes();

    let v_point = nonce_scalar * h_point;
    let v_bytes = v_point.compress().to_bytes();

    let c_scalar = challenge_ed25519(&y_bytes, &h_bytes, &gamma_bytes, &u_bytes, &v_bytes);
    let c_bytes_16 = &c_scalar.to_bytes()[0..16];

    let s_scalar = nonce_scalar + (c_scalar * x);
    let s_bytes = s_scalar.to_bytes();

    let mut proof = Vec::with_capacity(80);
    proof.extend_from_slice(&gamma_bytes);
    proof.extend_from_slice(c_bytes_16);
    proof.extend_from_slice(&s_bytes);

    let output = proof_to_hash_ed25519(&gamma);
    Ok((output, proof))
}

fn ecvrf_verify_ed25519(pub_key: &[u8], alpha: &[u8], proof: &[u8]) -> Result<[u8; 32]> {
    if proof.len() != 80 { return Err(anyhow!("Invalid Ed25519 VRF proof length")); }
    let gamma_bytes = &proof[0..32];
    let c_bytes = &proof[32..48];
    let s_bytes = &proof[48..80];

    let gamma = CompressedEdwardsY::from_slice(gamma_bytes)
        .map_err(|_| anyhow!("Invalid Gamma"))?.decompress()
        .ok_or_else(|| anyhow!("Gamma decompression failed"))?;
    
    let mut c_full = [0u8; 32];
    c_full[0..16].copy_from_slice(c_bytes);
    let c = Scalar::from_bytes_mod_order(c_full);

    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(s_bytes);
    let s = Scalar::from_bytes_mod_order(s_arr);

    let pk_point = CompressedEdwardsY::from_slice(pub_key)
        .map_err(|_| anyhow!("Invalid PK"))?.decompress()
        .ok_or_else(|| anyhow!("PK decompression failed"))?;

    let h_point = encode_to_curve_ed25519(pub_key, alpha);
    let h_bytes = h_point.compress().to_bytes();

    let u_point = (&s * ED25519_BASEPOINT_TABLE) - (c * pk_point);
    let u_bytes = u_point.compress().to_bytes();

    let v_point = (s * h_point) - (c * gamma);
    let v_bytes = v_point.compress().to_bytes();

    let c_prime = challenge_ed25519(pub_key, &h_bytes, gamma_bytes, &u_bytes, &v_bytes);
    if c_bytes != &c_prime.to_bytes()[0..16] {
        return Err(anyhow!("Challenge mismatch"));
    }

    Ok(proof_to_hash_ed25519(&gamma))
}

fn encode_to_curve_ed25519(pub_key: &[u8], alpha: &[u8]) -> EdwardsPoint {
    let mut h = Sha512::new();
    let mut ctr = 0u8;
    loop {
        h.reset();
        h.update(&[0x03, 0x01]);
        h.update(pub_key);
        h.update(alpha);
        h.update(&[ctr, 0x00]);
        let result = h.finalize_reset();
        if let Some(p) = CompressedEdwardsY::from_slice(&result[0..32]).ok().and_then(|c| c.decompress()) {
            let h_point = p.mul_by_cofactor();
            if !h_point.is_identity() { return h_point; }
        }
        ctr = ctr.checked_add(1).expect("Counter overflow");
    }
}

fn challenge_ed25519(p1: &[u8], p2: &[u8], p3: &[u8], p4: &[u8], p5: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(&[0x03, 0x02]);
    h.update(p1); h.update(p2); h.update(p3); h.update(p4); h.update(p5);
    h.update(&[0x00]);
    let d = h.finalize();
    let mut cb = [0u8; 32];
    cb[0..16].copy_from_slice(&d[0..16]);
    Scalar::from_bytes_mod_order(cb)
}

fn proof_to_hash_ed25519(gamma: &EdwardsPoint) -> [u8; 32] {
    let cofactor_gamma = gamma.mul_by_cofactor();
    let g_bytes = cofactor_gamma.compress().to_bytes();
    let mut h = Sha512::new();
    h.update(&[0x03, 0x03]);
    h.update(g_bytes);
    h.update(&[0x00]);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[0..32]);
    out
}


// --- P-256 Implementation ---

fn get_public_key_p256(secret: &[u8]) -> Result<Vec<u8>> {
    if secret.len() != 32 { return Err(anyhow!("Invalid P-256 scalar length")); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(secret);
    
    let sk_scalar: P256Scalar = Option::from(P256Scalar::from_repr(arr.into()))
        .ok_or_else(|| anyhow!("Invalid P-256 scalar"))?;
    
    let pk_point = ProjectivePoint::GENERATOR * sk_scalar;
    Ok(pk_point.to_encoded_point(true).as_bytes().to_vec())
}

fn ecvrf_prove_p256(secret: &[u8], alpha: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if secret.len() != 32 { return Err(anyhow!("Invalid P-256 scalar length")); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(secret);
    
    let x: P256Scalar = Option::from(P256Scalar::from_repr(arr.into()))
        .ok_or_else(|| anyhow!("Invalid scalar"))?;
        
    let y_point = ProjectivePoint::GENERATOR * x;
    let y_bytes = y_point.to_encoded_point(true).as_bytes().to_vec();

    let h_point = encode_to_curve_p256(&y_bytes, alpha);
    let h_bytes = h_point.to_encoded_point(true).as_bytes().to_vec();

    let gamma = h_point * x;
    let gamma_bytes = gamma.to_encoded_point(true).as_bytes().to_vec();

    let k = P256Scalar::random(&mut OsRng);

    let u_point = ProjectivePoint::GENERATOR * k;
    let u_bytes = u_point.to_encoded_point(true).as_bytes().to_vec();

    let v_point = h_point * k;
    let v_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();

    let c_scalar = challenge_p256(&y_bytes, &h_bytes, &gamma_bytes, &u_bytes, &v_bytes);
    let c_bytes_full = c_scalar.to_bytes();
    let c_bytes_16 = &c_bytes_full[0..16];

    let s_scalar: P256Scalar = k + (c_scalar * x);
    let s_bytes = s_scalar.to_bytes();

    let mut proof = Vec::with_capacity(81);
    proof.extend_from_slice(&gamma_bytes);
    proof.extend_from_slice(c_bytes_16);
    proof.extend_from_slice(&s_bytes);

    let output = proof_to_hash_p256(&gamma);
    Ok((output, proof))
}

fn ecvrf_verify_p256(pub_key: &[u8], alpha: &[u8], proof: &[u8]) -> Result<[u8; 32]> {
    if proof.len() != 81 { return Err(anyhow!("Invalid P-256 VRF proof length")); }
    let gamma_bytes = &proof[0..33];
    let c_bytes = &proof[33..49];
    let s_bytes = &proof[49..81];

    let gamma = Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_bytes(gamma_bytes).map_err(|_| anyhow!("Invalid Gamma"))?))
        .ok_or_else(|| anyhow!("Gamma point invalid"))?;

    let mut c_full = [0u8; 32];
    c_full[0..16].copy_from_slice(c_bytes);
    let c: P256Scalar = Option::from(P256Scalar::from_repr(c_full.into()))
        .ok_or_else(|| anyhow!("Invalid c"))?;

    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(s_bytes);
    let s: P256Scalar = Option::from(P256Scalar::from_repr(s_arr.into()))
        .ok_or_else(|| anyhow!("Invalid s"))?;

    let pk_point = Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_bytes(pub_key).map_err(|_| anyhow!("Invalid PK"))?))
        .ok_or_else(|| anyhow!("PK point invalid"))?;

    let h_point = encode_to_curve_p256(pub_key, alpha);
    let h_bytes = h_point.to_encoded_point(true).as_bytes().to_vec();

    let u_point = (ProjectivePoint::GENERATOR * s) - (pk_point * c);
    let u_bytes = u_point.to_encoded_point(true).as_bytes().to_vec();

    let v_point = (h_point * s) - (gamma * c);
    let v_bytes = v_point.to_encoded_point(true).as_bytes().to_vec();

    let c_prime = challenge_p256(pub_key, &h_bytes, gamma_bytes, &u_bytes, &v_bytes);
    if c_bytes != &c_prime.to_bytes()[0..16] {
        return Err(anyhow!("Challenge mismatch"));
    }

    Ok(proof_to_hash_p256(&gamma))
}

fn encode_to_curve_p256(pub_key: &[u8], alpha: &[u8]) -> ProjectivePoint {
    let mut h = Sha256::new();
    let mut ctr = 0u8;
    loop {
        h.reset();
        h.update(&[0x01, 0x01]);
        h.update(pub_key);
        h.update(alpha);
        h.update(&[ctr, 0x00]);
        let result = h.finalize_reset();
        
        let mut pt_bytes = vec![0x02u8];
        pt_bytes.extend_from_slice(&result);

        if let Ok(pt) = p256::EncodedPoint::from_bytes(&pt_bytes) {
            if let Some(p) = Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&pt)) {
                let choice = p.is_identity();
                let is_id: bool = choice.into();
                if !is_id {
                     return p;
                }
            }
        }
        ctr = ctr.checked_add(1).expect("TAI overflow");
    }
}

fn challenge_p256(p1: &[u8], p2: &[u8], p3: &[u8], p4: &[u8], p5: &[u8]) -> P256Scalar {
    let mut h = Sha256::new();
    h.update(&[0x01, 0x02]);
    h.update(p1); h.update(p2); h.update(p3); h.update(p4); h.update(p5);
    h.update(&[0x00]);
    let d = h.finalize();
    
    let mut cb = [0u8; 32];
    cb[0..16].copy_from_slice(&d[0..16]);
    P256Scalar::from_repr(cb.into()).unwrap()
}

fn proof_to_hash_p256(gamma: &ProjectivePoint) -> [u8; 32] {
    let g_bytes = gamma.to_encoded_point(true).as_bytes().to_vec();
    let mut h = Sha256::new();
    h.update(&[0x01, 0x03]);
    h.update(g_bytes);
    h.update(&[0x00]);
    let d = h.finalize();
    d.into()
}