// Deterministic known-answer vectors for the hashed and signed byte formats,
// anchored to draft-ietf-keytrans-protocol-05 sections. Another implementation
// can reproduce these from the documented inputs; a change here signals a
// wire-format break. The same vectors are mirrored in
// docs/spec/interop-vectors.json for cross-implementation comparison.

use crate::crypto::{
    self, CIPHER_SUITE_KT_128_SHA256_ED25519, PublicConfig, commit, construct_vrf_input,
    ecvrf_prove, ecvrf_verify, expand_vrf_secret, get_public_key, log_leaf_value, log_parent_value,
};
use crate::tree::prefix::hasher::{leaf_hash, parent_hash};

// fixed inputs shared by the vectors below
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const OPENING: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const LABEL: &[u8] = b"alice@example.com";

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn sample_config() -> PublicConfig {
    let pk = get_public_key(CIPHER_SUITE_KT_128_SHA256_ED25519, &SEED).unwrap();
    PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: pk.clone(),
        vrf_public_key: pk,
        leaf_public_key: None,
        auditor_public_key: None,
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: 10_000,
        max_behind: 10_000,
        reasonable_monitoring_window: 86_400_000,
        maximum_lifetime: None,
    }
}

#[test]
fn commitment_vector_s11_6() {
    // §11.6: commitment = HMAC-SHA256(Kc, opening || label || version || UpdateValue)
    let got = commit(LABEL, 7, b"pk_v7", &OPENING).unwrap();
    assert_eq!(
        hx(&got),
        "ea1df1367cab95d5fe5009826bb7c60d0eb972aeea68b032b4efe08d5e0a37f1"
    );
}

#[test]
fn vrf_input_vector_s11_7() {
    // §11.7: opaque label<0..2^8-1> || uint32 version
    let got = construct_vrf_input(LABEL, 7).unwrap();
    assert_eq!(hx(&got), "11616c696365406578616d706c652e636f6d00000007");
}

#[test]
fn prefix_hash_vectors_s11_9() {
    // §11.9: leaf = H(0x02 || vrf_output || commitment); parent = H(0x03 || left || right)
    assert_eq!(
        hx(&leaf_hash(&[0x11u8; 32], &[0x22u8; 32])),
        "c484058e7e2b8fe5bbaefcb523aa443ba4d8b5093038dc1f8147e74823eda8f1"
    );
    assert_eq!(
        hx(&parent_hash(&[0x33u8; 32], &[0x44u8; 32])),
        "a48926ac669d632e914a9abf64e6a79f33dcc0533aac83bc797c17a53b3385be"
    );
}

#[test]
fn log_hash_vectors_s11_8() {
    // §11.8: leaf = H(timestamp || prefix_root); parent tags leaf children 0x00, parents 0x01
    assert_eq!(
        hx(&log_leaf_value(0x0102030405060708, &[0x55u8; 32])),
        "be713bd94e9d86e157ec6f0b758b0b70fece954fa5e510b63ea250287eb6af6e"
    );
    assert_eq!(
        hx(&log_parent_value(&[0x66u8; 32], true, &[0x77u8; 32], false)),
        "2de4c8af25d34b82567bdd7720a4a18fedbe18b44e5d3ca7a7a577638ffe643e"
    );
}

#[test]
fn vrf_vectors_s11_7() {
    // §11.7: a fixed secret expands to a fixed public key, and a fixed proof
    // verifies to a fixed output — the cross-implementation VRF known-answer.
    let vrf_pk = get_public_key(CIPHER_SUITE_KT_128_SHA256_ED25519, &SEED).unwrap();
    assert_eq!(
        hx(&vrf_pk),
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    );

    let fixed_proof = hex::decode(
        "dff00db2d25b269d561655860a367a792f80db505089f56b05264828c725138a\
         975f9396e64973768db68ba4d81e58a6dffcb6ef7d114de30ba51b156c776dcc\
         41f795652f9be62512ff89dcd14f8f03",
    )
    .unwrap();
    let out = ecvrf_verify(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        &vrf_pk,
        b"alpha",
        &fixed_proof,
    )
    .unwrap();
    assert_eq!(
        hx(&out),
        "5add3d6938a61bb190b777f3555206c224d705aeb8c1498299c0d4539e87aece"
    );

    // freshly generated proofs randomize on the nonce but keep the same output
    let ctx = expand_vrf_secret(CIPHER_SUITE_KT_128_SHA256_ED25519, &SEED).unwrap();
    let (out_a, proof_a) = ecvrf_prove(&ctx, b"alpha").unwrap();
    let (_, proof_b) = ecvrf_prove(&ctx, b"alpha").unwrap();
    assert_ne!(proof_a, proof_b);
    assert_eq!(hx(&out_a), hx(&out));
}

#[test]
fn tree_head_tbs_vector_s11_2() {
    // §11.2: serialized Configuration || uint64 tree_size || opaque root[Nh]
    let got = crypto::construct_tree_head_tbs_public(&sample_config(), 42, &[0x99u8; 32]).unwrap();
    let expected = "000201002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc866\
         4125531b8002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc\
         8664125531b80000000000000000271000000000000027100000000005265c00\
         00000000000000002a9999999999999999999999999999999999999999999999999999999999999999"
        .replace(['\n', ' '], "");
    assert_eq!(hx(&got), expected);
}
