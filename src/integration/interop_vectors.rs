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
    let got = commit(LABEL, 7, b"pk_v7", None, &OPENING).unwrap();
    assert_eq!(
        hx(&got),
        "ea1df1367cab95d5fe5009826bb7c60d0eb972aeea68b032b4efe08d5e0a37f1"
    );
}

#[test]
fn commitment_tpm_suffix_vector_s11_5() {
    // §11.5: in third-party-management mode UpdateValue.suffix carries
    // opaque signature<0..2^16-1>, serialized as u16 length || bytes
    let sig = [0x5au8; 64];
    let got = commit(LABEL, 7, b"pk_v7", Some(&sig), &OPENING).unwrap();
    assert_eq!(
        hx(&got),
        "5d66b97ff882bae9ff164e9693d1517d9f10174c78ddfa4c7676e7cdb947386f"
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

    // proving is deterministic (RFC 9381 §5.4.2.2 nonce), so the proof pins too
    let ctx = expand_vrf_secret(CIPHER_SUITE_KT_128_SHA256_ED25519, &SEED).unwrap();
    let (out_a, proof_a) = ecvrf_prove(&ctx, b"alpha").unwrap();
    let (_, proof_b) = ecvrf_prove(&ctx, b"alpha").unwrap();
    assert_eq!(proof_a, proof_b);
    assert_eq!(
        hx(&proof_a),
        "dff00db2d25b269d561655860a367a792f80db505089f56b05264828c725138a\
         5749f77b4fa5da106bbdc7cbd723ba6915b029cde59458ae6a8c989edcd4c187\
         c8cf445103d7ee2a3afba16482acf307"
    );
    assert_eq!(hx(&out_a), hx(&out));
}

#[test]
fn rfc9381_appendix_b_vectors() {
    // RFC 9381 Appendix B known-answer vectors for both TAI suites; beta for
    // the Edwards suite is SHA-512 output, truncated here to the 32-byte index
    let cases: [(u16, &str, &[u8], &str, &str); 4] = [
        (
            CIPHER_SUITE_KT_128_SHA256_ED25519,
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            b"",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
             26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12\
             68a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff",
        ),
        (
            CIPHER_SUITE_KT_128_SHA256_ED25519,
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            b"\x72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
             3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926d\
             a3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb",
        ),
        (
            crypto::CIPHER_SUITE_KT_128_SHA256_P256,
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            b"sample",
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071\
             b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af\
             376b33edf7de17c6ea056d4d82de6bc02f",
            "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
        ),
        (
            crypto::CIPHER_SUITE_KT_128_SHA256_P256,
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            b"test",
            "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb\
             56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb08169\
             69d864f37625b443f30f1a5a33f2b3c854",
            "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
        ),
    ];

    for (suite, sk_hex, alpha, pi_hex, beta32_hex) in cases {
        let sk = hex::decode(sk_hex).unwrap();
        let pi = pi_hex.replace([' ', '\n'], "");
        let ctx = expand_vrf_secret(suite, &sk).unwrap();
        let (out, proof) = ecvrf_prove(&ctx, alpha).unwrap();
        assert_eq!(hx(&proof), pi, "pi mismatch: suite {suite:#x}");
        assert_eq!(hx(&out), beta32_hex, "beta mismatch: suite {suite:#x}");

        let pk = get_public_key(suite, &sk).unwrap();
        let verified = ecvrf_verify(suite, &pk, alpha, &proof).unwrap();
        assert_eq!(hx(&verified), beta32_hex);
    }
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

// §13.1: full server transcript for a greatest-version search from a client
// with no prior state (last = None), over a fixed three-entry tree
#[tokio::test]
async fn search_transcript_fresh_client_s13_1() -> anyhow::Result<()> {
    use crate::db::{RocksDbStore, TransparencyStore};
    use crate::proto::transparency::{SearchRequest, Signature as PbSignature, TreeHead};
    use crate::tree::Tree;
    use prost::Message;
    use std::collections::HashMap;
    use std::sync::Arc;

    const BASE_TS: u64 = 1_700_000_000_000;
    const MAX_AHEAD: u64 = 10_000;
    const MAX_BEHIND: u64 = 10_000_000_000_000;
    const RMW: u64 = 86_400_000;

    let sig_key = crypto::ServiceSigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&SEED));
    let config = crypto::PrivateConfig::new(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        sig_key,
        SEED.to_vec(),
        HashMap::new(),
        MAX_AHEAD,
        MAX_BEHIND,
        RMW,
        None,
        None,
        100,
    )?;

    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let mut tree = Tree::new(store.clone() as Arc<dyn TransparencyStore>, &config).await?;

    let entries: [(&[u8], &[u8]); 3] = [
        (b"alice@example.com", b"alice_pk_v0"),
        (b"bob@example.com", b"bob_pk_v0"),
        (b"carol@example.com", b"carol_pk_v0"),
    ];

    let mut current_ptr = None;
    let mut roots = Vec::new();
    for (i, (label, value)) in entries.iter().enumerate() {
        let opening: [u8; 16] = core::array::from_fn(|j| (0xa0 + 0x10 * i + j) as u8);
        let (index, _) = config.vrf_prove(label, 0)?;
        let commitment = commit(label, 0, value, None, &opening)?;
        let (r, _, ptr) = tree
            .prefix
            .batch_insert(i as u64, current_ptr, &[(index.to_vec(), commitment)])
            .await?;
        roots.push(r[0].clone());
        current_ptr = Some(ptr);
        tree.log.put_prefix_ptr(i as u64, i as u64)?;
        store.put_value(i as u64, value.to_vec())?;
        store.put_opening(i as u64, opening.to_vec())?;
        store.append_label_history(label, 0, i as u64)?;
    }
    tree.log.set_next_prefix_version(3)?;

    let log_entries: Vec<(u64, Vec<u8>)> = roots
        .iter()
        .enumerate()
        .map(|(i, r)| (BASE_TS + i as u64 * 1000, r.clone()))
        .collect();
    let root = tree.log.batch_append(0, log_entries)?;

    let tbs = crypto::construct_tree_head_tbs(&config, None, 3, &root)?;
    let signature = crypto::sign_data(&config.sig_key, &tbs);
    let th = TreeHead {
        tree_size: 3,
        timestamp: (BASE_TS + 2000) as i64,
        signatures: vec![PbSignature {
            auditor_public_key: config.sig_key.verifying_key().to_bytes(),
            signature,
        }],
    };
    let mut head_buf = Vec::new();
    th.encode(&mut head_buf)?;
    store.set_head(head_buf)?;
    tree.latest = Some(th);

    let resp = tree
        .search(&SearchRequest {
            label: b"alice@example.com".to_vec(),
            last: None,
            version: None,
        })
        .await?;
    assert_eq!(
        hx(&root),
        "ac10080d6471074171d5e386b5510a2d0f192c13da9409cbabddee8d6e220a3a"
    );
    let expected_hex = "0a730802126f080310d0df95ffbc311a640a2003a107bff3ce10be1d70dd18e7\
        4bc09967e4d6309ba50d5f1ddc8664125531b812404a5c3f8e733a3243c26850\
        f6e972f51cb280ed466544854e1cad915cfabdccb460c8ccc16741282665ae1b\
        8ab9ff8e1face9fef84cbcb6eecacb8504f3c6940e10001a10a0a1a2a3a4a5a6\
        a7a8a9aaabacadaeaf220d0a0b616c6963655f706b5f76302a740a500cf99154\
        200888939ddcc94e716372db27156d57975f1b1c12f84454e42a08df879711ea\
        ed31ad5ca1ad7f3d2f53ab04eacc45a70443af4d7d6be45fcd0890dbbf56a0d4\
        5455920f92c430847ecc17011220cc06d9124329c05c795fa4f686031627b421\
        d008f5e965c43b913bd2117da9012a520a504b8e58e658a31589e3b79e91ab13\
        8434dabbf5d6393929b7bd79a9c4f3fab2e06fddd6330743f343dcc61dc267ae\
        08db45a7fbf91531b347ce8c9b1a8a0bffe2ee68d4a4922701d137450b355259\
        ce0632b0040a0ce8d795ffbc31d0df95ffbc3112fc010a04080118010a4a0802\
        12440a202b64b56399a58d4188f667e4bb74c59698b916080a1b2e9606fde7e0\
        ec8afee7122034aea22e71013e6577e6b0553f363222a5ef2848c2260fb41fed\
        9cadfa92a34a180412206f39b8287aa549b46ceb823e71a74b865e3243004d94\
        d22ab758a79fa11b94291220db15ec3964853196118bb0afd333743fb8449152\
        5c830ec786e537c974ead9421220000000000000000000000000000000000000\
        0000000000000000000000000000122000000000000000000000000000000000\
        00000000000000000000000000000000122020ad03df0fecea520e2f44265dec\
        510aa126d7379d9386c90c40ac5115b2a3f112fc010a04080118010a4a080212\
        440a202b64b56399a58d4188f667e4bb74c59698b916080a1b2e9606fde7e0ec\
        8afee7122034aea22e71013e6577e6b0553f363222a5ef2848c2260fb41fed9c\
        adfa92a34a180412202fb3c73bdaf7035373d848dd83c454152da05227157caa\
        313467eda0fa1e19051220db15ec3964853196118bb0afd333743fb84491525c\
        830ec786e537c974ead942122000000000000000000000000000000000000000\
        000000000000000000000000001220b850ad2ff46aae94c3373b5bb94fd36c82\
        e0c9a0004b5255499b1eb4c1829f16122020ad03df0fecea520e2f44265dec51\
        0aa126d7379d9386c90c40ac5115b2a3f122220a2023703949a6be66bf571240\
        54d195ebd9de4113410a68cc893660b80655a64070"
        .replace(['\n', ' '], "");
    assert_eq!(hx(&resp.encode_to_vec()), expected_hex);

    // the pinned transcript must verify end-to-end in a conforming client
    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: config.sig_key.verifying_key().to_bytes(),
        vrf_public_key: config.vrf_public_key.clone(),
        leaf_public_key: None,
        auditor_public_key: None,
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: MAX_AHEAD,
        max_behind: MAX_BEHIND,
        reasonable_monitoring_window: RMW,
        maximum_lifetime: None,
    };
    drop(tree);
    let sig_key2 = crypto::ServiceSigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&SEED));
    let service = crate::service::KeyTransparencyImpl::new(
        store as Arc<dyn TransparencyStore>,
        sig_key2,
        SEED.to_vec(),
        HashMap::new(),
        None,
    )
    .await?;
    let channel = crate::integration::harness::serve_in_memory(service).await?;
    let mut client = crate::client::KtClient::with_channel(channel, public_config)?;
    let got = client.search(b"alice@example.com".to_vec(), None).await?;
    assert_eq!(got.value.unwrap().value, b"alice_pk_v0");
    Ok(())
}
