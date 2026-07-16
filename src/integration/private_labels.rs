use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_randomized_vrf_proofs() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service =
        KeyTransparencyImpl::new(db.clone(), signer, vrf_key, HashMap::new(), None).await?;
    let label = b"privacy_user".to_vec();

    let (output_1, proof_1) = service.config.vrf_prove(&label, 0)?;
    let (output_2, proof_2) = service.config.vrf_prove(&label, 0)?;

    assert_eq!(
        output_1, output_2,
        "VRF Output (Index) must be deterministic"
    );
    assert_ne!(
        proof_1, proof_2,
        "VRF Proof bytes must be randomized to prevent traffic correlation"
    );

    let input = crypto::construct_vrf_input(&label, 0)?;

    // Verify proof 1
    let verified_1 = crypto::ecvrf_verify(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        &service.config.vrf_public_key,
        &input,
        &proof_1,
    )?;

    // Verify proof 2
    let verified_2 = crypto::ecvrf_verify(
        CIPHER_SUITE_KT_128_SHA256_ED25519,
        &service.config.vrf_public_key,
        &input,
        &proof_2,
    )?;

    assert_eq!(verified_1, output_1, "Proof 1 verification failed");
    assert_eq!(verified_2, output_1, "Proof 2 verification failed");

    Ok(())
}
