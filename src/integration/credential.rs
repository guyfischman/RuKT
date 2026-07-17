use crate::client::KtClient;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use crate::db::RocksDbStore;
use crate::proto::transparency::CredentialType;
use crate::service::KeyTransparencyImpl;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_credential_offline_verification() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (sig_sk, sig_vk) = crypto::generate_sig_keypair();
    let (vrf_priv, vrf_pub) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);

    let service = KeyTransparencyImpl::new(db, sig_sk, vrf_priv, HashMap::new(), None).await?;

    let channel = crate::integration::harness::serve_in_memory(service).await?;
    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: sig_vk.to_bytes(),
        vrf_public_key: vrf_pub,
        leaf_public_key: None,
        auditor_public_key: None,
        auditor_start_pos: 0,
        max_auditor_lag: 60_000,
        max_ahead: 5000,
        max_behind: 5000,
        reasonable_monitoring_window: 86400000,
        maximum_lifetime: None,
    };
    let user = b"cred_user".to_vec();

    // the sender creates versions and obtains its credential
    let mut sender: KtClient = KtClient::with_channel(channel.clone(), public_config.clone())?;
    sender.update(user.clone(), b"val".to_vec()).await?;
    sender.update(b"noise_1".to_vec(), b"x".to_vec()).await?;
    sender.update(b"noise_2".to_vec(), b"y".to_vec()).await?;

    let cred = sender.get_credential(user.clone()).await?;
    assert_eq!(cred.label, user);
    assert_eq!(cred.version, 0);
    assert_eq!(cred.credential_type, CredentialType::Standard as i32);

    // the recipient learns the recent distinguished heads, then verifies the
    // credential without contacting the log again
    let mut recipient: KtClient = KtClient::with_channel(channel.clone(), public_config)?;
    recipient.distinguished(None).await?;
    assert!(recipient.distinguished_entries.contains_key(&cred.position));

    recipient.verify_credential(&cred)?;

    // a tampered value must not verify
    let mut bad = cred.clone();
    bad.value.as_mut().unwrap().value = b"forged".to_vec();
    assert!(recipient.verify_credential(&bad).is_err());

    // a label whose version postdates every distinguished entry gets a
    // provisional credential, verified against the anchor's retained subtrees;
    // the extra noise entry keeps it right of the (always distinguished) root
    sender.update(b"noise_3".to_vec(), b"z".to_vec()).await?;
    let fresh = b"fresh_user".to_vec();
    sender.update(fresh.clone(), b"fresh_val".to_vec()).await?;

    let prov = sender.get_credential(fresh.clone()).await?;
    assert_eq!(prov.credential_type, CredentialType::Provisional as i32);
    assert!(prov.position < prov.tree_head.as_ref().unwrap().tree_size);

    recipient.distinguished(None).await?;
    recipient.verify_credential(&prov)?;

    let mut bad_prov = prov.clone();
    bad_prov.value.as_mut().unwrap().value = b"forged".to_vec();
    assert!(recipient.verify_credential(&bad_prov).is_err());

    // §14.2: once a distinguished entry covers the credential's version, a
    // CredentialUpdate transitions it to a standard anchor
    for i in 0..4 {
        sender
            .update(format!("filler_{}", i).into_bytes(), b"f".to_vec())
            .await?;
    }
    let terminal = sender.credential_terminal(&prov)?;
    let update = sender
        .get_credential_update(fresh.clone(), terminal, prov.version)
        .await?;

    recipient.distinguished(None).await?;
    recipient.verify_credential_update(&prov, &update)?;

    Ok(())
}
