use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, GetCredentialRequest, CredentialType, LabelValue};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_credential_flow() -> Result<()> {
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    let user = b"cred_user".to_vec();

    service.update(tonic::Request::new(UpdateRequest {
        last: None,
        label: user.clone(),
        greatest_version: None,
        values: vec![LabelValue { value: b"val".to_vec() }],
    })).await?;

    let cred = service.get_credential(tonic::Request::new(GetCredentialRequest {
        search_key: user.clone(),
    })).await?.into_inner();

    assert_eq!(cred.version, 0);
    assert!(cred.value.is_some());
    assert!(!cred.binary_ladder.is_empty());
    assert_eq!(cred.credential_type, CredentialType::Standard as i32);
    
    Ok(())
}