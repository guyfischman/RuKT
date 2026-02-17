use crate::db::RocksDbStore;
use crate::service::KeyTransparencyImpl;
use crate::proto::transparency::{UpdateRequest, SignedUpdateRequest};
use crate::proto::kt::key_transparency_service_server::KeyTransparencyService;
use crate::crypto::{self, CIPHER_SUITE_KT_128_SHA256_ED25519};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_update_response_structure_compliance() -> Result<()> {
    // 1. Setup
    let dir = tempdir()?;
    let db = Arc::new(RocksDbStore::new(dir.path().to_str().unwrap())?);
    let (signer, _) = crypto::generate_sig_keypair();
    let (vrf_key, _) = crypto::generate_vrf_keypair(CIPHER_SUITE_KT_128_SHA256_ED25519);
    
    let service = KeyTransparencyImpl::new(db, signer, vrf_key, HashMap::new(), None).await?;
    
    let user_id = b"compliance_user".to_vec();

    // 2. Perform First Update (v0) -> Log Index 0
    // Previous Tree Size = 0.
    let req_v0 = tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: b"v0".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    });

    let resp_v0 = service.update(req_v0).await?.into_inner();
    
    // Check v0 structure
    let search_v0 = resp_v0.search.expect("Must have search proof");
    // For the very first entry (index 0), previous frontier is empty/start. 
    // Just 0 should be visited.
    assert_eq!(search_v0.timestamps.len(), 1, "Genesis update should have 1 timestamp (self)");
    assert_ne!(search_v0.timestamps[0], 0, "Timestamp should be real (non-zero epoch for genesis if possible, though tests run fast)");
    
    // 3. Perform Second Update (v1) -> Log Index 1
    // Previous Tree Size = 1. Previous Frontier = [0].
    // New Node = 1.
    // Traversal should visit [0, 1].
    let req_v1 = tonic::Request::new(SignedUpdateRequest {
        request: Some(UpdateRequest {
            search_key: user_id.clone(),
            value: b"v1".to_vec(),
            consistency: None,
            expected_pre_update_value: vec![],
            return_update_response: true,
        }),
        signature: vec![],
    });

    let resp_v1 = service.update(req_v1).await?.into_inner();
    let search_v1 = resp_v1.search.expect("Must have search proof");

    // Assertion 1: Timestamps are not the hardcoded placeholder
    // The previous implementation returned `vec![0]`.
    // The new implementation should return timestamps for node 0 and node 1.
    assert_eq!(search_v1.timestamps.len(), 2, "Should contain timestamps for previous frontier (0) and new node (1)");
    
    // Check monotonicity
    assert!(search_v1.timestamps[1] >= search_v1.timestamps[0]);

    // Assertion 2: Prefix Proofs
    // We expect proofs for both nodes to allow the client to verify the transition.
    // Node 0: Prove existence of v0.
    // Node 1: Prove existence of v1.
    assert!(!search_v1.prefix_proofs.is_empty(), "Must contain prefix proofs for verification");
    
    // In Draft 9.1 logic, we request proofs for both nodes visited.
    // Depending on optimization/caching, we might get roots or proofs. 
    // Since this is a fresh request with no 'last' consistency provided, likely proofs.
    assert!(search_v1.prefix_proofs.len() >= 1);

    // Assertion 3: Binary Ladder
    // The update response should contain the binary ladder for the new version
    assert!(!resp_v1.binary_ladder.is_empty());
    
    Ok(())
}