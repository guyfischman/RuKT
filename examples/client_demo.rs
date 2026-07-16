use rukt::client::KtClient;
use rukt::crypto::{self, ServiceVerifyingKey};
use rukt::crypto::CIPHER_SUITE_KT_128_SHA256_ED25519;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ---------------------------------------------------------
    // PASTE KEYS FROM SERVER OUTPUT HERE
    // ---------------------------------------------------------
    let server_sig_hex = "38f421dc0878d6d003d20904bf7b154617824b48e5479942b3d159d2116c7592";
    let server_vrf_hex = "42d784f1b9686c511e081ac62e738f8bc7b406f598d5ca5a01e590a159fc7b16";
    // ---------------------------------------------------------

    if server_sig_hex.contains("REPLACE") {
        panic!("Please paste the keys from the server logs into examples/client_demo.rs!");
    }

    // Decode Hex to Bytes
    let sig_bytes = hex::decode(server_sig_hex).expect("Invalid Hex for Sig Key");
    let vrf_bytes = hex::decode(server_vrf_hex).expect("Invalid Hex for VRF Key");

    // Convert bytes to Typed Keys
    let sig_vk = ServiceVerifyingKey::from_bytes(&sig_bytes)?;

    println!("Connecting with trusted keys...");

    // Must match the server's configuration constants in src/service.rs
    let public_config = crypto::PublicConfig {
        cipher_suite: CIPHER_SUITE_KT_128_SHA256_ED25519,
        mode: crypto::DEPLOYMENT_MODE_CONTACT_MONITORING,
        server_sig_pk: sig_vk.to_bytes(),
        vrf_public_key: vrf_bytes,
        leaf_public_key: None,
        max_ahead: 5000,
        max_behind: 5000,
        reasonable_monitoring_window: 86400000,
        maximum_lifetime: None,
    };

    let mut client = KtClient::connect(
        "http://0.0.0.0:8081".to_string(),
        public_config,
    ).await?;

    println!("Connected to Key Transparency Server");

    // 1. Update
    let user = b"bob".to_vec();
    let key = b"bob_pk_v1".to_vec();
    println!("Registering user 'bob'...");
    
    let update_resp = client.update(user.clone(), key.clone()).await?;
    let ts = update_resp.tree_head.unwrap().tree_head.unwrap().tree_size;
    println!("Update successful. New Tree Size: {}", ts);

    // 2. Search
    println!("Searching for user 'bob'...");
    let search_resp = client.search(user, None).await?;
    
    if let Some(val) = search_resp.value {
        println!("Verified Value: {:?}", String::from_utf8_lossy(&val.value));
    }

    Ok(())
}