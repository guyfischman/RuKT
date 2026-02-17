use rukt::client::KtClient;
use rukt::crypto::{self, ServiceVerifyingKey};

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

    let mut client = KtClient::connect(
        "http://0.0.0.0:8081".to_string(), 
        sig_vk, 
        vrf_bytes // VRF key is just Vec<u8>
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