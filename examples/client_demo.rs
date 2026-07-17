use rukt::client::KtClient;
use rukt::crypto::PublicConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("KT_CONFIG").unwrap_or_else(|_| "kt_data/config.json".into());
    let uri = std::env::var("KT_URI").unwrap_or_else(|_| "http://127.0.0.1:8081".into());

    let config_json = std::fs::read_to_string(&config_path).map_err(|e| {
        anyhow::anyhow!("reading {config_path}: {e}. Start the server first, or set KT_CONFIG.")
    })?;
    let config = PublicConfig::from_json(&config_json)?;

    let mut client = KtClient::connect(uri, config).await?;
    println!("Connected to Key Transparency Server");

    let user = b"bob".to_vec();
    let value = b"bob_pk_v1".to_vec();
    println!("Registering user 'bob'...");

    let update_resp = client.update(user.clone(), value).await?;
    let tree_size = update_resp
        .full_tree_head
        .unwrap()
        .tree_head
        .unwrap()
        .tree_size;
    println!("Update successful. New Tree Size: {}", tree_size);

    println!("Searching for user 'bob'...");
    let search_resp = client.search(user, None).await?;

    if let Some(val) = search_resp.value {
        println!("Verified Value: {:?}", String::from_utf8_lossy(&val.value));
    }

    Ok(())
}
