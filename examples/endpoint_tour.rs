//! Exercises every client-facing endpoint of a contact-monitoring log and
//! verifies each response. Point it at a deployed server:
//!
//!   curl -s https://kt.guyfischman.com/config.json > config.json
//!   KT_CONFIG=config.json KT_URI=https://kt.guyfischman.com \
//!     cargo run --example endpoint_tour
use rukt::client::KtClient;
use rukt::crypto::PublicConfig;
use std::time::{SystemTime, UNIX_EPOCH};

fn show(v: Option<rukt::proto::transparency::UpdateValue>) -> String {
    v.map(|v| String::from_utf8_lossy(&v.value).into_owned())
        .unwrap_or_else(|| "<none>".into())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("KT_CONFIG").unwrap_or_else(|_| "config.json".into());
    let uri = std::env::var("KT_URI").unwrap_or_else(|_| "https://kt.guyfischman.com".into());
    let config = PublicConfig::from_json(&std::fs::read_to_string(&config_path)?)?;

    let mut client = KtClient::connect(uri.clone(), config).await?;
    println!("connected to {uri}\n");

    // A unique label so simultaneous testers don't collide on the shared log.
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let label = format!("tour-{nonce}").into_bytes();
    let name = String::from_utf8_lossy(&label).into_owned();

    // update: register two versions (compare-and-swap on the greatest version)
    client.update(label.clone(), b"pk_v0".to_vec()).await?;
    client.update(label.clone(), b"pk_v1".to_vec()).await?;
    println!("update             registered {name} at v0 and v1");

    // search: greatest version, then a specific version
    let greatest = client.search(label.clone(), None).await?;
    println!(
        "search greatest    v{:?} = {:?}",
        greatest.version,
        show(greatest.value)
    );
    let v0 = client.search(label.clone(), Some(0)).await?;
    println!("search version 0   {:?}", show(v0.value));

    // a seeded label, to prove reads of pre-existing data verify too
    let alice = client.search(b"alice".to_vec(), None).await?;
    println!(
        "search alice       v{:?} = {:?}",
        alice.version,
        show(alice.value)
    );

    // contact monitor: discharge the monitoring obligation for the label
    client.contact_monitor(label.clone()).await?;
    println!("contact_monitor    OK");

    // distinguished: recent distinguished heads for fork detection (and the
    // trust anchor the offline credential checks below rely on)
    client.distinguished(None).await?;
    println!(
        "distinguished      {} head(s)",
        client.distinguished_roots()?.len()
    );

    // owner init + owner monitor: the owner-side monitoring path (§8.3)
    let greatest_version = greatest.version.unwrap();
    let start = (greatest_version + 1) as u64;
    client.owner_init(label.clone(), start).await?;
    client
        .owner_monitor(label.clone(), vec![], start, Some(greatest_version))
        .await?;
    println!("owner_init/monitor OK");

    // credentials: obtained here, verifiable offline by a recipient
    use rukt::proto::transparency::CredentialType;
    let cred = client.get_credential(label.clone()).await?;
    client.distinguished(None).await?;
    client.verify_credential(&cred)?;
    let kind = if cred.credential_type == CredentialType::Provisional as i32 {
        "provisional"
    } else {
        "standard"
    };
    println!(
        "get_credential     v{} verified offline ({kind})",
        cred.version
    );

    // §14.2: a credential update anchors a *provisional* credential (its version
    // postdates every distinguished entry) to the first distinguished entry to
    // its right, so it needs activity after the credential. A standard
    // credential is already anchored and has nothing to update.
    if cred.credential_type == CredentialType::Provisional as i32 {
        for i in 0..4 {
            client
                .update(format!("{name}-filler-{i}").into_bytes(), b"f".to_vec())
                .await?;
        }
        let terminal = client.credential_terminal(&cred)?;
        match client
            .get_credential_update(label.clone(), terminal, cred.version)
            .await
        {
            Ok(cred_update) => {
                client.distinguished(None).await?;
                client.verify_credential_update(&cred, &cred_update)?;
                println!("credential_update  verified offline");
            }
            // The update needs a distinguished entry past the terminal; on an
            // arbitrarily-shaped log a few entries may not have formed one yet.
            Err(e)
                if e.to_string()
                    .contains("distinguished log entry to the right") =>
            {
                println!("credential_update  n/a (no distinguished entry past the terminal yet)");
            }
            Err(e) => return Err(e),
        }
    } else {
        println!("credential_update  n/a (credential already anchored)");
    }

    println!("\nEvery endpoint verified against {uri}.");
    Ok(())
}
