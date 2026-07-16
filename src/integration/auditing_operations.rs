use super::harness::TestServer;
use crate::proto::transparency::CredentialType;
use anyhow::Result;

// Every client operation, under third-party-auditing mode, must verify the
// AuditorTreeHead the server attaches to each response. RMW=0 so every entry is
// distinguished and the monitoring/credential paths are fully exercised.
#[tokio::test]
async fn test_all_operations_verify_auditor_head() -> Result<()> {
    let server = TestServer::auditing_all_distinguished().await?;

    // populate a few labels
    {
        let mut writer = server.client().await?;
        writer.update(b"alice".to_vec(), b"a0".to_vec()).await?;
        writer.update(b"bob".to_vec(), b"b0".to_vec()).await?;
        writer.update(b"alice".to_vec(), b"a1".to_vec()).await?;
        writer.update(b"carol".to_vec(), b"c0".to_vec()).await?;
    }
    // auditor ingests everything and publishes a head covering the whole tree
    server.run_auditor().await?;

    // each operation runs on a fresh client so it receives an UPDATED head and
    // the auditor-head verification (§11.3) actually runs — an UPDATED response
    // in auditing mode always carries the AuditorTreeHead.

    // search (greatest + fixed)
    let mut c = server.client().await?;
    let latest = c.search(b"alice".to_vec(), None).await?;
    assert!(latest.full_tree_head.as_ref().unwrap().auditor_tree_head.is_some());
    assert_eq!(latest.version, Some(1));
    assert_eq!(c.search(b"alice".to_vec(), Some(0)).await?.value.unwrap().value, b"a0".to_vec());
    // the obligation the search recorded is then monitored (rides a SAME head)
    c.contact_monitor(b"alice".to_vec()).await?;

    // owner initialization from a distinguished start
    let mut c = server.client().await?;
    let init = c.owner_init(b"alice".to_vec(), 2).await?;
    assert!(init.full_tree_head.unwrap().auditor_tree_head.is_some());

    // owner monitoring
    let mut c = server.client().await?;
    let mon = c.owner_monitor(b"alice".to_vec(), vec![], 2, Some(1)).await?;
    assert!(mon.full_tree_head.unwrap().auditor_tree_head.is_some());

    // distinguished-heads walk
    let mut c = server.client().await?;
    let dist = c.distinguished(None).await?;
    assert!(dist.full_tree_head.unwrap().auditor_tree_head.is_some());

    // credential issuance + offline verification by a fresh recipient
    let mut issuer = server.client().await?;
    let cred = issuer.get_credential(b"alice".to_vec()).await?;
    assert_eq!(cred.credential_type, CredentialType::Standard as i32);
    let mut recipient = server.client().await?;
    recipient.distinguished(None).await?;
    recipient.verify_credential(&cred)?;

    Ok(())
}

// A stale auditor head (log advances well past the last signed size) is still
// verified against the derived sub-root, and the operation succeeds.
#[tokio::test]
async fn test_operations_accept_lagging_auditor() -> Result<()> {
    let server = TestServer::auditing_all_distinguished().await?;

    let mut writer = server.client().await?;
    writer.update(b"dana".to_vec(), b"d0".to_vec()).await?;
    server.run_auditor().await?;

    // the log grows past the auditor's signed size
    writer.update(b"eve".to_vec(), b"e0".to_vec()).await?;
    writer.update(b"dana".to_vec(), b"d1".to_vec()).await?;

    let mut client = server.client().await?;
    let resp = client.search(b"dana".to_vec(), None).await?;
    let ath = resp.full_tree_head.unwrap().auditor_tree_head.unwrap();
    assert_eq!(ath.tree_size, 1, "auditor head lags the current tree");
    assert_eq!(client.state.as_ref().unwrap().tree_size, 3);

    Ok(())
}
