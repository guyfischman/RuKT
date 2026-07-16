use super::harness::TestServer;
use anyhow::Result;

// One persisted client threads through every operation as the tree grows, each
// response proving consistency with the retained view, and the state survives a
// restart. Finally a rolled-back head is rejected.
#[tokio::test]
async fn test_cross_operation_state_continuity() -> Result<()> {
    let server = TestServer::contact_monitoring_all_distinguished().await?;
    let dir = tempfile::tempdir()?;
    let state_file = dir.path().join("state.json");
    let label = b"owner".to_vec();

    // build up a label and some unrelated activity
    {
        let mut writer = server.client().await?;
        writer.update(label.clone(), b"v0".to_vec()).await?;
        writer.update(b"noise0".to_vec(), b"x".to_vec()).await?;
        writer.update(label.clone(), b"v1".to_vec()).await?;
    }

    // a persisted client searches, recording a monitoring obligation and a head
    let (retained_size, retained_root) = {
        let mut client = server.client().await?;
        client.persist_to(&state_file)?;

        let s = client.search(label.clone(), None).await?;
        assert_eq!(s.version, Some(1));
        assert!(client.monitoring_map.contains_key(&label));

        let st = client.state.clone().unwrap();
        (st.tree_size, st.root_hash)
    };

    // the tree grows while the client is away
    {
        let mut writer = server.client().await?;
        writer.update(b"noise1".to_vec(), b"y".to_vec()).await?;
        writer.update(label.clone(), b"v2".to_vec()).await?;
    }

    // reload from disk: retained head, obligation, and versions all restored
    let mut client = server.client().await?;
    client.persist_to(&state_file)?;
    assert_eq!(client.state.as_ref().unwrap().tree_size, retained_size);
    assert_eq!(client.state.as_ref().unwrap().root_hash, retained_root);
    assert!(client.monitoring_map.contains_key(&label));
    assert_eq!(client.label_versions.get(&label), Some(&1));

    // a fresh search must prove the new head extends the retained one (advertises
    // `last`, folds retained subtrees) and advances the view
    let s = client.search(label.clone(), None).await?;
    assert_eq!(s.version, Some(2));
    assert!(client.state.as_ref().unwrap().tree_size > retained_size);

    // the remaining operations all ride the same evolving trusted state
    client.contact_monitor(label.clone()).await?;
    client.owner_init(label.clone(), 3).await?;
    client
        .owner_monitor(label.clone(), vec![], 3, Some(2))
        .await?;
    client.distinguished(None).await?;
    assert!(!client.distinguished_entries.is_empty());

    // the whole run is reproducible from the persisted state alone
    let mut reloaded = server.client().await?;
    reloaded.persist_to(&state_file)?;
    assert_eq!(
        reloaded.state.as_ref().unwrap().tree_size,
        client.state.as_ref().unwrap().tree_size
    );

    // a rolled-back head (tree size below the retained view) is rejected
    let mut fresh = server.client().await?;
    let good = fresh.search_raw(label.clone(), None).await?;
    let mut rolled_back = good.clone();
    {
        let th = rolled_back
            .full_tree_head
            .as_mut()
            .unwrap()
            .tree_head
            .as_mut()
            .unwrap();
        th.tree_size = 1;
    }
    let mut victim = server.client().await?;
    victim.persist_to(&state_file)?;
    let result = victim
        .verify_search_response(&label, None, &rolled_back)
        .await;
    assert!(
        result.is_err(),
        "a head below the retained tree size must be rejected"
    );

    Ok(())
}

// A client carrying state from one log must reject responses from a different
// log (a fork) because the retained subtrees can't reconstruct its head.
#[tokio::test]
async fn test_state_from_one_log_rejects_another() -> Result<()> {
    let server_a = TestServer::contact_monitoring().await?;
    let server_b = TestServer::contact_monitoring().await?;

    let mut ca = server_a.client().await?;
    ca.update(b"shared".to_vec(), b"a".to_vec()).await?;
    ca.update(b"shared".to_vec(), b"a2".to_vec()).await?;
    ca.search(b"shared".to_vec(), None).await?;

    // server B has its own independent history for the same label
    let mut cb = server_b.client().await?;
    cb.update(b"shared".to_vec(), b"b".to_vec()).await?;
    cb.update(b"shared".to_vec(), b"b2".to_vec()).await?;
    let from_b = cb.search_raw(b"shared".to_vec(), None).await?;

    // ca advertises last, so B's head must prove it extends A's retained view; it can't
    let result = ca.verify_search_response(b"shared", None, &from_b).await;
    assert!(
        result.is_err(),
        "a response from a divergent log must not verify"
    );

    Ok(())
}
