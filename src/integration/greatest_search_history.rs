use super::harness::TestServer;
use anyhow::Result;

// A multi-version label registered behind existing log history must still yield
// a verifiable greatest-version search. Regression: the greatest-search binary
// ladder is deduped to one step per version, and a version proved absent at an
// early frontier peak used to drop the commitment the rightmost peak needs, so
// the search failed to verify at certain tree sizes (e.g. the label at log
// positions 4-5, 8-9, ...). Every in-tree test happened to register its
// multi-version label at position 0, the one shape that always worked.
#[tokio::test]
async fn test_greatest_search_multi_version_behind_history() -> Result<()> {
    let label = b"target".to_vec();

    for filler in 0..12u32 {
        let server = TestServer::contact_monitoring().await?;
        {
            let mut writer = server.client().await?;
            for i in 0..filler {
                writer
                    .update(format!("filler-{i}").into_bytes(), b"x".to_vec())
                    .await?;
            }
            writer.update(label.clone(), b"v0".to_vec()).await?;
            writer.update(label.clone(), b"v1".to_vec()).await?;
        }

        // a fresh verifying client, no prior state
        let mut reader = server.client().await?;
        let resp = reader
            .search(label.clone(), None)
            .await
            .unwrap_or_else(|e| panic!("greatest search failed behind {filler} entries: {e:?}"));
        assert_eq!(
            resp.version,
            Some(1),
            "wrong greatest version (filler={filler})"
        );
        assert_eq!(
            resp.value.map(|v| v.value),
            Some(b"v1".to_vec()),
            "wrong value (filler={filler})"
        );
    }

    Ok(())
}

// The owner-monitoring paths build the same per-frontier ladders and must also
// verify for a multi-version label behind existing history. Regression:
// owner-init/owner-monitor emitted a two-step base ladder at nodes where the
// label was absent, desyncing the client's ladder decode.
#[tokio::test]
async fn test_owner_monitoring_multi_version_behind_history() -> Result<()> {
    let label = b"target".to_vec();

    for filler in [3u32, 4, 7, 8] {
        let server = TestServer::contact_monitoring().await?;
        {
            let mut writer = server.client().await?;
            for i in 0..filler {
                writer
                    .update(format!("pre-{i}").into_bytes(), b"x".to_vec())
                    .await?;
            }
            writer.update(label.clone(), b"v0".to_vec()).await?;
            writer.update(label.clone(), b"v1".to_vec()).await?;
        }

        let mut c = server.client().await?;
        let greatest = c.search(label.clone(), None).await?.version.unwrap();
        // a valid start (< tree size) at/before the label, so the init/monitor
        // walks cross nodes where the label is absent
        let start = greatest as u64;

        c.contact_monitor(label.clone()).await?;
        c.distinguished(None).await?;
        c.owner_init(label.clone(), start)
            .await
            .unwrap_or_else(|e| panic!("owner_init behind {filler}: {e:?}"));
        c.owner_monitor(label.clone(), vec![], start, Some(greatest))
            .await
            .unwrap_or_else(|e| panic!("owner_monitor behind {filler}: {e:?}"));
    }

    Ok(())
}
