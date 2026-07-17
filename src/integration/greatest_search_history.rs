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
