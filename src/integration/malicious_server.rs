use super::harness::TestServer;
use crate::proto::transparency::SearchResponse;
use anyhow::Result;

// A verifying client must reject every tampered field of an otherwise-valid
// greatest-version SearchResponse.
#[tokio::test]
async fn test_client_rejects_tampered_search_responses() -> Result<()> {
    let server = TestServer::contact_monitoring().await?;

    {
        let mut writer = server.client().await?;
        writer.update(b"victim".to_vec(), b"v0".to_vec()).await?;
        writer.update(b"victim".to_vec(), b"v1".to_vec()).await?;
        writer.update(b"victim".to_vec(), b"v2".to_vec()).await?;
        // unrelated entries so the frontier carries several prefix proofs
        writer.update(b"noise".to_vec(), b"x".to_vec()).await?;
    }

    let label = b"victim".to_vec();
    let mut fetcher = server.client().await?;
    let good = fetcher.search_raw(label.clone(), None).await?;

    // sanity: the untampered response verifies
    server
        .client()
        .await?
        .verify_search_response(&label, None, &good)
        .await
        .expect("honest response must verify");

    #[allow(clippy::type_complexity)]
    let mutations: Vec<(&str, Box<dyn Fn(&mut SearchResponse)>)> = vec![
        (
            "value bytes",
            Box::new(|r: &mut SearchResponse| {
                r.value.as_mut().unwrap().value = b"forged".to_vec();
            }),
        ),
        (
            "commitment opening",
            Box::new(|r: &mut SearchResponse| {
                r.opening[0] ^= 0xff;
            }),
        ),
        (
            "reported version",
            Box::new(|r: &mut SearchResponse| {
                r.version = Some(r.version.unwrap() + 1);
            }),
        ),
        (
            "ladder vrf proof",
            Box::new(|r: &mut SearchResponse| {
                r.binary_ladder[0].proof[0] ^= 0xff;
            }),
        ),
        (
            "ladder commitment",
            Box::new(|r: &mut SearchResponse| {
                for step in r.binary_ladder.iter_mut() {
                    if let Some(c) = step.commitment.as_mut() {
                        c[0] ^= 0xff;
                        break;
                    }
                }
            }),
        ),
        (
            "prefix proof element",
            Box::new(|r: &mut SearchResponse| {
                for p in r.search.as_mut().unwrap().prefix_proofs.iter_mut() {
                    if let Some(e) = p.elements.get_mut(0) {
                        e[0] ^= 0xff;
                        return;
                    }
                }
            }),
        ),
        (
            "log timestamp",
            Box::new(|r: &mut SearchResponse| {
                if let Some(ts) = r.search.as_mut().unwrap().timestamps.last_mut() {
                    *ts += 1;
                }
            }),
        ),
        (
            "inclusion proof",
            Box::new(|r: &mut SearchResponse| {
                let inc = r.search.as_mut().unwrap().inclusion.as_mut().unwrap();
                if let Some(e) = inc.elements.get_mut(0) {
                    e[0] ^= 0xff;
                }
            }),
        ),
        (
            "head signature",
            Box::new(|r: &mut SearchResponse| {
                let th = r
                    .full_tree_head
                    .as_mut()
                    .unwrap()
                    .tree_head
                    .as_mut()
                    .unwrap();
                th.signatures[0].signature[0] ^= 0xff;
            }),
        ),
    ];

    for (name, mutate) in mutations {
        let mut tampered = good.clone();
        mutate(&mut tampered);
        if tampered == good {
            panic!("mutation '{}' did not change the response", name);
        }
        let result = server
            .client()
            .await?
            .verify_search_response(&label, None, &tampered)
            .await;
        assert!(
            result.is_err(),
            "client must reject tampered field: {}",
            name
        );
    }

    Ok(())
}
