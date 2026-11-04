use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// `GET /hub/members` pages by the last row's `public_key`. It used to stop
/// at 1000 rows and say nothing, so a large hub's admin list was silently
/// short.
#[tokio::test]
async fn member_list_pages_to_exhaustion_without_repeats() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;
    for _ in 0..2 {
        common::authenticate(&server, &Identity::generate()).await;
    }

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    // Bounded, so an ignored cursor fails the assertion below instead of
    // looping forever on the same page.
    for _ in 0..10 {
        let url = match &cursor {
            Some(c) => format!("/hub/members?limit=1&cursor={c}"),
            None => "/hub/members?limit=1".to_string(),
        };
        let page: Vec<serde_json::Value> =
            server.get(&url).authorization_bearer(&token).await.json();
        let Some(last) = page.last() else { break };
        cursor = Some(last["public_key"].as_str().unwrap().to_string());
        seen.extend(
            page.iter()
                .map(|m| m["public_key"].as_str().unwrap().to_string()),
        );
    }
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(seen.len(), 3, "every member once: {seen:?}");
    assert_eq!(unique.len(), 3, "no member twice: {seen:?}");
}
