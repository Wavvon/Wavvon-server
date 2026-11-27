use wavvon_identity::Identity;

use crate::common;

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

/// A key that authenticated but never joined has a `users` row too; the admin
/// list showed it as a nameless member that the member sidebar never shows.
#[tokio::test]
async fn member_list_leaves_out_keys_that_never_joined() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;
    let stranger = Identity::generate();
    common::authenticate(&server, &stranger).await;
    sqlx::query("UPDATE users SET is_member = FALSE WHERE public_key = $1")
        .bind(stranger.public_key_hex())
        .execute(&server.state().db)
        .await
        .unwrap();

    let page: Vec<serde_json::Value> = server
        .get("/hub/members")
        .authorization_bearer(&token)
        .await
        .json();
    let keys: Vec<&str> = page
        .iter()
        .map(|m| m["public_key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, vec![owner.public_key_hex().as_str()]);
}
