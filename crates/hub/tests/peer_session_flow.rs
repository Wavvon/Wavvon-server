use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// A peer hub authenticates with `is_hub: true`, and any key may say so. Its
// session is not a membership: it must reach the alliance surface it is
// entitled to and nothing else, whatever the hub's admission settings.

async fn authenticate_as_hub(server: &axum_test::TestServer, hub: &Identity) -> String {
    let pub_key = hub.public_key_hex();
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let verify = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(hub.sign(&bytes).to_bytes()),
            "is_hub": true,
        }))
        .await;
    verify.assert_status_success();
    verify.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn make_channel(server: &axum_test::TestServer, owner: &str, name: &str) -> String {
    let ch: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(owner)
        .json(&json!({ "name": name, "channel_type": "text" }))
        .await
        .json();
    let id = ch["id"].as_str().unwrap().to_string();
    server
        .post(&format!("/channels/{id}/messages"))
        .authorization_bearer(owner)
        .json(&json!({ "content": "secret" }))
        .await
        .assert_status_success();
    id
}

async fn closed_hub() -> (common::TestHarness, String) {
    let (h, owner) = common::setup_with_owner().await;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('invite_only', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'")
        .execute(&h.state().db)
        .await
        .unwrap();
    (h, owner)
}

#[tokio::test]
async fn a_peer_session_on_an_invite_only_hub_is_not_a_member() {
    let (h, owner) = closed_hub().await;
    let channel = make_channel(&h, &owner, "general").await;

    let hub = Identity::generate();
    let token = authenticate_as_hub(&h, &hub).await;

    let me: serde_json::Value = h.get("/users").authorization_bearer(&owner).await.json();
    let owner_pk = me.as_array().unwrap()[0]["public_key"]
        .as_str()
        .unwrap()
        .to_string();

    let is_member: bool = sqlx::query_scalar("SELECT is_member FROM users WHERE public_key = $1")
        .bind(hub.public_key_hex())
        .fetch_one(&h.state().db)
        .await
        .unwrap();
    let mut leaks: Vec<String> = Vec::new();
    if is_member {
        leaks.push("admitted as a member".into());
    }

    for path in [
        "/users".to_string(),
        format!("/users/{owner_pk}/profile"),
        format!("/channels/{channel}/messages"),
        "/channels".to_string(),
    ] {
        let r = h.get(&path).authorization_bearer(&token).await;
        if !r.status_code().is_client_error() {
            leaks.push(format!("GET {path} -> {}", r.status_code()));
        }
    }

    let r = h
        .post(&format!("/channels/{channel}/messages"))
        .authorization_bearer(&token)
        .json(&json!({ "content": "hi" }))
        .await;
    if !r.status_code().is_client_error() {
        leaks.push(format!("POST message -> {}", r.status_code()));
    }
    assert!(leaks.is_empty(), "peer session leaks: {leaks:#?}");
}

#[tokio::test]
async fn an_allied_peer_reaches_only_what_the_alliance_shares() {
    let (h, owner) = closed_hub().await;
    let shared = make_channel(&h, &owner, "shared").await;
    let private = make_channel(&h, &owner, "private").await;

    let alliance: serde_json::Value = h
        .post("/alliances")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "A" }))
        .await
        .json();
    let aid = alliance["id"].as_str().unwrap().to_string();
    h.post(&format!("/alliances/{aid}/channels"))
        .authorization_bearer(&owner)
        .json(&json!({ "channel_id": shared }))
        .await
        .assert_status_success();

    let hub = Identity::generate();
    let token = authenticate_as_hub(&h, &hub).await;
    sqlx::query(
        "INSERT INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at)
         VALUES ($1, $2, 'peer', 'http://peer.invalid', 0)",
    )
    .bind(&aid)
    .bind(hub.public_key_hex())
    .execute(&h.state().db)
    .await
    .unwrap();

    h.get(&format!("/alliances/{aid}/channels"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();

    let read = h
        .get(&format!("/alliances/{aid}/channels/{shared}/messages"))
        .authorization_bearer(&token)
        .await;
    read.assert_status_ok();
    assert_eq!(
        read.json::<serde_json::Value>().as_array().unwrap().len(),
        1
    );

    h.post(&format!("/alliances/{aid}/channels/{shared}/messages"))
        .authorization_bearer(&token)
        .json(&json!({ "content": "from the ally" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // A channel the alliance does not share is not reachable by any route.
    let r = h
        .post(&format!("/alliances/{aid}/channels/{private}/messages"))
        .authorization_bearer(&token)
        .json(&json!({ "content": "nope" }))
        .await;
    assert!(r.status_code().is_client_error(), "got {}", r.status_code());
    let r = h
        .get(&format!("/alliances/{aid}/channels/{private}/messages"))
        .authorization_bearer(&token)
        .await;
    assert!(r.status_code().is_client_error(), "got {}", r.status_code());
    let r = h
        .get(&format!("/channels/{shared}/messages"))
        .authorization_bearer(&token)
        .await;
    assert!(r.status_code().is_client_error(), "got {}", r.status_code());
}
