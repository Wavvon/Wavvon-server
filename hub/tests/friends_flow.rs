
use serde_json::json;
use voxply_identity::Identity;

#[path = "common.rs"] mod common;

#[tokio::test]
async fn friend_request_accept_flow() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;

    // Alice sends friend request to Bob
    server
        .post("/friends")
        .authorization_bearer(&alice_token)
        .json(&json!({ "target_public_key": bob.public_key_hex() }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Bob sees pending request
    let resp = server
        .get("/friends/pending")
        .authorization_bearer(&bob_token)
        .await;
    let pending: serde_json::Value = resp.json();
    assert_eq!(pending.as_array().unwrap().len(), 1);

    // Alice's friends list is empty (request not yet accepted)
    let resp = server.get("/friends").authorization_bearer(&alice_token).await;
    let friends: serde_json::Value = resp.json();
    assert_eq!(friends.as_array().unwrap().len(), 0);

    // Bob accepts
    server
        .post(&format!("/friends/{}/accept", alice.public_key_hex()))
        .authorization_bearer(&bob_token)
        .await
        .assert_status_ok();

    // Both have each other in friends list
    let resp = server.get("/friends").authorization_bearer(&alice_token).await;
    let friends: serde_json::Value = resp.json();
    assert_eq!(friends.as_array().unwrap().len(), 1);

    let resp = server.get("/friends").authorization_bearer(&bob_token).await;
    let friends: serde_json::Value = resp.json();
    assert_eq!(friends.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn cannot_friend_yourself() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let token = common::authenticate(&server, &alice).await;

    let resp = server
        .post("/friends")
        .authorization_bearer(&token)
        .json(&json!({ "target_public_key": alice.public_key_hex() }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn remove_friend() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;

    // Establish friendship
    server
        .post("/friends")
        .authorization_bearer(&alice_token)
        .json(&json!({ "target_public_key": bob.public_key_hex() }))
        .await;
    server
        .post(&format!("/friends/{}/accept", alice.public_key_hex()))
        .authorization_bearer(&bob_token)
        .await;

    // Alice removes Bob
    server
        .delete(&format!("/friends/{}", bob.public_key_hex()))
        .authorization_bearer(&alice_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Both lists are empty
    let resp = server.get("/friends").authorization_bearer(&alice_token).await;
    let friends: serde_json::Value = resp.json();
    assert_eq!(friends.as_array().unwrap().len(), 0);

    let resp = server.get("/friends").authorization_bearer(&bob_token).await;
    let friends: serde_json::Value = resp.json();
    assert_eq!(friends.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn cross_hub_friend_add_skips_pending_and_caches_hub_url() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    // Bob is not a member of this hub — he lives on remote_hub.
    let bob = Identity::generate();
    let remote_hub = "https://other-hub.example.com";

    // Alice adds Bob as a cross-hub friend (hub_url provided + cached name)
    server
        .post("/friends")
        .authorization_bearer(&alice_token)
        .json(&json!({
            "target_public_key": bob.public_key_hex(),
            "hub_url": remote_hub,
            "display_name": "Bob from remote",
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // No pending request should appear — cross-hub adds skip pending state
    // because there's no federated notification path yet.
    let resp = server
        .get("/friends/pending")
        .authorization_bearer(&alice_token)
        .await;
    let pending: serde_json::Value = resp.json();
    assert_eq!(pending.as_array().unwrap().len(), 0, "cross-hub adds shouldn't be pending");

    // Bob should appear immediately in Alice's friends list, with hub_url
    // and the cached display_name surfaced.
    let resp = server
        .get("/friends")
        .authorization_bearer(&alice_token)
        .await;
    let friends = resp.json::<serde_json::Value>();
    let arr = friends.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let f = &arr[0];
    assert_eq!(f["public_key"], bob.public_key_hex());
    assert_eq!(f["hub_url"], remote_hub);
    assert_eq!(f["display_name"], "Bob from remote");
}

#[tokio::test]
async fn same_hub_friend_omits_hub_url_in_response() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;

    // Establish a same-hub friendship the normal way (no hub_url)
    server
        .post("/friends")
        .authorization_bearer(&alice_token)
        .json(&json!({ "target_public_key": bob.public_key_hex() }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    server
        .post(&format!("/friends/{}/accept", alice.public_key_hex()))
        .authorization_bearer(&bob_token)
        .await
        .assert_status_ok();

    let resp = server.get("/friends").authorization_bearer(&alice_token).await;
    let friends = resp.json::<serde_json::Value>();
    let arr = friends.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    // Same-hub friends don't carry a hub_url — the friend lives on this hub.
    assert!(arr[0]["hub_url"].is_null(), "same-hub friend should have null hub_url");
}

#[tokio::test]
async fn accept_nonexistent_request_returns_404() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post(&format!("/friends/{}/accept", bob.public_key_hex()))
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
