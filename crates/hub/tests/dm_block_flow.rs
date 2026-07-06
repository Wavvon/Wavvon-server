use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// PUT / GET dm-blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_and_get_dm_blocks() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;

    let resp = server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await;
    resp.assert_status_ok();

    let resp = server
        .get("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    let pubkeys = body["pubkeys"].as_array().unwrap();
    assert_eq!(pubkeys.len(), 1);
    assert_eq!(pubkeys[0], bob.public_key_hex());
}

#[tokio::test]
async fn put_dm_blocks_replaces_existing() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;

    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await;

    // Replace with carol only.
    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [carol.public_key_hex()] }))
        .await;

    let resp = server
        .get("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .await;
    let body = resp.json::<serde_json::Value>();
    let pubkeys = body["pubkeys"].as_array().unwrap();
    assert_eq!(pubkeys.len(), 1);
    assert_eq!(pubkeys[0], carol.public_key_hex());
}

// ---------------------------------------------------------------------------
// DM block enforcement: sender can't detect the block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocked_dm_returns_success_shaped_response() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob_token = common::authenticate(&server, &bob).await;

    // Alice blocks Bob.
    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await
        .assert_status_ok();

    // Bob starts a DM conversation with Alice.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&bob_token)
        .json(&json!({ "members": [alice.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv = resp.json::<serde_json::Value>();
    let conv_id = conv["id"].as_str().unwrap();

    // Bob sends a message to Alice. Should return 201 (success-shaped)
    // even though Alice has blocked Bob.
    let resp = server
        .post(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hello alice" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // The message must NOT appear in Alice's inbox.
    let resp = server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(
        arr.len(),
        0,
        "blocked message must not be stored in Alice's inbox"
    );
}

#[tokio::test]
async fn unblocked_dm_is_delivered_normally() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob_token = common::authenticate(&server, &bob).await;

    // Alice does NOT block Bob.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&bob_token)
        .json(&json!({ "members": [alice.public_key_hex()] }))
        .await;
    let conv = resp.json::<serde_json::Value>();
    let conv_id = conv["id"].as_str().unwrap();

    server
        .post(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hi" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&alice_token)
        .await;
    let messages = resp.json::<serde_json::Value>();
    assert_eq!(
        messages.as_array().unwrap().len(),
        1,
        "unblocked message should be stored"
    );
}
