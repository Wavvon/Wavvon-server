use serde_json::json;
use wavvon_identity::{DhKeyRecord, Identity};

#[path = "common.rs"]
mod common;

fn make_dh_publish_body(identity: &Identity) -> serde_json::Value {
    let (_, dh_pub) = identity.dh_keypair();
    let dh_pubkey_hex = hex::encode(dh_pub.as_bytes());
    let msg = DhKeyRecord::signing_bytes(&identity.public_key_hex(), &dh_pubkey_hex);
    let sig = hex::encode(identity.sign(&msg).to_bytes());
    json!({
        "dh_pubkey_hex": dh_pubkey_hex,
        "signature_hex": sig,
    })
}

#[tokio::test]
async fn publish_and_fetch_dh_key() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let token = common::authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();

    // GET before any key is published ? 404
    server
        .get(&format!("/identity/{pubkey}/dh-key"))
        .await
        .assert_status(axum::http::StatusCode::NOT_FOUND);

    // PUT the DH key
    let body = make_dh_publish_body(&alice);
    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .authorization_bearer(&token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::OK);

    // GET now returns the key
    let resp = server.get(&format!("/identity/{pubkey}/dh-key")).await;
    resp.assert_status_ok();
    let result: serde_json::Value = resp.json();
    assert_eq!(result["dh_pubkey_hex"], body["dh_pubkey_hex"]);
}

#[tokio::test]
async fn publish_dh_key_rejects_wrong_identity() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;

    // Alice tries to publish a DH key under Bob's pubkey — must be rejected.
    let bob_pubkey = bob.public_key_hex();
    let body = make_dh_publish_body(&bob);
    server
        .put(&format!("/identity/{bob_pubkey}/dh-key"))
        .authorization_bearer(&alice_token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_dh_key_rejects_bad_signature() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let token = common::authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();

    let (_, dh_pub) = alice.dh_keypair();
    let dh_pubkey_hex = hex::encode(dh_pub.as_bytes());
    // Tampered: signature is all-zeros.
    let bad_sig = "0".repeat(128);

    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .authorization_bearer(&token)
        .json(&json!({
            "dh_pubkey_hex": dh_pubkey_hex,
            "signature_hex": bad_sig,
        }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_requires_authentication() {
    let server = common::setup().await;
    let alice = Identity::generate();
    // Register alice so the pubkey exists, but don't use the token.
    common::authenticate(&server, &alice).await;
    let pubkey = alice.public_key_hex();
    let body = make_dh_publish_body(&alice);

    server
        .put(&format!("/identity/{pubkey}/dh-key"))
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::UNAUTHORIZED);
}
