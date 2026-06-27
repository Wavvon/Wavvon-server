use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Happy path: put contacts, read them back, delete one
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_and_get_contacts() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let contact_a = Identity::generate();
    let contact_b = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Set contacts with threshold 1.
    let resp = server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "contacts": [contact_a.public_key_hex(), contact_b.public_key_hex()],
            "threshold": 1
        }))
        .await;
    resp.assert_status_ok();

    // Read back.
    let resp = server
        .get("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    let contacts = body["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 2);
    assert_eq!(body["threshold"], 1);
}

#[tokio::test]
async fn put_replaces_existing_contacts() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let c1 = Identity::generate();
    let c2 = Identity::generate();
    let c3 = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&token)
        .json(&json!({ "contacts": [c1.public_key_hex(), c2.public_key_hex()], "threshold": 1 }))
        .await;

    // Replace with just c3.
    server
        .put("/recovery/contacts")
        .authorization_bearer(&token)
        .json(&json!({ "contacts": [c3.public_key_hex()], "threshold": 1 }))
        .await;

    let resp = server
        .get("/recovery/contacts")
        .authorization_bearer(&token)
        .await;
    let body = resp.json::<serde_json::Value>();
    let contacts = body["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["pubkey"], c3.public_key_hex());
}

#[tokio::test]
async fn cannot_set_more_than_5_contacts() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let six: Vec<String> = (0..6)
        .map(|_| Identity::generate().public_key_hex())
        .collect();
    let resp = server
        .put("/recovery/contacts")
        .authorization_bearer(&token)
        .json(&json!({ "contacts": six, "threshold": 1 }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_one_contact() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let c1 = Identity::generate();
    let c2 = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&token)
        .json(&json!({ "contacts": [c1.public_key_hex(), c2.public_key_hex()], "threshold": 1 }))
        .await;

    let resp = server
        .delete(&format!("/recovery/contacts/{}", c1.public_key_hex()))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    let resp = server
        .get("/recovery/contacts")
        .authorization_bearer(&token)
        .await;
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["contacts"].as_array().unwrap().len(), 1);
    assert_eq!(body["contacts"][0]["pubkey"], c2.public_key_hex());
}

// ---------------------------------------------------------------------------
// Rotation request + admin approve/deny
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotate_key_rejected_when_no_contacts_configured() {
    let server = common::setup().await;
    let new_key = Identity::generate();

    // Nobody configured contacts for old_pubkey.
    let old_pubkey = Identity::generate().public_key_hex();
    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": old_pubkey,
            "new_pubkey": new_key.public_key_hex(),
            "attestations": []
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotate_key_happy_path_and_admin_approve() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();

    // Owner must be registered to auth and set contacts.
    let owner_token = common::authenticate(&server, &owner).await;
    let _contact_token = common::authenticate(&server, &contact).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "contacts": [contact.public_key_hex()],
            "threshold": 1
        }))
        .await
        .assert_status_ok();

    // Open a rotation request with one (stub) attestation from the contact.
    // The hub doesn't verify the Ed25519 sig in the current implementation —
    // it checks that the attester is in the contact list.
    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "attestations": [{
                "attester": contact.public_key_hex(),
                "signature": "stub_sig"
            }]
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["attestation_count"], 1);
    // Threshold = 1, so should flip to ready_for_review.
    assert_eq!(body["status"], "ready_for_review");
    let request_id = body["id"].as_str().unwrap().to_string();

    // Grant owner the admin role so they can approve.
    server
        .put(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await;

    // Admin approve.
    let resp = server
        .post(&format!("/admin/recovery/{}/approve", request_id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn admin_list_pending_recovery_requests() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();

    let owner_token = common::authenticate(&server, &owner).await;
    common::authenticate(&server, &contact).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await;

    server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "attestations": [{ "attester": contact.public_key_hex(), "signature": "sig" }]
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Grant owner admin so they can list.
    server
        .put(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await;

    let resp = server
        .get("/admin/recovery/pending")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let arr = resp.json::<serde_json::Value>();
    assert!(arr.as_array().unwrap().len() >= 1);
}

#[tokio::test]
async fn admin_deny_recovery_request() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();

    let owner_token = common::authenticate(&server, &owner).await;
    common::authenticate(&server, &contact).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await;

    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "attestations": [{ "attester": contact.public_key_hex(), "signature": "sig" }]
        }))
        .await;
    let body = resp.json::<serde_json::Value>();
    let id = body["id"].as_str().unwrap().to_string();

    server
        .put(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await;

    let resp = server
        .post(&format!("/admin/recovery/{}/deny", id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
}
