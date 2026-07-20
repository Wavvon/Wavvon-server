use serde_json::json;
use wavvon_identity::{
    recovery_attestation_signing_bytes, recovery_request_signing_bytes, Identity,
};

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
// Helpers for the rotate-key / attest flow
// ---------------------------------------------------------------------------

/// Computes the new-key proof (recovery-attestation.md §4) the requester
/// must submit inline with `POST /recovery/rotate-key`.
fn new_key_proof(hub_pubkey: &str, old_pubkey: &str, new_key: &Identity) -> String {
    let bytes = recovery_request_signing_bytes(hub_pubkey, old_pubkey, &new_key.public_key_hex());
    hex::encode(new_key.sign(&bytes).to_bytes())
}

/// Computes a contact's attestation signature over the bundle returned by
/// `GET /recovery/rotation-request/:id`.
fn attestation_signature(
    hub_pubkey: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    nonce: &str,
    contact: &Identity,
) -> String {
    let bytes = recovery_attestation_signing_bytes(hub_pubkey, old_pubkey, new_pubkey, nonce);
    hex::encode(contact.sign(&bytes).to_bytes())
}

// ---------------------------------------------------------------------------
// Rotation request + admin approve/deny
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotate_key_rejected_when_no_contacts_configured() {
    let server = common::setup().await;
    let hub_pubkey = server.state().hub_identity.public_key_hex();
    let new_key = Identity::generate();

    // Nobody configured contacts for old_pubkey.
    let old_pubkey = Identity::generate().public_key_hex();
    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": old_pubkey,
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": new_key_proof(&hub_pubkey, &old_pubkey, &new_key),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotate_key_rejected_without_new_key_proof() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await
        .assert_status_ok();

    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": "not-a-valid-signature",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rotate_key_rejected_with_inline_attestations() {
    let server = common::setup().await;
    let hub_pubkey = server.state().hub_identity.public_key_hex();

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await
        .assert_status_ok();

    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": new_key_proof(&hub_pubkey, &owner.public_key_hex(), &new_key),
            "attestations": [{ "attester": contact.public_key_hex(), "signature": "stub" }],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

/// Full happy path: open a request with new-key proof, contact fetches the
/// bundle, signs it, posts the attestation, request flips to
/// ready_for_review at threshold, and admin approve still works.
#[tokio::test]
async fn rotate_key_open_attest_and_admin_approve() {
    let server = common::setup().await;
    let hub_pubkey = server.state().hub_identity.public_key_hex();

    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();

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

    // Open the request with the new-key proof, no inline attestations.
    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": new_key_proof(&hub_pubkey, &owner.public_key_hex(), &new_key),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["attestation_count"], 0);
    assert_eq!(body["status"], "pending");
    let request_id = body["id"].as_str().unwrap().to_string();
    assert!(!body["nonce"].as_str().unwrap().is_empty());

    // Contact fetches the bundle to sign.
    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    resp.assert_status_ok();
    let bundle = resp.json::<serde_json::Value>();
    assert_eq!(bundle["hub_pubkey"], hub_pubkey);
    assert_eq!(bundle["old_pubkey"], owner.public_key_hex());
    assert_eq!(bundle["new_pubkey"], new_key.public_key_hex());
    assert_eq!(bundle["threshold"], 1);
    assert_eq!(bundle["attestation_count"], 0);
    let nonce = bundle["nonce"].as_str().unwrap().to_string();

    // Contact signs and posts the attestation.
    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &contact,
    );
    let resp = server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": sig }))
        .await;
    resp.assert_status_ok();

    // Now ready_for_review (threshold 1 reached).
    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let bundle = resp.json::<serde_json::Value>();
    assert_eq!(bundle["status"], "ready_for_review");
    assert_eq!(bundle["attestation_count"], 1);

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

// ---------------------------------------------------------------------------
// Attestation rejections
// ---------------------------------------------------------------------------

async fn open_request_with_one_contact(
    server: &common::TestHarness,
) -> (String, String, Identity, Identity, Identity, String) {
    let hub_pubkey = server.state().hub_identity.public_key_hex();
    let owner = Identity::generate();
    let contact = Identity::generate();
    let new_key = Identity::generate();
    let owner_token = common::authenticate(server, &owner).await;
    common::authenticate(server, &contact).await;

    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await
        .assert_status_ok();

    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": owner.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": new_key_proof(&hub_pubkey, &owner.public_key_hex(), &new_key),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    let request_id = body["id"].as_str().unwrap().to_string();

    (hub_pubkey, request_id, owner, contact, new_key, owner_token)
}

#[tokio::test]
async fn attest_rejected_with_bad_signature() {
    let server = common::setup().await;
    let (hub_pubkey, request_id, owner, contact, new_key, _owner_token) =
        open_request_with_one_contact(&server).await;

    // Sign with the wrong key (new_key instead of contact).
    let bad_sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        "wrong-nonce",
        &new_key,
    );

    let resp = server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": bad_sig }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attest_rejected_when_attester_not_a_contact() {
    let server = common::setup().await;
    let (hub_pubkey, request_id, owner, _contact, new_key, _owner_token) =
        open_request_with_one_contact(&server).await;

    let stranger = Identity::generate();
    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let nonce = resp.json::<serde_json::Value>()["nonce"]
        .as_str()
        .unwrap()
        .to_string();

    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &stranger,
    );
    let resp = server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": stranger.public_key_hex(), "signature": sig }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn attest_rejected_when_attester_is_old_or_new() {
    let server = common::setup().await;
    let (hub_pubkey, request_id, owner, _contact, new_key, _owner_token) =
        open_request_with_one_contact(&server).await;

    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let nonce = resp.json::<serde_json::Value>()["nonce"]
        .as_str()
        .unwrap()
        .to_string();

    // Attester == new_pubkey.
    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &new_key,
    );
    let resp = server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": new_key.public_key_hex(), "signature": sig }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Attester == old_pubkey.
    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &owner,
    );
    let resp = server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": owner.public_key_hex(), "signature": sig }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn attest_dedupes_repeat_submissions_from_same_contact() {
    let server = common::setup().await;
    let (hub_pubkey, request_id, owner, contact, new_key, owner_token) =
        open_request_with_one_contact(&server).await;

    // Bump threshold to 2 so a duplicate from the same contact can't flip
    // status on its own -- but there's only one contact configured, so
    // reuse the existing single-contact list and raise threshold via a
    // second contact instead.
    let contact_2 = Identity::generate();
    server
        .put("/recovery/contacts")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "contacts": [contact.public_key_hex(), contact_2.public_key_hex()],
            "threshold": 2
        }))
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let nonce = resp.json::<serde_json::Value>()["nonce"]
        .as_str()
        .unwrap()
        .to_string();

    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &contact,
    );

    // Post the same attestation twice.
    server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": sig.clone() }))
        .await
        .assert_status_ok();
    server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": sig }))
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let bundle = resp.json::<serde_json::Value>();
    // Still 1, not 2 -- deduped, and below the threshold of 2.
    assert_eq!(bundle["attestation_count"], 1);
    assert_eq!(bundle["status"], "pending");
}

#[tokio::test]
async fn admin_list_pending_recovery_requests() {
    let server = common::setup().await;
    let (_hub_pubkey, request_id, owner, _contact, _new_key, owner_token) =
        open_request_with_one_contact(&server).await;
    let _ = request_id;

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
    assert!(!arr.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn admin_deny_recovery_request() {
    let server = common::setup().await;
    let (_hub_pubkey, request_id, owner, _contact, _new_key, owner_token) =
        open_request_with_one_contact(&server).await;

    server
        .put(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await;

    let resp = server
        .post(&format!("/admin/recovery/{}/deny", request_id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
}

// ---------------------------------------------------------------------------
// 14-day expiry sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pending_request_expires_after_14_days() {
    let server = common::setup().await;
    let (_hub_pubkey, request_id, _owner, _contact, _new_key, _owner_token) =
        open_request_with_one_contact(&server).await;

    // Backdate the request past the 14-day expiry window.
    let fifteen_days_ago = wavvon_hub::auth::handlers::unix_timestamp() - 15 * 24 * 3600;
    sqlx::query("UPDATE key_rotation_requests SET created_at = $1 WHERE id = $2")
        .bind(fifteen_days_ago)
        .bind(&request_id)
        .execute(&server.state().db)
        .await
        .unwrap();

    wavvon_hub::retention_worker::run_sweep(server.state()).await;

    let resp = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await;
    let bundle = resp.json::<serde_json::Value>();
    assert_eq!(bundle["status"], "expired");
}

// ---------------------------------------------------------------------------
// Approve transfers non-owner roles only; owner never rides along
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_transfers_non_owner_roles_and_never_owner() {
    let server = common::setup().await;
    let (hub_pubkey, request_id, owner, contact, new_key, owner_token) =
        open_request_with_one_contact(&server).await;

    // Old key holds owner + a custom role.
    server
        .put(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await;
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "moderator", "priority": 10, "permissions": ["kick"] }))
        .await;
    let role_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    server
        .put(&format!(
            "/users/{}/roles/{}",
            owner.public_key_hex(),
            role_id
        ))
        .authorization_bearer(&owner_token)
        .await;

    // Attest to threshold and approve.
    let bundle = server
        .get(&format!("/recovery/rotation-request/{}", request_id))
        .await
        .json::<serde_json::Value>();
    let nonce = bundle["nonce"].as_str().unwrap().to_string();
    let sig = attestation_signature(
        &hub_pubkey,
        &owner.public_key_hex(),
        &new_key.public_key_hex(),
        &nonce,
        &contact,
    );
    server
        .post(&format!("/recovery/rotation-request/{}/attest", request_id))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": sig }))
        .await
        .assert_status_ok();
    server
        .post(&format!("/admin/recovery/{}/approve", request_id))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // New key gained the custom role but NOT owner; old key keeps only owner.
    let new_roles = sqlx::query_scalar::<_, String>(
        "SELECT role_id FROM user_roles WHERE user_public_key = $1 ORDER BY role_id",
    )
    .bind(new_key.public_key_hex())
    .fetch_all(&server.state().db)
    .await
    .unwrap();
    assert!(new_roles.contains(&role_id));
    assert!(!new_roles.contains(&"builtin-owner".to_string()));
    let old_roles = sqlx::query_scalar::<_, String>(
        "SELECT role_id FROM user_roles WHERE user_public_key = $1 ORDER BY role_id",
    )
    .bind(owner.public_key_hex())
    .fetch_all(&server.state().db)
    .await
    .unwrap();
    assert_eq!(old_roles, vec!["builtin-owner".to_string()]);
}
