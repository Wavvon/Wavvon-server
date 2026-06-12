use axum_test::TestServer;
use serde_json::{json, Value};
use voxply_hub::auth::models::ChallengeResponse;
use voxply_identity::{compute_security_level, Identity};

#[path = "common.rs"]
mod common;

async fn do_auth_with_pow(
    server: &TestServer,
    identity: &Identity,
    pow_nonce: Option<u64>,
    pow_level: Option<u8>,
) -> axum_test::TestResponse {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });

    if let (Some(nonce), Some(level)) = (pow_nonce, pow_level) {
        body["pow_proof"] = json!({
            "level": level,
            "nonce": nonce.to_string(),
        });
    }

    server.post("/auth/verify").json(&body).await
}

// ---- /admin/settings/pow ----

#[tokio::test]
async fn get_pow_settings_defaults_to_zero() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/settings/pow")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 0);
}

#[tokio::test]
async fn patch_and_get_pow_settings() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 5 }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/settings/pow")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 5);
}

#[tokio::test]
async fn pow_settings_routes_reject_non_admin() {
    let server = common::setup().await;
    // First user becomes owner
    let owner = Identity::generate();
    let _owner_token = common::authenticate(&server, &owner).await;

    // Second user is plain member
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    server
        .get("/admin/settings/pow")
        .authorization_bearer(&member_token)
        .await
        .assert_status_forbidden();

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&member_token)
        .json(&json!({ "min_pow_level": 3 }))
        .await
        .assert_status_forbidden();
}

// ---- /info includes min_pow_level ----

#[tokio::test]
async fn info_includes_min_pow_level() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Default: 0
    let resp = server.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 0, "info must include min_pow_level");

    // After raising it
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 4 }))
        .await
        .assert_status_ok();

    let resp = server.get("/info").await;
    let body: Value = resp.json();
    assert_eq!(body["min_pow_level"], 4);
}

// ---- Auth enforcement ----

#[tokio::test]
async fn auth_succeeds_without_pow_when_min_is_zero() {
    let server = common::setup().await;
    let user = Identity::generate();
    // min_pow_level defaults to 0 — no proof needed
    let resp = do_auth_with_pow(&server, &user, None, None).await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn auth_rejected_when_pow_missing_and_min_level_set() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Raise the minimum
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 4 }))
        .await
        .assert_status_ok();

    // New user tries to auth without pow_proof
    let newcomer = Identity::generate();
    let resp = do_auth_with_pow(&server, &newcomer, None, None).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}

#[tokio::test]
async fn auth_rejected_when_pow_level_below_minimum() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 8 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let pub_key = newcomer.public_key_hex();

    // Find a nonce whose hash achieves exactly 4–7 leading zero bits: it
    // satisfies the low level-4 target but provably falls short of the
    // hub's minimum of 8.  Such nonces are the overwhelming majority
    // (probability ~255/256 per candidate), so this loop terminates almost
    // immediately and makes the test fully deterministic.
    const LOW: u32 = 4;
    const MIN: u32 = 8;
    let (nonce, level) = {
        let mut search_start: u64 = 0;
        loop {
            let (n, lvl) = compute_security_level(&pub_key, search_start, LOW);
            if lvl < MIN {
                // This nonce satisfies LOW but not MIN — exactly what we need.
                break (n, lvl);
            }
            // Unlucky: the nonce accidentally meets MIN too.  Skip past it
            // and keep searching from the next candidate.
            search_start = n + 1;
        }
    };
    assert!(level >= LOW, "nonce must satisfy the low target");
    assert!(
        level < MIN,
        "nonce must NOT satisfy the hub minimum (test invariant)"
    );

    // Submit with the low level — must be rejected
    let resp = do_auth_with_pow(&server, &newcomer, Some(nonce), Some(level as u8)).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}

#[tokio::test]
async fn auth_succeeds_with_valid_pow_proof() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Use a very low level so the test runs fast
    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 1 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let pub_key = newcomer.public_key_hex();
    let (nonce, level) = compute_security_level(&pub_key, 0, 1);
    assert!(level >= 1);

    let resp = do_auth_with_pow(&server, &newcomer, Some(nonce), Some(level as u8)).await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn auth_rejected_with_fake_nonce() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/pow")
        .authorization_bearer(&token)
        .json(&json!({ "min_pow_level": 1 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();

    // Claim level 32 with nonce=0. SHA256(pubkey||0) having ≥32 leading zero
    // bits is a 1-in-4-billion chance per key, so this is deterministically rejected.
    let resp = do_auth_with_pow(&server, &newcomer, Some(0), Some(32)).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "pow_required");
}
