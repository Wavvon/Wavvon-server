use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::me::MeResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn full_auth_flow() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let pub_key = identity.public_key_hex();

    // 1. Request challenge
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    resp.assert_status_ok();
    let challenge: ChallengeResponse = resp.json();

    // 2. Sign the challenge
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature.to_bytes());

    // 3. Verify (get token)
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": signature_hex,
        }))
        .await;
    resp.assert_status_ok();
    let verify: VerifyResponse = resp.json();
    assert!(!verify.token.is_empty());

    // 4. Use token to access /me
    let resp = server.get("/me").authorization_bearer(&verify.token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, pub_key);
}

#[tokio::test]
async fn concurrent_challenges_for_same_key_do_not_stomp() {
    // Regression: pending challenges used to be keyed by pubkey, so a second
    // challenge request overwrote the first and the earlier auth flow died
    // with "No pending challenge" — e.g. two simultaneous federated DM
    // deliveries to the same peer hub. Both outstanding challenges must now
    // be independently verifiable.
    let server = common::setup().await;
    let identity = Identity::generate();
    let pub_key = identity.public_key_hex();

    let first: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let second: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    assert_ne!(first.challenge, second.challenge);

    // Verify the FIRST challenge (issued before the second overwrote it in
    // the old scheme) — must still succeed.
    for challenge in [&first, &second] {
        let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
        let resp = server
            .post("/auth/verify")
            .json(&json!({
                "public_key": pub_key,
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
            }))
            .await;
        resp.assert_status_ok();
        let verify: VerifyResponse = resp.json();
        assert!(!verify.token.is_empty());
    }
}

#[tokio::test]
async fn challenge_cannot_be_verified_by_a_different_key() {
    // A challenge is bound to the pubkey it was issued to; another identity
    // must not be able to consume it, even with a valid signature of its own.
    let server = common::setup().await;
    let alice = Identity::generate();
    let mallory = Identity::generate();

    let challenge: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": alice.public_key_hex() }))
        .await
        .json();

    let signature = mallory.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": mallory.public_key_hex(),
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn me_rejects_no_token() {
    let server = common::setup().await;
    let resp = server.get("/me").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn me_bio_and_pronouns_round_trip_through_patch_and_profile() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let pub_key = owner.public_key_hex();
    let token = common::authenticate(&server, &owner).await;

    // Happy path: PATCH bio + pronouns.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "bio": "Loves synths and long walks.", "pronouns": "she/her" }))
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.bio.as_deref(), Some("Loves synths and long walks."));
    assert_eq!(me.pronouns.as_deref(), Some("she/her"));

    // Read back via GET /me.
    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.bio.as_deref(), Some("Loves synths and long walks."));
    assert_eq!(me.pronouns.as_deref(), Some("she/her"));

    // Read back via the public profile endpoint.
    let resp = server
        .get(&format!("/users/{pub_key}/profile"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let profile: serde_json::Value = resp.json();
    assert_eq!(profile["bio"], "Loves synths and long walks.");
    assert_eq!(profile["pronouns"], "she/her");
}

#[tokio::test]
async fn me_rejects_oversized_bio_and_pronouns() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // 501 chars: over the 500-char bio limit.
    let long_bio = "a".repeat(501);
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "bio": long_bio }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // 41 chars: over the 40-char pronouns limit.
    let long_pronouns = "a".repeat(41);
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "pronouns": long_pronouns }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn me_clears_bio_and_pronouns_with_empty_string() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Set them first.
    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "bio": "temporary bio", "pronouns": "they/them" }))
        .await
        .assert_status_ok();

    // Empty string clears both to null.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "bio": "", "pronouns": "" }))
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.bio, None);
    assert_eq!(me.pronouns, None);
}

#[tokio::test]
async fn me_interests_accent_color_and_cover_round_trip_through_patch_and_profile() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let pub_key = owner.public_key_hex();
    let token = common::authenticate(&server, &owner).await;

    // Happy path: PATCH interests + accent_color + cover.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({
            "interests": [
                { "kind": "playing", "text": "Stardew Valley" },
                { "kind": "lfg", "text": "co-op puzzle games" },
            ],
            "accent_color": "#7c5cff",
            "cover": "data:image/png;base64,aGVsbG8=",
        }))
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.interests.len(), 2);
    assert_eq!(me.interests[0].kind, "playing");
    assert_eq!(me.interests[0].text, "Stardew Valley");
    assert_eq!(me.interests[1].kind, "lfg");
    assert_eq!(me.interests[1].text, "co-op puzzle games");
    assert_eq!(me.accent_color.as_deref(), Some("#7c5cff"));
    assert_eq!(me.cover.as_deref(), Some("data:image/png;base64,aGVsbG8="));

    // Read back via GET /me.
    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.interests.len(), 2);
    assert_eq!(me.accent_color.as_deref(), Some("#7c5cff"));
    assert_eq!(me.cover.as_deref(), Some("data:image/png;base64,aGVsbG8="));

    // Read back via the public profile endpoint.
    let resp = server
        .get(&format!("/users/{pub_key}/profile"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let profile: serde_json::Value = resp.json();
    assert_eq!(profile["interests"][0]["kind"], "playing");
    assert_eq!(profile["interests"][0]["text"], "Stardew Valley");
    assert_eq!(profile["interests"][1]["kind"], "lfg");
    assert_eq!(profile["accent_color"], "#7c5cff");
    assert_eq!(profile["cover"], "data:image/png;base64,aGVsbG8=");
}

#[tokio::test]
async fn me_rejects_invalid_interests_accent_color_and_cover() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Bad interest kind.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "interests": [{ "kind": "obsessed", "text": "raiding" }] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // 7 entries: over the 6-entry cap.
    let too_many: Vec<serde_json::Value> = (0..7)
        .map(|i| json!({ "kind": "into", "text": format!("thing {i}") }))
        .collect();
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "interests": too_many }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // 81-char interest text: over the 80-char cap.
    let long_text = "a".repeat(81);
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "interests": [{ "kind": "want", "text": long_text }] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Malformed accent_color.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "accent_color": "not-a-color" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Over-long cover.
    let long_cover = "a".repeat(400_001);
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "cover": long_cover }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn me_clears_interests_accent_color_and_cover_with_empty_values() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Set them first.
    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({
            "interests": [{ "kind": "into", "text": "synths" }],
            "accent_color": "#123abc",
            "cover": "data:image/png;base64,aGVsbG8=",
        }))
        .await
        .assert_status_ok();

    // Empty array / empty strings clear all three to null.
    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "interests": [], "accent_color": "", "cover": "" }))
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert!(me.interests.is_empty());
    assert_eq!(me.accent_color, None);
    assert_eq!(me.cover, None);
}

#[tokio::test]
async fn pending_members_are_blocked_until_approved() {
    let server = common::setup().await;

    // Owner signs up first — auto-approved since they're the hub creator.
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Owner turns on require_approval.
    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "require_approval": true }))
        .await
        .assert_status_ok();

    // New member joins — they get a token but start pending.
    let newbie = Identity::generate();
    let newbie_token = common::authenticate(&server, &newbie).await;

    // Can see their own status
    let resp = server.get("/me").authorization_bearer(&newbie_token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.approval_status, "pending");

    // Cannot see channels or anything else
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner sees them in the pending queue
    let resp = server
        .get("/hub/pending")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pending: serde_json::Value = resp.json();
    assert_eq!(pending.as_array().unwrap().len(), 1);

    // Owner approves
    server
        .post(&format!("/hub/pending/{}/approve", newbie.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // Newbie can now access channels
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status_ok();
}
