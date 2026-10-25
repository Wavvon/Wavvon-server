//! The farm-token door into a hub must apply the same admission gate as
//! `/auth/verify` (farm-impl.md, "Hub-side admission"). Issue #101: it used to
//! admit any non-member on the spot, bypassing `invite_only`.

use axum::http::StatusCode;
use base64::Engine;
use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

fn farm_token(farm: &Identity, sub: &str) -> String {
    let payload = json!({
        "exp": wavvon_hub::auth::handlers::unix_timestamp() + 600,
        "iss_pk": farm.public_key_hex(),
        "sub": sub,
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    let sig = farm.sign(&bytes);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}", b64.encode(&bytes), b64.encode(sig.to_bytes()))
}

/// A hub with an owner, a trusted farm key, and `invite_only` set as asked.
async fn farm_hub(invite_only: bool) -> (common::TestHarness, Identity, String) {
    let server = common::setup().await;
    common::authenticate(&server, &Identity::generate()).await;
    let farm = Identity::generate();
    *server.state().cached_farm_pubkey.write().await = Some(farm.public_key_hex());
    if invite_only {
        wavvon_hub::routes::hub::upsert_setting(&server.state().db, "invite_only", "true")
            .await
            .unwrap();
    }
    let owner: String = sqlx::query_scalar("SELECT public_key FROM users LIMIT 1")
        .fetch_one(&server.state().db)
        .await
        .unwrap();
    (server, farm, owner)
}

async fn is_member(server: &common::TestHarness, pk: &str) -> bool {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT is_member FROM users WHERE public_key = $1), FALSE)",
    )
    .bind(pk)
    .fetch_one(&server.state().db)
    .await
    .unwrap()
}

async fn add_invite(server: &common::TestHarness, code: &str) {
    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at)
         VALUES ($1, 'system', NULL, 0, NULL, $2)",
    )
    .bind(code)
    .bind(wavvon_hub::auth::handlers::unix_timestamp())
    .execute(&server.state().db)
    .await
    .unwrap();
}

#[tokio::test]
async fn non_member_on_invite_only_hub_is_refused_like_verify() {
    let (server, farm, _) = farm_hub(true).await;
    let stranger = Identity::generate().public_key_hex();
    let resp = server
        .get("/me")
        .authorization_bearer(farm_token(&farm, &stranger))
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(resp.text(), "This hub requires an invite code");
    assert!(!is_member(&server, &stranger).await);
}

#[tokio::test]
async fn non_member_with_valid_invite_is_admitted_through_join() {
    let (server, farm, _) = farm_hub(true).await;
    add_invite(&server, "farmcode").await;
    let stranger = Identity::generate().public_key_hex();
    let token = farm_token(&farm, &stranger);

    server
        .post("/join/farmcode")
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert!(is_member(&server, &stranger).await);
    server
        .get("/me")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn join_with_a_bad_invite_does_not_admit_a_farm_user() {
    let (server, farm, _) = farm_hub(true).await;
    let stranger = Identity::generate().public_key_hex();
    server
        .post("/join/nosuchcode")
        .authorization_bearer(farm_token(&farm, &stranger))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    assert!(!is_member(&server, &stranger).await);
}

#[tokio::test]
async fn non_member_on_open_hub_is_admitted() {
    let (server, farm, _) = farm_hub(false).await;
    let stranger = Identity::generate().public_key_hex();
    server
        .get("/me")
        .authorization_bearer(farm_token(&farm, &stranger))
        .await
        .assert_status_ok();
    assert!(is_member(&server, &stranger).await);
}

#[tokio::test]
async fn existing_member_passes_on_invite_only_hub() {
    let (server, farm, owner) = farm_hub(true).await;
    server
        .get("/me")
        .authorization_bearer(farm_token(&farm, &owner))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn banned_farm_user_is_refused_even_with_an_invite_route() {
    let (server, farm, _) = farm_hub(false).await;
    let owner_token = {
        // Re-auth the owner on the open hub is not possible by key; ban directly.
        let stranger = Identity::generate().public_key_hex();
        server
            .get("/me")
            .authorization_bearer(farm_token(&farm, &stranger))
            .await
            .assert_status_ok();
        stranger
    };
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO bans (target_public_key, banned_by, reason, created_at)
         VALUES ($1, 'system', 'test', $2)",
    )
    .bind(&owner_token)
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();
    wavvon_hub::routes::hub::upsert_setting(&server.state().db, "invite_only", "true")
        .await
        .unwrap();
    add_invite(&server, "c").await;

    for resp in [
        server
            .get("/me")
            .authorization_bearer(farm_token(&farm, &owner_token))
            .await,
        server
            .post("/join/c")
            .authorization_bearer(farm_token(&farm, &owner_token))
            .await,
    ] {
        resp.assert_status(StatusCode::FORBIDDEN);
        assert_eq!(resp.text(), "User is banned");
    }
}
