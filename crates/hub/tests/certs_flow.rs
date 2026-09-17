//! Integration tests for hub certification issuance (#20) and auth gate (#21).

use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::cert_worker;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::certs::{Certification, IssuanceRow};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Shared test setup
// ---------------------------------------------------------------------------

#[path = "common.rs"]
mod common;

async fn make_state() -> (Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_wt_url: None,
        canonical_url: Arc::new(RwLock::new(None)),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_optouts: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_talk_blocked: Default::default(),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        bots_allow_video: false,
        bot_video_stream_budget: 2,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            std::sync::Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        webauthn_auth_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: false,
        lan_tls_mode: None,
        lan_fingerprint: None,
    });
    (state, guard)
}

async fn setup() -> (Arc<AppState>, common::TestHarness) {
    let (state, guard) = make_state().await;
    let app = server::create_router(state.clone());
    let server = common::TestHarness::new(TestServer::new(app), guard);
    (state, server)
}

/// Authenticate an identity against the test server; returns a session token.
async fn do_auth(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    resp.assert_status_ok();
    let ch: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = identity.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": ch.challenge,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status_ok();
    let v: VerifyResponse = resp.json();
    v.token
}

// ---------------------------------------------------------------------------
// Task #20 — Issuance
// ---------------------------------------------------------------------------

/// Admin can manually issue a cert for an existing member.
#[tokio::test]
async fn admin_issue_happy_path() {
    let (_, server) = setup().await;

    // First user becomes owner.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Second user registers.
    let member = Identity::generate();
    let _member_token = do_auth(&server, &member).await;

    // Admin issues a cert.
    let resp = server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let cert: Certification = resp.json();

    assert_eq!(cert.payload.subject_pubkey, member.public_key_hex());
    assert_eq!(cert.payload.standing, "good");
    assert!(!cert.signature.is_empty());
}

/// Admin list returns the issued cert.
#[tokio::test]
async fn admin_list_certs() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let _mt = do_auth(&server, &member).await;

    server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get("/admin/certs")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let rows: Vec<IssuanceRow> = resp.json();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].subject_pubkey, member.public_key_hex());
}

/// Admin can revoke a cert; it no longer appears in the public endpoint.
#[tokio::test]
async fn admin_revoke_cert() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let _mt = do_auth(&server, &member).await;
    let member_pk = member.public_key_hex();

    // Issue then revoke.
    server
        .post(&format!("/admin/certs/{member_pk}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .post(&format!("/admin/certs/{member_pk}/revoke"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Public endpoint returns empty (revoked cert filtered out).
    let resp = server.get(&format!("/identity/{member_pk}/certs")).await;
    resp.assert_status_ok();
    let certs: Vec<Certification> = resp.json();
    assert!(
        certs.is_empty(),
        "revoked cert should not appear in public list"
    );
}

/// Non-admin cannot issue a cert.
#[tokio::test]
async fn non_admin_cannot_issue() {
    let (_, server) = setup().await;
    let _owner = Identity::generate();
    let _owner_token = do_auth(&server, &_owner).await;
    let member = Identity::generate();
    let member_token = do_auth(&server, &member).await;

    let resp = server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&member_token)
        .await;
    resp.assert_status_forbidden();
}

/// Issuing a cert for an unknown pubkey returns 404.
#[tokio::test]
async fn issue_unknown_pubkey_returns_404() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let resp = server
        .post("/admin/certs/deadbeef0000000000000000000000000000000000000000000000000000abcd")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_not_found();
}

/// Cert worker tick issues certs to members whose first_seen_at is old enough.
#[tokio::test]
async fn cert_worker_issues_on_tick() {
    let (state, guard) = make_state().await;
    let server =
        common::TestHarness::new(TestServer::new(server::create_router(state.clone())), guard);

    // Register a member.
    let member = Identity::generate();
    let member_pk = member.public_key_hex();
    let _owner = Identity::generate();
    do_auth(&server, &_owner).await;
    do_auth(&server, &member).await;

    // Back-date first_seen_at to 31 days ago so the worker considers them eligible.
    let thirty_one_days_ago = wavvon_hub::auth::handlers::unix_timestamp() - 31 * 86400;
    sqlx::query("UPDATE users SET first_seen_at = $1 WHERE public_key = $2")
        .bind(thirty_one_days_ago)
        .bind(&member_pk)
        .execute(&state.db)
        .await
        .unwrap();

    // Run a worker tick.
    cert_worker::tick(&state).await.unwrap();

    // Check the public endpoint returns a cert (reads cert_issuances).
    let resp = server.get(&format!("/identity/{member_pk}/certs")).await;
    resp.assert_status_ok();
    let certs: Vec<Certification> = resp.json();
    assert!(!certs.is_empty(), "worker should have issued a cert");
    assert_eq!(certs[0].payload.subject_pubkey, member_pk);
}

// ---------------------------------------------------------------------------
// Task #21 — Auth gate
// ---------------------------------------------------------------------------

/// When cert_mode = 'none' (default), /auth/verify succeeds without any certs.
#[tokio::test]
async fn cert_mode_none_no_cert_needed() {
    let (_, server) = setup().await;
    let id = Identity::generate();
    let _ = do_auth(&server, &Identity::generate()).await; // owner
    let token = do_auth(&server, &id).await;
    assert!(!token.is_empty());
}

/// When cert_mode = 'any', /auth/verify without a cert returns 403 cert_required.
#[tokio::test]
async fn cert_mode_any_rejects_no_cert() {
    let (state, server) = setup().await;

    // Set up owner.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Enable cert_mode = 'any'.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // A new user tries to auth without a cert.
    let newcomer = Identity::generate();
    let pk = newcomer.public_key_hex();
    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = newcomer.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pk,
            "challenge": ch.challenge,
            "signature": sig_hex,
        }))
        .await;
    resp.assert_status_forbidden();
    assert!(resp.text().contains("cert_required"));

    // Suppress unused state warning.
    let _ = state.hub_name.as_str();
}

/// When cert_mode = 'any', a valid cert from any hub is accepted.
#[tokio::test]
async fn cert_mode_any_accepts_valid_cert() {
    let (state, server) = setup().await;

    // Owner registers first.
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Enable cert_mode = 'any'.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Create a newcomer and issue them a cert from THIS hub (simulates
    // them having been a member of a hub that trusts them).
    let newcomer = Identity::generate();
    let newcomer_pk = newcomer.public_key_hex();

    // Insert minimal user row so issue_cert_for can find them.
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status)
         VALUES ($1, $2, $3, 'approved')",
    )
    .bind(&newcomer_pk)
    .bind(now - 86400)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let cert = wavvon_hub::routes::certs::issue_cert_for(&state, &newcomer_pk)
        .await
        .unwrap();

    // Now authenticate presenting the cert. Use newcomer_pk as both public_key and
    // the cert's subject (no subkey cert, so master = auth pubkey).
    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": newcomer_pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let challenge_bytes = hex::decode(&ch.challenge).unwrap();
    let sig = newcomer.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": newcomer_pk,
            "challenge": ch.challenge,
            "signature": sig_hex,
            "certifications": [cert],
        }))
        .await;
    resp.assert_status_ok();
    let v: VerifyResponse = resp.json();
    assert!(!v.token.is_empty());
}

/// GET /info includes cert_requirement when cert_mode != 'none'.
#[tokio::test]
async fn info_includes_cert_requirement() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    // Default: cert_requirement is absent.
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("cert_requirement").is_none());

    // Enable cert gate.
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "any" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let info: serde_json::Value = server.get("/info").await.json();
    let req = info
        .get("cert_requirement")
        .expect("cert_requirement should be present");
    assert_eq!(req["mode"], "any");
}

/// PATCH /admin/settings/certs rejects invalid cert_mode values.
#[tokio::test]
async fn patch_cert_settings_rejects_invalid_mode() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_mode": "banana" }))
        .await;
    resp.assert_status_bad_request();
}

// ---------------------------------------------------------------------------
// §11 — the receiving hub pulls a portfolio from its trusted issuers
// ---------------------------------------------------------------------------

/// A mock issuing hub: serves `GET /identity/:pubkey/certs` with whatever
/// portfolio the test hands it. Returns its base URL.
async fn start_mock_portfolio_issuer(portfolio: serde_json::Value) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = portfolio.to_string();
    let app = axum::Router::new().route(
        "/identity/{pubkey}/certs",
        axum::routing::get(move || {
            let b = body.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [("content-type", "application/json")],
                    b,
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    format!("http://127.0.0.1:{port}")
}

/// A standing cert for `subject`, signed by `issuer` the way an issuing hub
/// signs one: Ed25519 over the payload's JSON.
fn signed_cert(issuer: &Identity, issuer_url: &str, subject_pubkey: &str) -> serde_json::Value {
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    // Built from the real payload type, not a `json!` literal: the signature
    // covers `serde_json::to_string(&payload)` in *struct field order*, and a
    // hand-written map serialises its keys sorted. Same bytes or no signature.
    let payload = wavvon_hub::routes::certs::CertPayload {
        subject_kind: "user".to_string(),
        issuer_pubkey: issuer.public_key_hex(),
        issuer_url: issuer_url.to_string(),
        subject_pubkey: subject_pubkey.to_string(),
        member_since: now - 90 * 86400,
        standing: "good".to_string(),
        pow_level: None,
        issued_at: now,
        expires_at: now + 86400,
        capabilities: Vec::new(),
        label: None,
        description: None,
        icon: None,
    };
    let payload_json = serde_json::to_string(&payload).unwrap();
    let signature = issuer.sign(payload_json.as_bytes());
    json!({
        "payload": serde_json::from_str::<serde_json::Value>(&payload_json).unwrap(),
        "signature": hex::encode(signature.to_bytes()),
    })
}

/// Turn on `cert_mode = trusted` for `issuer_pubkey`, optionally telling the
/// hub where to reach it.
async fn trust_issuer(
    server: &TestServer,
    owner_token: &str,
    issuer_pubkey: &str,
    issuer_url: Option<&str>,
) {
    let mut body = json!({
        "cert_mode": "trusted",
        "cert_trusted_issuers": [issuer_pubkey],
    });
    if let Some(url) = issuer_url {
        body["cert_issuer_urls"] = json!({ issuer_pubkey: url });
    }
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(owner_token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
}

/// The whole point of §11: nothing presents a cert, so the hub fetches the
/// candidate's portfolio from the issuers it trusts and admits them on what it
/// finds. Without this a hub with `cert_mode != none` refuses everyone, which
/// is a lockout rather than a relay.
#[tokio::test]
async fn a_trusted_issuer_is_pulled_when_the_client_presents_nothing() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let newcomer = Identity::generate();
    let newcomer_pk = newcomer.public_key_hex();

    let issuer_url = start_mock_portfolio_issuer(json!([signed_cert(
        &issuer,
        "http://issuer.example",
        &newcomer_pk
    )]))
    .await;

    trust_issuer(
        &server,
        &owner_token,
        &issuer.public_key_hex(),
        Some(&issuer_url),
    )
    .await;

    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": newcomer_pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let sig = newcomer.sign(&hex::decode(&ch.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": newcomer_pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
            // Deliberately no `certifications`: no client sends one.
        }))
        .await;
    resp.assert_status_ok();
    let v: VerifyResponse = resp.json();
    assert!(!v.token.is_empty());
}

/// Trust and reachability are different facts, and the setting that carries
/// the address is optional. An issuer with no URL is simply not pullable —
/// its pushed certs would still be honoured — so this candidate is refused.
#[tokio::test]
async fn an_issuer_with_no_url_is_not_pulled() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let newcomer = Identity::generate();
    let newcomer_pk = newcomer.public_key_hex();

    trust_issuer(&server, &owner_token, &issuer.public_key_hex(), None).await;

    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": newcomer_pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let sig = newcomer.sign(&hex::decode(&ch.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": newcomer_pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert!(resp.text().contains("cert_required"));
}

/// A pulled cert goes through exactly the predicate a presented one does, so
/// answering the fetch with someone else's cert buys an issuer nothing. This
/// is what makes "the hub pulls" safe: the fetch chooses *where* to look, never
/// what counts.
#[tokio::test]
async fn a_pulled_cert_signed_by_someone_untrusted_is_refused() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let stranger = Identity::generate();
    let newcomer = Identity::generate();
    let newcomer_pk = newcomer.public_key_hex();

    // Served from the trusted issuer's address, but signed by a key this hub
    // has never trusted.
    let issuer_url = start_mock_portfolio_issuer(json!([signed_cert(
        &stranger,
        "http://issuer.example",
        &newcomer_pk
    )]))
    .await;

    trust_issuer(
        &server,
        &owner_token,
        &issuer.public_key_hex(),
        Some(&issuer_url),
    )
    .await;

    let ch_resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": newcomer_pk }))
        .await;
    ch_resp.assert_status_ok();
    let ch: ChallengeResponse = ch_resp.json();
    let sig = newcomer.sign(&hex::decode(&ch.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": newcomer_pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert!(resp.text().contains("cert_required"));
}

/// The admin UI PATCHes the settings object it rendered: booleans as booleans,
/// numbers as numbers. This pins that shape down.
#[tokio::test]
async fn patch_accepts_the_shape_the_admin_ui_sends() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let resp = server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "cert_mode": "any",
            "cert_auto_issue": false,
            "cert_min_age_days": 30,
            "cert_validity_days": 90,
            "cert_trusted_issuers": [],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let read = server
        .get("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .await;
    read.assert_status_ok();
    let v: serde_json::Value = read.json();
    assert_eq!(
        v["cert_auto_issue"], false,
        "the toggle the admin flipped must stick"
    );
}
