//! Integration tests for hub certification issuance and certified admission.

use std::sync::Arc;

use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::cert_worker;
use wavvon_hub::routes::certs::{Certification, IssuanceRow};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use wavvon_test_server::TestServer;

// ---------------------------------------------------------------------------
// Shared test setup
// ---------------------------------------------------------------------------

use crate::common;

async fn make_state() -> (Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = self::common::create_test_db().await;
    let state = Arc::new(common::base_state(db));
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
    let sig =
        identity.sign(&wavvon_identity::auth_challenge_signing_bytes(&challenge_bytes).unwrap());
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
        .delete(&format!("/admin/certs/{member_pk}"))
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
// Certified admission: the fast lane (certified-admission.md)
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

/// A cert for `subject`, signed by `issuer` the way an issuing hub signs one:
/// Ed25519 over the payload's JSON. `label` makes it a badge, `cert_type` a
/// typed certificate.
fn signed(
    issuer: &Identity,
    issuer_url: &str,
    subject_pubkey: &str,
    label: Option<&str>,
    cert_type: Option<&str>,
) -> serde_json::Value {
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
        label: label.map(str::to_string),
        description: None,
        icon: None,
        cert_type: cert_type.map(str::to_string),
    };
    let payload_json = serde_json::to_string(&payload).unwrap();
    let signature = issuer.sign(payload_json.as_bytes());
    json!({
        "payload": serde_json::from_str::<serde_json::Value>(&payload_json).unwrap(),
        "signature": hex::encode(signature.to_bytes()),
    })
}

fn signed_cert(issuer: &Identity, issuer_url: &str, subject_pubkey: &str) -> serde_json::Value {
    signed(issuer, issuer_url, subject_pubkey, None, None)
}

/// A cert whose signed `issuer_url` points at a live issuer that still
/// lists it, the way a real hub answers for a certificate it has not revoked.
/// `still_listed: false` is the issuer after a revocation.
async fn live_cert(
    issuer: &Identity,
    subject_pubkey: &str,
    cert_type: Option<&str>,
    still_listed: bool,
) -> serde_json::Value {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let cert = signed(issuer, &url, subject_pubkey, None, cert_type);
    let body = if still_listed {
        json!([cert])
    } else {
        json!([])
    }
    .to_string();
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
    cert
}

async fn patch_certs(server: &TestServer, owner_token: &str, body: serde_json::Value) {
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(owner_token)
        .json(&body)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
}

/// Trust every certificate of `issuer_pubkey` and refuse everyone else, so
/// a refusal in these tests can only mean "not certified". Optionally tells
/// the hub where to reach the issuer.
async fn trust_issuer(
    server: &TestServer,
    owner_token: &str,
    issuer_pubkey: &str,
    issuer_url: Option<&str>,
) {
    let mut body = json!({
        "cert_trusted_issuers": [issuer_pubkey],
        "cert_others": "refuse",
    });
    if let Some(url) = issuer_url {
        body["cert_issuer_urls"] = json!({ issuer_pubkey: url });
    }
    patch_certs(server, owner_token, body).await;
}

/// Sign in as a newcomer, presenting `certs` and an optional invite.
async fn verify_as(
    server: &TestServer,
    who: &Identity,
    certs: Option<serde_json::Value>,
    invite: Option<&str>,
) -> wavvon_test_server::TestResponse {
    let pk = who.public_key_hex();
    let ch: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await
        .json();
    let sig = who.sign(
        &wavvon_identity::auth_challenge_signing_bytes(&hex::decode(&ch.challenge).unwrap())
            .unwrap(),
    );
    let mut body = json!({
        "public_key": pk,
        "challenge": ch.challenge,
        "signature": hex::encode(sig.to_bytes()),
    });
    if let Some(c) = certs {
        body["certifications"] = c;
    }
    if let Some(code) = invite {
        body["invite_code"] = json!(code);
    }
    server.post("/auth/verify").json(&body).await
}

async fn set_hub_setting(state: &AppState, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(&state.db)
    .await
    .unwrap();
}

async fn approval_status(state: &AppState, pk: &str) -> String {
    sqlx::query_scalar("SELECT approval_status FROM users WHERE public_key = $1")
        .bind(pk)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

/// With both trust lists empty there is no fast lane: admission is what
/// Joining alone sets, as on a hub that never touched certificates.
#[tokio::test]
async fn no_trust_lists_no_cert_needed() {
    let (_, server) = setup().await;
    let alice = Identity::generate();
    let token = do_auth(&server, &alice).await;
    assert!(!token.is_empty());
}

/// A hub set to refuse turns away a newcomer with nothing trusted.
#[tokio::test]
async fn refuse_turns_away_the_uncertified() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    trust_issuer(
        &server,
        &owner_token,
        &Identity::generate().public_key_hex(),
        None,
    )
    .await;

    let resp = verify_as(&server, &Identity::generate(), None, None).await;
    resp.assert_status_forbidden();
    assert!(resp.text().contains("cert_required"));
}

/// A pushed certificate from a trusted hub admits its holder.
#[tokio::test]
async fn a_trusted_hubs_certificate_admits() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    trust_issuer(&server, &owner_token, &issuer.public_key_hex(), None).await;

    let newcomer = Identity::generate();
    let cert = live_cert(&issuer, &newcomer.public_key_hex(), None, true).await;
    verify_as(&server, &newcomer, Some(json!([cert])), None)
        .await
        .assert_status_ok();
}

/// A copy of a certificate its issuer has since revoked (a ban there, #463)
/// is still signed and unexpired, but the issuer no longer lists it, and
/// that live answer is the one that counts (#469).
#[tokio::test]
async fn a_presented_certificate_its_issuer_revoked_does_not_admit() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    patch_certs(
        &server,
        &owner_token,
        json!({ "cert_trusted_issuers": [issuer.public_key_hex()], "cert_others": "refuse" }),
    )
    .await;

    let banned = Identity::generate();
    let cert = live_cert(&issuer, &banned.public_key_hex(), None, false).await;
    verify_as(&server, &banned, Some(json!([cert])), None)
        .await
        .assert_status_forbidden();
}

/// The specific list trusts one type of one hub: that type admits, another
/// type of the same hub does not.
#[tokio::test]
async fn a_trusted_type_admits_and_another_type_does_not() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    patch_certs(
        &server,
        &owner_token,
        json!({
            "cert_trusted_types": [{ "issuer": issuer.public_key_hex(), "cert_type": "verified" }],
            "cert_others": "refuse",
        }),
    )
    .await;

    let good = Identity::generate();
    let cert = live_cert(&issuer, &good.public_key_hex(), Some("verified"), true).await;
    verify_as(&server, &good, Some(json!([cert])), None)
        .await
        .assert_status_ok();

    let other = Identity::generate();
    let cert = signed(
        &issuer,
        "http://issuer.example",
        &other.public_key_hex(),
        None,
        Some("organiser"),
    );
    verify_as(&server, &other, Some(json!([cert])), None)
        .await
        .assert_status_forbidden();

    let plain = Identity::generate();
    let cert = signed_cert(&issuer, "http://issuer.example", &plain.public_key_hex());
    verify_as(&server, &plain, Some(json!([cert])), None)
        .await
        .assert_status_forbidden();
}

/// A badge is a cert with a label, and it used to pass the admission check
/// like a standing certificate: any badge from a trusted hub let its holder in.
#[tokio::test]
async fn a_badge_never_admits() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    trust_issuer(&server, &owner_token, &issuer.public_key_hex(), None).await;

    let newcomer = Identity::generate();
    let badge = signed(
        &issuer,
        "http://issuer.example",
        &newcomer.public_key_hex(),
        Some("Raid Leader"),
        None,
    );
    verify_as(&server, &newcomer, Some(json!([badge])), None)
        .await
        .assert_status_forbidden();
}

/// The fast lane skips approval; the usual way in (`lobby`) still applies it.
#[tokio::test]
async fn the_fast_lane_skips_approval_and_the_usual_way_keeps_it() {
    let (state, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    patch_certs(
        &server,
        &owner_token,
        json!({ "cert_trusted_issuers": [issuer.public_key_hex()] }),
    )
    .await;
    set_hub_setting(&state, "require_approval", "true").await;

    let certified = Identity::generate();
    let cert = live_cert(&issuer, &certified.public_key_hex(), None, true).await;
    verify_as(&server, &certified, Some(json!([cert])), None)
        .await
        .assert_status_ok();
    assert_eq!(
        approval_status(&state, &certified.public_key_hex()).await,
        "approved"
    );

    let usual = Identity::generate();
    verify_as(&server, &usual, None, None)
        .await
        .assert_status_ok();
    assert_eq!(
        approval_status(&state, &usual.public_key_hex()).await,
        "pending"
    );
}

/// On an invite-only hub a trusted certificate stands in for an invite only
/// when the admin says so.
#[tokio::test]
async fn a_certificate_replaces_an_invite_only_when_switched_on() {
    let (state, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    patch_certs(
        &server,
        &owner_token,
        json!({ "cert_trusted_issuers": [issuer.public_key_hex()] }),
    )
    .await;
    set_hub_setting(&state, "invite_only", "true").await;

    let first = Identity::generate();
    let cert = signed_cert(&issuer, "http://issuer.example", &first.public_key_hex());
    verify_as(&server, &first, Some(json!([cert])), None)
        .await
        .assert_status_forbidden();

    patch_certs(
        &server,
        &owner_token,
        json!({ "cert_replaces_invite": true }),
    )
    .await;
    let second = Identity::generate();
    let cert = live_cert(&issuer, &second.public_key_hex(), None, true).await;
    verify_as(&server, &second, Some(json!([cert])), None)
        .await
        .assert_status_ok();
}

/// GET /info advertises the trust lists while either is set.
#[tokio::test]
async fn info_includes_cert_requirement() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("cert_requirement").is_none());

    let issuer = Identity::generate().public_key_hex();
    patch_certs(
        &server,
        &owner_token,
        json!({ "cert_trusted_issuers": [issuer] }),
    )
    .await;
    let info: serde_json::Value = server.get("/info").await.json();
    let req = info
        .get("cert_requirement")
        .expect("cert_requirement should be present");
    assert_eq!(req["trusted_issuers"][0], issuer);
    assert_eq!(req["others"], "lobby");
    assert_eq!(req["replaces_invite"], false);
}

#[tokio::test]
async fn patch_cert_settings_rejects_invalid_values() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_others": "banana" }))
        .await
        .assert_status_bad_request();
    server
        .patch("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_trusted_types": ["not an object"] }))
        .await
        .assert_status_bad_request();
}

/// The catalogue: public to read, admin-only to change, and an issuance must
/// name a type that exists.
#[tokio::test]
async fn certificate_types_catalogue() {
    let (state, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let member_token = do_auth(&server, &member).await;

    server
        .post("/admin/cert-types")
        .authorization_bearer(&member_token)
        .json(&json!({ "name": "Verified identity" }))
        .await
        .assert_status_forbidden();
    let created: serde_json::Value = server
        .post("/admin/cert-types")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Verified identity", "description": "Checked by a moderator" }))
        .await
        .json();
    let id = created["id"].as_str().unwrap().to_string();

    let listed: Vec<serde_json::Value> = server.get("/certs/types").await.json();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["name"], "Verified identity");

    let cert: Certification = server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_type": id }))
        .await
        .json();
    assert_eq!(cert.payload.cert_type.as_deref(), Some(id.as_str()));

    server
        .post(&format!("/admin/certs/{}", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .json(&json!({ "cert_type": "no-such-type" }))
        .await
        .assert_status_bad_request();

    server
        .delete(&format!("/admin/cert-types/{id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    let listed: Vec<serde_json::Value> = server.get("/certs/types").await.json();
    assert!(listed.is_empty());
    let _ = state;
}

/// The whole point of §11: nothing presents a cert, so the hub fetches the
/// candidate's portfolio from the issuers it trusts and admits them on what it
/// finds.
#[tokio::test]
async fn a_trusted_issuer_is_pulled_when_the_client_presents_nothing() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let newcomer = Identity::generate();
    let issuer_url = start_mock_portfolio_issuer(json!([signed_cert(
        &issuer,
        "http://issuer.example",
        &newcomer.public_key_hex()
    )]))
    .await;
    trust_issuer(
        &server,
        &owner_token,
        &issuer.public_key_hex(),
        Some(&issuer_url),
    )
    .await;

    verify_as(&server, &newcomer, None, None)
        .await
        .assert_status_ok();
}

/// The issuers named only by the specific list are pulled too.
#[tokio::test]
async fn an_issuer_trusted_for_one_type_is_pulled() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let newcomer = Identity::generate();
    let issuer_url = start_mock_portfolio_issuer(json!([signed(
        &issuer,
        "http://issuer.example",
        &newcomer.public_key_hex(),
        None,
        Some("verified")
    )]))
    .await;
    patch_certs(
        &server,
        &owner_token,
        json!({
            "cert_trusted_types": [{ "issuer": issuer.public_key_hex(), "cert_type": "verified" }],
            "cert_issuer_urls": { issuer.public_key_hex(): issuer_url },
            "cert_others": "refuse",
        }),
    )
    .await;

    verify_as(&server, &newcomer, None, None)
        .await
        .assert_status_ok();
}

/// Trust and reachability are different facts. An issuer with no URL is
/// simply not pullable, so this candidate is refused.
#[tokio::test]
async fn an_issuer_with_no_url_is_not_pulled() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let issuer = Identity::generate();
    trust_issuer(&server, &owner_token, &issuer.public_key_hex(), None).await;

    let resp = verify_as(&server, &Identity::generate(), None, None).await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert!(resp.text().contains("cert_required"));
}

/// A pulled cert goes through exactly the predicate a presented one does, so
/// answering the fetch with someone else's cert buys an issuer nothing.
#[tokio::test]
async fn a_pulled_cert_signed_by_someone_untrusted_is_refused() {
    let (_, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;

    let issuer = Identity::generate();
    let stranger = Identity::generate();
    let newcomer = Identity::generate();
    let issuer_url = start_mock_portfolio_issuer(json!([signed_cert(
        &stranger,
        "http://issuer.example",
        &newcomer.public_key_hex()
    )]))
    .await;
    trust_issuer(
        &server,
        &owner_token,
        &issuer.public_key_hex(),
        Some(&issuer_url),
    )
    .await;

    let resp = verify_as(&server, &newcomer, None, None).await;
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

    patch_certs(
        &server,
        &owner_token,
        json!({
            "cert_auto_issue": false,
            "cert_min_age_days": 30,
            "cert_validity_days": 90,
            "cert_trusted_issuers": [],
            "cert_trusted_types": [],
            "cert_others": "lobby",
            "cert_replaces_invite": false,
        }),
    )
    .await;

    let v: serde_json::Value = server
        .get("/admin/settings/certs")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert_eq!(
        v["cert_auto_issue"], false,
        "the toggle the admin flipped must stick"
    );
    assert_eq!(v["cert_others"], "lobby");
}

/// A ban withdraws what the hub vouched for: certificates and badges issued
/// before it used to stay valid until they expired.
#[tokio::test]
async fn a_ban_revokes_the_members_certificates_and_badges() {
    let (state, server) = setup().await;
    let owner = Identity::generate();
    let owner_token = do_auth(&server, &owner).await;
    let member = Identity::generate();
    let member_pk = member.public_key_hex();
    do_auth(&server, &member).await;

    wavvon_hub::routes::certs::issue_cert_for(&state, &member_pk, None)
        .await
        .unwrap();
    server
        .post(&format!("/admin/certs/{member_pk}/badge"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "label": "Raid Leader" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let live = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM cert_issuances WHERE subject_pubkey = $1 AND revoked_at IS NULL",
        )
        .bind(&member_pk)
        .fetch_one(&state.db)
        .await
        .unwrap()
    };
    assert_eq!(live().await, 2);

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": member_pk, "duration_seconds": 3600 }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    assert_eq!(live().await, 0, "a temporary ban revokes too");
}
