//! Integration coverage for LAN/offline mode (lan-mode.md).
//!
//! `wavvon_hub::lan`'s pure guard/cert logic is unit-tested in
//! `crates/hub/src/lan.rs` (private-address acceptance/rejection, self-signed
//! cert generation + reload idempotency). This file covers the HTTP-visible
//! trust-establishment surface: `/info` exposing `lan_mode` / `lan_tls` /
//! `lan_fingerprint` so a client on the LAN can tell a self-signed or
//! plaintext connection is expected, not a downgrade.
//!
//! mDNS advertisement itself is covered by a smoke test that tolerates a
//! sandboxed/no-multicast CI environment (it never asserts success).

use std::sync::Arc;

use axum_test::TestServer;
use serde_json::Value;
use wavvon_hub::server;
use wavvon_hub::state::AppState;

#[path = "common.rs"]
mod common;

/// Build a test server with LAN-mode `AppState` fields set directly (no real
/// bind/mDNS involved — this is exercising the `/info` surface only).
async fn setup_with_lan(
    lan_mode: bool,
    lan_tls_mode: Option<&str>,
    lan_fingerprint: Option<&str>,
) -> common::TestHarness {
    let (db, guard) = common::create_test_db().await;

    let state = Arc::new(AppState {
        lan_mode,
        lan_tls_mode: lan_tls_mode.map(|s| s.to_string()),
        lan_fingerprint: lan_fingerprint.map(|s| s.to_string()),
        ..common::base_state(db)
    });

    let app = server::create_router(state);
    common::TestHarness::new(TestServer::new(app), guard)
}

// ── /info trust-establishment surface ───────────────────────────────────────

/// Happy path: LAN mode on with the self-signed tier surfaces `lan_mode`,
/// `lan_tls`, and the fingerprint on `/info` so a client can pin it.
#[tokio::test]
async fn info_reports_lan_self_signed_fingerprint() {
    let fp = "a".repeat(64);
    let server = setup_with_lan(true, Some("self"), Some(&fp)).await;

    let resp = server.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    assert_eq!(body["lan_mode"], Value::Bool(true));
    assert_eq!(body["lan_tls"], Value::String("self".to_string()));
    assert_eq!(body["lan_fingerprint"], Value::String(fp));
}

/// Happy path: LAN plaintext tier surfaces `lan_tls: "none"` and a
/// fingerprint field carrying the hub's identity pubkey (nothing to pin a
/// TLS cert to, but clients still get something to verify).
#[tokio::test]
async fn info_reports_lan_plaintext_tier() {
    let pubkey_hex = "b".repeat(64);
    let server = setup_with_lan(true, Some("none"), Some(&pubkey_hex)).await;

    let resp = server.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    assert_eq!(body["lan_mode"], Value::Bool(true));
    assert_eq!(body["lan_tls"], Value::String("none".to_string()));
    assert_eq!(body["lan_fingerprint"], Value::String(pubkey_hex));
}

/// Rejection / negative path: LAN mode off must never leak `lan_tls` or
/// `lan_fingerprint`, and `lan_mode` must read false. This is the
/// non-LAN-hub baseline that every existing deployment sees today.
#[tokio::test]
async fn info_omits_lan_fields_when_lan_mode_off() {
    let server = setup_with_lan(false, None, None).await;

    let resp = server.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    assert_eq!(body["lan_mode"], Value::Bool(false));
    assert!(
        body.get("lan_tls").is_none(),
        "lan_tls must be omitted (skip_serializing_if) when unset; got: {body}"
    );
    assert!(
        body.get("lan_fingerprint").is_none(),
        "lan_fingerprint must be omitted when unset; got: {body}"
    );
}

// ── private-address guard (HTTP-adjacent smoke coverage) ────────────────────
//
// The exhaustive guard unit tests (private accepted / public rejected / bad
// literal rejected) live next to the implementation in
// crates/hub/src/lan.rs. Re-asserting the two headline outcomes here keeps
// them visible from the integration-test layer without duplicating the
// implementation's own test module.

#[test]
fn private_address_guard_happy_path() {
    let ip = wavvon_hub::lan::resolve_lan_address(Some("192.168.1.50"))
        .expect("private address must be accepted");
    assert_eq!(ip, "192.168.1.50".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn private_address_guard_rejects_public_address() {
    let err = wavvon_hub::lan::resolve_lan_address(Some("8.8.8.8"))
        .expect_err("public address must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Refusing to start") && msg.contains("public internet"),
        "expected the hard-guard refusal message, got: {msg}"
    );
}

// ── mDNS smoke test (no multicast dependency) ───────────────────────────────

/// Smoke test only: verifies `start_mdns_advertiser` doesn't panic and
/// returns *some* `Result` for a normal private address/port. Does not
/// assert `Ok` — sandboxed/CI environments without multicast support are
/// expected to return `Err`, which callers (main.rs) already treat as
/// non-fatal. This never fails the build regardless of network sandboxing.
#[test]
fn mdns_advertiser_start_does_not_panic() {
    let params = wavvon_hub::lan::MdnsAnnounceParams {
        hub_name: "test-hub",
        advertise_ip: "192.168.1.50".parse().unwrap(),
        port: 3000,
        tls_mode: "self",
        fingerprint_or_pubkey: &"c".repeat(64),
    };
    match wavvon_hub::lan::start_mdns_advertiser(&params) {
        Ok(daemon) => {
            // Shut down cleanly if the sandbox happened to allow multicast.
            let _ = daemon.shutdown();
        }
        Err(e) => {
            eprintln!("mDNS unavailable in this environment (expected in CI): {e}");
        }
    }
}
