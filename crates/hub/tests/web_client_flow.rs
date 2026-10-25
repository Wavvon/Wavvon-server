//! Integration tests for the optional static web-client serving feature.
//!
//! Tests are split into two sections:
//! - With `web_client_dir` set to a temp dir containing index.html + an asset.
//! - With `web_client_dir` unset (API-only, today's behaviour).

use std::sync::Arc;

use axum::http::header;
use axum_test::TestServer;
use wavvon_hub::server;
use wavvon_hub::web_client::WebClientConfig;

/// Build a test server with an optional WebClientConfig.
#[path = "common.rs"]
mod common;

async fn setup_with_web_client(cfg: Option<Arc<WebClientConfig>>) -> common::TestHarness {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(common::base_state(db));

    let app = server::create_router_full(state, "*", false, cfg);
    common::TestHarness::new(TestServer::new(app), guard)
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_web_client_dir() -> (tempfile::TempDir, Arc<WebClientConfig>) {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write a minimal index.html with a </head> tag so injection is testable.
    let index_html = b"<html><head><title>Wavvon</title></head><body>hello</body></html>";
    std::fs::write(dir.path().join("index.html"), index_html).unwrap();

    // Write a static asset.
    std::fs::write(dir.path().join("app.js"), b"console.log('wavvon');").unwrap();

    let cfg = WebClientConfig::load(dir.path()).expect("WebClientConfig::load");
    (dir, Arc::new(cfg))
}

// ── with web client ───────────────────────────────────────────────────────────

/// GET / with Accept: text/html → returns index.html containing __WAVVON_HOME_HUB__.
#[tokio::test]
async fn root_with_html_accept_returns_index() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/")
        .add_header(header::ACCEPT, "text/html,application/xhtml+xml")
        .await;

    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("__WAVVON_HOME_HUB__"),
        "Expected injected config script in index.html; got: {body}"
    );
    assert!(
        body.contains("</head>"),
        "Expected </head> in index.html; got: {body}"
    );
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/html"),
        "Expected text/html content-type; got: {ct}"
    );
}

/// GET /some/spa/route with Accept: text/html → SPA fallback serves index.html.
#[tokio::test]
async fn spa_route_with_html_accept_returns_index() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/some/spa/route")
        .add_header(header::ACCEPT, "text/html,*/*;q=0.8")
        .await;

    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("__WAVVON_HOME_HUB__"),
        "SPA fallback should serve injected index.html; got: {body}"
    );
}

/// GET /nonexistent with Accept: application/json → plain 404 (not index.html).
/// This is the critical API-semantics preservation test.
#[tokio::test]
async fn non_api_path_with_json_accept_returns_404() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/nonexistent-path-xyz")
        .add_header(header::ACCEPT, "application/json")
        .await;

    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    let body = resp.text();
    // Must NOT be the index.html content.
    assert!(
        !body.contains("__WAVVON_HOME_HUB__"),
        "JSON client must receive a plain 404, not the SPA index; got: {body}"
    );
}

/// GET /health still returns the health JSON even with web client enabled.
/// This verifies that named API routes take priority over the fallback.
#[tokio::test]
async fn health_route_unaffected_by_web_client() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/health")
        .add_header(header::ACCEPT, "text/html,*/*;q=0.8") // browser-like
        .await;

    resp.assert_status_ok();
    // Should be JSON, not HTML.
    let body = resp.text();
    assert!(
        body.contains("ok") || body.contains("status"),
        "Expected health JSON; got: {body}"
    );
    assert!(
        !body.contains("__WAVVON_HOME_HUB__"),
        "Health route should not be overridden by web client fallback; got: {body}"
    );
}

/// GET /app.js → static asset is served with 200.
#[tokio::test]
async fn static_asset_is_served() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server.get("/app.js").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("wavvon"),
        "Expected JS asset content; got: {body}"
    );
}

// ── without web client (API-only, today's behaviour) ─────────────────────────

/// Without web_client_dir, GET / returns 404 (the current behaviour — no root handler registered).
#[tokio::test]
async fn root_without_web_client_returns_404() {
    let server = setup_with_web_client(None).await;

    let resp = server.get("/").await;
    // The hub has no GET / route registered; axum returns 404 for unmatched paths
    // when no fallback is registered.
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Without web_client_dir, GET /health still works normally.
#[tokio::test]
async fn health_without_web_client() {
    let server = setup_with_web_client(None).await;

    let resp = server.get("/health").await;
    resp.assert_status_ok();
}
