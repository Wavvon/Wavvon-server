use std::sync::Arc;

use axum_test::TestServer;
use wavvon_hub::server::create_router_with_cors;

#[path = "common.rs"]
mod common;

async fn setup_with_cors(cors_origins: &str) -> common::TestHarness {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(common::base_state(db));

    let app = create_router_with_cors(state, cors_origins);
    common::TestHarness::new(TestServer::new(app), guard)
}

/// Default wildcard CORS: GET /health returns `access-control-allow-origin: *`.
#[tokio::test]
async fn wildcard_cors_on_get() {
    let server = setup_with_cors("*").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://app.example.com")
        .await;
    resp.assert_status_ok();
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_some(),
        "access-control-allow-origin header should be present"
    );
    assert_eq!(acao.unwrap(), "*", "wildcard CORS should return *");
}

/// Default wildcard CORS: OPTIONS preflight returns the CORS headers.
#[tokio::test]
async fn wildcard_cors_preflight() {
    let server = setup_with_cors("*").await;
    let resp = server
        .method(axum::http::Method::OPTIONS, "/health")
        .add_header("origin", "https://app.example.com")
        .add_header("access-control-request-method", "GET")
        .add_header("access-control-request-headers", "authorization")
        .await;
    // Tower-http CorsLayer responds to OPTIONS preflight with 200 and the
    // appropriate headers even when the route doesn't explicitly handle OPTIONS.
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_some(),
        "preflight should include access-control-allow-origin"
    );
    assert_eq!(acao.unwrap(), "*");
    assert!(
        resp.headers().get("access-control-allow-methods").is_some(),
        "preflight should include access-control-allow-methods"
    );
}

/// Restricted origins: matching origin is reflected back.
#[tokio::test]
async fn restricted_cors_matching_origin() {
    let server = setup_with_cors("https://allowed.example.com,https://other.example.com").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://allowed.example.com")
        .await;
    resp.assert_status_ok();
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .expect("ACAO header should be present for a matching origin");
    assert_eq!(acao, "https://allowed.example.com");
}

/// Restricted origins: non-matching origin gets no ACAO header (or a vary
/// response that does not allow the foreign origin).
#[tokio::test]
async fn restricted_cors_non_matching_origin() {
    let server = setup_with_cors("https://allowed.example.com").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://evil.example.com")
        .await;
    // The response itself should still be 200 (CORS is a browser-side policy;
    // the server returns the resource but omits the allow header).
    resp.assert_status_ok();
    let acao = resp.headers().get("access-control-allow-origin");
    // Either the header is absent or it does NOT equal the disallowed origin.
    if let Some(v) = acao {
        assert_ne!(
            v, "https://evil.example.com",
            "non-matching origin must not be reflected"
        );
    }
}
