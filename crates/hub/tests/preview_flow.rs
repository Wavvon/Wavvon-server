use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn preview_requires_auth() {
    let server = common::setup().await;
    let resp = server.get("/preview?url=https%3A%2F%2Fexample.com").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn preview_rejects_non_http_scheme() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server
        .get("/preview?url=ftp%3A%2F%2Fexample.com%2Ffile")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "invalid_scheme");
}

#[tokio::test]
async fn preview_rejects_localhost() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server
        .get("/preview?url=http%3A%2F%2Flocalhost%2Fpath")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "ssrf_blocked");
}

#[tokio::test]
async fn preview_rejects_private_ip() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    // 192.168.1.1 is a private IP — SSRF check must block it.
    let resp = server
        .get("/preview?url=http%3A%2F%2F192.168.1.1%2F")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "ssrf_blocked");
}

#[tokio::test]
async fn preview_rejects_loopback_ip() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server
        .get("/preview?url=http%3A%2F%2F127.0.0.1%3A8080%2F")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "ssrf_blocked");
}

#[tokio::test]
async fn preview_rejects_missing_url_param() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server.get("/preview").authorization_bearer(&token).await;
    // axum returns 400 for a missing required query param
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

/// After the per-user burst cap (10/min) is exhausted, the endpoint must
/// respond 429 for that user. A private-IP URL is used so the SSRF check
/// fires before any outbound fetch, making this test fast and deterministic.
#[tokio::test]
async fn preview_rate_limited_after_burst() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    // Burn through the 10-request burst limit using a URL that is
    // immediately rejected by the SSRF check (no outbound fetch happens).
    let ssrf_url = "http%3A%2F%2F192.168.1.1%2F";
    for _ in 0..10 {
        let resp = server
            .get(&format!("/preview?url={ssrf_url}"))
            .authorization_bearer(&token)
            .await;
        // Each call should be a 400 (SSRF) not a 429 yet.
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    // The 11th call must be rate-limited.
    let resp = server
        .get(&format!("/preview?url={ssrf_url}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);

    // A different user must NOT be affected by the first user's exhaustion.
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;
    let resp = server
        .get(&format!("/preview?url={ssrf_url}"))
        .authorization_bearer(&other_token)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

/// The rate limiter counts each user's requests independently — a heavy
/// user does not spill over into other users' windows.
#[tokio::test]
async fn preview_rate_limit_is_per_user() {
    let server = common::setup().await;
    let ssrf_url = "http%3A%2F%2F10.0.0.1%2F";

    // Create two users and alternate requests between them.
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;

    // Both users can make 10 requests each without hitting the cap.
    for _ in 0..10 {
        server
            .get(&format!("/preview?url={ssrf_url}"))
            .authorization_bearer(&alice_token)
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);
        server
            .get(&format!("/preview?url={ssrf_url}"))
            .authorization_bearer(&bob_token)
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    // Alice is now rate-limited; Bob is not (independent window).
    server
        .get(&format!("/preview?url={ssrf_url}"))
        .authorization_bearer(&alice_token)
        .await
        .assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
    server
        .get(&format!("/preview?url={ssrf_url}"))
        .authorization_bearer(&bob_token)
        .await
        .assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}
