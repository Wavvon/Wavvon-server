use voxply_identity::Identity;

#[path = "common.rs"] mod common;

#[tokio::test]
async fn preview_requires_auth() {
    let server = common::setup().await;
    let resp = server
        .get("/preview?url=https%3A%2F%2Fexample.com")
        .await;
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

    let resp = server
        .get("/preview")
        .authorization_bearer(&token)
        .await;
    // axum returns 400 for a missing required query param
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
