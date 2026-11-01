use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;

#[path = "common.rs"]
mod common;

const STRICT: &str = "default-src 'none'; sandbox";

fn csp(resp: &axum_test::TestResponse) -> String {
    resp.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn web_client_responses_carry_the_html_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><html><head></head><body></body></html>",
    )
    .unwrap();
    std::fs::write(dir.path().join("app.js"), "1").unwrap();
    let (server, owner_token) = common::setup_with_owner_and_web_client(dir.path()).await;

    for resp in [
        server.get("/").await,
        server.get("/app.js").await,
        server
            .get("/deep/link")
            .add_header("accept", "text/html")
            .await,
    ] {
        resp.assert_status_ok();
        let p = csp(&resp);
        assert!(p.contains("frame-ancestors 'none'") && p.contains("object-src 'none'"));
        assert!(!p.contains("'unsafe-eval'") && !p.contains("script-src 'unsafe-inline'"));
    }

    let invite: serde_json::Value = server
        .post("/invites")
        .authorization_bearer(&owner_token)
        .json(&json!({}))
        .await
        .json();
    let join = server
        .get(&format!("/join/{}", invite["code"].as_str().unwrap()))
        .add_header("accept", "text/html")
        .await;
    assert!(csp(&join).contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn api_and_user_content_get_the_strict_policy() {
    let (server, token) = common::setup_with_owner().await;
    server
        .post("/admin/emojis")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "ok",
            "mime": "image/png",
            "data_b64": STANDARD.encode(b"\x89PNG\r\n\x1a\nbody"),
        }))
        .await
        .assert_status(StatusCode::CREATED);
    let list: serde_json::Value = server.get("/emojis").await.json();
    let emoji = server.get(list[0]["url"].as_str().unwrap()).await;
    emoji.assert_status_ok();
    assert_eq!(csp(&emoji), STRICT);

    for path in [
        "/info",
        "/preview/image/none",
        "/uploads/none",
        "/stickers/none",
        "/soundboard/none/audio",
    ] {
        assert_eq!(csp(&server.get(path).await), STRICT, "{path}");
    }
}
