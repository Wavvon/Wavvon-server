use std::io::Write;

use axum::body::Bytes;
use axum::http::StatusCode;
use wavvon_identity::Identity;
use zip::write::SimpleFileOptions;

#[path = "common.rs"]
mod common;

fn pack(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in entries {
        w.start_file(*name, SimpleFileOptions::default()).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

const MANIFEST: &str = r##"{"format":"wavvon.theme","version":1,"name":"Sakura","colors":{"dark":{"--accent":"#ff8fb1"}},"preview":"preview.png"}"##;

#[tokio::test]
async fn owner_uploads_and_anyone_fetches_by_hash() {
    let (server, token) = common::setup_with_owner().await;
    let package = pack(&[("theme.json", MANIFEST.as_bytes()), ("preview.png", b"png")]);

    let resp = server
        .put("/hub/theme")
        .authorization_bearer(&token)
        .bytes(Bytes::from(package.clone()))
        .await;
    resp.assert_status_ok();
    let sha = resp.json::<serde_json::Value>()["sha256"]
        .as_str()
        .unwrap()
        .to_string();

    let info: serde_json::Value = server.get("/info").await.json();
    assert_eq!(info["theme"]["sha256"], sha);
    assert_eq!(info["theme"]["has_preview"], true);
    assert!(info["capabilities"]
        .as_array()
        .unwrap()
        .contains(&"hub.theme".into()));

    let got = server.get(&format!("/hub/theme/{sha}")).await;
    got.assert_status_ok();
    assert_eq!(got.as_bytes().as_ref(), package.as_slice());
    assert!(got
        .header("cache-control")
        .to_str()
        .unwrap()
        .contains("immutable"));
    let preview = server.get(&format!("/hub/theme/{sha}/preview")).await;
    preview.assert_status_ok();
    assert_eq!(preview.header("content-type"), "image/png");
    server
        .get("/hub/theme/0000")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    server
        .delete("/hub/theme")
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("theme").is_none());
    server
        .get(&format!("/hub/theme/{sha}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_packages_and_members_are_refused() {
    let (server, token) = common::setup_with_owner().await;
    let bad_token = MANIFEST.replace("#ff8fb1", "url(https://x)");
    let bad = [
        pack(&[
            ("theme.json", MANIFEST.as_bytes()),
            ("../preview.png", b"x"),
        ]),
        pack(&[("theme.json", bad_token.as_bytes()), ("preview.png", b"x")]),
        pack(&[("theme.json", MANIFEST.as_bytes()), ("preview.bmp", b"x")]),
        b"not a zip".to_vec(),
    ];
    for body in bad {
        server
            .put("/hub/theme")
            .authorization_bearer(&token)
            .bytes(Bytes::from(body))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    let member = common::authenticate(&server, &Identity::generate()).await;
    server
        .put("/hub/theme")
        .authorization_bearer(&member)
        .bytes(Bytes::from(pack(&[
            ("theme.json", MANIFEST.as_bytes()),
            ("preview.png", b"png"),
        ])))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}
