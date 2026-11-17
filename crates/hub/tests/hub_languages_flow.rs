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

fn lang(code: &str, strings: &str) -> Vec<u8> {
    let manifest = format!(
        r#"{{"format":"wavvon.lang","version":1,"code":"{code}","name":"Sardu","strings":{strings}}}"#
    );
    pack(&[("lang.json", manifest.as_bytes())])
}

#[tokio::test]
async fn owner_uploads_and_anyone_lists_and_fetches_by_hash() {
    let (server, token) = common::setup_with_owner().await;
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("languages").is_none());
    assert!(info["capabilities"]
        .as_array()
        .unwrap()
        .contains(&"hub.languages".into()));

    let package = lang("SC", r#"{"modal.cancel":"Lassa"}"#);
    let resp = server
        .put("/hub/languages")
        .authorization_bearer(&token)
        .bytes(Bytes::from(package.clone()))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["code"], "sc");
    let sha = body["sha256"].as_str().unwrap().to_string();

    server
        .put("/hub/languages/default")
        .authorization_bearer(&token)
        .json(&serde_json::json!({ "code": "sc" }))
        .await
        .assert_status_ok();

    let list: serde_json::Value = server.get("/hub/languages").await.json();
    assert_eq!(list["default"], "sc");
    assert_eq!(list["packs"][0]["sha256"], sha);
    assert_eq!(list["packs"][0]["name"], "Sardu");
    let info: serde_json::Value = server.get("/info").await.json();
    assert_eq!(info["languages"], list);

    let got = server.get(&format!("/hub/languages/{sha}")).await;
    got.assert_status_ok();
    assert_eq!(got.as_bytes().as_ref(), package.as_slice());
    assert!(got
        .header("cache-control")
        .to_str()
        .unwrap()
        .contains("immutable"));

    // Same code again replaces the pack, and the old hash is gone.
    let resp = server
        .put("/hub/languages")
        .authorization_bearer(&token)
        .bytes(Bytes::from(lang("sc", r#"{"modal.cancel":"Annulla"}"#)))
        .await;
    let sha2 = resp.json::<serde_json::Value>()["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    server
        .get(&format!("/hub/languages/{sha}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    let list: serde_json::Value = server.get("/hub/languages").await.json();
    assert_eq!(list["packs"].as_array().unwrap().len(), 1);

    server
        .delete(&format!("/hub/languages/{sha2}"))
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .put("/hub/languages/default")
        .authorization_bearer(&token)
        .json(&serde_json::json!({ "code": null }))
        .await
        .assert_status_ok();
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("languages").is_none());
}

const MINIMAL: &str =
    r#"{"format":"wavvon.lang","version":1,"code":"sc","name":"Sardu","strings":{}}"#;

#[tokio::test]
async fn invalid_packages_and_non_owners_are_refused() {
    let (server, token) = common::setup_with_owner().await;
    let oversized = format!(r#"{{"modal.cancel":"{}"}}"#, "x".repeat(600 * 1024));
    let bad = [
        lang("sc", &oversized),
        lang("sc", r#"{"modal.cancel":3}"#),
        lang("sc", r#"{"modal":{"cancel":"x"}}"#),
        lang("not a tag", "{}"),
        pack(&[("lang.json", MINIMAL.as_bytes()), ("extra.png", b"x")]),
        b"not a zip".to_vec(),
    ];
    for body in bad {
        server
            .put("/hub/languages")
            .authorization_bearer(&token)
            .bytes(Bytes::from(body))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    server
        .put("/hub/languages/default")
        .authorization_bearer(&token)
        .json(&serde_json::json!({ "code": "<script>" }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    let member = common::authenticate(&server, &Identity::generate()).await;
    server
        .put("/hub/languages")
        .authorization_bearer(&member)
        .bytes(Bytes::from(lang("sc", "{}")))
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .put("/hub/languages/default")
        .authorization_bearer(&member)
        .json(&serde_json::json!({ "code": "it" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}
