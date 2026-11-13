//! The public online widget (Wavvon-server#341). One test: the widget's
//! answer is cached process-wide for a few seconds, so separate tests in one
//! binary would read each other's hubs.

use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn widget_is_off_by_default_and_never_shows_the_hidden_or_a_key() {
    let (h, owner) = common::setup_with_owner().await;
    let state = h.state();

    // Off: nothing is revealed, not even that the feature exists.
    h.get("/public/widget.json").await.assert_status_not_found();
    h.get("/widget").await.assert_status_not_found();

    let visible = Identity::generate();
    let invisible = Identity::generate();
    let opted_out = Identity::generate();
    let mut tokens = Vec::new();
    for (id, name) in [
        (&visible, "Alice"),
        (&invisible, "Bob"),
        (&opted_out, "Carol"),
    ] {
        let token = common::authenticate(&h, id).await;
        h.patch("/me")
            .authorization_bearer(&token)
            .json(&json!({ "display_name": name }))
            .await
            .assert_status_success();
        state
            .online_users
            .write()
            .await
            .insert(id.public_key_hex(), 1);
        tokens.push(token);
    }
    sqlx::query("UPDATE users SET presence_status = 'invisible' WHERE public_key = $1")
        .bind(invisible.public_key_hex())
        .execute(&state.db)
        .await
        .unwrap();
    let me: Value = h
        .patch("/me")
        .authorization_bearer(&tokens[2])
        .json(&json!({ "widget_hidden": true }))
        .await
        .json();
    assert_eq!(me["widget_hidden"], true);

    // Only an admin turns it on, and only to a known mode.
    h.put("/admin/settings/widget")
        .authorization_bearer(&tokens[0])
        .json(&json!({ "mode": "names" }))
        .await
        .assert_status_forbidden();
    h.put("/admin/settings/widget")
        .authorization_bearer(&owner)
        .json(&json!({ "mode": "everything" }))
        .await
        .assert_status_bad_request();
    h.put("/admin/settings/widget")
        .authorization_bearer(&owner)
        .json(&json!({ "mode": "names", "invite_code": "abc123" }))
        .await
        .assert_status_success();

    let resp = h.get("/public/widget.json").await;
    resp.assert_status_ok();
    let text = resp.text();
    let body: Value = serde_json::from_str(&text).unwrap();
    let names: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Alice"], "{text}");
    assert_eq!(body["online_count"], 1);
    for id in [&visible, &invisible, &opted_out] {
        assert!(!text.contains(&id.public_key_hex()), "a key leaked: {text}");
    }

    // The page may be framed by any site; the client's pages may not.
    let page = h.get("/widget").add_query_param("theme", "dark").await;
    page.assert_status_ok();
    let csp = page.header("content-security-policy");
    let csp = csp.to_str().unwrap();
    assert!(csp.contains("frame-ancestors *"), "{csp}");
    assert!(!csp.contains("script-src"), "{csp}");
    assert!(page.text().contains("Alice"));
    assert!(!page.text().contains("Carol"));

    // Counts mode drops the names.
    h.put("/admin/settings/widget")
        .authorization_bearer(&owner)
        .json(&json!({ "mode": "counts" }))
        .await
        .assert_status_success();
    let body: Value = h.get("/public/widget.json").await.json();
    assert_eq!(body["online_count"], 1);
    assert!(body.get("members").is_none(), "{body}");
}
