//! Pagination on the previously-unbounded list endpoints (2026-08-08).
//!
//! `GET /users` capped at a hardcoded 50 rows with no way to reach row 51, so
//! member lists on larger hubs silently truncated. `GET /conversations/{id}/
//! messages` accepted no query params at all and returned the entire DM
//! history on every open — while both clients had been sending `before` and
//! `limit` all along.

use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Registers `n` members and returns their pubkeys. Display names are
/// zero-padded so the roster's `(display_name, public_key)` ordering is
/// deterministic and a cursor walk can be checked against it.
async fn seed_members(server: &axum_test::TestServer, n: usize) -> Vec<String> {
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let id = Identity::generate();
        let token = common::authenticate(server, &id).await;
        server
            .patch("/me")
            .authorization_bearer(&token)
            .json(&json!({ "display_name": format!("member-{i:03}") }))
            .await
            .assert_status_ok();
        keys.push(id.public_key_hex());
    }
    keys
}

#[tokio::test]
async fn users_beyond_the_old_fifty_row_cap_are_reachable() {
    let server = common::setup().await;
    let viewer = Identity::generate();
    let token = common::authenticate(&server, &viewer).await;

    // 60 members + the viewer: more than the old hardcoded LIMIT 50.
    seed_members(&server, 60).await;

    let resp = server.get("/users").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let all = resp.json::<Vec<serde_json::Value>>();
    assert_eq!(
        all.len(),
        61,
        "default page must hold a whole small hub, not truncate at 50"
    );
}

#[tokio::test]
async fn users_cursor_walks_the_whole_roster_without_gaps_or_repeats() {
    let server = common::setup().await;
    let viewer = Identity::generate();
    let token = common::authenticate(&server, &viewer).await;
    seed_members(&server, 25).await;

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut req = server
            .get("/users")
            .authorization_bearer(&token)
            .add_query_param("limit", "10");
        if let Some(c) = &cursor {
            req = req.add_query_param("cursor", c.as_str());
        }
        let page = req.await.json::<Vec<serde_json::Value>>();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 10, "limit must be honoured");
        for u in &page {
            seen.push(u["public_key"].as_str().unwrap().to_string());
        }
        cursor = Some(seen.last().unwrap().clone());
    }

    assert_eq!(seen.len(), 26, "every member reachable by paging");
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "no member served twice");
}

#[tokio::test]
async fn users_limit_is_clamped_to_the_maximum() {
    let server = common::setup().await;
    let viewer = Identity::generate();
    let token = common::authenticate(&server, &viewer).await;
    seed_members(&server, 3).await;

    // Absurd and nonsensical values must not reach SQL untouched.
    for bad in ["100000", "0", "-5"] {
        let resp = server
            .get("/users")
            .authorization_bearer(&token)
            .add_query_param("limit", bad)
            .await;
        resp.assert_status_ok();
        let rows = resp.json::<Vec<serde_json::Value>>();
        assert!(!rows.is_empty(), "limit={bad} should still return rows");
        assert!(rows.len() <= 500, "limit={bad} must clamp to the max");
    }
}

#[tokio::test]
async fn users_search_still_filters_and_pages() {
    let server = common::setup().await;
    let viewer = Identity::generate();
    let token = common::authenticate(&server, &viewer).await;
    seed_members(&server, 12).await;

    let resp = server
        .get("/users")
        .authorization_bearer(&token)
        .add_query_param("q", "member-00")
        .await;
    resp.assert_status_ok();
    let rows = resp.json::<Vec<serde_json::Value>>();
    // member-000 .. member-009
    assert_eq!(rows.len(), 10);

    let resp = server
        .get("/users")
        .authorization_bearer(&token)
        .add_query_param("q", "member-00")
        .add_query_param("limit", "4")
        .await;
    let page = resp.json::<Vec<serde_json::Value>>();
    assert_eq!(page.len(), 4, "search and limit compose");
}

/// The `q` cap used to truncate with `&s[..64]`, a *byte* index — so any
/// search whose 64th byte landed mid-codepoint panicked the handler. 22 or
/// more three-byte characters was enough, and the hub ships in four locales.
#[tokio::test]
async fn users_search_survives_multibyte_queries_past_the_cap() {
    let server = common::setup().await;
    let viewer = Identity::generate();
    let token = common::authenticate(&server, &viewer).await;
    seed_members(&server, 2).await;

    for q in [
        "€".repeat(30),  // 3-byte: byte 64 lands inside a character
        "😀".repeat(40), // 4-byte
        "à".repeat(50),  // 2-byte
        "日本語".repeat(30),
    ] {
        let resp = server
            .get("/users")
            .authorization_bearer(&token)
            .add_query_param("q", q.as_str())
            .await;
        resp.assert_status_ok();
        // Nobody is named this; the point is that it answers at all.
        assert!(resp.json::<Vec<serde_json::Value>>().is_empty());
    }
}

// ---- DM history ----

/// Opens a 1:1 conversation between two fresh identities and returns
/// `(conversation_id, sender_token)`.
async fn open_conversation(server: &axum_test::TestServer) -> (String, String) {
    let a = Identity::generate();
    let a_token = common::authenticate(server, &a).await;
    let b = Identity::generate();
    let _ = common::authenticate(server, &b).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&a_token)
        .json(&json!({ "members": [b.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv = resp.json::<serde_json::Value>();
    (conv["id"].as_str().unwrap().to_string(), a_token)
}

#[tokio::test]
async fn dm_history_is_limited_and_pages_backwards() {
    let server = common::setup().await;
    let (conv_id, token) = open_conversation(&server).await;

    for i in 0..30 {
        server
            .post(&format!("/conversations/{conv_id}/messages"))
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("msg-{i:02}") }))
            .await
            .assert_status(axum::http::StatusCode::CREATED);
    }

    // A bare open now returns one page, not all 30 rows.
    let resp = server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&token)
        .add_query_param("limit", "10")
        .await;
    resp.assert_status_ok();
    let page = resp.json::<Vec<serde_json::Value>>();
    assert_eq!(page.len(), 10);
    // Rows come back oldest-first — the order both clients render.
    let stamps: Vec<i64> = page
        .iter()
        .map(|m| m["created_at"].as_i64().unwrap())
        .collect();
    assert!(stamps.windows(2).all(|w| w[0] <= w[1]), "ascending by time");

    // Walking `cursor` backwards must cover the history exactly once. The
    // keyset tiebreaks on the message id (a uuid), so messages sharing a
    // one-second `created_at` have an arbitrary but *stable* relative order —
    // enough for gap-free paging, which is what is asserted here.
    let mut seen: Vec<String> = page
        .iter()
        .map(|m| m["content"].as_str().unwrap().to_string())
        .collect();
    let mut cursor = page[0]["id"].as_str().unwrap().to_string();
    // Bounded, so an ignored cursor fails the assertion below instead of
    // looping forever on the same page.
    for _ in 0..10 {
        let older = server
            .get(&format!("/conversations/{conv_id}/messages"))
            .authorization_bearer(&token)
            .add_query_param("limit", "10")
            .add_query_param("cursor", cursor.as_str())
            .await
            .json::<Vec<serde_json::Value>>();
        if older.is_empty() {
            break;
        }
        assert!(older.len() <= 10);
        cursor = older[0]["id"].as_str().unwrap().to_string();
        for m in &older {
            seen.push(m["content"].as_str().unwrap().to_string());
        }
    }

    assert_eq!(seen.len(), 30, "every message reachable by paging");
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 30, "no message served twice");
}

#[tokio::test]
async fn dm_history_non_member_is_still_rejected() {
    let server = common::setup().await;
    let (conv_id, _) = open_conversation(&server).await;

    let outsider = Identity::generate();
    let outsider_token = common::authenticate(&server, &outsider).await;

    server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&outsider_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

/// Channel history pages with the dialect's `cursor` (Wavvon-server#172). A
/// thread pages forward with the same parameter instead of stopping at one
/// page.
#[tokio::test]
async fn channel_history_and_threads_page_with_cursor() {
    let (server, token) = common::setup_with_owner().await;
    let channel: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "history" }))
        .await
        .json();
    let url = format!("/channels/{}/messages", channel["id"].as_str().unwrap());

    let mut posted = Vec::new();
    for i in 0..5 {
        let m: serde_json::Value = server
            .post(&url)
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("m{i}") }))
            .await
            .json();
        posted.push(m["id"].as_str().unwrap().to_string());
    }
    let root = posted[0].clone();
    let mut replies = Vec::new();
    for i in 0..3 {
        let m: serde_json::Value = server
            .post(&url)
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("r{i}"), "reply_to": root }))
            .await
            .json();
        replies.push(m["id"].as_str().unwrap().to_string());
    }

    let page = |query: String| {
        let (server, url, token) = (&server, url.clone(), token.clone());
        async move {
            let list: Vec<serde_json::Value> = server
                .get(&format!("{url}?{query}"))
                .authorization_bearer(&token)
                .await
                .json();
            list.iter()
                .map(|m| m["id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        }
    };

    let mut walked = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = match &cursor {
            Some(c) => format!("limit=3&cursor={c}"),
            None => "limit=3".to_string(),
        };
        let ids = page(query).await;
        if ids.is_empty() {
            break;
        }
        cursor = ids.last().cloned();
        walked.extend(ids);
    }
    let mut expected: Vec<String> = posted.iter().chain(&replies).cloned().collect();
    expected.reverse();
    assert_eq!(walked, expected, "newest first, no gaps or repeats");

    let first = page(format!("thread_root={root}&limit=2")).await;
    assert_eq!(first, replies[..2]);
    let rest = page(format!("thread_root={root}&limit=2&cursor={}", first[1])).await;
    assert_eq!(rest, replies[2..]);
}
