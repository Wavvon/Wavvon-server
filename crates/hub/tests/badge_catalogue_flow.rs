//! The badge catalogue (achievement-badges.md): hand badges granted to several
//! members, rule badges that are retroactive and climb levels, conditional
//! badges that go when the condition does, and program badges.

use serde_json::json;
use wavvon_identity::Identity;

use crate::common;

async fn live_badge_certs(state: &wavvon_hub::state::AppState, pk: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM cert_issuances
         WHERE subject_pubkey = $1 AND revoked_at IS NULL AND payload_json LIKE '%\"label\"%'",
    )
    .bind(pk)
    .fetch_one(&state.db)
    .await
    .unwrap()
}

async fn award_level(state: &wavvon_hub::state::AppState, badge: &str, pk: &str) -> Option<i32> {
    sqlx::query_scalar("SELECT level FROM badge_awards WHERE badge_id = $1 AND subject_pubkey = $2")
        .bind(badge)
        .bind(pk)
        .fetch_optional(&state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_hand_badge_goes_to_several_members_and_back() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let a = Identity::generate();
    let b = Identity::generate();
    common::authenticate(&server, &a).await;
    common::authenticate(&server, &b).await;

    let def: serde_json::Value = server
        .post("/admin/badge-defs")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "Raid Leader", "rule": "manual", "levels": [{ "level": 0, "name": "Raid Leader" }] }))
        .await
        .json();
    let id = def["id"].as_str().unwrap().to_string();

    server
        .post(&format!("/admin/badge-defs/{id}/grant"))
        .authorization_bearer(&owner)
        .json(&json!({ "subjects": [a.public_key_hex(), b.public_key_hex()] }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    let awards: Vec<serde_json::Value> = server
        .get(&format!("/admin/badge-defs/{id}/awards"))
        .authorization_bearer(&owner)
        .await
        .json();
    assert_eq!(awards.len(), 2);

    server
        .delete(&format!(
            "/admin/badge-defs/{id}/awards/{}",
            a.public_key_hex()
        ))
        .authorization_bearer(&owner)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    let state = server.state();
    assert_eq!(live_badge_certs(state, &a.public_key_hex()).await, 0);
    assert_eq!(live_badge_certs(state, &b.public_key_hex()).await, 1);
}

#[tokio::test]
async fn a_rule_badge_is_retroactive_and_climbs_levels() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;
    let pk = member.public_key_hex();
    let state = server.state();
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    let set_age = |days: i64| {
        sqlx::query("UPDATE users SET first_seen_at = $1 WHERE public_key = $2")
            .bind(now - days * 86400)
            .bind(pk.clone())
            .execute(&state.db)
    };
    set_age(40).await.unwrap();

    let body = json!({
        "name": "Veteran", "rule": "member_age",
        "levels": [
            { "level": 0, "name": "Veteran", "threshold": 30 * 86400 },
            { "level": 0, "name": "Gold veteran", "threshold": 365 * 86400 }
        ]
    });
    let preview: serde_json::Value = server
        .post("/admin/badge-defs/preview")
        .authorization_bearer(&owner)
        .json(&body)
        .await
        .json();
    assert_eq!(
        preview["1"], 1,
        "the member already qualifies for level 1: {preview}"
    );

    let def: serde_json::Value = server
        .post("/admin/badge-defs")
        .authorization_bearer(&owner)
        .json(&body)
        .await
        .json();
    let id = def["id"].as_str().unwrap().to_string();
    assert_eq!(
        award_level(state, &id, &pk).await,
        Some(1),
        "retroactive on creation"
    );

    set_age(400).await.unwrap();
    wavvon_hub::cert_worker::tick(state).await.unwrap();
    assert_eq!(award_level(state, &id, &pk).await, Some(2));
    assert_eq!(
        live_badge_certs(state, &pk).await,
        1,
        "one current level, the old cert revoked"
    );
}

#[tokio::test]
async fn a_conditional_badge_goes_with_the_role() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;
    let pk = member.public_key_hex();
    let state = server.state();
    let now = wavvon_hub::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO roles (id, name, priority, created_at) VALUES ('mod', 'Moderator', 50, $1)",
    )
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, 'mod', $2)",
    )
    .bind(&pk)
    .bind(now - 70 * 86400)
    .execute(&state.db)
    .await
    .unwrap();

    let def: serde_json::Value = server
        .post("/admin/badge-defs")
        .authorization_bearer(&owner)
        .json(&json!({
            "name": "Senior Moderator", "rule": "role_held", "role_id": "mod", "keep_while": true,
            "levels": [{ "level": 0, "name": "Senior Moderator", "threshold": 60 * 86400 }]
        }))
        .await
        .json();
    let id = def["id"].as_str().unwrap().to_string();
    assert_eq!(award_level(state, &id, &pk).await, Some(1));

    sqlx::query("DELETE FROM user_roles WHERE user_public_key = $1 AND role_id = 'mod'")
        .bind(&pk)
        .execute(&state.db)
        .await
        .unwrap();
    wavvon_hub::cert_worker::tick(state).await.unwrap();
    assert_eq!(award_level(state, &id, &pk).await, None);
    assert_eq!(live_badge_certs(state, &pk).await, 0);
}

#[tokio::test]
async fn chat_counters_feed_a_rule_badge() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;
    let pk = member.public_key_hex();
    let state = server.state();
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    for _ in 0..3 {
        wavvon_hub::routes::badge_defs::count_message(&state.db, &pk, now).await;
    }
    let (messages, days): (i64, i64) =
        sqlx::query_as("SELECT messages, active_days FROM member_stats WHERE public_key = $1")
            .bind(&pk)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!((messages, days), (3, 1), "three messages on one day");

    let def: serde_json::Value = server
        .post("/admin/badge-defs")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "Chatty", "rule": "messages", "levels": [{ "level": 0, "name": "Chatty", "threshold": 3 }] }))
        .await
        .json();
    assert_eq!(
        award_level(state, def["id"].as_str().unwrap(), &pk).await,
        Some(1)
    );
}

#[tokio::test]
async fn a_program_runs_its_own_badges_only() {
    let server = common::setup().await;
    // The owner holds every permission, badges.programs included: it stands
    // in for a program here.
    let program = common::authenticate(&server, &Identity::generate()).await;
    let player = Identity::generate();
    let player_token = common::authenticate(&server, &player).await;
    let pk = player.public_key_hex();

    let def: serde_json::Value = server
        .post("/badges/programs")
        .authorization_bearer(&program)
        .json(&json!({
            "name": "Tournament champion", "declared_rule": "Win weekly tournaments: 1, 5, 20 wins",
            "levels": ["Bronze", "Silver", "Gold"]
        }))
        .await
        .json();
    let id = def["id"].as_str().unwrap().to_string();
    assert!(def["program_pubkey"].is_string());
    assert_eq!(def["levels"].as_array().unwrap().len(), 3);

    server
        .post(&format!("/badges/programs/{id}/grant"))
        .authorization_bearer(&program)
        .json(&json!({ "subject": pk, "level": 2 }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    assert_eq!(award_level(server.state(), &id, &pk).await, Some(2));

    // A member without the permission cannot grant anything.
    server
        .post(&format!("/badges/programs/{id}/grant"))
        .authorization_bearer(&player_token)
        .json(&json!({ "subject": pk }))
        .await
        .assert_status_forbidden();

    // A hand-granting route refuses a program's badge.
    server
        .post(&format!("/admin/badge-defs/{id}/grant"))
        .authorization_bearer(&program)
        .json(&json!({ "subjects": [pk] }))
        .await
        .assert_status(axum::http::StatusCode::CONFLICT);

    // Hidden from members, deleted with its awards revoked.
    server
        .patch(&format!("/admin/badge-defs/{id}"))
        .authorization_bearer(&program)
        .json(&json!({ "hidden": true }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    let seen: Vec<serde_json::Value> = server
        .get("/badges/defs")
        .authorization_bearer(&player_token)
        .await
        .json();
    assert!(seen.iter().all(|d| d["id"] != id.as_str()));
    server
        .delete(&format!("/admin/badge-defs/{id}"))
        .authorization_bearer(&program)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    assert_eq!(live_badge_certs(server.state(), &pk).await, 0);
}
