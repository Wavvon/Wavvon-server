//! `DELETE /me` — a member removing themselves (decisions.md, "Leaving a hub
//! clears the profile and the membership, and keeps the pubkey as an anchor").

use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn join(server: &common::TestHarness, who: &Identity) -> String {
    common::authenticate(server, who).await
}

#[tokio::test]
async fn leaving_clears_the_profile_and_the_roles_but_keeps_the_row() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let member = Identity::generate();
    let token = join(&server, &member).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "display_name": "Wanda", "bio": "here for the voice channels" }))
        .await
        .assert_status_ok();

    server
        .delete("/me")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Two things at once. The roster drops them — `/users` already requires a
    // role row, so clearing the membership is what removes them from the
    // member list, with no separate filter to remember. And the underlying row
    // survives, which is what the 22 foreign keys need and what the ban test
    // below depends on.
    let owner_token = common::authenticate(&server, &owner).await;
    let users: serde_json::Value = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(
        !users
            .as_array()
            .expect("users array")
            .iter()
            .any(|u| u["public_key"] == member.public_key_hex()),
        "someone who left is not a member any more"
    );

    let row: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT display_name, bio, approval_status FROM users WHERE public_key = $1",
    )
    .bind(member.public_key_hex())
    .fetch_optional(&server.state().db)
    .await
    .unwrap();
    let (display_name, bio, status) =
        row.expect("the pubkey stays as an anchor for what it authored");
    assert_eq!(
        display_name, None,
        "the profile is what the hub held on their behalf"
    );
    assert_eq!(bio, None);
    assert_eq!(status, "left");

    let roles: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_public_key = $1")
            .bind(member.public_key_hex())
            .fetch_one(&server.state().db)
            .await
            .unwrap();
    assert_eq!(roles, 0, "membership is the roles");
}

#[tokio::test]
async fn a_ban_survives_the_person_leaving() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let member = Identity::generate();
    let member_token = join(&server, &member).await;

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": member.public_key_hex(), "reason": "spam" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Leaving must not be a way to shed a ban. This is the whole reason the
    // row is kept rather than deleted: `bans.target_public_key` references it,
    // so a cascade would take the ban with the person.
    let resp = server
        .delete("/me")
        .authorization_bearer(&member_token)
        .await;
    assert!(
        resp.status_code().is_success() || resp.status_code().is_client_error(),
        "a banned member's session may already be gone; either answer is fine"
    );

    let bans: serde_json::Value = server
        .get("/moderation/bans")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let still_banned = bans.as_array().expect("bans array").iter().any(|b| {
        b["public_key"] == member.public_key_hex()
            || b["target_public_key"] == member.public_key_hex()
    });
    assert!(
        still_banned,
        "the ban outlives the departure it was dodging"
    );
}

#[tokio::test]
async fn the_owner_cannot_leave() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // The first user to authenticate is the owner. Letting them go would leave
    // the hub with nobody able to administer it and nobody able to let anyone
    // back in — transferring ownership first is the documented path.
    server
        .delete("/me")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn leaving_ends_the_session_it_was_asked_with() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let member = Identity::generate();
    let token = join(&server, &member).await;

    server
        .delete("/me")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Still holding a token for a hub you left is the kind of loose end that
    // reads as "it did not work".
    let resp = server.get("/me").authorization_bearer(&token).await;
    assert!(
        !resp.status_code().is_success(),
        "the session goes with the membership"
    );
}

/// The consequence the design says to choose rather than inherit: membership
/// *is* the roles, and the invite gate is `has_roles == 0`. So on an
/// invite-only hub, leaving turns a return that is free today into one that
/// needs a fresh invite — which is why the client's confirmation says so
/// before asking, and only when the hub is actually invite-only.
#[tokio::test]
async fn leaving_an_invite_only_hub_re_arms_the_invite_gate() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    // Written straight into hub_settings: only bootstrap sets `invite_only`,
    // there is no admin route for it, and a PATCH carrying it is ignored in
    // silence. The integration harness builds AppState directly and so never
    // gets bootstrap's default — the same gap that once let two hubs think
    // they could federate when a real pair could not (alliance_flow.rs).
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('invite_only', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'")
        .execute(&server.state().db)
        .await
        .unwrap();
    let _ = &owner_token;

    // Still a member: re-authenticating needs no invite, because the gate is
    // "has no roles" and they have builtin-everyone.
    common::authenticate(&server, &member).await;

    server
        .delete("/me")
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Now the same person is a stranger to this hub.
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": member.public_key_hex() }))
        .await
        .json();
    let challenge_hex = challenge["challenge"].as_str().expect("challenge");
    let signature = member.sign(&hex::decode(challenge_hex).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": member.public_key_hex(),
            "challenge": challenge_hex,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    assert!(
        resp.status_code().is_client_error(),
        "leaving an invite-only hub is one-way without a fresh invite; got {}",
        resp.status_code()
    );
}
