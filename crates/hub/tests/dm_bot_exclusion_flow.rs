use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Bots are not DM participants (bots.md, "Hard-coded in v1").
//
// A bot authenticates through the ordinary session flow and its token reaches
// every route a person's does, so nothing about being a bot kept it out of the
// DM routes on its own. These cover the three ways in: opening a conversation
// with one, being one, and being added to a group after the fact.
// ---------------------------------------------------------------------------

/// Invites `bot` as an external bot and completes the challenge/verify flow,
/// returning its session token. Mirrors `bots_flow.rs`'s helper.
async fn invite_and_auth_bot(
    server: &axum_test::TestServer,
    admin_token: &str,
    bot: &Identity,
) -> String {
    let pub_key = bot.public_key_hex();

    server
        .post("/bots")
        .authorization_bearer(admin_token)
        .json(&json!({ "pubkey": pub_key }))
        .await
        .assert_status_success();

    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = bot.sign(&challenge_bytes);

    let verify: serde_json::Value = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
            "is_bot": true,
            "bot_meta": { "name": "DmBot" },
        }))
        .await
        .json();
    verify["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_person_cannot_open_a_dm_with_a_bot() {
    let (server, owner_token) = common::setup_with_owner().await;
    let bot = Identity::generate();
    let _bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&owner_token)
        .json(&json!({ "members": [bot.public_key_hex()] }))
        .await;

    resp.assert_status_forbidden();
}

#[tokio::test]
async fn a_bot_cannot_open_a_dm_with_a_person() {
    let (server, owner_token) = common::setup_with_owner().await;
    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;
    let human = Identity::generate();

    let resp = server
        .post("/conversations")
        .authorization_bearer(&bot_token)
        .json(&json!({ "members": [human.public_key_hex()] }))
        .await;

    resp.assert_status_forbidden();
}

#[tokio::test]
async fn a_bot_cannot_be_added_to_an_existing_group() {
    let (server, owner_token) = common::setup_with_owner().await;
    let bot = Identity::generate();
    let _bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;
    let friend = Identity::generate();
    let other = Identity::generate();

    // A group of humans opens fine — the guard is about bots, not about
    // conversations, and this is what proves the rest of the route still works.
    let conv: serde_json::Value = server
        .post("/conversations")
        .authorization_bearer(&owner_token)
        .json(&json!({ "members": [friend.public_key_hex(), other.public_key_hex()] }))
        .await
        .json();
    let conv_id = conv["id"].as_str().unwrap();

    let resp = server
        .post(&format!("/conversations/{conv_id}/members"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "public_key": bot.public_key_hex() }))
        .await;

    resp.assert_status_forbidden();
}
