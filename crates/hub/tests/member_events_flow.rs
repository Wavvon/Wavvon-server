//! `member.joined` / `member.left` mean the hub, `voice.joined` / `voice.left`
//! mean a voice channel.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::server;
use wavvon_identity::Identity;

use crate::common;

async fn subscribed_app(server: &common::TestHarness, events: &[&str]) -> String {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission)
         VALUES ('builtin-everyone', 'apps.register') ON CONFLICT DO NOTHING",
    )
    .execute(&server.state().db)
    .await
    .unwrap();
    let app = Identity::generate();
    let token = common::authenticate(server, &app).await;
    server
        .put("/me/app/profile")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Greeter" }))
        .await
        .assert_status_success();
    let subs: Vec<Value> = events.iter().map(|e| json!({ "event": e })).collect();
    server
        .put("/me/app/subscriptions")
        .authorization_bearer(&token)
        .json(&json!({ "subscriptions": subs }))
        .await
        .assert_status_success();
    token
}

async fn poll(server: &common::TestHarness, token: &str) -> Vec<Value> {
    server
        .get("/me/events")
        .authorization_bearer(token)
        .await
        .json()
}

#[tokio::test]
async fn a_new_member_and_a_leaver_reach_a_subscribed_app() {
    let (server, _owner_token) = common::setup_with_owner().await;
    let app_token = subscribed_app(&server, &["member.joined", "member.left"]).await;
    let before = poll(&server, &app_token).await.len();

    let newcomer = Identity::generate();
    let token = common::authenticate(&server, &newcomer).await;

    let events = poll(&server, &app_token).await;
    let joined: Vec<&Value> = events[before..].iter().collect();
    assert_eq!(joined.len(), 1, "{events:?}");
    assert_eq!(joined[0]["event"], "member.joined");
    assert_eq!(joined[0]["target_pubkey"], newcomer.public_key_hex());
    assert!(joined[0]["channel_id"].is_null());

    // Logging in again is not joining.
    common::authenticate(&server, &newcomer).await;
    assert_eq!(poll(&server, &app_token).await.len(), before + 1);

    server
        .delete("/me")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    let events = poll(&server, &app_token).await;
    assert_eq!(events.last().unwrap()["event"], "member.left");
    assert_eq!(events.len(), before + 2);
}

#[tokio::test]
async fn a_voice_join_is_voice_joined_not_member_joined() {
    let (db, _guard) = common::create_test_db().await;
    let state = std::sync::Arc::new(common::base_state(db));
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let owner = Identity::generate();
    let token = authenticate(&base, &owner).await;
    let chan: Value = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&token)
        .json(&json!({ "name": "room", "channel_type": "voice" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (mut tx, mut rx) = ws.split();
    tx.send(TsMessage::Text(
        json!({ "type": "voice_join", "channel_id": chan["id"], "udp_port": 0 }).to_string(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(Ok(TsMessage::Text(raw))) = rx.next().await {
            if raw.contains("\"voice_joined\"") {
                return;
            }
        }
        panic!("socket closed");
    })
    .await
    .expect("no voice_joined");

    let owner_pk = owner.public_key_hex();
    let mut kinds = Vec::new();
    for _ in 0..50 {
        kinds = sqlx::query_scalar::<_, String>(
            "SELECT event_type FROM hub_audit_log WHERE channel_id = $1 AND event_type LIKE '%.joined'",
        )
        .bind(chan["id"].as_str().unwrap())
        .fetch_all(&state.db)
        .await
        .unwrap();
        if !kinds.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(kinds, vec!["voice.joined"], "owner {owner_pk}");
}

async fn authenticate(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pk = identity.public_key_hex();
    let ch: Value = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pk }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = ch["challenge"].as_str().unwrap();
    let sig = identity.sign(
        &wavvon_identity::auth_challenge_signing_bytes(&hex::decode(challenge).unwrap()).unwrap(),
    );
    let v: Value = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pk,
            "challenge": challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_live_push_carries_who_joined() {
    let (server, _owner_token) = common::setup_with_owner().await;
    let _app_token = subscribed_app(&server, &["member.joined"]).await;
    let app_pk: String = sqlx::query_scalar("SELECT DISTINCT app_pubkey FROM app_subscriptions")
        .fetch_one(&server.state().db)
        .await
        .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    server
        .state()
        .app_sessions
        .write()
        .await
        .entry(app_pk)
        .or_default()
        .insert("s1".into(), tx);

    let newcomer = Identity::generate();
    common::authenticate(&server, &newcomer).await;

    let raw = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("no live push")
        .unwrap();
    let live: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(live["event"], "member.joined");
    assert_eq!(live["target_pubkey"], newcomer.public_key_hex());
    assert!(live.get("channel_id").is_none(), "{live}");
    assert!(live.get("replayed").is_none());
}
