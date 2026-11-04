use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// `voice_speaking` named its channel and was broadcast there as sent, so a
// member who was not in the room could light up a speaking indicator in it.
// Multi-thread for the reason ban_closes_socket_flow.rs gives.

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let state = Arc::new(common::base_state(db));
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state, guard)
}

async fn authenticate(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();
    let resp: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = identity.sign(
        &wavvon_identity::auth_challenge_signing_bytes(&hex::decode(&resp.challenge).unwrap())
            .unwrap(),
    );
    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_participant_cannot_speak_in_a_room() {
    let (base, _state, _guard) = start_hub().await;
    let owner = authenticate(&base, &Identity::generate()).await;
    let outsider = authenticate(&base, &Identity::generate()).await;

    let channel: Value = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&owner)
        .json(&json!({ "name": "lounge" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let ws = |token: String| {
        let url = format!("{}/ws?token={token}", base.replace("http://", "ws://"));
        async move { tokio_tungstenite::connect_async(&url).await.unwrap().0 }
    };
    let mut watcher = ws(owner).await;
    let mut speaker = ws(outsider).await;
    let _ = watcher.next().await;
    let _ = speaker.next().await;
    watcher
        .send(Message::Text(
            json!({ "type": "voice_watch", "channel_id": channel_id }).to_string(),
        ))
        .await
        .unwrap();
    // Let the hub register the watch before anything is said.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    speaker
        .send(Message::Text(
            json!({ "type": "voice_speaking", "channel_id": channel_id, "speaking": true })
                .to_string(),
        ))
        .await
        .unwrap();

    let ghost = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match watcher.next().await {
                Some(Ok(Message::Text(t))) if t.contains("voice_participant_speaking") => {
                    return true
                }
                Some(Ok(_)) => {}
                _ => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        !ghost,
        "a speaking indicator reached the room from outside it"
    );
}

// `voice_watch` used to set the same connection state `voice_join` sets, so a
// member who only watched a room could create zones in it and post positions
// into them. Watching subscribes to speaking events and grants nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn watching_a_room_does_not_put_you_in_it() {
    let (base, state, _guard) = start_hub().await;
    let owner = authenticate(&base, &Identity::generate()).await;

    let channel: Value = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&owner)
        .json(&json!({ "name": "lounge" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let url = format!("{}/ws?token={owner}", base.replace("http://", "ws://"));
    let mut watcher = tokio_tungstenite::connect_async(&url).await.unwrap().0;
    let _ = watcher.next().await;
    watcher
        .send(Message::Text(
            json!({ "type": "voice_watch", "channel_id": channel_id }).to_string(),
        ))
        .await
        .unwrap();
    watcher
        .send(Message::Text(
            json!({
                "type": "voice_zone_create",
                "zone_id": "z1",
                "name": "arena",
                "attenuation": {},
            })
            .to_string(),
        ))
        .await
        .unwrap();

    let refused = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match watcher.next().await {
                Some(Ok(Message::Text(t))) if t.contains("voice_zone_create") => return t,
                Some(Ok(_)) => {}
                _ => return String::new(),
            }
        }
    })
    .await
    .unwrap_or_default();
    assert!(
        refused.contains("Must be in voice"),
        "a watcher was treated as in the room: {refused}"
    );
    assert!(state.voice_zones.read().await.is_empty());
}

// `session_roster` was accepted at zone creation and then refused every
// position update, so a zone created with it could never be used.
#[tokio::test(flavor = "multi_thread")]
async fn a_zone_with_an_unsupported_auth_mode_is_refused() {
    let (base, state, _guard) = start_hub().await;
    let owner = authenticate(&base, &Identity::generate()).await;

    let channel: Value = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&owner)
        .json(&json!({ "name": "arena", "channel_type": "voice" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let url = format!("{}/ws?token={owner}", base.replace("http://", "ws://"));
    let mut ws = tokio_tungstenite::connect_async(&url).await.unwrap().0;
    let _ = ws.next().await;
    ws.send(Message::Text(
        json!({ "type": "voice_join", "channel_id": channel_id, "udp_port": 0 }).to_string(),
    ))
    .await
    .unwrap();
    ws.send(Message::Text(
        json!({
            "type": "voice_zone_create",
            "zone_id": "z1",
            "name": "arena",
            "attenuation": {},
            "auth_mode": "session_roster",
        })
        .to_string(),
    ))
    .await
    .unwrap();

    let refused = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.contains("voice_zone_create") => return t,
                Some(Ok(_)) => {}
                _ => return String::new(),
            }
        }
    })
    .await
    .unwrap_or_default();
    assert!(
        refused.contains("Unsupported zone auth_mode"),
        "zone was not refused: {refused}"
    );
    assert!(state.voice_zones.read().await.is_empty());
}
