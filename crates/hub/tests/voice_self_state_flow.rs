//! Self-mute and deafen reach the room (#452): a participant's report is
//! relayed as `voice_participant_self_state`, and the voice roster carries it
//! for whoever looks later.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::server;
use wavvon_identity::Identity;

use crate::common;

type Rx = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;
type Tx = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;

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
        .json(&json!({ "public_key": pk, "challenge": challenge, "signature": hex::encode(sig.to_bytes()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["token"].as_str().unwrap().to_string()
}

async fn join_voice(base: &str, token: &str, channel_id: &str) -> (Tx, Rx) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (mut tx, mut rx) = ws.split();
    tx.send(TsMessage::Text(
        json!({ "type": "voice_join", "channel_id": channel_id, "udp_port": 0 }).to_string(),
    ))
    .await
    .unwrap();
    wait_for(&mut rx, "voice_joined").await;
    (tx, rx)
}

async fn wait_for(rx: &mut Rx, kind: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(Ok(msg)) = rx.next().await {
            if let TsMessage::Text(raw) = msg {
                let v: Value = serde_json::from_str(&raw).unwrap();
                if v["type"] == kind {
                    return v;
                }
            }
        }
        panic!("socket closed before {kind}");
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind}"))
}

#[tokio::test]
async fn self_mute_reaches_the_room_and_the_roster() {
    let (db, _guard) = common::create_test_db().await;
    let state = std::sync::Arc::new(common::base_state(db));
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let owner = Identity::generate();
    let owner_token = authenticate(&base, &owner).await;
    let member = Identity::generate();
    let member_token = authenticate(&base, &member).await;
    let chan: Value = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "room", "channel_type": "voice" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = chan["id"].as_str().unwrap();

    let (_owner_tx, mut owner_rx) = join_voice(&base, &owner_token, channel_id).await;
    let (mut member_tx, _member_rx) = join_voice(&base, &member_token, channel_id).await;

    member_tx
        .send(TsMessage::Text(
            json!({ "type": "voice_self_state", "channel_id": channel_id, "muted": true, "deafened": false }).to_string(),
        ))
        .await
        .unwrap();
    let ev = wait_for(&mut owner_rx, "voice_participant_self_state").await;
    assert_eq!(ev["public_key"], member.public_key_hex());
    assert_eq!(ev["muted"], true);
    assert_eq!(ev["deafened"], false);

    let roster: Value = reqwest::Client::new()
        .get(format!("{base}/voice/participants"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let me = roster[channel_id]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["public_key"] == member.public_key_hex())
        .unwrap();
    assert_eq!(me["muted"], true);
}
