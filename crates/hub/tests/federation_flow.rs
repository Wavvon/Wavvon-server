use std::sync::Arc;

use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::models::{
    FederatedChannelResponse, FederatedMessageResponse, PeerInfo,
};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn start_hub(name: &str) -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(AppState {
        hub_name: name.to_string(),
        ..common::base_state(db)
    });

    let app = server::create_router(state.clone());

    // Bind to a random available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (url, state, guard)
}

async fn authenticate_user(hub_url: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    verify.token
}

#[tokio::test]
async fn two_hubs_federate() {
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    // Create users on each hub
    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;

    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    // Create a channel on Hub B
    let channel: ChannelResponse = client
        .post(format!("{hub_b_url}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "hub-b-general" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Send a message on Hub B
    client
        .post(format!("{hub_b_url}/channels/{}/messages", channel.id))
        .bearer_auth(&token_b)
        .json(&json!({ "content": "hello from hub B!" }))
        .send()
        .await
        .unwrap();

    // Hub A: add Hub B as a peer
    let resp = client
        .post(format!("{hub_a_url}/federation/peers"))
        .bearer_auth(&token_a)
        .json(&json!({ "url": hub_b_url }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let peer: PeerInfo = resp.json().await.unwrap();
    assert_eq!(peer.name, "hub-b");
    assert_eq!(peer.public_key, hub_b_state.hub_identity.public_key_hex());

    // Hub A: list peers
    let peers: Vec<PeerInfo> = client
        .get(format!("{hub_a_url}/federation/peers"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(peers.len(), 1);

    // Hub A: fetch channels from Hub B
    let fed_channels: Vec<FederatedChannelResponse> = client
        .get(format!(
            "{hub_a_url}/federation/peers/{}/channels",
            peer.public_key
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fed_channels.len(), 1);
    assert_eq!(fed_channels[0].name, "hub-b-general");

    // Hub A: fetch messages from the federated channel
    let fed_messages: Vec<FederatedMessageResponse> = client
        .get(format!(
            "{hub_a_url}/federation/channels/{}/messages",
            fed_channels[0].id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fed_messages.len(), 1);
    assert_eq!(fed_messages[0].content, "hello from hub B!");
    assert_eq!(fed_messages[0].sender, user_b.public_key_hex());

    // Hub A: send a message TO Hub B's channel via federation
    let resp = client
        .post(format!(
            "{hub_a_url}/federation/channels/{}/messages",
            fed_channels[0].id
        ))
        .bearer_auth(&token_a)
        .json(&json!({ "content": "hello from hub A!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sent: FederatedMessageResponse = resp.json().await.unwrap();
    assert_eq!(sent.content, "hello from hub A!");

    // Verify the message appears on Hub B
    let messages: Vec<wavvon_hub::routes::chat_models::MessageResponse> = client
        .get(format!("{hub_b_url}/channels/{}/messages", channel.id))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|m| m.content == "hello from hub A!"));
    assert!(messages.iter().any(|m| m.content == "hello from hub B!"));
}
