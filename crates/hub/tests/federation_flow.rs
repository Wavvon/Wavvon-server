use std::sync::Arc;

use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::models::PeerInfo;
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
async fn two_hubs_peer_without_gaining_membership() {
    let (hub_a_url, hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
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

    // Peering is not membership: Hub A's session on Hub B reaches neither
    // Hub B's channel list nor its messages. What a peer may read is what an
    // alliance shares with it (alliance_flow, peer_session_flow).
    let peer_token = hub_a_state
        .federation_client
        .authenticate(&hub_b_url, &hub_a_state.hub_identity)
        .await
        .unwrap();
    for path in [
        "/channels".to_string(),
        format!("/channels/{}/messages", channel.id),
    ] {
        let resp = client
            .get(format!("{hub_b_url}{path}"))
            .bearer_auth(&peer_token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "peer session must be refused GET {path}"
        );
    }
}
