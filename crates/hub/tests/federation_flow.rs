use std::sync::Arc;

use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
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
    let signature = identity.sign(&wavvon_identity::auth_challenge_signing_bytes(
        &challenge_bytes,
    ));

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
async fn a_peer_session_does_not_gain_membership() {
    let (_hub_a_url, hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

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

/// The hub key signs alliance invite tokens (a signature over the alliance
/// id) among other things, so signing whatever a peer sends as a challenge
/// would hand that peer an invite token. Only a challenge of the length a
/// Wavvon hub issues is signed.
#[tokio::test]
async fn the_hub_refuses_to_sign_a_challenge_shaped_like_anything_else() {
    use axum::routing::post;
    let alliance_id = "11111111-2222-3333-4444-555555555555";
    let app = axum::Router::new()
        .route(
            "/auth/challenge",
            post(
                move || async move { axum::Json(json!({ "challenge": hex::encode(alliance_id) })) },
            ),
        )
        .route(
            "/auth/verify",
            post(|| async { axum::Json(json!({ "token": "x" })) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let result = wavvon_hub::federation::client::FederationClient::new()
        .authenticate(&url, &Identity::generate())
        .await;
    assert!(result.is_err(), "a 36-byte challenge must not be signed");
}
