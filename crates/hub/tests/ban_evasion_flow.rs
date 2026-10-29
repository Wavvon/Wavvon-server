//! The ban-evasion flag over a real socket: the in-process test server gives
//! no peer address, so the flag would never fire there. The hub runs in
//! trusted-proxy mode and each request names its client in
//! `X-Forwarded-For`, because the flag ignores loopback and private
//! addresses (a proxy's, not a person's) and every socket here is 127.0.0.1.

use std::sync::Arc;

use serde_json::{json, Value};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = common::create_test_db().await;
    let state = Arc::new(common::base_state(db));
    let app = server::create_router_full(state.clone(), "*", true, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
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

async fn authenticate(hub_url: &str, identity: &Identity, from: &str) -> String {
    let client = reqwest::Client::new();
    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .header("x-forwarded-for", from)
        .json(&json!({ "public_key": identity.public_key_hex() }))
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
        .header("x-forwarded-for", from)
        .json(&json!({
            "public_key": identity.public_key_hex(),
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

async fn pending(hub_url: &str, token: &str) -> Vec<Value> {
    reqwest::Client::new()
        .get(format!("{hub_url}/hub/pending"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn me_status(hub_url: &str, token: &str) -> u16 {
    reqwest::Client::new()
        .get(format!("{hub_url}/channels"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

const SHARED: &str = "203.0.113.7";
const ELSEWHERE: &str = "198.51.100.20";

#[tokio::test]
async fn a_newcomer_from_a_banned_address_waits_for_a_moderator() {
    let (hub, _state, _guard) = start_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate(&hub, &owner, ELSEWHERE).await;
    let bystander = Identity::generate();
    let bystander_token = authenticate(&hub, &bystander, SHARED).await;
    let troll = Identity::generate();
    authenticate(&hub, &troll, SHARED).await;

    let resp = client
        .post(format!("{hub}/moderation/bans"))
        .bearer_auth(&owner_token)
        .json(&json!({ "target_public_key": troll.public_key_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // The troll's new key, from the same address: seated, but pending.
    let alt = Identity::generate();
    let alt_token = authenticate(&hub, &alt, SHARED).await;
    assert_eq!(
        me_status(&hub, &alt_token).await,
        403,
        "pending until approved"
    );

    let queue = pending(&hub, &owner_token).await;
    let entry = queue
        .iter()
        .find(|p| p["public_key"] == alt.public_key_hex())
        .expect("the newcomer is in the approval queue");
    assert_eq!(entry["ban_evasion_match"], troll.public_key_hex());

    // A member who was already seated keeps their standing.
    let bystander_again = authenticate(&hub, &bystander, SHARED).await;
    assert_eq!(me_status(&hub, &bystander_token).await, 200);
    assert_eq!(me_status(&hub, &bystander_again).await, 200);

    // The moderator decides; approval clears the flag.
    let resp = client
        .post(format!(
            "{hub}/hub/pending/{}/approve",
            alt.public_key_hex()
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(me_status(&hub, &alt_token).await, 200);
    assert!(pending(&hub, &owner_token).await.is_empty());
}

#[tokio::test]
async fn lifting_the_ban_lifts_the_flag() {
    let (hub, _state, _guard) = start_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate(&hub, &owner, ELSEWHERE).await;
    let troll = Identity::generate();
    authenticate(&hub, &troll, SHARED).await;

    client
        .post(format!("{hub}/moderation/bans"))
        .bearer_auth(&owner_token)
        .json(&json!({ "target_public_key": troll.public_key_hex() }))
        .send()
        .await
        .unwrap();
    let resp = client
        .delete(format!("{hub}/moderation/bans/{}", troll.public_key_hex()))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let newcomer = Identity::generate();
    let token = authenticate(&hub, &newcomer, SHARED).await;
    assert_eq!(me_status(&hub, &token).await, 200, "no live ban, no flag");
}

/// Loopback is a proxy's address, not a person's: a ban seen only from there
/// flags nobody, or a hub behind an untrusted local proxy would hold every
/// newcomer after its first ban.
#[tokio::test]
async fn a_loopback_address_flags_nobody() {
    let (hub, _state, _guard) = start_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate(&hub, &owner, ELSEWHERE).await;
    let troll = Identity::generate();
    authenticate(&hub, &troll, "127.0.0.1").await;
    client
        .post(format!("{hub}/moderation/bans"))
        .bearer_auth(&owner_token)
        .json(&json!({ "target_public_key": troll.public_key_hex() }))
        .send()
        .await
        .unwrap();

    let newcomer = Identity::generate();
    let token = authenticate(&hub, &newcomer, "127.0.0.1").await;
    assert_eq!(me_status(&hub, &token).await, 200);
}
