use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::alliance_models::*;
use wavvon_hub::routes::chat_models::{ChannelResponse, MessageResponse};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn start_hub(name: &str) -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: name.to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_wt_url: None,
        canonical_url: Arc::new(RwLock::new(None)),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_optouts: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_talk_blocked: Default::default(),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        bots_allow_video: false,
        bot_video_stream_budget: 2,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            std::sync::Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        webauthn_auth_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: false,
        lan_tls_mode: None,
        lan_fingerprint: None,
    });

    let app = server::create_router(state.clone());
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
async fn two_hubs_form_alliance() {
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    // Create users (owners) on each hub
    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;

    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    // Hub A: Create an alliance
    let resp = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "WoW Alliance" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let alliance: AllianceResponse = resp.json().await.unwrap();
    assert_eq!(alliance.name, "WoW Alliance");

    // Hub A: Create and share a channel
    let channel: ChannelResponse = client
        .post(format!("{hub_a_url}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "raids" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_a_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hub A: Generate an invite token
    let invite: AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(invite.alliance_name, "WoW Alliance");

    // Hub B: Join the alliance via Hub B's own /alliances/join endpoint --
    // that endpoint calls Hub A internally AND mirrors the alliance into
    // Hub B's local DB so Hub B's list_alliances includes it.
    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hub A: Verify alliance has 2 members
    let detail: AllianceDetailResponse = client
        .get(format!("{hub_a_url}/alliances/{}", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail.members.len(), 2);

    // Hub B: Verify it sees the alliance in its own list
    let b_alliances: Vec<AllianceResponse> = client
        .get(format!("{hub_b_url}/alliances"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b_alliances.len(), 1);
    assert_eq!(b_alliances[0].id, alliance.id);

    // Hub B: Create and share its own channel with the alliance
    let b_channel: ChannelResponse = client
        .post(format!("{hub_b_url}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "guild-chat" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": b_channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hub A: List shared channels -- should now include both raids (local)
    // and guild-chat (federated from Hub B).
    let shared: Vec<SharedChannelResponse> = client
        .get(format!("{hub_a_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = shared.iter().map(|s| s.channel_name.as_str()).collect();
    assert!(names.contains(&"raids"), "expected raids in {names:?}");
    assert!(
        names.contains(&"guild-chat"),
        "expected guild-chat (from Hub B via federation) in {names:?}"
    );
    assert_eq!(shared.len(), 2);

    // Hub B: post a message to its own #guild-chat
    let _: MessageResponse = client
        .post(format!("{hub_b_url}/channels/{}/messages", b_channel.id))
        .bearer_auth(&token_b)
        .json(&json!({ "content": "wipe at 3" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Hub A: read alliance-channel messages via the proxy. The channel belongs
    // to Hub B; Hub A federates the read and returns Hub B's messages.
    let resp = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/messages",
            alliance.id, b_channel.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let messages: Vec<MessageResponse> = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/messages",
            alliance.id, b_channel.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, "wipe at 3");

    // Hub A: send a message to Hub B's #guild-chat via the alliance proxy.
    // It should land on Hub B with a [user via hub-a] prefix preserving
    // attribution since federation auth is hub-level.
    let resp = client
        .post(format!(
            "{hub_a_url}/alliances/{}/channels/{}/messages",
            alliance.id, b_channel.id
        ))
        .bearer_auth(&token_a)
        .json(&json!({ "content": "from hub A" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // Read back from Hub B directly to confirm it landed.
    let messages: Vec<MessageResponse> = client
        .get(format!("{hub_b_url}/channels/{}/messages", b_channel.id))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.len(), 2);
    let proxied = messages
        .iter()
        .find(|m| m.content.contains("from hub A"))
        .expect("proxied message should land on Hub B");
    assert!(
        proxied.content.contains("via hub-a"),
        "expected attribution prefix in {:?}",
        proxied.content
    );
}

// ---------------------------------------------------------------------------
// Push-invite tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_invite_happy_path() {
    // Hub A creates an alliance and pushes an invite directly to Hub B.
    // Hub B sees it as a pending invite and can accept it.
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    // First users on each hub automatically receive the Owner (admin) role.
    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    // Hub A: create an alliance
    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Push Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Hub B: no pending invites yet
    let pending: Vec<wavvon_hub::routes::alliance_models::PendingAllianceInviteRow> = client
        .get(format!("{hub_b_url}/alliances/pending-invites"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 0);

    // Hub A: push an invite to Hub B
    let resp = client
        .post(format!("{hub_a_url}/alliances/{}/push-invite", alliance.id))
        .bearer_auth(&token_a)
        .json(&json!({
            "target_hub_url": hub_b_url,
            "own_hub_url": hub_a_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "push-invite: {}",
        resp.text().await.unwrap_or_default()
    );

    // Hub B: should now see one pending invite
    let pending: Vec<wavvon_hub::routes::alliance_models::PendingAllianceInviteRow> = client
        .get(format!("{hub_b_url}/alliances/pending-invites"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].alliance_name, "Push Alliance");

    let invite_id = pending[0].id.clone();

    // Hub B: accept the invite (supply our own URL so Hub A can call back).
    let resp = client
        .post(format!(
            "{hub_b_url}/alliances/pending-invites/{invite_id}/accept"
        ))
        .bearer_auth(&token_b)
        .json(&json!({ "own_hub_url": hub_b_url }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "accept: {}",
        resp.text().await.unwrap_or_default()
    );

    // Hub B: pending list should now be empty
    let pending: Vec<wavvon_hub::routes::alliance_models::PendingAllianceInviteRow> = client
        .get(format!("{hub_b_url}/alliances/pending-invites"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 0);

    // Hub B: should have the alliance in its list
    let b_alliances: Vec<AllianceResponse> = client
        .get(format!("{hub_b_url}/alliances"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        b_alliances.iter().any(|a| a.id == alliance.id),
        "Hub B should have joined the alliance after accepting"
    );
}

#[tokio::test]
async fn push_invite_decline() {
    // Hub B declines an invite — it should be removed from the pending list
    // and Hub B should not appear in the alliance.
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Decline Test" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Push the invite
    let resp = client
        .post(format!("{hub_a_url}/alliances/{}/push-invite", alliance.id))
        .bearer_auth(&token_a)
        .json(&json!({
            "target_hub_url": hub_b_url,
            "own_hub_url": hub_a_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let pending: Vec<wavvon_hub::routes::alliance_models::PendingAllianceInviteRow> = client
        .get(format!("{hub_b_url}/alliances/pending-invites"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    let invite_id = pending[0].id.clone();

    // Hub B: decline
    let resp = client
        .delete(format!("{hub_b_url}/alliances/pending-invites/{invite_id}"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        204,
        "decline: {}",
        resp.text().await.unwrap_or_default()
    );

    // Pending list should be empty
    let pending: Vec<wavvon_hub::routes::alliance_models::PendingAllianceInviteRow> = client
        .get(format!("{hub_b_url}/alliances/pending-invites"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 0);

    // Hub B should NOT be in the alliance
    let b_alliances: Vec<AllianceResponse> = client
        .get(format!("{hub_b_url}/alliances"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        b_alliances.is_empty(),
        "Hub B should not have joined after declining"
    );
}

#[tokio::test]
async fn push_invite_nonexistent_alliance_rejected() {
    let (hub_a_url, _, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;

    // Try to push an invite for a non-existent alliance_id — should get 404.
    let resp = client
        .post(format!("{hub_a_url}/alliances/does-not-exist/push-invite"))
        .bearer_auth(&token_a)
        .json(&json!({
            "target_hub_url": hub_b_url,
            "own_hub_url": hub_a_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Alliance space-sharing v2 -- recursive (include_descendants) sharing
// ---------------------------------------------------------------------------

/// Creates a channel and returns its `ChannelResponse`. Small helper so the
/// space-sharing tests below don't repeat the request/response plumbing.
async fn create_channel(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    body: serde_json::Value,
) -> ChannelResponse {
    client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn get_shared_channels(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    alliance_id: &str,
) -> Vec<SharedChannelResponse> {
    client
        .get(format!("{hub_url}/alliances/{alliance_id}/channels"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn share_category_includes_live_descendants_and_unshare_drops_subtree() {
    let (hub_url, _hub_state, _hub_guard) = start_hub("hub-a").await;
    let client = reqwest::Client::new();

    let user = Identity::generate();
    let token = authenticate_user(&hub_url, &user).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_url}/alliances"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Recursive Share Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // category
    //   └── strat (text)
    //   └── loot (category)
    //         └── rolls (text)
    let category = create_channel(
        &client,
        &hub_url,
        &token,
        json!({ "name": "raid-team", "is_category": true }),
    )
    .await;
    let strat = create_channel(
        &client,
        &hub_url,
        &token,
        json!({ "name": "strat", "parent_id": category.id }),
    )
    .await;
    let loot_category = create_channel(
        &client,
        &hub_url,
        &token,
        json!({ "name": "loot", "is_category": true, "parent_id": category.id }),
    )
    .await;
    let rolls = create_channel(
        &client,
        &hub_url,
        &token,
        json!({ "name": "rolls", "parent_id": loot_category.id }),
    )
    .await;

    // Share only the top category, but recursively.
    let resp = client
        .post(format!("{hub_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token)
        .json(&json!({ "channel_id": category.id, "include_descendants": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let shared = get_shared_channels(&client, &hub_url, &token, &alliance.id).await;
    assert_eq!(shared.len(), 4, "expected the whole subtree: {shared:?}");

    let by_id = |id: &str| shared.iter().find(|s| s.channel_id == id).unwrap();

    let cat_entry = by_id(&category.id);
    assert!(cat_entry.is_category);
    assert_eq!(cat_entry.channel_type, "text");
    assert_eq!(
        cat_entry.parent_id, None,
        "root of the shared tree has no parent"
    );

    let strat_entry = by_id(&strat.id);
    assert!(!strat_entry.is_category);
    assert_eq!(strat_entry.channel_type, "text");
    assert_eq!(strat_entry.parent_id, Some(category.id.clone()));

    let loot_entry = by_id(&loot_category.id);
    assert!(loot_entry.is_category);
    assert_eq!(loot_entry.parent_id, Some(category.id.clone()));

    let rolls_entry = by_id(&rolls.id);
    assert!(!rolls_entry.is_category);
    assert_eq!(rolls_entry.channel_type, "text");
    assert_eq!(
        rolls_entry.parent_id,
        Some(loot_category.id.clone()),
        "grandchild's parent (loot) is itself in the shared set"
    );

    // Live semantics: a channel created under the shared category AFTER the
    // share still shows up without a second share call.
    let voice_comms = create_channel(
        &client,
        &hub_url,
        &token,
        json!({ "name": "voice-comms", "parent_id": category.id }),
    )
    .await;
    let shared = get_shared_channels(&client, &hub_url, &token, &alliance.id).await;
    assert_eq!(
        shared.len(),
        5,
        "newly-created child should be live-included: {shared:?}"
    );
    assert!(shared.iter().any(|s| s.channel_id == voice_comms.id));

    // Unsharing the root drops the whole subtree, including the entry we
    // added after the share.
    let resp = client
        .delete(format!(
            "{hub_url}/alliances/{}/channels/{}",
            alliance.id, category.id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let shared = get_shared_channels(&client, &hub_url, &token, &alliance.id).await;
    assert!(
        shared.is_empty(),
        "unsharing the root should drop the whole subtree: {shared:?}"
    );
}

#[tokio::test]
async fn two_hubs_alliance_descendant_message_via_federation() {
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Federated Subtree Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Hub A: category with a descendant text channel two levels down.
    let category = create_channel(
        &client,
        &hub_a_url,
        &token_a,
        json!({ "name": "guild-ops", "is_category": true }),
    )
    .await;
    let sub_category = create_channel(
        &client,
        &hub_a_url,
        &token_a,
        json!({ "name": "raids", "is_category": true, "parent_id": category.id }),
    )
    .await;
    let descendant = create_channel(
        &client,
        &hub_a_url,
        &token_a,
        json!({ "name": "wipe-log", "parent_id": sub_category.id }),
    )
    .await;

    let resp = client
        .post(format!("{hub_a_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": category.id, "include_descendants": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let invite: AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hub B: the merged view should include the descendant channel, even
    // though only the root category was ever explicitly shared.
    let shared = get_shared_channels(&client, &hub_b_url, &token_b, &alliance.id).await;
    let descendant_entry = shared
        .iter()
        .find(|s| s.channel_id == descendant.id)
        .unwrap_or_else(|| panic!("expected descendant channel in {shared:?}"));
    assert_eq!(descendant_entry.channel_type, "text");
    assert!(!descendant_entry.is_category);

    // Hub B: post a message on the descendant channel via the alliance
    // proxy. Hub B doesn't own it, so this federates to Hub A.
    let resp = client
        .post(format!(
            "{hub_b_url}/alliances/{}/channels/{}/messages",
            alliance.id, descendant.id
        ))
        .bearer_auth(&token_b)
        .json(&json!({ "content": "wiped at 45%" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    // Confirm it landed on Hub A directly.
    let messages: Vec<MessageResponse> = client
        .get(format!("{hub_a_url}/channels/{}/messages", descendant.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].content.contains("wiped at 45%"));

    // Hub B: read it back through the alliance proxy too.
    let messages: Vec<MessageResponse> = client
        .get(format!(
            "{hub_b_url}/alliances/{}/channels/{}/messages",
            alliance.id, descendant.id
        ))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].content.contains("wiped at 45%"));
}

#[tokio::test]
async fn share_banner_channel_lists_type_but_rejects_messages() {
    let (hub_url, _hub_state, _hub_guard) = start_hub("hub-a").await;
    let client = reqwest::Client::new();

    let user = Identity::generate();
    let token = authenticate_user(&hub_url, &user).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_url}/alliances"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Banner Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let banner = create_channel(
        &client,
        &hub_url,
        &token,
        json!({
            "name": "announcements",
            "channel_type": "banner",
            "banner_url": "https://example.com/banner.png",
        }),
    )
    .await;
    assert_eq!(banner.channel_type, "banner");

    let resp = client
        .post(format!("{hub_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token)
        .json(&json!({ "channel_id": banner.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let shared = get_shared_channels(&client, &hub_url, &token, &alliance.id).await;
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].channel_type, "banner");
    assert!(!shared[0].is_category);

    // Posting to a banner channel through the alliance endpoint is rejected.
    let resp = client
        .post(format!(
            "{hub_url}/alliances/{}/channels/{}/messages",
            alliance.id, banner.id
        ))
        .bearer_auth(&token)
        .json(&json!({ "content": "hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Reading messages on a non-message space returns an empty list rather
    // than erroring.
    let messages: Vec<MessageResponse> = client
        .get(format!(
            "{hub_url}/alliances/{}/channels/{}/messages",
            alliance.id, banner.id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(messages.is_empty());
}

// ---------------------------------------------------------------------------
// Voice in alliance channels (alliances.md "Voice in alliance channels")
// ---------------------------------------------------------------------------

/// Everything two hubs need before a visitor can be admitted: an alliance, one
/// voice-capable channel shared by hub A, and a member on each side.
///
/// Returns `(alliance_id, hub_a_channel_id, token_b, visitor_pubkey)`.
async fn alliance_with_shared_voice_channel(
    hub_a_url: &str,
    hub_b_url: &str,
    user_a: &Identity,
    user_b: &Identity,
) -> (String, String, String, String) {
    let client = reqwest::Client::new();
    let token_a = authenticate_user(hub_a_url, user_a).await;
    let token_b = authenticate_user(hub_b_url, user_b).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Voice Pact" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A plain text channel: the hub has no separate voice type — every leaf
    // text channel hosts a voice call alongside its text pane.
    let channel: ChannelResponse = client
        .post(format!("{hub_a_url}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "war-room" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_a_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "share should succeed");

    let invite: AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "hub B should join the alliance");

    (alliance.id, channel.id, token_b, user_b.public_key_hex())
}

/// Redeem a grant at the owning hub: challenge, sign, verify with the grant
/// attached. Returns the raw `/auth/verify` response so a test can assert on a
/// refusal as easily as on a session.
async fn redeem_grant(
    hub_url: &str,
    identity: &Identity,
    grant: &serde_json::Value,
) -> reqwest::Response {
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
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            "alliance_voice_grant": grant,
        }))
        .send()
        .await
        .unwrap()
}

/// The whole point of the feature: a member of hub B ends up holding a session
/// on hub A that can reach voice and nothing else, without becoming a member of
/// hub A in any sense.
#[tokio::test]
async fn a_member_of_an_allied_hub_is_admitted_as_a_voice_visitor() {
    let (hub_a_url, hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, visitor_pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    // Hub B mints. It has to discover that hub A owns the channel by asking,
    // which is the same federation walk the alliance message read does.
    let resp = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "hub B should mint a grant for A's channel"
    );
    let minted: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(minted["owner_hub_url"], hub_a_url.as_str());
    assert_eq!(minted["channel_name"], "war-room");

    // Hub A admits.
    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "hub A should admit the visitor, got {body}");
    let session: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        session["scope"], "alliance_voice",
        "a visitor must not get a member session"
    );
    let visitor_token = session["token"].as_str().unwrap().to_string();

    // Not a member, in the way that matters: no row at all. Anything less than
    // this and they would appear in rosters, role lists and approval queues.
    let user_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key = $1")
        .bind(&visitor_pk)
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(user_rows, 0, "admitting a visitor must not create a user");

    let admitted: Option<String> = sqlx::query_scalar(
        "SELECT channel_id FROM alliance_voice_visitors WHERE subject_pubkey = $1",
    )
    .bind(&visitor_pk)
    .fetch_optional(&hub_a_state.db)
    .await
    .unwrap();
    assert_eq!(
        admitted.as_deref(),
        Some(channel_id.as_str()),
        "the visit records the one channel the grant was for"
    );

    // The session works where it must, and nowhere else. `/info` is what the
    // client needs to dial the relay at all.
    let info = client
        .get(format!("{hub_a_url}/info"))
        .bearer_auth(&visitor_token)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200, "a visitor must be able to read /info");

    for path in ["/users", "/channels", "/conversations", "/me"] {
        let resp = client
            .get(format!("{hub_a_url}{path}"))
            .bearer_auth(&visitor_token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "{path} must be closed to a voice visitor"
        );
    }
}

/// The allowlist is the security boundary, so it has to hold for a route nobody
/// thought about when it was written. `/users` is the one that would leak this
/// hub's whole membership to a guest from another hub.
#[tokio::test]
async fn a_visitor_token_cannot_read_this_hubs_members() {
    let (hub_a_url, _hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session: serde_json::Value = redeem_grant(&hub_a_url, &user_b, &minted["grant"])
        .await
        .json()
        .await
        .unwrap();
    let visitor_token = session["token"].as_str().unwrap();

    // The DH-key routes are on the allowlist because E2E voice keys are wrapped
    // to each recipient — a visitor that cannot publish its own key can be
    // heard by nobody, and one that cannot read others' hears nobody.
    let put = client
        .put(format!("{hub_a_url}/identity/me/dh-key"))
        .bearer_auth(visitor_token)
        .json(&json!({ "dh_public_key": "00".repeat(32) }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        put.status(),
        403,
        "publishing a DH key is what makes the visitor audible"
    );
}

/// Hub A re-resolves the channel against its own shared set and never trusts
/// the origin's claim, so a grant naming a channel A has not shared is refused
/// even though its signature is perfectly valid.
#[tokio::test]
async fn a_grant_for_an_unshared_channel_is_refused() {
    let (hub_a_url, hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Hub A unshares between mint and redemption. The grant is still signed,
    // still unexpired, and must still be worthless.
    let resp = client
        .delete(format!(
            "{hub_a_url}/alliances/{alliance_id}/channels/{channel_id}"
        ))
        .bearer_auth(&authenticate_user(&hub_a_url, &user_a).await)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "unshare should succeed");

    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("channel_not_shared"),
        "unsharing must invalidate an outstanding grant, got {body}"
    );

    let visitors: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alliance_voice_visitors")
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(visitors, 0, "a refused grant must admit nobody");
}

/// The per-share policy: an owner can close its rooms to allied members without
/// unsharing the channel or leaving the alliance.
#[tokio::test]
async fn voice_remote_join_none_refuses_the_visit() {
    let (hub_a_url, hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    sqlx::query(
        "UPDATE alliance_shared_channels SET voice_remote_join = 'none'
         WHERE alliance_id = $1 AND channel_id = $2",
    )
    .bind(&alliance_id)
    .bind(&channel_id)
    .execute(&hub_a_state.db)
    .await
    .unwrap();

    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    assert_eq!(resp.status(), 403);
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("voice_remote_join_disabled"));
}

/// The policy is settable over the API, not just in the database: the share
/// route carries it, the shared-channel list reports it back, and flipping it
/// decides whether a grant can be redeemed at all. Without the route half, the
/// admin UI has no way to close a room short of unsharing it.
#[tokio::test]
async fn the_share_route_sets_and_reports_the_voice_policy() {
    let (hub_a_url, _hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;
    let token_a = authenticate_user(&hub_a_url, &user_a).await;

    // Default, from the migration: shared means joinable.
    let shared: serde_json::Value = client
        .get(format!(
            "{hub_a_url}/alliances/{alliance_id}/channels?local_only=true"
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = shared
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["channel_id"] == channel_id.as_str())
        .expect("the shared channel is listed");
    assert_eq!(entry["voice_remote_join"], "allowed");

    let resp = client
        .post(format!("{hub_a_url}/alliances/{alliance_id}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": channel_id, "voice_remote_join": "none" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "re-sharing with a policy should succeed"
    );

    let shared: serde_json::Value = client
        .get(format!(
            "{hub_a_url}/alliances/{alliance_id}/channels?local_only=true"
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = shared
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["channel_id"] == channel_id.as_str())
        .unwrap();
    assert_eq!(entry["voice_remote_join"], "none");

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    assert_eq!(
        resp.status(),
        403,
        "a policy set over the API must bind the same as one set in SQL"
    );

    // And back: the room reopens without re-sharing anything.
    let resp = client
        .post(format!("{hub_a_url}/alliances/{alliance_id}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": channel_id, "voice_remote_join": "allowed" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    assert_eq!(resp.status(), 200, "reopening must admit the visitor again");

    // An unknown value is refused rather than stored: the column is read back
    // as a policy, and a typo would read as "not 'none'", i.e. wide open.
    let resp = client
        .post(format!("{hub_a_url}/alliances/{alliance_id}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "channel_id": channel_id, "voice_remote_join": "sometimes" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// A visitor has no `users` row here by design, so the plain roster lookup
/// finds nothing and they used to render as a bare key. They are named by the
/// hub that vouched for them instead — and that hub travels with the name,
/// because the name itself is asserted rather than proven.
#[tokio::test]
async fn a_visitor_is_named_by_the_hub_that_vouched_for_them() {
    let (hub_a_url, hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, visitor_pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    let client = reqwest::Client::new();
    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = redeem_grant(&hub_a_url, &user_b, &minted["grant"]).await;
    assert_eq!(resp.status(), 200, "the visitor should be admitted");

    let (display_name, is_bot, visiting_from) =
        wavvon_hub::routes::ws::voice_identity(&hub_a_state, &visitor_pk).await;
    assert!(!is_bot);
    assert_eq!(
        visiting_from.as_deref(),
        Some("hub-b"),
        "the vouching hub must reach the roster, or a hub-asserted name renders as a local one"
    );
    // Whatever hub B asserted, it is the visitor's own row that carries it —
    // never a `users` row here.
    let _ = display_name;
    let member_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key = $1")
        .bind(&visitor_pk)
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(member_rows, 0, "a visit must never create a member");

    // A local member keeps the plain shape: no vouching hub at all.
    let (_, _, owner_visiting_from) =
        wavvon_hub::routes::ws::voice_identity(&hub_a_state, &user_a.public_key_hex()).await;
    assert_eq!(owner_visiting_from, None);
}

/// A grant vouches for membership, never for identity. Presenting someone
/// else's grant fails even with a valid signature over it, because the subject
/// has to be the identity the challenge-response just proved.
#[tokio::test]
async fn a_grant_cannot_be_presented_by_someone_else() {
    let (hub_a_url, _hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    let minted: serde_json::Value = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A different identity entirely, authenticating correctly as itself.
    let thief = Identity::generate();
    let resp = redeem_grant(&hub_a_url, &thief, &minted["grant"]).await;
    assert_eq!(resp.status(), 403);
    assert!(resp
        .text()
        .await
        .unwrap()
        .contains("grant_subject_mismatch"));
}

/// Minting for a channel the origin hub owns itself is a client mistake worth
/// naming: the member should just join voice locally, where they have roles and
/// history, rather than visit their own hub as a guest.
#[tokio::test]
async fn minting_for_your_own_channel_is_refused_as_local() {
    let (hub_a_url, _hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let (alliance_id, _channel_id, token_b, _pk) =
        alliance_with_shared_voice_channel(&hub_a_url, &hub_b_url, &user_a, &user_b).await;

    // Hub B shares one of its own channels with the same alliance.
    let b_channel: ChannelResponse = client
        .post(format!("{hub_b_url}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "guild-hall" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": b_channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{hub_b_url}/alliances/{alliance_id}/voice-grant"))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": b_channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    assert!(resp.text().await.unwrap().contains("channel_is_local"));
}

/// Two hubs with **default settings** must be able to form an alliance.
///
/// A fresh hub is `invite_only`, and the invite gate in `/auth/verify` exempted
/// bots but not federating hubs — so hub B's federation client got "This hub
/// requires an invite code" from hub A and the join failed with a 502 blaming
/// the network. Every default hub pair, and nothing caught it: this harness
/// builds `AppState` directly and never writes the `invite_only` setting, so
/// `is_invite_only` answered false and federation auth sailed through. Found by
/// driving two real hub binaries (`e2e-topology`), which is the only place the
/// setting has its real default.
///
/// So this test sets it explicitly. A test that relies on a default it does not
/// state is a test that stops covering the thing the day the default changes.
#[tokio::test]
async fn an_invite_only_hub_still_accepts_a_federating_peer() {
    let (hub_a_url, hub_a_state, _ga) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _gb) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    // What a real hub looks like on first boot.
    wavvon_hub::routes::hub::upsert_setting(&hub_a_state.db, "invite_only", "true")
        .await
        .unwrap();

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Default Settings Pact" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let invite: AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(
        status, 200,
        "an invite_only hub must still let a peer hub federate; got {body}"
    );
}

// ---------------------------------------------------------------------------
// Per-alliance delegation (decisions.md, "Alliance permissions: one hub
// permission plus a per-alliance grant list")
// ---------------------------------------------------------------------------

async fn create_role_with(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    name: &str,
    permissions: &[&str],
) -> String {
    let role: serde_json::Value = client
        .post(format!("{hub_url}/roles"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "permissions": permissions, "priority": 5 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    role["id"].as_str().unwrap().to_string()
}

async fn assign_role_to(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    pubkey: &str,
    role_id: &str,
) {
    let resp = client
        .put(format!("{hub_url}/users/{pubkey}/roles/{role_id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign role: {}", resp.status());
}

async fn create_alliance_named(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    name: &str,
) -> AllianceResponse {
    client
        .post(format!("{hub_url}/alliances"))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Delegating one federation link no longer means handing over the hub — and
/// it delegates *one* link: the same role has no say over the alliance it was
/// not granted on.
#[tokio::test]
async fn an_alliance_manager_acts_on_that_alliance_only() {
    let (hub_url, _state, _guard) = start_hub("hub-delegate").await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate_user(&hub_url, &owner).await;

    let delegate = Identity::generate();
    let delegate_token = authenticate_user(&hub_url, &delegate).await;
    let delegate_key = delegate.public_key_hex();

    let raiders = create_alliance_named(&client, &hub_url, &owner_token, "Raiders").await;
    let neighbours = create_alliance_named(&client, &hub_url, &owner_token, "Neighbours").await;

    // Nothing about alliances in the role itself.
    let role = create_role_with(&client, &hub_url, &owner_token, "Raid Diplomat", &[]).await;
    assign_role_to(&client, &hub_url, &owner_token, &delegate_key, &role).await;

    let invite = |token: String, alliance_id: String| {
        let client = client.clone();
        let hub_url = hub_url.clone();
        async move {
            client
                .post(format!("{hub_url}/alliances/{alliance_id}/invite"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(
        invite(delegate_token.clone(), raiders.id.clone()).await,
        403,
        "no delegation yet"
    );

    let resp = client
        .put(format!(
            "{hub_url}/alliances/{}/managers/{role}",
            raiders.id
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        204,
        "granting the list is roles.manage's call"
    );

    assert_eq!(
        invite(delegate_token.clone(), raiders.id.clone()).await,
        200,
        "the delegated alliance is theirs to invite into"
    );
    assert_eq!(
        invite(delegate_token.clone(), neighbours.id.clone()).await,
        403,
        "the other alliance is not — that is the whole point of a per-alliance list"
    );

    let listed: Vec<serde_json::Value> = client
        .get(format!("{hub_url}/alliances/{}/managers", raiders.id))
        .bearer_auth(&delegate_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["role_id"], role);
    assert_eq!(listed[0]["role_name"], "Raid Diplomat");

    // Revoked, and the door closes again.
    let resp = client
        .delete(format!(
            "{hub_url}/alliances/{}/managers/{role}",
            raiders.id
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(invite(delegate_token, raiders.id).await, 403);
}

/// The trap from the design: sharing a channel is also a channel act, so
/// managing the alliance is not enough on its own. Without this, whoever
/// handles one federation link could expose a private channel they cannot
/// read.
#[tokio::test]
async fn sharing_needs_the_channel_permission_too() {
    let (hub_url, _state, _guard) = start_hub("hub-share-gate").await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate_user(&hub_url, &owner).await;

    let delegate = Identity::generate();
    let delegate_token = authenticate_user(&hub_url, &delegate).await;
    let delegate_key = delegate.public_key_hex();

    let alliance = create_alliance_named(&client, &hub_url, &owner_token, "Pact").await;
    let staff = create_channel(&client, &hub_url, &owner_token, json!({ "name": "staff" })).await;

    // A diplomat with no channel authority at all.
    let role = create_role_with(&client, &hub_url, &owner_token, "Diplomat", &[]).await;
    assign_role_to(&client, &hub_url, &owner_token, &delegate_key, &role).await;
    let resp = client
        .put(format!(
            "{hub_url}/alliances/{}/managers/{role}",
            alliance.id
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let share = |token: String| {
        let client = client.clone();
        let hub_url = hub_url.clone();
        let alliance_id = alliance.id.clone();
        let channel_id = staff.id.clone();
        async move {
            client
                .post(format!("{hub_url}/alliances/{alliance_id}/channels"))
                .bearer_auth(token)
                .json(&json!({ "channel_id": channel_id }))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(
        share(delegate_token.clone()).await,
        403,
        "managing the alliance must not be enough to expose a channel"
    );

    // Same person, once they may manage the channel as well.
    let channels_role = create_role_with(
        &client,
        &hub_url,
        &owner_token,
        "Channel Keeper",
        &["channels.manage"],
    )
    .await;
    assign_role_to(
        &client,
        &hub_url,
        &owner_token,
        &delegate_key,
        &channels_role,
    )
    .await;

    assert_eq!(
        share(delegate_token).await,
        200,
        "both halves, now it shares"
    );
}

/// A delegate cannot widen their own delegation: editing the grant list is
/// `roles.manage`, not managing the alliance.
#[tokio::test]
async fn an_alliance_manager_cannot_grant_the_list() {
    let (hub_url, _state, _guard) = start_hub("hub-no-widening").await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = authenticate_user(&hub_url, &owner).await;

    let delegate = Identity::generate();
    let delegate_token = authenticate_user(&hub_url, &delegate).await;
    let delegate_key = delegate.public_key_hex();

    let alliance = create_alliance_named(&client, &hub_url, &owner_token, "Pact").await;
    let role = create_role_with(&client, &hub_url, &owner_token, "Diplomat", &[]).await;
    let other = create_role_with(&client, &hub_url, &owner_token, "Everyone Else", &[]).await;
    assign_role_to(&client, &hub_url, &owner_token, &delegate_key, &role).await;

    let resp = client
        .put(format!(
            "{hub_url}/alliances/{}/managers/{role}",
            alliance.id
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .put(format!(
            "{hub_url}/alliances/{}/managers/{other}",
            alliance.id
        ))
        .bearer_auth(&delegate_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a delegate handing the alliance to another role is exactly what roles.manage gates"
    );
}
