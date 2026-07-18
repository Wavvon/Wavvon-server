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
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_udp_addr: None,
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
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
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
