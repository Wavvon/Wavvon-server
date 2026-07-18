/// Integration tests for the voice-move primitive, Phase 1 (events.md §7.1).
///
/// Drives two real WS connections (mover + target) through a real TCP hub,
/// exercising the `voice_move` client message end-to-end: permission gate,
/// target-in-voice gate, target-read-access gate, and the targeted
/// `voice_move` push (with the §7.2 `auto` consent computation).
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::role_models::RoleResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Harness — mirrors proximity_voice_flow.rs / voice_relay_flow.rs so real WS
// upgrades work over a real TCP listener.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "voice-move-test".to_string(),
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
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        voice_consumed_tokens: RwLock::new(HashMap::new()),
        voice_ws_senders: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        voice_udp_socket: Arc::new(RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
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
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (url, state, guard)
}

async fn authenticate_http(base: &str, identity: &Identity) -> String {
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

    let challenge_bytes = hex::decode(&resp.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
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

async fn create_channel(base: &str, token: &str, name: &str) -> ChannelResponse {
    reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn create_role(base: &str, token: &str, name: &str, permissions: &[&str]) -> RoleResponse {
    reqwest::Client::new()
        .post(format!("{base}/roles"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "permissions": permissions, "priority": 10 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn assign_role(base: &str, token: &str, pubkey: &str, role_id: &str) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/users/{pubkey}/roles/{role_id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign_role failed: {resp:?}");
}

async fn deny_overwrite(base: &str, token: &str, channel_id: &str, role_id: &str, deny: &[&str]) {
    let resp = reqwest::Client::new()
        .put(format!(
            "{base}/channels/{channel_id}/permissions/{role_id}"
        ))
        .bearer_auth(token)
        .json(&json!({ "allow": [], "deny": deny }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "deny_overwrite failed: {resp:?}"
    );
}

#[derive(serde::Deserialize)]
struct EventResponse {
    id: String,
}

async fn create_event(base: &str, token: &str, channel_id: &str, title: &str) -> EventResponse {
    let resp = reqwest::Client::new()
        .post(format!("{base}/events"))
        .bearer_auth(token)
        .json(&json!({
            "channel_id": channel_id,
            "title": title,
            "starts_at": 0,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create_event failed: {resp:?}");
    resp.json().await.unwrap()
}

async fn rsvp_going(base: &str, token: &str, event_id: &str) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/events/{event_id}/rsvp"))
        .bearer_auth(token)
        .json(&json!({ "status": "going" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "rsvp failed: {resp:?}");
}

/// Like `create_event` but lets the caller set `ends_at` (events.md §7.3
/// prune: assignments die at event end).
async fn create_event_with_ends_at(
    base: &str,
    token: &str,
    channel_id: &str,
    title: &str,
    ends_at: i64,
) -> EventResponse {
    let resp = reqwest::Client::new()
        .post(format!("{base}/events"))
        .bearer_auth(token)
        .json(&json!({
            "channel_id": channel_id,
            "title": title,
            "starts_at": 0,
            "ends_at": ends_at,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create_event failed: {resp:?}");
    resp.json().await.unwrap()
}

async fn get_assignments(base: &str, token: &str, event_id: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{base}/events/{event_id}/assignments"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn get_assignments_ok(base: &str, token: &str, event_id: &str) -> Vec<Value> {
    let resp = get_assignments(base, token, event_id).await;
    assert!(
        resp.status().is_success(),
        "get assignments failed: {resp:?}"
    );
    resp.json().await.unwrap()
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

async fn connect_ws(base: &str, token: &str) -> (WsSink, WsStream) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_ws(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

/// Reads WS frames from `rx` until one of type `want` arrives, or panics
/// after a 5s timeout.
async fn wait_for(rx: &mut WsStream, want: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(want) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                other => panic!("WS stream ended before `{want}` arrived: {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("`{want}` not received within 5s"))
}

/// Asserts no frame of type `unwanted` arrives within a short grace window.
async fn assert_not_received(rx: &mut WsStream, unwanted: &str) {
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(unwanted) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                _ => return Value::Null,
            }
        }
    })
    .await;
    if let Ok(v) = result {
        if v != Value::Null {
            panic!("unexpected `{unwanted}` frame received: {v:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Shared fixture: owner (admin) + mover (move_members role) + target user,
// two voice-capable channels (source + dest), target already joined to
// source over its own WS connection.
// ---------------------------------------------------------------------------

struct Fixture {
    base: String,
    _guard: common::TestDbGuard,
    owner_token: String,
    #[allow(dead_code)]
    mover_token: String,
    target_token: String,
    target_pubkey: String,
    source: ChannelResponse,
    dest: ChannelResponse,
    mover_ws: (WsSink, WsStream),
    target_ws: (WsSink, WsStream),
}

async fn build_fixture(grant_mover_move_members: bool) -> Fixture {
    let (base, _state, guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mover = Identity::generate();
    let mover_token = authenticate_http(&base, &mover).await;
    let mover_key = mover.public_key_hex();

    let target = Identity::generate();
    let target_token = authenticate_http(&base, &target).await;
    let target_pubkey = target.public_key_hex();

    let source = create_channel(&base, &owner_token, "voice-source").await;
    let dest = create_channel(&base, &owner_token, "voice-dest").await;

    if grant_mover_move_members {
        let mover_role = create_role(&base, &owner_token, "Marshal", &["move_members"]).await;
        assign_role(&base, &owner_token, &mover_key, &mover_role.id).await;
    }

    // Target joins the source channel's voice over its own WS connection
    // first, so it's registered in `voice_channels` before the move.
    let mut target_ws = connect_ws(&base, &target_token).await;
    send_ws(
        &mut target_ws.0,
        json!({ "type": "voice_join", "channel_id": source.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut target_ws.1, "voice_joined").await;

    let mover_ws = connect_ws(&base, &mover_token).await;

    Fixture {
        base,
        _guard: guard,
        owner_token,
        mover_token,
        target_token,
        target_pubkey,
        source,
        dest,
        mover_ws,
        target_ws,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: a mover holding `move_members` on the destination moves a
/// target that's in voice and can read the destination. The target receives
/// the targeted `voice_move` push with `auto: false` (no event context) and
/// the correct channel name / source.
#[tokio::test]
async fn happy_path_delivers_voice_move_with_auto_false() {
    let mut fx = build_fixture(true).await;

    send_ws(
        &mut fx.mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": fx.target_pubkey,
            "target_channel_id": fx.dest.id,
        }),
    )
    .await;

    let push = wait_for(&mut fx.target_ws.1, "voice_move").await;
    assert_eq!(push["target_channel_id"], fx.dest.id);
    assert_eq!(push["target_channel_name"], "voice-dest");
    assert_eq!(push["source_channel_id"], fx.source.id);
    assert_eq!(push["auto"], false);
    assert!(push["event_id"].is_null());
}

/// `auto: true` when `event_id` is present and the target has RSVP'd
/// "going" on that event (slot claim implies going, but a plain RSVP is
/// enough on its own).
#[tokio::test]
async fn auto_true_when_target_rsvpd_going() {
    let mut fx = build_fixture(true).await;

    let event = create_event(&fx.base, &fx.owner_token, &fx.dest.id, "Raid Night").await;
    rsvp_going(&fx.base, &fx.target_token, &event.id).await;

    send_ws(
        &mut fx.mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": fx.target_pubkey,
            "target_channel_id": fx.dest.id,
            "event_id": event.id,
        }),
    )
    .await;

    let push = wait_for(&mut fx.target_ws.1, "voice_move").await;
    assert_eq!(push["auto"], true);
    assert_eq!(push["event_id"], event.id);
}

/// A mover lacking `move_members` on the destination gets an error and the
/// target receives no push.
#[tokio::test]
async fn rejects_mover_without_move_members() {
    let mut fx = build_fixture(false).await;

    send_ws(
        &mut fx.mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": fx.target_pubkey,
            "target_channel_id": fx.dest.id,
        }),
    )
    .await;

    let err = wait_for(&mut fx.mover_ws.1, "error").await;
    assert_eq!(err["context"], "voice_move");

    assert_not_received(&mut fx.target_ws.1, "voice_move").await;
}

/// A target that is not currently in voice anywhere is rejected (queued
/// assignments are Phase 2 — out of scope here).
#[tokio::test]
async fn rejects_target_not_in_voice() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mover = Identity::generate();
    let mover_token = authenticate_http(&base, &mover).await;
    let mover_key = mover.public_key_hex();

    let target = Identity::generate();
    let target_token = authenticate_http(&base, &target).await;
    let target_pubkey = target.public_key_hex();

    let dest = create_channel(&base, &owner_token, "voice-dest-2").await;

    let mover_role = create_role(&base, &owner_token, "Marshal2", &["move_members"]).await;
    assign_role(&base, &owner_token, &mover_key, &mover_role.id).await;

    // Target authenticates (and has a WS connection open to observe
    // non-delivery) but never joins voice anywhere.
    let mut target_ws = connect_ws(&base, &target_token).await;
    let mut mover_ws = connect_ws(&base, &mover_token).await;

    send_ws(
        &mut mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": target_pubkey,
            "target_channel_id": dest.id,
        }),
    )
    .await;

    let err = wait_for(&mut mover_ws.1, "error").await;
    assert_eq!(err["context"], "voice_move");
    assert!(
        err["message"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("not currently in voice"),
        "expected a clear 'target not in voice' error, got: {err:?}"
    );

    assert_not_received(&mut target_ws.1, "voice_move").await;
}

/// A target that lacks effective `READ_MESSAGES` on the destination is
/// rejected when the move carries no `event_id` — a generic mod-tool move
/// must not reveal a hidden channel (events.md §7.4). The voice-only
/// presence grant only kicks in with an event context; see
/// `voice_only_grant_allows_join_but_not_message_history` below.
#[tokio::test]
async fn rejects_target_without_read_access_to_destination() {
    let mut fx = build_fixture(true).await;

    // Deny read_messages for @everyone on the destination — the target
    // holds only builtin-everyone, so this removes their read access there.
    deny_overwrite(
        &fx.base,
        &fx.owner_token,
        &fx.dest.id,
        "builtin-everyone",
        &["read_messages"],
    )
    .await;

    send_ws(
        &mut fx.mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": fx.target_pubkey,
            "target_channel_id": fx.dest.id,
        }),
    )
    .await;

    let err = wait_for(&mut fx.mover_ws.1, "error").await;
    assert_eq!(err["context"], "voice_move");

    assert_not_received(&mut fx.target_ws.1, "voice_move").await;
}

// ---------------------------------------------------------------------------
// Phase 2: queued assignments (events.md §7.3)
// ---------------------------------------------------------------------------

/// A move to a target that isn't in voice, with an `event_id`, queues an
/// `event_move_assignments` row instead of erroring (no push either, since
/// the target isn't there to receive it). Re-issuing the move overwrites
/// the assignment's `target_channel_id` (latest wins) rather than creating
/// a second row.
#[tokio::test]
async fn queued_assignment_upserted_and_overwritten_on_reissue() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mover = Identity::generate();
    let mover_token = authenticate_http(&base, &mover).await;
    let mover_key = mover.public_key_hex();

    let target = Identity::generate();
    let target_token = authenticate_http(&base, &target).await;
    let target_pubkey = target.public_key_hex();

    let squad_a = create_channel(&base, &owner_token, "squad-a").await;
    let squad_b = create_channel(&base, &owner_token, "squad-b").await;

    let mover_role = create_role(&base, &owner_token, "MarshalQueue", &["move_members"]).await;
    assign_role(&base, &owner_token, &mover_key, &mover_role.id).await;

    let event = create_event(&base, &owner_token, &squad_a.id, "Raid Night").await;

    // Target authenticates (so it can observe non-delivery) but never joins
    // voice anywhere.
    let mut target_ws = connect_ws(&base, &target_token).await;
    let mut mover_ws = connect_ws(&base, &mover_token).await;

    send_ws(
        &mut mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": target_pubkey,
            "target_channel_id": squad_a.id,
            "event_id": event.id,
        }),
    )
    .await;

    // No error to the mover, no push to the absent target.
    assert_not_received(&mut mover_ws.1, "error").await;
    assert_not_received(&mut target_ws.1, "voice_move").await;

    let assignments = get_assignments_ok(&base, &owner_token, &event.id).await;
    assert_eq!(assignments.len(), 1, "expected one queued assignment");
    assert_eq!(assignments[0]["user_pubkey"], target_pubkey);
    assert_eq!(assignments[0]["target_channel_id"], squad_a.id);
    assert_eq!(assignments[0]["assigned_by"], mover_key);

    // Re-issue to a different channel -- overwrites, doesn't duplicate.
    send_ws(
        &mut mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": target_pubkey,
            "target_channel_id": squad_b.id,
            "event_id": event.id,
        }),
    )
    .await;
    assert_not_received(&mut mover_ws.1, "error").await;

    let assignments = get_assignments_ok(&base, &owner_token, &event.id).await;
    assert_eq!(
        assignments.len(),
        1,
        "re-issuing must overwrite, not duplicate"
    );
    assert_eq!(assignments[0]["target_channel_id"], squad_b.id);
}

/// A queued assignment auto-applies the moment the target joins any voice
/// channel: the hub pushes a `voice_move` for the assigned channel. Because
/// the target never claimed a slot or RSVP'd "going" on the driving event,
/// an assignment alone does not imply consent (§7.2) -- the push carries
/// `auto: false`. The row is not consumed on application: leaving and
/// rejoining voice re-applies it.
#[tokio::test]
async fn queued_assignment_applies_on_join_auto_false_and_persists_across_rejoin() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mover = Identity::generate();
    let mover_token = authenticate_http(&base, &mover).await;
    let mover_key = mover.public_key_hex();

    let target = Identity::generate();
    let target_token = authenticate_http(&base, &target).await;
    let target_pubkey = target.public_key_hex();

    let lobby = create_channel(&base, &owner_token, "lobby-voice").await;
    let squad = create_channel(&base, &owner_token, "squad-voice").await;

    let mover_role = create_role(&base, &owner_token, "MarshalApply", &["move_members"]).await;
    assign_role(&base, &owner_token, &mover_key, &mover_role.id).await;

    let event = create_event(&base, &owner_token, &squad.id, "Raid Night").await;
    // Target intentionally never RSVPs.

    let mut target_ws = connect_ws(&base, &target_token).await;
    let mut mover_ws = connect_ws(&base, &mover_token).await;

    // Queue the assignment while the target is not in voice.
    send_ws(
        &mut mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": target_pubkey,
            "target_channel_id": squad.id,
            "event_id": event.id,
        }),
    )
    .await;
    assert_not_received(&mut target_ws.1, "voice_move").await;

    // Target joins some unrelated voice channel -> assignment auto-applies.
    send_ws(
        &mut target_ws.0,
        json!({ "type": "voice_join", "channel_id": lobby.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut target_ws.1, "voice_joined").await;

    let push = wait_for(&mut target_ws.1, "voice_move").await;
    assert_eq!(push["target_channel_id"], squad.id);
    assert_eq!(push["source_channel_id"], lobby.id);
    assert_eq!(push["event_id"], event.id);
    assert_eq!(
        push["auto"], false,
        "an assignment alone must not imply consent for a non-RSVP'd target"
    );

    // Client runs its normal leave-and-join per the push, then later drops
    // and rejoins the lobby again -- the row was not consumed, so it
    // re-applies.
    send_ws(
        &mut target_ws.0,
        json!({ "type": "voice_leave", "channel_id": lobby.id }),
    )
    .await;
    send_ws(
        &mut target_ws.0,
        json!({ "type": "voice_join", "channel_id": lobby.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut target_ws.1, "voice_joined").await;
    let push2 = wait_for(&mut target_ws.1, "voice_move").await;
    assert_eq!(push2["target_channel_id"], squad.id);

    let assignments = get_assignments_ok(&base, &owner_token, &event.id).await;
    assert_eq!(
        assignments.len(),
        1,
        "assignment row must persist, not be consumed, across application"
    );
}

// ---------------------------------------------------------------------------
// Phase 2: voice-only presence (events.md §7.4)
// ---------------------------------------------------------------------------

/// A move with an `event_id` to a destination the target can't read
/// succeeds (voice-only presence, §7.4): the target's join to that channel
/// is admitted despite lacking `READ_MESSAGES`, but message history on that
/// channel still 403s them -- the grant bypasses exactly one gate. Leaving
/// voice drops the grant, so a fresh direct join attempt afterward fails
/// again.
#[tokio::test]
async fn voice_only_grant_allows_join_but_not_message_history_and_evaporates_on_leave() {
    let mut fx = build_fixture(true).await;

    // Deny read_messages for @everyone on the destination -- the target
    // holds only builtin-everyone, so this removes their read access there.
    deny_overwrite(
        &fx.base,
        &fx.owner_token,
        &fx.dest.id,
        "builtin-everyone",
        &["read_messages"],
    )
    .await;

    let event = create_event(&fx.base, &fx.owner_token, &fx.dest.id, "Raid Night").await;

    send_ws(
        &mut fx.mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": fx.target_pubkey,
            "target_channel_id": fx.dest.id,
            "event_id": event.id,
        }),
    )
    .await;

    let push = wait_for(&mut fx.target_ws.1, "voice_move").await;
    assert_eq!(push["target_channel_id"], fx.dest.id);

    // Target's client runs its normal leave-and-join per the push -- this
    // must succeed despite lacking READ_MESSAGES on the destination.
    send_ws(
        &mut fx.target_ws.0,
        json!({ "type": "voice_leave", "channel_id": fx.source.id }),
    )
    .await;
    send_ws(
        &mut fx.target_ws.0,
        json!({ "type": "voice_join", "channel_id": fx.dest.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut fx.target_ws.1, "voice_joined").await;

    // Message history on the destination is still 403 for the voice-only
    // participant -- the grant bypasses only the voice-join gate.
    let resp = reqwest::Client::new()
        .get(format!("{}/channels/{}/messages", fx.base, fx.dest.id))
        .bearer_auth(&fx.target_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // Leaving voice drops the grant.
    send_ws(
        &mut fx.target_ws.0,
        json!({ "type": "voice_leave", "channel_id": fx.dest.id }),
    )
    .await;

    // A fresh, un-consented direct join attempt now fails again.
    send_ws(
        &mut fx.target_ws.0,
        json!({ "type": "voice_join", "channel_id": fx.dest.id, "udp_port": 0 }),
    )
    .await;
    let err = wait_for(&mut fx.target_ws.1, "error").await;
    assert_eq!(err["context"], "voice_join");
}

// ---------------------------------------------------------------------------
// Phase 2: staging panel data surface (events.md §7.5)
// ---------------------------------------------------------------------------

/// `GET /events/:id/assignments` happy path (organizer sees queued rows) and
/// its gating: a member who can read the anchor channel but holds neither
/// organizer nor mover rights gets 403; once the anchor channel is hidden
/// from them entirely, the same request 404s instead (an id alone must not
/// confirm a hidden channel's existence, matching `get_event`'s posture).
#[tokio::test]
async fn get_assignments_happy_path_and_gated_for_non_organizer() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mover = Identity::generate();
    let mover_token = authenticate_http(&base, &mover).await;
    let mover_key = mover.public_key_hex();

    let target = Identity::generate();
    let target_token = authenticate_http(&base, &target).await;
    let target_pubkey = target.public_key_hex();

    let outsider = Identity::generate();
    let outsider_token = authenticate_http(&base, &outsider).await;

    let dest = create_channel(&base, &owner_token, "assignments-dest").await;
    let mover_role = create_role(&base, &owner_token, "MarshalGet", &["move_members"]).await;
    assign_role(&base, &owner_token, &mover_key, &mover_role.id).await;

    let event = create_event(&base, &owner_token, &dest.id, "Raid Night").await;

    let mut target_ws = connect_ws(&base, &target_token).await;
    let mut mover_ws = connect_ws(&base, &mover_token).await;

    send_ws(
        &mut mover_ws.0,
        json!({
            "type": "voice_move",
            "target_pubkey": target_pubkey,
            "target_channel_id": dest.id,
            "event_id": event.id,
        }),
    )
    .await;
    assert_not_received(&mut target_ws.1, "voice_move").await;

    // Happy path: the event creator (also hub admin here) sees the queued row.
    let assignments = get_assignments_ok(&base, &owner_token, &event.id).await;
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0]["user_pubkey"], target_pubkey);

    // A member who can read the channel but has neither organizer nor mover
    // rights is forbidden.
    let resp = get_assignments(&base, &outsider_token, &event.id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // Once the anchor channel is hidden from them entirely, the same
    // request 404s instead of 403ing.
    deny_overwrite(
        &base,
        &owner_token,
        &dest.id,
        "builtin-everyone",
        &["read_messages"],
    )
    .await;
    let resp = get_assignments(&base, &outsider_token, &event.id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Phase 2: assignment prune at event end (events.md §7.3)
// ---------------------------------------------------------------------------

/// The reminder worker's 60s sweep also prunes `event_move_assignments` for
/// events whose `ends_at` is in the past; an event still in the future
/// keeps its assignments.
#[tokio::test]
async fn reminder_worker_sweep_prunes_assignments_for_ended_events() {
    let (base, state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let target = Identity::generate();
    let target_pubkey = target.public_key_hex();
    let mover = Identity::generate();
    let mover_key = mover.public_key_hex();

    let dest = create_channel(&base, &owner_token, "prune-dest").await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();

    let ended_event =
        create_event_with_ends_at(&base, &owner_token, &dest.id, "Ended Raid", now - 3600).await;
    let live_event =
        create_event_with_ends_at(&base, &owner_token, &dest.id, "Live Raid", now + 3600).await;

    for (event_id, ch) in [(&ended_event.id, &dest.id), (&live_event.id, &dest.id)] {
        sqlx::query(
            "INSERT INTO event_move_assignments
                 (event_id, user_pubkey, target_channel_id, assigned_by, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(event_id)
        .bind(&target_pubkey)
        .bind(ch)
        .bind(&mover_key)
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();
    }

    wavvon_hub::reminder_worker::tick(&state)
        .await
        .expect("tick should succeed");

    let ended_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM event_move_assignments WHERE event_id = $1")
            .bind(&ended_event.id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(ended_count, 0, "ended event's assignments should be pruned");

    let live_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM event_move_assignments WHERE event_id = $1")
            .bind(&live_event.id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(live_count, 1, "still-live event's assignment must survive");
}
