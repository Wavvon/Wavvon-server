//! Soundboard (soundboard.md §1): upload/list/delete clip metadata + audio
//! bytes, hard caps, and the `played` attribution event with its
//! channel-scoped `use_soundboard` gate.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Boot a real TCP listener on a random port. A real socket is needed
/// because the `played` test exercises `tokio_tungstenite` over the main
/// chat WS, which (like `screen_share_flow.rs`/`ws_read_gating_flow.rs`)
/// `axum_test`'s in-process harness can't drive.
async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "soundboard-test".to_string(),
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
    });

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

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

async fn create_role(base: &str, token: &str, name: &str, permissions: &[&str]) -> String {
    let resp: Value = reqwest::Client::new()
        .post(format!("{base}/roles"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "permissions": permissions, "priority": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["id"].as_str().unwrap().to_string()
}

async fn assign_role(base: &str, token: &str, pubkey: &str, role_id: &str) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/users/{pubkey}/roles/{role_id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "assign_role failed: {}",
        resp.status()
    );
}

async fn deny_channel_permission(
    base: &str,
    token: &str,
    channel_id: &str,
    role_id: &str,
    perm: &str,
) {
    let resp = reqwest::Client::new()
        .put(format!(
            "{base}/channels/{channel_id}/permissions/{role_id}"
        ))
        .bearer_auth(token)
        .json(&json!({ "allow": [], "deny": [perm] }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "deny_channel_permission failed: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Minimal, hand-built Ogg Opus fixtures. Real audio content isn't needed --
// only the structural shape the server validator checks: a well-formed Ogg
// page sequence whose first page carries an OpusHead identification header,
// with the final page's granule position encoding total duration.
// ---------------------------------------------------------------------------

fn ogg_page(granule: i64, seq: u32, payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() < 255,
        "test fixture uses single-segment lacing only"
    );
    let mut page = Vec::new();
    page.extend_from_slice(b"OggS");
    page.push(0); // version
    page.push(0); // header_type (unused by the validator)
    page.extend_from_slice(&granule.to_le_bytes());
    page.extend_from_slice(&1u32.to_le_bytes()); // bitstream serial number
    page.extend_from_slice(&seq.to_le_bytes()); // page sequence number
    page.extend_from_slice(&0u32.to_le_bytes()); // CRC (unchecked by the validator)
    page.push(1); // number of segments
    page.push(payload.len() as u8); // single-segment lacing value
    page.extend_from_slice(payload);
    page
}

fn build_ogg_opus(duration_ms: i64) -> Vec<u8> {
    let mut head_payload = Vec::new();
    head_payload.extend_from_slice(b"OpusHead");
    head_payload.push(1); // version
    head_payload.push(1); // channel count
    head_payload.extend_from_slice(&0u16.to_le_bytes()); // pre-skip
    head_payload.extend_from_slice(&48_000u32.to_le_bytes()); // input sample rate
    head_payload.extend_from_slice(&0i16.to_le_bytes()); // output gain
    head_payload.push(0); // channel mapping family

    let mut tags_payload = Vec::new();
    tags_payload.extend_from_slice(b"OpusTags");
    tags_payload.extend_from_slice(&0u32.to_le_bytes()); // vendor string length
    tags_payload.extend_from_slice(&0u32.to_le_bytes()); // comment list length

    let granule = (duration_ms * 48_000) / 1000;
    let data_payload = vec![0u8; 20]; // opaque "opus packet" bytes

    let mut out = Vec::new();
    out.extend(ogg_page(0, 0, &head_payload));
    out.extend(ogg_page(-1, 1, &tags_payload));
    out.extend(ogg_page(granule, 2, &data_payload));
    out
}

async fn upload_clip(
    base: &str,
    token: &str,
    name: &str,
    emoji: Option<&str>,
    audio: Vec<u8>,
) -> reqwest::Response {
    let mut form = reqwest::multipart::Form::new().text("name", name.to_string());
    if let Some(e) = emoji {
        form = form.text("emoji", e.to_string());
    }
    let part = reqwest::multipart::Part::bytes(audio)
        .file_name("clip.ogg")
        .mime_str("audio/ogg")
        .unwrap();
    form = form.part("audio", part);

    reqwest::Client::new()
        .post(format!("{base}/soundboard"))
        .bearer_auth(token)
        .multipart(form)
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Upload / list / audio bytes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_happy_path_lists_and_serves_audio() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let audio = build_ogg_opus(3_000);
    let resp = upload_clip(&base, &owner_token, "Airhorn", Some("📯"), audio.clone()).await;
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let clip: Value = resp.json().await.unwrap();
    assert_eq!(clip["name"], "Airhorn");
    assert_eq!(clip["emoji"], "📯");
    assert_eq!(clip["duration_ms"], 3_000);
    assert_eq!(clip["size_bytes"], audio.len());
    let clip_id = clip["id"].as_str().unwrap().to_string();

    let list: Vec<Value> = reqwest::Client::new()
        .get(format!("{base}/soundboard"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list.iter().any(|c| c["id"] == clip_id));

    let audio_resp = reqwest::Client::new()
        .get(format!("{base}/soundboard/{clip_id}/audio"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(audio_resp.status(), reqwest::StatusCode::OK);
    let content_type = audio_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(content_type, "audio/ogg");
    let bytes = audio_resp.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), audio.as_slice());
}

#[tokio::test]
async fn upload_rejects_uploader_without_manage_soundboard() {
    let (base, _state, _guard) = start_hub().await;
    let _owner_token = authenticate_http(&base, &Identity::generate()).await;
    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;

    let resp = upload_clip(&base, &member_token, "Nope", None, build_ogg_opus(1_000)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn upload_rejects_oversize_file() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;

    // Content doesn't need to be valid Ogg -- the size cap is enforced
    // during multipart read, before format validation runs.
    let oversized = vec![0u8; 512 * 1024 + 1];
    let resp = upload_clip(&base, &owner_token, "TooBig", None, oversized).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_rejects_too_long_duration() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;

    let resp = upload_clip(&base, &owner_token, "TooLong", None, build_ogg_opus(12_000)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_rejects_bad_format() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;

    let resp = upload_clip(
        &base,
        &owner_token,
        "NotOgg",
        None,
        b"definitely not ogg".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_rejects_fifty_first_clip() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;

    for i in 0..50 {
        let resp = upload_clip(
            &base,
            &owner_token,
            &format!("clip-{i}"),
            None,
            build_ogg_opus(500),
        )
        .await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::CREATED,
            "clip {i} should upload successfully"
        );
    }

    let resp = upload_clip(&base, &owner_token, "clip-51", None, build_ogg_opus(500)).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_clip_removes_metadata_and_audio() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;

    let resp = upload_clip(&base, &owner_token, "Bye", None, build_ogg_opus(1_000)).await;
    let clip: Value = resp.json().await.unwrap();
    let clip_id = clip["id"].as_str().unwrap().to_string();

    let del = reqwest::Client::new()
        .delete(format!("{base}/soundboard/{clip_id}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::NO_CONTENT);

    let list: Vec<Value> = reqwest::Client::new()
        .get(format!("{base}/soundboard"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!list.iter().any(|c| c["id"] == clip_id));

    let audio_resp = reqwest::Client::new()
        .get(format!("{base}/soundboard/{clip_id}/audio"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(audio_resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_clip_rejects_uploader_without_manage_soundboard() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let member_token = authenticate_http(&base, &Identity::generate()).await;

    let resp = upload_clip(
        &base,
        &owner_token,
        "Protected",
        None,
        build_ogg_opus(1_000),
    )
    .await;
    let clip: Value = resp.json().await.unwrap();
    let clip_id = clip["id"].as_str().unwrap().to_string();

    let del = reqwest::Client::new()
        .delete(format!("{base}/soundboard/{clip_id}"))
        .bearer_auth(&member_token)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), reqwest::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// /played — attribution broadcast + channel-scoped use_soundboard gate
// ---------------------------------------------------------------------------

async fn connect_ws(
    base: &str,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws
}

#[tokio::test]
async fn played_broadcasts_soundboard_played_to_channel() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;

    let ch = create_channel(&base, &owner_token, "played-broadcast").await;
    let role_id = create_role(&base, &owner_token, "Speaker", &["use_soundboard"]).await;
    assign_role(&base, &owner_token, &member.public_key_hex(), &role_id).await;

    let resp = upload_clip(&base, &owner_token, "Airhorn", None, build_ogg_opus(1_000)).await;
    let clip: Value = resp.json().await.unwrap();
    let clip_id = clip["id"].as_str().unwrap().to_string();

    // Connect after the role is assigned so auto-subscribe sees current
    // readable channels; drain frames until "hello" so we know we're past
    // connection setup.
    let ws = connect_ws(&base, &member_token).await;
    let (_tx, mut rx) = ws.split();
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                break;
            }
        }
    }

    let played = reqwest::Client::new()
        .post(format!("{base}/soundboard/{clip_id}/played"))
        .bearer_auth(&member_token)
        .json(&json!({ "channel_id": ch.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(played.status(), reqwest::StatusCode::NO_CONTENT);

    let event = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let msg = rx.next().await.unwrap().unwrap();
            if let TsMessage::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "soundboard_played" {
                    return v;
                }
            }
        }
    })
    .await
    .expect("expected a soundboard_played event before timeout");

    assert_eq!(event["channel_id"], ch.id);
    assert_eq!(event["clip_id"], clip_id);
    assert_eq!(event["clip_name"], "Airhorn");
    assert_eq!(event["public_key"], member.public_key_hex());
}

#[tokio::test]
async fn played_denied_by_channel_scoped_use_soundboard_deny() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;

    let ch = create_channel(&base, &owner_token, "played-denied").await;
    let role_id = create_role(&base, &owner_token, "Speaker2", &["use_soundboard"]).await;
    assign_role(&base, &owner_token, &member.public_key_hex(), &role_id).await;

    let resp = upload_clip(&base, &owner_token, "Trombone", None, build_ogg_opus(1_000)).await;
    let clip: Value = resp.json().await.unwrap();
    let clip_id = clip["id"].as_str().unwrap().to_string();

    // Deny use_soundboard for this role specifically on this channel --
    // the hub-wide grant from the role still applies elsewhere.
    deny_channel_permission(&base, &owner_token, &ch.id, &role_id, "use_soundboard").await;

    let played = reqwest::Client::new()
        .post(format!("{base}/soundboard/{clip_id}/played"))
        .bearer_auth(&member_token)
        .json(&json!({ "channel_id": ch.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(played.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn played_rejects_member_without_use_soundboard() {
    let (base, _state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let member_token = authenticate_http(&base, &Identity::generate()).await;

    let ch = create_channel(&base, &owner_token, "played-no-perm").await;
    let resp = upload_clip(&base, &owner_token, "Silence", None, build_ogg_opus(1_000)).await;
    let clip: Value = resp.json().await.unwrap();
    let clip_id = clip["id"].as_str().unwrap().to_string();

    let played = reqwest::Client::new()
        .post(format!("{base}/soundboard/{clip_id}/played"))
        .bearer_auth(&member_token)
        .json(&json!({ "channel_id": ch.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(played.status(), reqwest::StatusCode::FORBIDDEN);
}
