//! Paired-device DM attribution & cert-chained verification
//! (docs/docs/decisions.md "Paired-device DMs attribute to canonical via
//! cert-chained envelopes; DH capability is a wrapped canonical scalar").
//!
//! Covers: a paired device (subkey, no cert) attaching a `signer_cert` to an
//! encrypted 1:1 DM envelope attributes the stored/broadcast message to the
//! canonical (master) identity; the cert-less path is unchanged (regression);
//! a bad/mismatched cert is rejected; and a federated hub accepts + attributes
//! a `signer_cert`-bearing DM without a session.

use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::dm_models::ConversationResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::{DeviceSubkey, Identity, MasterIdentity, SubkeyCert};

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_cert(master: &MasterIdentity, subkey_pubkey: &str, label: &str) -> SubkeyCert {
    let master_pubkey = master.public_key_hex();
    let issued_at = 1_700_000_000;
    let bytes =
        SubkeyCert::signing_bytes(&master_pubkey, subkey_pubkey, label, issued_at, None, &[]);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    SubkeyCert {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        device_label: label.to_string(),
        issued_at,
        not_after: None,
        fallback_hubs: vec![],
        signature,
    }
}

async fn auth_with_cert(
    server: &TestServer,
    subkey: &DeviceSubkey,
    cert: Option<&SubkeyCert>,
) -> String {
    let pub_key = subkey.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = subkey.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });
    if let Some(cert) = cert {
        body["subkey_cert"] = serde_json::to_value(cert).unwrap();
    }

    let resp = server.post("/auth/verify").json(&body).await;
    resp.assert_status_ok();
    let verify: VerifyResponse = resp.json();
    verify.token
}

/// Build a valid 1:1 encrypted DM envelope signed by `signer` (the actual
/// signing key used) with `sender_pubkey` (the canonical identity the
/// envelope claims to be from) and an optional `signer_cert`.
fn make_encrypted_envelope(
    signer: &dyn Fn(&[u8]) -> Vec<u8>,
    sender_pubkey: &str,
    conv_id: &str,
    signer_cert: Option<&SubkeyCert>,
) -> serde_json::Value {
    let ciphertext_hex = "63697068657274657874".to_string(); // hex("ciphertext")
    let nonce_hex = "0102030405060708090a0b0c".to_string();
    let dh_pubkey_hex = "aa".repeat(32);

    let signing_bytes = wavvon_identity::dm_envelope_signing_bytes(
        conv_id,
        &ciphertext_hex,
        &nonce_hex,
        &dh_pubkey_hex,
    );
    let sig_hex = hex::encode(signer(&signing_bytes));

    let mut env = json!({
        "sender_pubkey": sender_pubkey,
        "conv_id": conv_id,
        "ciphertext_hex": ciphertext_hex,
        "nonce_hex": nonce_hex,
        "dh_pubkey_hex": dh_pubkey_hex,
        "signature_hex": sig_hex,
        "v": 1,
    });
    if let Some(cert) = signer_cert {
        env["signer_cert"] = serde_json::to_value(cert).unwrap();
    }
    env
}

// ---------------------------------------------------------------------------
// Happy path: paired device (subkey + cert) attributes to canonical
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paired_device_encrypted_dm_attributes_to_canonical() {
    let server = common::setup().await;

    // Alice's master identity, paired "phone" subkey.
    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = auth_with_cert(&server, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;

    // Conversation between Alice's canonical identity and Bob.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert!(
        conv.members.contains(&alice_canonical),
        "conversation should be keyed to Alice's canonical pubkey, not her subkey"
    );

    // Alice's phone signs the envelope with its own (subkey) key, attaches
    // its cert, but claims sender_pubkey = canonical (Mechanism B).
    let envelope = make_encrypted_envelope(
        &|msg| phone.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&phone_cert),
    );

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let msg: serde_json::Value = resp.json();
    assert_eq!(
        msg["sender"], alice_canonical,
        "stored/broadcast sender must be the canonical identity, not the subkey"
    );

    // Bob reads it back — same attribution.
    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&bob_token)
        .await;
    resp.assert_status_ok();
    let messages: serde_json::Value = resp.json();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["sender"], alice_canonical);
    assert_eq!(
        arr[0]["encrypted_envelope"]["signer_cert"]["subkey_pubkey"],
        phone.public_key_hex()
    );
}

// ---------------------------------------------------------------------------
// Group DMs and sender keys: the same rule, which had only ever been
// implemented for 1:1
// ---------------------------------------------------------------------------

/// A group conversation with `alice_canonical` and `bob` in it.
async fn group_conversation(
    server: &TestServer,
    alice_token: &str,
    bob_pubkey: &str,
    carol_pubkey: &str,
) -> ConversationResponse {
    let resp = server
        .post("/conversations")
        .authorization_bearer(alice_token)
        .json(&json!({ "members": [bob_pubkey, carol_pubkey] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json()
}

fn make_group_envelope(
    signer: &dyn Fn(&[u8]) -> Vec<u8>,
    sender_pubkey: &str,
    conv_id: &str,
    signer_cert: Option<&SubkeyCert>,
) -> serde_json::Value {
    let ciphertext_hex = "63697068657274657874".to_string();
    let nonce_hex = "0102030405060708090a0b0c".to_string();
    let (version, iteration) = (1u32, 0u32);

    let signing_bytes = wavvon_identity::group_dm_envelope_signing_bytes(
        conv_id,
        version,
        iteration,
        &ciphertext_hex,
        &nonce_hex,
    );
    let sig_hex = hex::encode(signer(&signing_bytes));

    let mut env = json!({
        "sender_pubkey": sender_pubkey,
        "conv_id": conv_id,
        "sender_key_version": version,
        "iteration": iteration,
        "ciphertext_hex": ciphertext_hex,
        "nonce_hex": nonce_hex,
        "signature_hex": sig_hex,
    });
    if let Some(cert) = signer_cert {
        env["signer_cert"] = serde_json::to_value(cert).unwrap();
    }
    env
}

/// A paired device can start a group conversation — which means distributing
/// a sender key, and then sending under it.
///
/// Neither path had a cert tier: both verified the signature against the
/// canonical pubkey, which a paired device cannot produce one for. It holds
/// its subkey and the cert naming it, and nothing else — so group DMs worked
/// from exactly one device per identity, the one that created it, and failed
/// on every other with "Invalid signature". The decision this implements has
/// been recorded since the 1:1 path shipped; only 1:1 was built.
#[tokio::test]
async fn paired_device_can_distribute_a_sender_key_and_send_under_it() {
    let server = common::setup().await;

    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = auth_with_cert(&server, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;
    let carol = Identity::generate();
    common::authenticate(&server, &carol).await;

    let conv = group_conversation(
        &server,
        &alice_token,
        &bob.public_key_hex(),
        &carol.public_key_hex(),
    )
    .await;

    // Step one of any group message: hand every member the sender key.
    let recipients = json!([
        {
            "recipient_pubkey": bob.public_key_hex(),
            "wrapped_key_hex": "aa".repeat(48),
            "wrap_nonce_hex": "0102030405060708090a0b0c",
            "iteration": 0,
        },
        {
            "recipient_pubkey": carol.public_key_hex(),
            "wrapped_key_hex": "bb".repeat(48),
            "wrap_nonce_hex": "0c0b0a090807060504030201",
            "iteration": 0,
        },
    ]);
    // The signature covers (pubkey, wrapped_hex) — the nonce is not in it.
    let dist_bytes = wavvon_identity::sender_key_dist_signing_bytes(
        &conv.id,
        1,
        &[
            (bob.public_key_hex(), "aa".repeat(48)),
            (carol.public_key_hex(), "bb".repeat(48)),
        ],
    );

    let resp = server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({
            "sender_key_version": 1,
            "recipients": recipients,
            "signature_hex": hex::encode(phone.sign(&dist_bytes).to_bytes()),
            "signer_cert": phone_cert,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // And step two: the message itself, under that key.
    let envelope = make_group_envelope(
        &|msg| phone.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&phone_cert),
    );
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let msg: serde_json::Value = resp.json();
    assert_eq!(
        msg["sender"], alice_canonical,
        "a group message from a paired device is still from the canonical identity"
    );

    // Bob can see who it is from and which device signed it.
    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&bob_token)
        .await;
    resp.assert_status_ok();
    let messages: serde_json::Value = resp.json();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["sender"], alice_canonical);
    assert_eq!(
        arr[0]["group_encrypted_envelope"]["signer_cert"]["subkey_pubkey"],
        phone.public_key_hex()
    );
}

/// Someone else's cert does not let its holder speak as this session.
///
/// The signature checks out — it is a real signature by a real subkey under a
/// real cert. What must not check out is the claim that the cert belongs to
/// the authenticated identity.
#[tokio::test]
async fn group_envelope_rejects_a_cert_from_another_master() {
    let server = common::setup().await;

    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = auth_with_cert(&server, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;
    let carol = Identity::generate();
    common::authenticate(&server, &carol).await;
    let conv = group_conversation(
        &server,
        &alice_token,
        &bob.public_key_hex(),
        &carol.public_key_hex(),
    )
    .await;

    // A cert from an unrelated identity, over an unrelated device.
    let mallory_master = Identity::generate().master().unwrap();
    let mallory_device = DeviceSubkey::generate("laptop".into());
    let mallory_cert = make_cert(&mallory_master, &mallory_device.public_key_hex(), "laptop");

    let envelope = make_group_envelope(
        &|msg| mallory_device.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&mallory_cert),
    );
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(
        resp.text().contains("signer_cert master"),
        "the refusal must name the binding that failed, got {}",
        resp.text()
    );
}

/// The cert-less group path is exactly as it was: the canonical identity
/// signing for itself, verified against itself.
#[tokio::test]
async fn certless_group_envelope_unchanged() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;
    let carol = Identity::generate();
    common::authenticate(&server, &carol).await;

    let conv = group_conversation(
        &server,
        &alice_token,
        &bob.public_key_hex(),
        &carol.public_key_hex(),
    )
    .await;

    let good = make_group_envelope(
        &|msg| alice.sign(msg).to_bytes().to_vec(),
        &alice.public_key_hex(),
        &conv.id,
        None,
    );
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": good }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // And a signature by a key that is not the sender is still refused, with
    // no cert to excuse it.
    let stranger = Identity::generate();
    let bad = make_group_envelope(
        &|msg| stranger.sign(msg).to_bytes().to_vec(),
        &alice.public_key_hex(),
        &conv.id,
        None,
    );
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": bad }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Regression: cert-less encrypted DM path is unchanged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn certless_encrypted_dm_unchanged() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // No cert: primary device signs directly as its own (canonical) key.
    let envelope = make_encrypted_envelope(
        &|msg| alice.sign(msg).to_bytes().to_vec(),
        &alice.public_key_hex(),
        &conv.id,
        None,
    );

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let msg: serde_json::Value = resp.json();
    assert_eq!(msg["sender"], alice.public_key_hex());
    assert!(msg["encrypted_envelope"]["signer_cert"].is_null());
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dm_rejects_signer_cert_for_different_master() {
    let server = common::setup().await;

    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = auth_with_cert(&server, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // A validly-signed cert, but for a DIFFERENT master than the one bound
    // to this authenticated session — must not be accepted as attribution
    // proof for Alice's session.
    let other_master = Identity::generate().master().unwrap();
    let mismatched_cert = make_cert(&other_master, &phone.public_key_hex(), "phone");

    let envelope = make_encrypted_envelope(
        &|msg| phone.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&mismatched_cert),
    );

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dm_rejects_tampered_signer_cert_signature() {
    let server = common::setup().await;

    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = auth_with_cert(&server, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Tamper with the cert's device_label post-signing so its signature no
    // longer verifies.
    let mut tampered_cert = phone_cert.clone();
    tampered_cert.device_label = "tampered".to_string();

    let envelope = make_encrypted_envelope(
        &|msg| phone.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&tampered_cert),
    );

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dm_rejects_sender_pubkey_not_matching_session() {
    let server = common::setup().await;

    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Envelope signed correctly by Alice but claiming a different
    // sender_pubkey than the authenticated session.
    let impostor = Identity::generate();
    let envelope = make_encrypted_envelope(
        &|msg| alice.sign(msg).to_bytes().to_vec(),
        &impostor.public_key_hex(),
        &conv.id,
        None,
    );

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Federated: signer_cert accepted and attributed cross-hub
// ---------------------------------------------------------------------------

async fn start_real_hub_with_state(name: &str) -> (String, Arc<AppState>, common::TestDbGuard) {
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

async fn authenticate_http_with_cert(
    hub_url: &str,
    subkey: &DeviceSubkey,
    cert: Option<&SubkeyCert>,
) -> String {
    let client = reqwest::Client::new();
    let pub_key = subkey.public_key_hex();

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
    let signature = subkey.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });
    if let Some(cert) = cert {
        body["subkey_cert"] = serde_json::to_value(cert).unwrap();
    }

    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

/// Plain (cert-less) HTTP auth for a normal `Identity`. Mirrors
/// `dms_flow.rs::authenticate_http`.
async fn authenticate_http(hub_url: &str, identity: &Identity) -> String {
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

/// Poll the recipient hub until the federated DM lands (federated delivery
/// is asynchronous). Mirrors `dms_flow.rs::wait_for_federated_dms`.
async fn wait_for_federated_dms(
    client: &reqwest::Client,
    hub_url: &str,
    token: &str,
    conversation_id: &str,
    expected_len: usize,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let resp = client
            .get(format!(
                "{hub_url}/conversations/{conversation_id}/messages"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            if let Ok(messages) = serde_json::from_str::<serde_json::Value>(&body) {
                if messages.as_array().is_some_and(|a| a.len() >= expected_len) {
                    return messages;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("federated DM never arrived on {hub_url}: last response: {status} {body}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn federated_dm_with_signer_cert_accepted_and_attributed() {
    let (hub_a, _hub_a_state, _hub_a_guard) = start_real_hub_with_state("hub-a-attrib").await;
    let (hub_b, hub_b_state, _hub_b_guard) = start_real_hub_with_state("hub-b-attrib").await;
    let client = reqwest::Client::new();

    // Alice pairs a "phone" subkey to her master on Hub A.
    let alice_master_identity = Identity::generate();
    let alice_master = alice_master_identity.master().unwrap();
    let phone = DeviceSubkey::generate("phone".into());
    let phone_cert = make_cert(&alice_master, &phone.public_key_hex(), "phone");
    let alice_token = authenticate_http_with_cert(&hub_a, &phone, Some(&phone_cert)).await;
    let alice_canonical = alice_master.public_key_hex();

    let bob = Identity::generate();
    authenticate_http(&hub_b, &bob).await;

    // Hub B needs to know Bob's plain pubkey to route to — create the
    // cross-hub conversation from Hub A with Bob's real pubkey.
    let mut member_hubs = HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create conversation failed");
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Hub B learns Alice's canonical→master binding via the local users
    // row (the simplest binding tier — mirrors how an already-known sender
    // resolves without a device-registry fetch). Since the canonical
    // identity IS its own subkey-0/entropy master in this test's setup,
    // master_pubkey == public_key here.
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, master_pubkey)
         VALUES ($1, 0, 0, $1) ON CONFLICT (public_key) DO UPDATE SET master_pubkey = $1",
    )
    .bind(&alice_canonical)
    .execute(&hub_b_state.db)
    .await
    .unwrap();

    // Alice's phone sends an encrypted DM signed by its own subkey, cert
    // attached, sender_pubkey = canonical.
    let envelope = make_encrypted_envelope(
        &|msg| phone.sign(msg).to_bytes().to_vec(),
        &alice_canonical,
        &conv.id,
        Some(&phone_cert),
    );
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "encrypted_envelope": envelope }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Bob reads it from Hub B — attributed to Alice's canonical pubkey.
    let bob_token = authenticate_http(&hub_b, &bob).await;

    let messages = wait_for_federated_dms(&client, &hub_b, &bob_token, &conv.id, 1).await;
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["sender"], alice_canonical);
}
