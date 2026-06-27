/// End-to-end integration test: server agent WebSocket flow.
///
/// Unlike the other farm tests (which use axum-test's in-memory transport),
/// this test binds a real TCP listener so that tokio-tungstenite can establish
/// a genuine WebSocket connection.  The flow exercised:
///
///   1. Farm starts on a random localhost port.
///   2. User authenticates → becomes farm admin.
///   3. Admin generates a one-time server-registration token.
///   4. Mock agent connects via WebSocket, sends `hello`.
///   5. GET /farm/admin/servers confirms the agent is listed as connected.
///   6. POST /farm/hubs → farm delegates spawn to the connected agent.
///   7. Mock agent reads the `spawn_hub` command and replies `hub_spawned`.
///   8. Hub row in DB has `server_id` set (proves delegation, not local spawn).
///   9. TOTP setup → confirm → admin re-auth requires TOTP code.
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use totp_rs::{Algorithm, Secret, TOTP};
use wavvon_farm::{db, hub_manager::HubManager, server, state::FarmState};
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Test database helper
// ---------------------------------------------------------------------------

async fn create_test_db() -> PgPool {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string());
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base_url}/postgres"))
        .await
        .expect("connect to postgres admin");
    let db_name = format!("wavvon_farm_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin_pool)
        .await
        .expect("create test database");
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("connect to test database")
}

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn start_farm() -> (String, Arc<FarmState>) {
    let db = create_test_db().await;
    db::migrations::run(&db).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let now = unix_now();

    sqlx::query(
        "INSERT INTO farms (id, public_key, created_at, creation_policy)
         VALUES (1, $1, $2, 'open')",
    )
    .bind(&farm_pubkey)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let farm_url = format!("http://127.0.0.1:{port}");

    let hub_manager = Arc::new(HubManager::new(
        "wavvon-hub".to_string(),
        farm_url.clone(),
        9100,
    ));
    let state = Arc::new(FarmState::new(
        db,
        keypair,
        farm_url.clone(),
        hub_manager,
        "/tmp/wavvon-e2e-hubs".to_string(),
    ));

    let app = server::create_router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Brief pause so the server is ready to accept connections.
    tokio::time::sleep(Duration::from_millis(10)).await;

    (farm_url, state)
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

async fn authenticate(client: &Client, base: &str, identity: &Identity) -> String {
    // Challenge
    let resp = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": identity.public_key_hex() }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let challenge_hex = body["challenge"].as_str().unwrap();
    let challenge_bytes = hex::decode(challenge_hex).unwrap();
    let signature = identity.sign(&challenge_bytes);

    // Verify
    let resp = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": identity.public_key_hex(),
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "verify failed: {}",
        resp.status()
    );
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// E2E: server agent WebSocket delegation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_agent_connects_and_receives_hub_spawn() {
    let (base, state) = start_farm().await;
    let client = Client::new();

    // --- 1. Auth as admin user ---
    let admin = Identity::generate();
    let token = authenticate(&client, &base, &admin).await;

    // Make this user the farm admin.
    sqlx::query("UPDATE farms SET admin_pubkey = $1 WHERE id = 1")
        .bind(admin.public_key_hex())
        .execute(&state.db)
        .await
        .unwrap();

    // --- 2. Generate server registration token ---
    let resp = client
        .post(format!("{base}/farm/admin/server-token"))
        .bearer_auth(&token)
        .json(&json!({ "name": "e2e-server", "region": "test" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "server-token failed: {}",
        resp.status()
    );
    let reg: Value = resp.json().await.unwrap();
    let reg_token = reg["token"].as_str().unwrap().to_string();
    let server_id = reg["server_id"].as_str().unwrap().to_string();

    // --- 3. Connect mock agent via WebSocket ---
    let ws_base = base.replacen("http://", "ws://", 1);
    let ws_url = format!("{ws_base}/ws/agent?token={reg_token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");
    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Send hello.
    ws_write
        .send(Message::Text(
            json!({"type":"hello","version":"0.1.0"}).to_string().into(),
        ))
        .await
        .unwrap();

    // Brief pause for the farm to process the hello and update last_seen_at.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- 4. Confirm server shows as connected ---
    let resp = client
        .get(format!("{base}/farm/admin/servers"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let servers: Value = resp.json().await.unwrap();
    let list = servers["servers"].as_array().unwrap();
    assert!(!list.is_empty(), "server list should be non-empty");
    let our_server = list.iter().find(|s| s["id"] == server_id).unwrap();
    assert!(
        our_server["connected"].as_bool().unwrap_or(false),
        "server should be connected: {our_server}"
    );

    // --- 5. Create a hub → farm should delegate to agent ---
    let resp = client
        .post(format!("{base}/farm/hubs"))
        .bearer_auth(&token)
        .json(&json!({ "name": "e2e-hub", "visibility": "private" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create hub failed: {}",
        resp.status()
    );
    let hub: Value = resp.json().await.unwrap();
    let hub_id = hub["id"].as_str().unwrap().to_string();

    // --- 6. Mock agent reads spawn_hub command ---
    let cmd_msg = tokio::time::timeout(Duration::from_secs(5), ws_read.next())
        .await
        .expect("timeout waiting for spawn_hub")
        .unwrap()
        .unwrap();
    let cmd: Value = serde_json::from_str(&cmd_msg.into_text().unwrap()).unwrap();
    assert_eq!(cmd["type"], "spawn_hub", "expected spawn_hub, got: {cmd}");
    assert_eq!(cmd["hub_id"], hub_id);

    // --- 7. Agent replies hub_spawned ---
    ws_write
        .send(Message::Text(
            json!({"type":"hub_spawned","hub_id":hub_id,"port":9200})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- 8. Verify hub row is assigned to our server ---
    let assigned_server_id: Option<String> =
        sqlx::query_scalar("SELECT server_id FROM hubs WHERE id = $1")
            .bind(&hub_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(
        assigned_server_id.as_deref(),
        Some(server_id.as_str()),
        "hub must be assigned to the connected server agent"
    );
}

// ---------------------------------------------------------------------------
// E2E: TOTP setup → confirm → login enforces TOTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn totp_setup_confirm_and_login_enforcement() {
    let (base, state) = start_farm().await;
    let client = Client::new();

    // Auth as admin.
    let admin = Identity::generate();
    let token = authenticate(&client, &base, &admin).await;
    sqlx::query("UPDATE farms SET admin_pubkey = $1 WHERE id = 1")
        .bind(admin.public_key_hex())
        .execute(&state.db)
        .await
        .unwrap();

    // --- TOTP setup: get secret ---
    let resp = client
        .post(format!("{base}/farm/admin/totp/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "totp/setup failed: {}",
        resp.status()
    );
    let setup: Value = resp.json().await.unwrap();
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(!secret.is_empty());

    // --- Generate a valid TOTP code from the secret and confirm ---
    let code = totp_code_from_secret(&secret);

    let resp = client
        .post(format!("{base}/farm/admin/totp/confirm"))
        .bearer_auth(&token)
        .json(&json!({ "secret": secret, "code": code }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "totp/confirm failed: {} — code={code}",
        resp.status()
    );

    // --- Attempt to log in WITHOUT TOTP code → must be rejected ---
    let resp = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": admin.public_key_hex() }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let challenge_hex = body["challenge"].as_str().unwrap();
    let sig = admin.sign(&hex::decode(challenge_hex).unwrap());

    let resp = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": admin.public_key_hex(),
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "should require TOTP but got {}",
        resp.status()
    );
    // auth.rs returns plain-text error strings, not JSON objects.
    let body = resp.text().await.unwrap();
    assert_eq!(body, "totp_required");

    // --- Log in WITH valid TOTP code → must succeed ---
    let resp2 = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": admin.public_key_hex() }))
        .send()
        .await
        .unwrap();
    let body2: Value = resp2.json().await.unwrap();
    let ch2 = body2["challenge"].as_str().unwrap();
    let sig2 = admin.sign(&hex::decode(ch2).unwrap());

    let code2 = totp_code_from_secret(&secret);
    let resp2 = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": admin.public_key_hex(),
            "signature": hex::encode(sig2.to_bytes()),
            "totp_code": code2,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp2.status().is_success(),
        "TOTP login should succeed: {}",
        resp2.status()
    );
}

/// Generate a current TOTP code from a base32 secret using the same algorithm
/// the farm uses (SHA1, 6 digits, 30-second window).
fn totp_code_from_secret(secret_b32: &str) -> String {
    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .expect("invalid base32 secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        "test".to_string(),
    )
    .unwrap();
    totp.generate_current().unwrap()
}
