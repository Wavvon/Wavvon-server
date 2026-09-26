//! The farm→hub path with real processes.
//!
//! Every other farm test mocks the hub: `e2e_server_agent` uses a mock agent,
//! `serial_routing_flow` uses a stub HTTP server, and the rest seed rows by
//! hand. That is why three separate bugs lived in this path for months without
//! a single red test — each one only exists between the farm and a real
//! `wavvon-hub` process:
//!
//! - `hubs.hub_pubkey` was never written by anyone, so the proxy could resolve
//!   nothing and every farm-routed request 404'd;
//! - the hub's public URL could not be passed at spawn (it contains a key that
//!   does not exist yet), so voice had no endpoint at all;
//! - no database configuration was passed, so every spawned hub fell back to
//!   the same default and they all shared one.
//!
//! This test creates a hub through the farm's own API, lets the real binary
//! start, and then asks the farm's proxy for that hub's `/info`. Any of those
//! three regressing fails it.
//!
//! Needs a built `wavvon-hub`, which `cargo test --workspace` produces. When it
//! is absent the test says so and passes — but CI sets `WAVVON_REQUIRE_E2E=1`,
//! which turns the skip into a failure, because a test that skips itself is a
//! test that can stop running without anyone noticing.

#[path = "common.rs"]
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::json;
use tokio::net::TcpListener;
use wavvon_farm::token::{sign_token, FarmTokenPayload};
use wavvon_farm::{db, hub_manager::HubManager, server, state::FarmState, unix_now};

/// Locate the `wavvon-hub` binary next to this test executable.
///
/// `CARGO_BIN_EXE_*` only exists for binaries in the *same* package, and the
/// hub lives in another one — so this walks up from the test binary
/// (`target/<profile>/deps/farm_hub_e2e-<hash>`) to `target/<profile>/`.
fn hub_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.parent()?; // deps/ -> <profile>/
    let name = if cfg!(windows) {
        "wavvon-hub.exe"
    } else {
        "wavvon-hub"
    };
    let path = dir.join(name);
    path.exists().then_some(path)
}

fn token_for(state: &FarmState, pubkey: &str, farm_url: &str) -> String {
    let now = unix_now();
    sign_token(
        &state.keypair,
        &FarmTokenPayload {
            v: 1,
            iss: farm_url.to_string(),
            iss_pk: state.public_key_hex(),
            sub: pubkey.to_string(),
            master: None,
            jti: "e2e".to_string(),
            iat: now,
            exp: now + 3600,
            scope: "member".to_string(),
        },
    )
}

/// A farm on a real port, wired to spawn the real hub binary.
async fn start_farm(
    hub_bin: PathBuf,
    base_port: u16,
    voice_base_port: u16,
) -> (String, Arc<FarmState>, common::TestDbGuard) {
    let (db_pool, guard) = common::create_test_db().await;
    db::migrations::run(&db_pool).await.unwrap();

    // Reconstruct the URL of the database this test is using, so hubs are
    // provisioned inside it rather than wherever a database-less URL lands.
    let farm_db_url = {
        let opts = db_pool.connect_options();
        format!(
            "{}/{}",
            common::base_db_url(),
            opts.get_database().unwrap_or("postgres")
        )
    };

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let admin = "e2e".repeat(21) + "a"; // 64 hex-ish chars, only used as an id
    sqlx::query(
        "INSERT INTO farms (id, public_key, created_at, admin_pubkey, creation_policy)
         VALUES (1, $1, $2, $3, 'open')",
    )
    .bind(&farm_pubkey)
    .bind(unix_now())
    .bind(&admin)
    .execute(&db_pool)
    .await
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let farm_url = format!("http://127.0.0.1:{port}");

    // A directory per test run, so two spawned hubs never meet each other's
    // identity file — which is exactly the bug this harness surfaced.
    let hubs_dir = std::env::temp_dir()
        .join(format!("wavvon-e2e-{}", uuid::Uuid::new_v4().simple()))
        .to_string_lossy()
        .to_string();

    let hub_manager = Arc::new(HubManager::new(
        hub_bin.to_string_lossy().to_string(),
        farm_url.clone(),
        base_port,
        voice_base_port,
        // The FULL url, database included: schema isolation keeps the base
        // URL's database and only adds a search_path, so a base without one
        // would put the hub somewhere other than the farm's own database.
        farm_db_url,
        hubs_dir.clone(),
    ));
    let state = Arc::new(FarmState::new(
        db_pool,
        keypair,
        farm_url.clone(),
        hub_manager,
        hubs_dir,
    ));

    let app = server::create_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (farm_url, state, guard)
}

/// Poll until `f` succeeds or the deadline passes.
async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_hub_created_through_the_farm_becomes_reachable_through_it() {
    let Some(hub_bin) = hub_binary() else {
        assert!(
            std::env::var("WAVVON_REQUIRE_E2E").is_err(),
            "wavvon-hub is not built, and WAVVON_REQUIRE_E2E is set — this \
             environment is supposed to run the end-to-end path"
        );
        eprintln!("WAVVON-TEST-SKIPPED: farm_hub_e2e — wavvon-hub not built");
        return;
    };

    let (farm_url, state, _guard) = start_farm(hub_bin, 9800, 10800).await;
    let owner = "11".repeat(32);
    let token = token_for(&state, &owner, &farm_url);
    let client = Client::new();

    // 1. Create a hub. The farm provisions its database, picks a node, and
    //    spawns the real binary.
    let created: serde_json::Value = client
        .post(format!("{farm_url}/farm/hubs"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Osteria di Pippo" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hub_id = created["id"].as_str().expect("hub id").to_string();

    // 2. Give it a human address.
    let slug_res = client
        .post(format!("{farm_url}/farm/hubs/{hub_id}/slugs"))
        .bearer_auth(&token)
        .json(&json!({ "slug": "MangiaDaPippo" }))
        .send()
        .await
        .unwrap();
    assert_eq!(slug_res.status(), 201, "claiming a slug");

    // 3. Its own database, not the one every hub used to share.
    let db_url: Option<String> = sqlx::query_scalar("SELECT db_url FROM hubs WHERE id = $1")
        .bind(&hub_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    let db_url = db_url.expect("the hub must have been given a database");
    assert!(
        db_url.contains(&hub_id) || db_url.contains("hub_"),
        "the hub's database must be its own, got {db_url}"
    );

    // 4. The hub boots and heartbeats, which is what claims its serial. Until
    //    that happens the farm has a hub it cannot route to — the bug this
    //    whole test exists to catch.
    let pool = state.db.clone();
    let id_for_wait = hub_id.clone();
    wait_for(
        "the hub to claim its serial",
        Duration::from_secs(45),
        || {
            let pool = pool.clone();
            let id = id_for_wait.clone();
            async move {
                sqlx::query_scalar::<_, Option<String>>("SELECT hub_pubkey FROM hubs WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            }
        },
    )
    .await;

    // 5. Reachable through the farm at its human address.
    let client2 = client.clone();
    let url = farm_url.clone();
    wait_for(
        "the hub to answer through the proxy",
        Duration::from_secs(30),
        || {
            let c = client2.clone();
            let u = url.clone();
            async move {
                c.get(format!("{u}/hub/mangiadapippo/info"))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            }
        },
    )
    .await;

    let info: serde_json::Value = client
        .get(format!("{farm_url}/hub/mangiadapippo/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // The serial the farm recorded is the key the hub reports for itself. If
    // these ever disagree, the proxy is routing to something other than the
    // hub the farm thinks it is.
    let recorded: String = sqlx::query_scalar("SELECT hub_pubkey FROM hubs WHERE id = $1")
        .bind(&hub_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(
        info["public_key"].as_str().unwrap(),
        recorded,
        "the hub behind the address must be the hub the farm recorded"
    );

    // 6. It knows its own public address, and it is the slug one — which is
    //    what clients store and follow through a rename.
    assert_eq!(
        info["canonical_url"].as_str().unwrap(),
        format!("{farm_url}/hub/mangiadapippo"),
        "the hub must have learned its address from the heartbeat response"
    );

    // 7. And it has a voice endpoint, which needs a public URL it could only
    //    have derived itself.
    assert!(
        info["voice_wt_url"].is_string(),
        "a farm-hosted hub with no voice endpoint is the public-URL bug \
         returning: {info}"
    );

    // Reachable by pubkey too — the address of last resort.
    let by_key = client
        .get(format!("{farm_url}/hub/{recorded}/info"))
        .send()
        .await
        .unwrap();
    assert!(
        by_key.status().is_success(),
        "the pubkey address must work too"
    );

    // 8. And the WebSocket, through the proxy's socket bridge to the real hub.
    //
    // This is the one part of a farm-hosted hub a client cannot reach over the
    // ordinary buffered path: an Upgrade needs the raw connection handed over.
    // The client builds its socket URL as `${hub_url}/ws`, so behind a farm
    // that is `/hub/<slug>/ws` — a path-prefixed upgrade, bridged to another
    // process, on a hub authenticating with a farm-issued token. Every one of
    // those is new here, and none is exercised by the farm's own bridge test
    // (a stub hub) or by the hub's WS tests (no farm).
    let ws_url = format!(
        "{}/hub/mangiadapippo/ws?token={}",
        farm_url.replace("http://", "ws://"),
        token,
    );
    let (mut socket, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("the client's WebSocket must reach the hub through the farm");

    // The hub greets an accepted socket. Any frame proves the bridge carried
    // real traffic from the hub process, rather than the handshake merely
    // completing against the proxy.
    let greeting = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .expect("timed out waiting for the hub's first frame")
        .expect("the socket closed instead of speaking");
    assert!(
        greeting.is_ok(),
        "expected a frame from the hub, got {greeting:?}"
    );

    let _ = socket.close(None).await;
    let _ = state.hub_manager.stop_hub(&hub_id).await;
}

/// The same path with `hub_isolation = 'schema'`: one database, a schema per
/// hub, selected by `search_path` on the connection.
///
/// This mode exists because a managed PostgreSQL plan routinely grants one
/// database and no `CREATEDB` — without it the farm cannot create a single hub
/// in an entire class of hosting. And it had never been *run*: the unit tests
/// cover building the URL, nothing had started a hub behind one.
///
/// The failure it guards against is silent in the worst way. If the hub's
/// driver ignored the `options` parameter, every hub would migrate into
/// `public` and share it again — the exact bug per-hub isolation replaced,
/// wearing the appearance of a fix.
#[tokio::test]
async fn a_schema_isolated_hub_gets_its_own_schema_and_not_public() {
    let Some(hub_bin) = hub_binary() else {
        assert!(
            std::env::var("WAVVON_REQUIRE_E2E").is_err(),
            "wavvon-hub is not built, and WAVVON_REQUIRE_E2E is set"
        );
        eprintln!("WAVVON-TEST-SKIPPED: farm_hub_e2e schema — wavvon-hub not built");
        return;
    };

    let (farm_url, state, _guard) = start_farm(hub_bin, 9900, 10900).await;
    sqlx::query("UPDATE farms SET hub_isolation = 'schema' WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    let token = token_for(&state, &"22".repeat(32), &farm_url);
    let created: serde_json::Value = Client::new()
        .post(format!("{farm_url}/farm/hubs"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Schema Hub" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hub_id = created["id"].as_str().expect("hub id").to_string();

    let db_url: String = sqlx::query_scalar("SELECT db_url FROM hubs WHERE id = $1")
        .bind(&hub_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(
        db_url.contains("search_path") || db_url.contains("options"),
        "a schema-isolated hub's URL must carry its search_path, got {db_url}"
    );

    // The hub boots and claims its serial — which means it connected, ran its
    // migrations and heartbeated, all inside its own schema.
    let pool = state.db.clone();
    let id = hub_id.clone();
    wait_for(
        "the schema-isolated hub to start",
        Duration::from_secs(45),
        || {
            let pool = pool.clone();
            let id = id.clone();
            async move {
                sqlx::query_scalar::<_, Option<String>>("SELECT hub_pubkey FROM hubs WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            }
        },
    )
    .await;

    // And the tables landed in the hub's schema, not in the farm's `public`.
    // This is the assertion that would have caught a driver quietly dropping
    // `options`: the hub would have looked perfectly healthy while writing
    // into the shared namespace.
    let schema = format!("hub_{hub_id}");
    let in_schema: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_tables WHERE schemaname = $1 AND tablename = 'channels'",
    )
    .bind(&schema)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(in_schema, 1, "the hub's tables must be in {schema}");

    let in_public: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public' AND tablename = 'channels'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        in_public, 0,
        "nothing may land in public — that is the shared namespace this mode avoids"
    );

    let _ = state.hub_manager.stop_hub(&hub_id).await;
}

/// The same path with `hub_db_role = 'per_hub'`: the hub connects as a role of
/// its own rather than as the farm.
///
/// A database each and a schema each stop hubs colliding; neither stops one
/// hub reading another, because they all connect as the farm's role. This is
/// the mode that contains it — and the thing that has to be *run* rather than
/// unit-tested is whether a hub can still do its job under the narrower
/// grants. A hub that cannot run its own migrations is not isolated, it is
/// broken, and that failure only shows up with a real binary against a real
/// server.
#[tokio::test]
async fn a_hub_with_its_own_role_still_boots_and_migrates() {
    let Some(hub_bin) = hub_binary() else {
        assert!(
            std::env::var("WAVVON_REQUIRE_E2E").is_err(),
            "wavvon-hub is not built, and WAVVON_REQUIRE_E2E is set"
        );
        eprintln!("WAVVON-TEST-SKIPPED: farm_hub_e2e per_hub — wavvon-hub not built");
        return;
    };

    let (farm_url, state, _guard) = start_farm(hub_bin, 9950, 10950).await;
    sqlx::query("UPDATE farms SET hub_db_role = 'per_hub' WHERE id = 1")
        .execute(&state.db)
        .await
        .unwrap();

    let token = token_for(&state, &"33".repeat(32), &farm_url);
    let created: serde_json::Value = Client::new()
        .post(format!("{farm_url}/farm/hubs"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Own Role Hub" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hub_id = created["id"].as_str().expect("hub id").to_string();

    let db_url: String = sqlx::query_scalar("SELECT db_url FROM hubs WHERE id = $1")
        .bind(&hub_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    let role = format!("wavvon_hub_{hub_id}");
    assert!(
        db_url.contains(&role),
        "the hub must be handed credentials of its own, got {db_url}"
    );

    // Claiming its serial means it connected, migrated and heartbeated — all
    // as a role that owns nothing but its own database.
    let pool = state.db.clone();
    let id = hub_id.clone();
    wait_for(
        "the hub with its own role to start",
        Duration::from_secs(45),
        || {
            let pool = pool.clone();
            let id = id.clone();
            async move {
                sqlx::query_scalar::<_, Option<String>>("SELECT hub_pubkey FROM hubs WHERE id = $1")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
            }
        },
    )
    .await;

    let _ = state.hub_manager.stop_hub(&hub_id).await;

    // Roles are server-wide, so the suite's database teardown never reaches
    // them.
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{role}\""))
        .execute(&state.db)
        .await;
}
