//! Hub slugs: owner-chosen addresses that resolve alongside the pubkey.
//!
//! The unit tests in `slug.rs` pin the naming rules. These pin the behaviour
//! an owner actually meets: claiming, the quota, releasing, the cooling-off
//! window, and — the property the whole design rests on — that a slug is an
//! alias and the pubkey keeps working regardless.

#[path = "common.rs"]
mod common;

use std::sync::Arc;

use axum_test::TestServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use wavvon_farm::token::{sign_token, FarmTokenPayload};
use wavvon_farm::{db, hub_manager::HubManager, server, state::FarmState, unix_now};

/// Mint a member token for `pubkey`, the way `/auth/verify` would.
fn token_for(state: &FarmState, pubkey: &str) -> String {
    let now = unix_now();
    sign_token(
        &state.keypair,
        &FarmTokenPayload {
            v: 1,
            iss: FARM_URL.to_string(),
            iss_pk: state.public_key_hex(),
            sub: pubkey.to_string(),
            master: None,
            jti: "test-jti".to_string(),
            iat: now,
            exp: now + 3600,
            scope: "member".to_string(),
        },
    )
}

const FARM_URL: &str = "https://farm.test";

struct Harness {
    server: TestServer,
    state: Arc<FarmState>,
    owner_token: String,
    owner_pubkey: String,
    _guard: common::TestDbGuard,
}

async fn setup() -> Harness {
    let (db_pool, guard) = common::create_test_db().await;
    db::migrations::run(&db_pool).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    sqlx::query("INSERT INTO farms (id, public_key, created_at) VALUES (1, $1, $2)")
        .bind(&farm_pubkey)
        .bind(unix_now())
        .execute(&db_pool)
        .await
        .unwrap();

    let hub_manager = Arc::new(HubManager::new(
        "wavvon-hub".to_string(),
        FARM_URL.to_string(),
        9600,
        10600,
        // Creating a hub provisions it a database on this server.
        common::base_db_url(),
        // Per-hub working directory root: hubs must not share an identity file.
        std::env::temp_dir()
            .join("wavvon-test-hubs")
            .to_string_lossy()
            .to_string(),
    ));
    let state = Arc::new(FarmState::new(
        db_pool,
        keypair,
        FARM_URL.to_string(),
        hub_manager,
    ));

    let owner_pubkey = "1".repeat(64);
    let owner_token = token_for(&state, &owner_pubkey);

    let app = server::create_router(state.clone());
    Harness {
        server: TestServer::new(app),
        state,
        owner_token,
        owner_pubkey,
        _guard: guard,
    }
}

async fn insert_hub(h: &Harness, id: &str, pubkey: Option<&str>) {
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, created_at,
                           hub_pubkey, process_port)
         VALUES ($1, $2, 'Osteria di Pippo', 'private', $3, $4, 4000)",
    )
    .bind(id)
    .bind(&h.owner_pubkey)
    .bind(unix_now())
    .bind(pubkey)
    .execute(&h.state.db)
    .await
    .unwrap();
}

async fn claim(h: &Harness, hub: &str, slug: &str) -> axum_test::TestResponse {
    h.server
        .post(&format!("/farm/hubs/{hub}/slugs"))
        .authorization_bearer(&h.owner_token)
        .json(&json!({ "slug": slug }))
        .await
}

async fn set_cooloff(h: &Harness, days: i64) {
    sqlx::query("UPDATE farms SET slug_cooloff_days = $1 WHERE id = 1")
        .bind(days)
        .execute(&h.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_claimed_slug_is_stored_lowercase_and_becomes_canonical() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;

    let res = claim(&h, "hub-1", "MangiaDaPippo").await;
    assert_eq!(res.status_code(), 201);

    let body: serde_json::Value = res.json();
    assert_eq!(
        body["slug"], "mangiadapippo",
        "matching is case-insensitive"
    );
    assert_eq!(body["display_slug"], "MangiaDaPippo", "shown as typed");
    assert_eq!(
        body["is_canonical"], true,
        "the first slug must be canonical, or the hub advertises nothing"
    );
}

/// The impersonation the lowercase key prevents: a second owner taking the
/// capitalisation variant of a popular hub's address.
#[tokio::test]
async fn a_case_variant_is_the_same_slug_and_cannot_be_taken_twice() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;
    insert_hub(&h, "hub-2", None).await;

    assert_eq!(claim(&h, "hub-1", "MangiaDaPippo").await.status_code(), 201);
    let res = claim(&h, "hub-2", "mangiadapippo").await;
    assert_eq!(res.status_code(), 409);
    assert_eq!(res.json::<serde_json::Value>()["error"], "slug_taken");
}

#[tokio::test]
async fn a_name_shaped_like_a_pubkey_is_refused() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;

    // Two addresses that resolve differently must never be the same string.
    let res = claim(&h, "hub-1", &"a".repeat(64)).await;
    assert_eq!(res.status_code(), 400);
    assert_eq!(res.json::<serde_json::Value>()["error"], "invalid_slug");
}

#[tokio::test]
async fn the_quota_is_enforced_and_says_what_to_do() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;
    sqlx::query("UPDATE farms SET max_slugs_per_hub = 2 WHERE id = 1")
        .execute(&h.state.db)
        .await
        .unwrap();

    assert_eq!(claim(&h, "hub-1", "primo").await.status_code(), 201);
    assert_eq!(claim(&h, "hub-1", "secondo").await.status_code(), 201);

    let res = claim(&h, "hub-1", "terzo").await;
    assert_eq!(res.status_code(), 409);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "slug_quota_reached");
    assert!(
        body["details"].as_str().unwrap().contains("release one"),
        "the error has to tell the owner the way out, got: {}",
        body["details"]
    );
}

/// Releasing frees a quota slot without deleting the row — the row is what
/// enforces the cooling-off window afterwards.
#[tokio::test]
async fn releasing_frees_a_slot_and_promotes_the_next_slug() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;
    claim(&h, "hub-1", "primo").await;
    claim(&h, "hub-1", "secondo").await;

    let res = h
        .server
        .delete("/farm/hubs/hub-1/slugs/primo")
        .authorization_bearer(&h.owner_token)
        .await;
    assert_eq!(res.status_code(), 204);

    let listed: serde_json::Value = h
        .server
        .get("/farm/hubs/hub-1/slugs")
        .authorization_bearer(&h.owner_token)
        .await
        .json();
    assert_eq!(listed["used"], 1, "the released slug frees its slot");

    let secondo = listed["slugs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["slug"] == "secondo")
        .expect("secondo still listed");
    assert_eq!(
        secondo["is_canonical"], true,
        "releasing the canonical one must promote another, never leave none"
    );
}

/// Anyone else must wait; the hub that let it go may take it back at once.
#[tokio::test]
async fn a_released_slug_is_reserved_for_its_previous_holder() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;
    insert_hub(&h, "hub-2", None).await;
    set_cooloff(&h, 60).await;

    claim(&h, "hub-1", "pippo").await;
    h.server
        .delete("/farm/hubs/hub-1/slugs/pippo")
        .authorization_bearer(&h.owner_token)
        .await;

    let stolen = claim(&h, "hub-2", "pippo").await;
    assert_eq!(stolen.status_code(), 409);
    assert_eq!(
        stolen.json::<serde_json::Value>()["error"],
        "slug_reserved",
        "releasing a name is exactly when inheriting its links is worth most"
    );

    assert_eq!(
        claim(&h, "hub-1", "pippo").await.status_code(),
        201,
        "the hub that released it can always change its mind"
    );
}

/// The names do come back — that was the whole point of not tombstoning them.
#[tokio::test]
async fn after_the_cooling_off_period_a_slug_returns_to_the_pool() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;
    insert_hub(&h, "hub-2", None).await;
    set_cooloff(&h, 0).await;

    claim(&h, "hub-1", "pippo").await;
    h.server
        .delete("/farm/hubs/hub-1/slugs/pippo")
        .authorization_bearer(&h.owner_token)
        .await;

    assert_eq!(claim(&h, "hub-2", "pippo").await.status_code(), 201);
}

#[tokio::test]
async fn only_the_hub_owner_may_manage_its_slugs() {
    let h = setup().await;
    insert_hub(&h, "hub-1", None).await;

    let stranger = token_for(&h.state, &"9".repeat(64));
    let res = h
        .server
        .post("/farm/hubs/hub-1/slugs")
        .authorization_bearer(&stranger)
        .json(&json!({ "slug": "pippo" }))
        .await;
    assert_eq!(res.status_code(), 403);
}

/// The heartbeat reply is how a running hub learns it has been renamed —
/// an env var set at spawn could never carry a later change.
#[tokio::test]
async fn the_heartbeat_reports_the_canonical_url_and_follows_a_rename() {
    let h = setup().await;
    let pubkey = "cc".repeat(32);
    insert_hub(&h, "hub-1", Some(&pubkey)).await;

    let beat = || async {
        h.server
            .post("/farm/heartbeat")
            .json(&json!({ "hub_id": "hub-1", "hub_pubkey": pubkey }))
            .await
            .json::<serde_json::Value>()
    };

    // No slug yet: the pubkey form, which always resolves.
    assert_eq!(
        beat().await["canonical_url"],
        format!("{FARM_URL}/hub/{pubkey}")
    );

    claim(&h, "hub-1", "MangiaDaPippo").await;
    assert_eq!(
        beat().await["canonical_url"],
        format!("{FARM_URL}/hub/mangiadapippo"),
        "a hub must learn its new address without being restarted"
    );

    claim(&h, "hub-1", "OsteriaPippo").await;
    h.server
        .put("/farm/hubs/hub-1/slugs/osteriapippo/canonical")
        .authorization_bearer(&h.owner_token)
        .await;
    assert_eq!(
        beat().await["canonical_url"],
        format!("{FARM_URL}/hub/osteriapippo")
    );
}

// ---------------------------------------------------------------------------
// Placement — capacity per server (placement.rs)
// ---------------------------------------------------------------------------

/// The operator's own example, end to end through the API: a server capped at
/// N stops taking hubs once it holds N. The unit tests cover the choice; this
/// covers that the choice is actually wired into hub creation.
#[tokio::test]
async fn a_full_farm_refuses_a_new_hub_instead_of_overflowing() {
    let h = setup().await;
    sqlx::query("UPDATE farms SET max_local_hubs = 1, creation_policy = 'open' WHERE id = 1")
        .execute(&h.state.db)
        .await
        .unwrap();

    let first = h
        .server
        .post("/farm/hubs")
        .authorization_bearer(&h.owner_token)
        .json(&json!({ "name": "Primo" }))
        .await;
    assert_eq!(first.status_code(), 201);

    let second = h
        .server
        .post("/farm/hubs")
        .authorization_bearer(&h.owner_token)
        .json(&json!({ "name": "Secondo" }))
        .await;
    assert_eq!(second.status_code(), 409);
    let body: serde_json::Value = second.json();
    assert_eq!(body["error"], "no_capacity");
    assert!(
        body["details"].as_str().unwrap().contains("raise one"),
        "the refusal must say what to do, got: {}",
        body["details"]
    );
}

/// Naming a server that is not a connected agent is refused rather than
/// quietly placed somewhere else.
#[tokio::test]
async fn naming_an_unknown_server_is_refused() {
    let h = setup().await;
    sqlx::query("UPDATE farms SET creation_policy = 'open' WHERE id = 1")
        .execute(&h.state.db)
        .await
        .unwrap();

    let res = h
        .server
        .post("/farm/hubs")
        .authorization_bearer(&h.owner_token)
        .json(&json!({ "name": "Terzo", "server_id": "no-such-server" }))
        .await;

    assert_eq!(res.status_code(), 409);
    assert_eq!(
        res.json::<serde_json::Value>()["error"],
        "unknown_server",
        "an operator who named a server must not silently get a different one"
    );
}

/// A refused placement must not leave a half-created hub behind.
#[tokio::test]
async fn a_refused_placement_leaves_no_hub_row() {
    let h = setup().await;
    sqlx::query("UPDATE farms SET max_local_hubs = 0, creation_policy = 'open' WHERE id = 1")
        .execute(&h.state.db)
        .await
        .unwrap();

    h.server
        .post("/farm/hubs")
        .authorization_bearer(&h.owner_token)
        .json(&json!({ "name": "Quarto", "server_id": "no-such-server" }))
        .await;

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE deleted_at IS NULL")
        .fetch_one(&h.state.db)
        .await
        .unwrap();
    assert_eq!(live, 0, "a refused creation must not leave a live hub row");
}

// ---------------------------------------------------------------------------
// Sibling wiring — the farm offers, the hub decides
// ---------------------------------------------------------------------------

/// The heartbeat reports a hub's siblings so it can subscribe to their ban
/// lists in soft-flag and trust their certifications — the anti-bot story
/// built from federation primitives, not a farm-level reputation store.
#[tokio::test]
async fn the_heartbeat_reports_sibling_hubs_by_their_current_address() {
    let h = setup().await;
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    insert_hub(&h, "hub-a", Some(&a)).await;
    insert_hub(&h, "hub-b", Some(&b)).await;
    claim(&h, "hub-b", "OsteriaPippo").await;

    let body: serde_json::Value = h
        .server
        .post("/farm/heartbeat")
        .json(&json!({ "hub_id": "hub-a", "hub_pubkey": a }))
        .await
        .json();

    let siblings = body["siblings"].as_array().expect("siblings array");
    assert_eq!(siblings.len(), 1, "a hub is not its own sibling");
    assert_eq!(siblings[0]["hub_pubkey"], b);
    assert_eq!(
        siblings[0]["hub_url"], "https://farm.test/hub/osteriapippo",
        "addressed by canonical slug, so the URL survives a rename"
    );
}

/// A suspended hub is not offered: wiring trust to a hub the farm has just
/// taken offline is the opposite of what an operator meant by suspending it.
#[tokio::test]
async fn suspended_and_unclaimed_hubs_are_not_offered_as_siblings() {
    let h = setup().await;
    let a = "aa".repeat(32);
    insert_hub(&h, "hub-a", Some(&a)).await;
    insert_hub(&h, "hub-b", Some(&"bb".repeat(32))).await;
    // Never claimed a serial: unverifiable as an issuer, so not offered.
    insert_hub(&h, "hub-c", None).await;

    sqlx::query("UPDATE hubs SET suspended_at = $1 WHERE id = 'hub-b'")
        .bind(unix_now())
        .execute(&h.state.db)
        .await
        .unwrap();

    let body: serde_json::Value = h
        .server
        .post("/farm/heartbeat")
        .json(&json!({ "hub_id": "hub-a", "hub_pubkey": a }))
        .await
        .json();

    assert!(
        body["siblings"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true),
        "got {}",
        body["siblings"]
    );
}
