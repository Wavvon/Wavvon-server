/// Integration tests for first-run bootstrap (HW2).
///
/// These tests exercise `wavvon_hub::bootstrap::maybe_bootstrap` against a
/// real (ephemeral) PostgreSQL database spun up via `common::create_test_db()`.
/// They do not start an HTTP server; they call the bootstrap function directly.
use serde_json::json;

#[path = "common.rs"]
mod common;

use wavvon_hub::bootstrap::{maybe_bootstrap, BootstrapConfig};

fn no_config() -> BootstrapConfig {
    BootstrapConfig {
        template_url: None,
        bootstrap_token: None,
        discovery_url: "https://discovery.wavvon.io".into(),
    }
}

fn config_with_template(template_url: &str) -> BootstrapConfig {
    BootstrapConfig {
        template_url: Some(template_url.into()),
        bootstrap_token: None,
        discovery_url: "https://discovery.wavvon.io".into(),
    }
}

// ── Test 1: bootstrapped_at marker prevents re-run ───────────────────────────

#[tokio::test]
async fn bootstrap_skipped_when_marker_already_set() {
    let db = common::create_test_db().await;

    // Simulate a previously bootstrapped hub.
    sqlx::query("UPDATE hub_settings SET value = '1000000' WHERE key = 'bootstrapped_at'")
        .execute(&db)
        .await
        .unwrap();

    let http = reqwest::Client::new();
    let cfg = config_with_template("https://unreachable.invalid/template.json");
    // Must succeed even though the URL is unreachable — marker short-circuits.
    maybe_bootstrap(&db, &http, &cfg).await.unwrap();

    let ch_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        ch_count, 0,
        "No channels should be created; hub was already bootstrapped"
    );
}

// ── Test 2: non-empty channels table is a no-op ───────────────────────────────

#[tokio::test]
async fn bootstrap_skipped_when_channels_exist() {
    let db = common::create_test_db().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // channels.created_by has a FK to users.public_key.
    sqlx::query(
        "INSERT INTO users(public_key, first_seen_at, last_seen_at)
         VALUES('system', $1, $1) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(now)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO channels(id, name, created_by, is_category, display_order, created_at)
         VALUES('existing-ch', 'general', 'system', false, 0, $1)",
    )
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    let http = reqwest::Client::new();
    maybe_bootstrap(
        &db,
        &http,
        &config_with_template("https://unreachable.invalid/t"),
    )
    .await
    .unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "Only the pre-existing channel; no bootstrap should have run"
    );
}

// ── Test 3: no config set is a no-op ─────────────────────────────────────────

#[tokio::test]
async fn bootstrap_noop_when_no_config() {
    let db = common::create_test_db().await;
    let http = reqwest::Client::new();
    maybe_bootstrap(&db, &http, &no_config()).await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 0);

    // Marker should still be empty (no bootstrap happened).
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
    )
    .fetch_optional(&db)
    .await
    .unwrap();
    assert!(
        marker.is_none(),
        "bootstrapped_at should remain empty when nothing ran"
    );
}

// ── Test 4: template JSON is fully applied ────────────────────────────────────

#[tokio::test]
async fn template_applies_channels_roles_settings_and_welcome_message() {
    let db = common::create_test_db().await;

    // Inject the template directly via apply_template (bypasses HTTP).
    let template = json!({
        "name": "Test Community",
        "settings": {
            "invite_only": "true",
            "min_security_level": "2"
        },
        "channels": [
            {"name": "Community", "is_category": true,  "display_order": 0},
            {"name": "general",   "is_category": false, "display_order": 1,
             "channel_type": "text", "category": "Community"},
            {"name": "voice",     "is_category": false, "display_order": 2,
             "channel_type": "voice", "category": "Community"}
        ],
        "roles": [
            {
                "name": "Member",
                "priority": 5,
                "permissions": ["send_messages", "read_messages", "create_posts"]
            }
        ],
        "welcome_message": "Hello and welcome!",
        "suggested_bots": ["modbot", "pollbot"]
    });

    // Call the private fn via the internal test helper exposed through #[cfg(test)].
    // Since apply_template is private, we drive it through maybe_bootstrap with
    // an in-process mock: we write the template to hub_settings as a placeholder
    // and call apply_template directly using cfg(test) re-export.
    //
    // Simpler approach: use the public apply path by writing a tiny mock HTTP server.
    // But since this is an integration suite without a network dependency, we use
    // the crate-private path via a re-export for test only.
    //
    // Alternatively, we expose apply_template as pub(crate) and call it here.
    // For now call the crate-internal function via the test module defined inside
    // bootstrap.rs which re-exports apply_template.  Because we can't easily call
    // a private fn from outside the crate, we use a mock HTTP server from
    // the `axum` test utilities to serve the template.

    use axum::{routing::get, Router};

    let template_clone = template.clone();
    let app = Router::new().route(
        "/template.json",
        get(move || {
            let t = template_clone.clone();
            async move { axum::Json(t) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://127.0.0.1:{port}/template.json");

    let http = reqwest::Client::new();
    let cfg = config_with_template(&url);
    maybe_bootstrap(&db, &http, &cfg).await.unwrap();

    // Channels
    let ch_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category = false")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(ch_count, 2, "2 non-category channels expected");

    let cat_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category = true")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(cat_count, 1, "1 category expected");

    let parent: Option<String> =
        sqlx::query_scalar("SELECT parent_id FROM channels WHERE name = 'general'")
            .fetch_optional(&db)
            .await
            .unwrap();
    assert!(
        parent.is_some(),
        "general should have parent_id set to Community category"
    );

    // Roles
    let role: Option<String> = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'Member'")
        .fetch_optional(&db)
        .await
        .unwrap();
    assert!(role.is_some(), "Member role should exist");

    let perm_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions rp
         JOIN roles r ON rp.role_id = r.id WHERE r.name = 'Member'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(perm_count, 3, "Member should have 3 permissions");

    // Settings
    let invite_only: String =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'invite_only'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(invite_only, "true");

    let min_sec: String =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'min_security_level'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(min_sec, "2");

    // Welcome message
    let msg: Option<String> = sqlx::query_scalar("SELECT content FROM messages LIMIT 1")
        .fetch_optional(&db)
        .await
        .unwrap();
    assert_eq!(msg.as_deref(), Some("Hello and welcome!"));

    // suggested_bots
    let bots: Option<String> =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'suggested_bots'")
            .fetch_optional(&db)
            .await
            .unwrap();
    assert!(bots.is_some(), "suggested_bots entry should be recorded");

    // bootstrapped_at marker written
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
    )
    .fetch_optional(&db)
    .await
    .unwrap();
    assert!(
        marker.is_some(),
        "bootstrapped_at should be set after successful bootstrap"
    );
}
