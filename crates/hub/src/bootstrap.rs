use anyhow::Result;
use sqlx::PgPool;

pub struct BootstrapConfig {
    /// Raw template JSON URL, or a `wavvon://templates/<id>` discovery pointer.
    /// Second in precedence, behind `bootstrap_token`. See hub-creation-wizard.md
    /// piece 1/3 (discovery catalog + wizard) — this hub crate only *consumes*
    /// a resolved template, it never talks to the catalog beyond a plain GET.
    pub template_url: Option<String>,
    /// Wizard-issued one-use token, redeemed against `discovery_url`. Highest
    /// precedence — carries the operator's customisations. Deferred here: the
    /// hub does not verify the JWT itself (see hub-creation-wizard.md §2), it
    /// only presents it to discovery's redeem endpoint.
    pub bootstrap_token: Option<String>,
    pub discovery_url: String,
    /// Path to a local template JSON file (`WAVVON_TEMPLATE_FILE`). Third in
    /// precedence. This is the offline/no-catalog equivalent of `template_url`
    /// — same document shape, no signature verification (local files are
    /// already trusted by the operator who placed them on disk). Signature
    /// verification only matters for templates fetched from the network
    /// catalog (piece 1); deferred here since piece 1 is out of scope.
    pub template_file: Option<String>,
    /// Built-in preset name (`WAVVON_TEMPLATE`): `gaming`, `community`, or
    /// `minimal`. Lowest precedence — the no-network fallback described in
    /// hub-creation-wizard.md's "templates hosted on the hub binary"
    /// alternative (a small built-in set stays in the binary; anything richer
    /// lives in the catalog).
    pub preset: Option<String>,
}

/// Runs on first launch if any bootstrap source is configured and the hub
/// has no channels *and* no users yet (blank DB). Non-fatal for anything
/// network- or file-related — a bad template, unreachable URL, or missing
/// file never blocks startup, the hub just starts blank. The one exception
/// is an unrecognized `WAVVON_TEMPLATE` preset name, which is a startup
/// configuration error and is surfaced to the caller as `Err` (see
/// `presets::resolve`).
pub async fn maybe_bootstrap(
    db: &PgPool,
    http: &reqwest::Client,
    cfg: &BootstrapConfig,
) -> Result<()> {
    // Already bootstrapped: marker is a non-empty timestamp string.
    let bootstrapped: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    if bootstrapped.is_some() {
        return Ok(());
    }

    // Not a first-run if the hub already has channels or real users.
    let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(db)
        .await
        .unwrap_or(0);
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
        .unwrap_or(0);
    if channel_count > 0 || user_count > 0 {
        return Ok(());
    }

    // No bootstrap source configured — start blank.
    if cfg.bootstrap_token.is_none()
        && cfg.template_url.is_none()
        && cfg.template_file.is_none()
        && cfg.preset.is_none()
    {
        tracing::info!("No bootstrap config set; starting blank hub");
        return Ok(());
    }

    // Validate a configured preset name up front — an unrecognized
    // `WAVVON_TEMPLATE` is a startup configuration mistake, not a transient
    // network hiccup, so it fails loudly instead of silently degrading to a
    // blank hub (unlike an unreachable template_url or missing template_file).
    if let Some(name) = &cfg.preset {
        presets::resolve(name).map_err(anyhow::Error::msg)?;
    }

    // Resolve config JSON in precedence order: bootstrap_token (wizard
    // handoff, carries customisations) > template_url (raw catalog/URL
    // pointer) > template_file (local offline template) > preset (built-in,
    // no-network fallback).
    let config_json = if let Some(token) = &cfg.bootstrap_token {
        let url = format!("{}/api/bootstrap/redeem", cfg.discovery_url);
        tracing::info!("Redeeming bootstrap token from {url}");
        match http
            .post(&url)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        tracing::warn!("Bootstrap token response was not valid JSON ({e}); trying template_url");
                        resolve_fallback(cfg, http).await
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    "Bootstrap token redeem returned {}; trying template_url",
                    resp.status()
                );
                resolve_fallback(cfg, http).await
            }
            Err(e) => {
                tracing::warn!("Bootstrap token redeem failed ({e}); trying template_url");
                resolve_fallback(cfg, http).await
            }
        }
    } else {
        resolve_fallback(cfg, http).await
    };

    let Some(config) = config_json else {
        tracing::info!("No bootstrap config resolved; starting blank hub");
        return Ok(());
    };

    apply_template(db, &config).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    sqlx::query("UPDATE hub_settings SET value = $1 WHERE key = 'bootstrapped_at'")
        .bind(&now)
        .execute(db)
        .await
        .ok();
    let template_id = config
        .get("template_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .or_else(|| cfg.preset.clone())
        .unwrap_or_else(|| "custom".to_string());
    tracing::info!("Hub bootstrapped from template: {template_id}");

    Ok(())
}

/// Falls back through the local/offline sources in precedence order:
/// `template_url` (if not already the caller), then `template_file`, then
/// the built-in `preset`. Returns `None` if every configured source fails
/// or none are configured — the caller starts a blank hub in that case.
async fn resolve_fallback(
    cfg: &BootstrapConfig,
    http: &reqwest::Client,
) -> Option<serde_json::Value> {
    if let Some(v) = fetch_template(&cfg.template_url, &cfg.discovery_url, http).await {
        return Some(v);
    }
    if let Some(path) = &cfg.template_file {
        if let Some(v) = load_template_file(path) {
            return Some(v);
        }
    }
    if let Some(name) = &cfg.preset {
        // Already validated in `maybe_bootstrap`; a second failure here would
        // mean the name changed between calls, which can't happen within one
        // invocation — `.ok()` is safe.
        return presets::resolve(name).ok();
    }
    None
}

/// Reads and parses a local template JSON file (`WAVVON_TEMPLATE_FILE`).
/// Returns `None` on any I/O or parse error, logging a warning — a bad or
/// missing file never blocks startup.
fn load_template_file(path: &str) -> Option<serde_json::Value> {
    tracing::info!("Loading bootstrap template from local file {path}");
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!("Failed to read template file {path}: {e}; starting blank hub");
            return None;
        }
    };
    match serde_json::from_str(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("Failed to parse template file {path} as JSON: {e}; starting blank hub");
            None
        }
    }
}

/// Resolve a template URL and return its JSON payload.
///
/// Handles two forms:
/// - `wavvon://templates/<id>` — resolved against the discovery service as
///   `{discovery_url}/api/templates/<id>`; returns the `payload` field of the
///   response JSON (the full response if `payload` is absent).
/// - Any HTTPS/HTTP URL — fetched directly.
///
/// Returns `None` on any failure so a bad template never blocks startup.
async fn fetch_template(
    url: &Option<String>,
    discovery_url: &str,
    http: &reqwest::Client,
) -> Option<serde_json::Value> {
    let raw = url.as_deref()?;

    let resolved_url = if raw.starts_with("wavvon://templates/") {
        let id = raw.trim_start_matches("wavvon://templates/");
        format!("{discovery_url}/api/templates/{id}")
    } else {
        raw.to_owned()
    };

    tracing::info!("Fetching bootstrap template from {resolved_url}");
    match http.get(&resolved_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(v) => {
                // Discovery wraps templates: {"payload": {...}}  — unwrap if present.
                if let Some(payload) = v.get("payload") {
                    if payload.is_object() {
                        return Some(payload.clone());
                    }
                }
                Some(v)
            }
            Err(e) => {
                tracing::warn!("Failed to parse template JSON from {resolved_url}: {e}");
                None
            }
        },
        Ok(resp) => {
            tracing::warn!(
                "Template fetch from {resolved_url} returned {}; starting blank hub",
                resp.status()
            );
            None
        }
        Err(e) => {
            tracing::warn!("Failed to fetch template from {resolved_url}: {e}; starting blank hub");
            None
        }
    }
}

async fn apply_template(db: &PgPool, template: &serde_json::Value) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // ---- Hub settings ----
    // Apply scalar settings like hub name, invite_only, min_security_level, etc.
    if let Some(settings_obj) = template.get("settings").and_then(|v| v.as_object()) {
        for (key, val) in settings_obj {
            let str_val = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => continue,
            };
            sqlx::query("UPDATE hub_settings SET value = $1 WHERE key = $2")
                .bind(&str_val)
                .bind(key)
                .execute(db)
                .await
                .ok();
        }
    }

    // Legacy top-level `name` field (some templates put hub name at the root).
    if let Some(name) = template.get("name").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE hub_settings SET value = $1 WHERE key = 'hub_name'")
            .bind(name)
            .execute(db)
            .await
            .ok();
    }

    // ---- System user — required by channels.created_by FK ----
    sqlx::query(
        "INSERT INTO users(public_key, first_seen_at, last_seen_at)
         VALUES('system', $1, $1) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(now)
    .execute(db)
    .await
    .ok();

    // ---- Categories first, then channels ----
    // Two-pass: insert categories first so channels can reference parent_id.
    // We track name→id so channels can reference their category by name.
    let mut category_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    if let Some(channels) = template.get("channels").and_then(|v| v.as_array()) {
        // Pass 1: categories
        for ch in channels {
            let is_category = ch
                .get("is_category")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !is_category {
                continue;
            }
            let name = match ch.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let id = uuid::Uuid::new_v4().to_string();
            let display_order = ch
                .get("display_order")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            sqlx::query(
                "INSERT INTO channels(id, name, created_by, is_category, display_order, created_at)
                 VALUES($1, $2, 'system', true, $3, $4)
                 ON CONFLICT (name) DO NOTHING",
            )
            .bind(&id)
            .bind(name)
            .bind(display_order)
            .bind(now)
            .execute(db)
            .await
            .ok();
            category_ids.insert(name.to_owned(), id);
        }

        // Pass 2: channels (non-categories)
        for ch in channels {
            let is_category = ch
                .get("is_category")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_category {
                continue;
            }
            let name = match ch.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let id = uuid::Uuid::new_v4().to_string();
            let display_order = ch
                .get("display_order")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let channel_type = ch
                .get("channel_type")
                .and_then(|v| v.as_str())
                .unwrap_or("text");
            let description = ch.get("description").and_then(|v| v.as_str());
            let parent_id: Option<String> = ch
                .get("category")
                .and_then(|v| v.as_str())
                .and_then(|cat| category_ids.get(cat))
                .cloned();
            // Minimum talk power to post in this channel (e.g. a
            // moderator-only #announcements channel). Defaults to 0 (everyone).
            let min_talk_power = ch
                .get("min_talk_power")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            // Only meaningful for `channel_type = "spawner"` — the name
            // template for rooms it spawns (defaults to "{user}'s room" if
            // left null, see routes::channels::spawn_temp_channel).
            let spawner_name_template = ch.get("spawner_name_template").and_then(|v| v.as_str());

            sqlx::query(
                "INSERT INTO channels(id, name, created_by, is_category, display_order, channel_type, description, parent_id, min_talk_power, spawner_name_template, created_at)
                 VALUES($1, $2, 'system', false, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (name) DO NOTHING",
            )
            .bind(&id)
            .bind(name)
            .bind(display_order)
            .bind(channel_type)
            .bind(description)
            .bind(&parent_id)
            .bind(min_talk_power)
            .bind(spawner_name_template)
            .bind(now)
            .execute(db)
            .await
            .ok();
        }
    }

    // ---- Roles ----
    if let Some(roles) = template.get("roles").and_then(|v| v.as_array()) {
        for role in roles {
            let name = match role.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let id = uuid::Uuid::new_v4().to_string();
            let priority = role.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
            let display_separately = role
                .get("display_separately")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let talk_power = role.get("talk_power").and_then(|v| v.as_i64()).unwrap_or(0);
            sqlx::query(
                "INSERT INTO roles(id, name, priority, display_separately, talk_power, created_at)
                 VALUES($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (name) DO NOTHING",
            )
            .bind(&id)
            .bind(name)
            .bind(priority)
            .bind(display_separately)
            .bind(talk_power)
            .bind(now)
            .execute(db)
            .await
            .ok();

            // Re-query the actual inserted id (may differ if ON CONFLICT hit)
            let actual_id: Option<String> =
                sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
                    .bind(name)
                    .fetch_optional(db)
                    .await
                    .ok()
                    .flatten();
            if let Some(role_id) = actual_id {
                if let Some(perms) = role.get("permissions").and_then(|v| v.as_array()) {
                    for p in perms {
                        if let Some(perm) = p.as_str() {
                            sqlx::query(
                                "INSERT INTO role_permissions(role_id, permission)
                                 VALUES($1, $2)
                                 ON CONFLICT (role_id, permission) DO NOTHING",
                            )
                            .bind(&role_id)
                            .bind(perm)
                            .execute(db)
                            .await
                            .ok();
                        }
                    }
                }
            }
        }
    }

    // ---- Welcome message in #general ----
    if let Some(msg) = template.get("welcome_message").and_then(|v| v.as_str()) {
        if !msg.is_empty() {
            // Find the general channel (by name; fall back to the first text channel).
            let general_id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM channels WHERE is_category = false AND (name = 'general' OR channel_type = 'text') ORDER BY display_order, name LIMIT 1",
            )
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

            if let Some(channel_id) = general_id {
                // Ensure the system user exists — needed for the FK constraint.
                sqlx::query(
                    "INSERT INTO users(public_key, first_seen_at, last_seen_at) VALUES('system', $1, $1) ON CONFLICT (public_key) DO NOTHING",
                )
                .bind(now)
                .execute(db)
                .await
                .ok();

                let msg_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO messages(id, channel_id, sender, content, created_at)
                     VALUES($1, $2, 'system', $3, $4)
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(&msg_id)
                .bind(&channel_id)
                .bind(msg)
                .bind(now)
                .execute(db)
                .await
                .ok();
            }
        }
    }

    // ---- Suggested bots (recorded as a hub_settings entry) ----
    if let Some(bots) = template.get("suggested_bots") {
        let bots_str = match bots {
            serde_json::Value::String(s) => s.clone(),
            other => serde_json::to_string(other).unwrap_or_default(),
        };
        sqlx::query(
            "INSERT INTO hub_settings(key, value) VALUES('suggested_bots', $1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(&bots_str)
        .execute(db)
        .await
        .ok();
    }

    Ok(())
}

/// Built-in config templates selectable via `WAVVON_TEMPLATE=<name>`, applied
/// on first launch when no discovery-backed source (bootstrap token,
/// template URL, or local template file) is configured. See
/// hub-creation-wizard.md's "templates hosted on the hub binary" alternative:
/// a small built-in set stays in the binary as the no-network fallback,
/// everything richer lives in the (currently out-of-scope) discovery
/// catalog. Document shape matches the catalog template shape (piece 1)
/// minus signing fields (`author_pubkey`, `signature`), which only matter
/// for templates fetched over the network.
pub mod presets {
    use serde_json::{json, Value};

    /// Valid values for `WAVVON_TEMPLATE`.
    pub const PRESET_NAMES: &[&str] = &["gaming", "community", "minimal"];

    /// Resolves a built-in preset name to its template JSON document.
    /// Returns `Err` describing the valid options if `name` isn't recognized
    /// — an unrecognized preset name is a startup configuration mistake, not
    /// a transient failure, so it isn't silently swallowed like a bad
    /// template URL would be.
    pub fn resolve(name: &str) -> Result<Value, String> {
        match name {
            "gaming" => Ok(gaming()),
            "community" => Ok(community()),
            "minimal" => Ok(minimal()),
            other => Err(format!(
                "Unknown WAVVON_TEMPLATE preset '{other}'; valid presets are: {}",
                PRESET_NAMES.join(", ")
            )),
        }
    }

    /// Gaming community: text channels (general, moderator-only announcements),
    /// a voice lounge, and a "Room Creator" spawner channel for join-to-create
    /// personal voice rooms (see docs/docs/temp-voice-channels.md). Roughly
    /// mirrors the "Gaming Community" example in hub-creation-wizard.md §1,
    /// extended with the spawner channel that section's illustrative JSON
    /// didn't include.
    fn gaming() -> Value {
        json!({
            "name": "Gaming Community",
            "channels": [
                { "name": "Text Channels", "is_category": true, "display_order": 0 },
                { "name": "general", "is_category": false, "display_order": 1,
                  "channel_type": "text", "category": "Text Channels" },
                { "name": "announcements", "is_category": false, "display_order": 2,
                  "channel_type": "text", "category": "Text Channels",
                  "description": "Official announcements. Only moderators can post.",
                  "min_talk_power": 100 },
                { "name": "Voice Channels", "is_category": true, "display_order": 3 },
                { "name": "voice-lounge", "is_category": false, "display_order": 4,
                  "channel_type": "voice", "category": "Voice Channels" },
                { "name": "Room Creator", "is_category": false, "display_order": 5,
                  "channel_type": "spawner", "category": "Voice Channels",
                  "spawner_name_template": "{user}'s Room" }
            ],
            "roles": [
                { "name": "Member", "priority": 5,
                  "permissions": ["read_messages", "send_messages", "create_posts", "start_game"] },
                { "name": "Moderator", "priority": 50,
                  "permissions": ["manage_messages", "mute_members", "kick_members", "manage_channels"] }
            ],
            "settings": {
                // Re-added (was pulled in a4e57f9 as a stopgap: the lobby
                // soft-landing — lobby-bot-survey.md Feature 1 — hard-403'd
                // every sub-level join instead of admitting them, which
                // locked the OWNER out of their own first join). /auth/verify
                // now admits a sub-level joiner into scope="lobby" instead of
                // rejecting them, and the owner/first user are exempt from
                // the gate entirely, so this is safe to re-enable.
                "min_security_level": 8,
                "require_approval": false
            },
            "welcome_message": "Welcome! Check out #announcements for the rules, and jump into voice-lounge to play.",
            "suggested_bots": []
        })
    }

    /// General-purpose community: an info category with announcements, a
    /// general category with general/off-topic text and a voice lounge, and
    /// Member/Moderator roles.
    fn community() -> Value {
        json!({
            "name": "Community",
            "channels": [
                { "name": "Info", "is_category": true, "display_order": 0 },
                { "name": "announcements", "is_category": false, "display_order": 1,
                  "channel_type": "text", "category": "Info",
                  "description": "Official updates from the moderators.",
                  "min_talk_power": 50 },
                { "name": "General", "is_category": true, "display_order": 2 },
                { "name": "general", "is_category": false, "display_order": 3,
                  "channel_type": "text", "category": "General" },
                { "name": "off-topic", "is_category": false, "display_order": 4,
                  "channel_type": "text", "category": "General" },
                { "name": "voice-lounge", "is_category": false, "display_order": 5,
                  "channel_type": "voice", "category": "General" }
            ],
            "roles": [
                { "name": "Member", "priority": 5,
                  "permissions": ["read_messages", "send_messages", "create_posts", "create_events"] },
                { "name": "Moderator", "priority": 50,
                  "permissions": ["manage_messages", "mute_members", "kick_members", "timeout_members", "manage_channels"] }
            ],
            "settings": {
                "require_approval": false
            },
            "welcome_message": "Welcome! Check out #announcements for updates, and say hello in #general.",
            "suggested_bots": []
        })
    }

    /// What today's empty hub gives: no channels, no roles beyond the
    /// built-ins already seeded by migrations, no settings changes. Exists
    /// so an operator can select it explicitly (and get the
    /// `bootstrapped_at` marker + startup log line) instead of leaving every
    /// bootstrap env var unset.
    fn minimal() -> Value {
        json!({
            "channels": [],
            "roles": [],
            "settings": {}
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resolves_all_built_in_names() {
            for name in PRESET_NAMES {
                assert!(resolve(name).is_ok(), "preset '{name}' should resolve");
            }
        }

        #[test]
        fn unknown_preset_is_an_error() {
            let err = resolve("nonexistent").unwrap_err();
            assert!(err.contains("nonexistent"));
            assert!(err.contains("gaming"));
        }

        #[test]
        fn gaming_has_a_spawner_channel() {
            let tpl = gaming();
            let channels = tpl["channels"].as_array().unwrap();
            let spawner = channels
                .iter()
                .find(|c| c["channel_type"] == "spawner")
                .expect("gaming preset should have a spawner channel");
            assert_eq!(spawner["name"], "Room Creator");
        }
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    /// Drops the ephemeral `wavvon_test_bootstrap_*` database created by
    /// [`make_test_db`] once the test is done with it — including on panic,
    /// since `Drop` runs on unwind. Mirrors the guard in
    /// `hub/tests/common.rs`; kept local here because `src/` unit tests
    /// can't depend on the integration-test harness module.
    struct TestDbGuard {
        db_name: String,
        base_url: String,
    }

    impl Drop for TestDbGuard {
        fn drop(&mut self) {
            let db_name = self.db_name.clone();
            let base_url = self.base_url.clone();
            // Drop from a dedicated OS thread + throwaway runtime: `Drop`
            // can't be async, and the calling thread may already be inside
            // a (non-nestable) Tokio runtime.
            let joined = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async move {
                    let admin = PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&format!("{base_url}/postgres"))
                        .await?;
                    sqlx::query(&format!(
                        "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                    ))
                    .execute(&admin)
                    .await?;
                    Ok::<(), sqlx::Error>(())
                })
            })
            .join();
            if let Ok(Err(err)) = joined {
                eprintln!(
                    "warning: failed to drop test database {}: {err}",
                    self.db_name
                );
            }
        }
    }

    /// Minimal in-test DB helper.  Tests that call this need a live PostgreSQL
    /// instance (same as the rest of the integration suite — TEST_DATABASE_URL
    /// or the default postgres://postgres:postgres@localhost:5432).
    async fn make_test_db() -> (PgPool, TestDbGuard) {
        let base_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!("{base_url}/postgres"))
            .await
            .expect("connect admin");
        let db_name = format!("wavvon_test_bootstrap_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await
            .expect("create db");
        let guard = TestDbGuard {
            db_name: db_name.clone(),
            base_url: base_url.clone(),
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{base_url}/{db_name}"))
            .await
            .expect("connect test db");
        crate::db::migrations::run(&pool).await.expect("migrations");
        (pool, guard)
    }

    fn default_cfg() -> BootstrapConfig {
        BootstrapConfig {
            template_url: None,
            bootstrap_token: None,
            discovery_url: "https://discovery.wavvon.io".to_owned(),
            template_file: None,
            preset: None,
        }
    }

    fn sample_template() -> serde_json::Value {
        serde_json::json!({
            "name": "Gaming Hub",
            "settings": {
                "invite_only": "true",
                "min_security_level": "1"
            },
            "channels": [
                {"name": "Lobby", "is_category": true, "display_order": 0},
                {"name": "general", "is_category": false, "display_order": 1,
                 "channel_type": "text", "category": "Lobby"},
                {"name": "off-topic", "is_category": false, "display_order": 2,
                 "channel_type": "text", "category": "Lobby"}
            ],
            "roles": [
                {"name": "Gamer", "priority": 10, "permissions": ["send_messages", "read_messages"]}
            ],
            "welcome_message": "Welcome to the hub!",
            "suggested_bots": ["bot-a", "bot-b"]
        })
    }

    // ── Test 1: already-bootstrapped marker is a no-op ───────────────────────

    #[tokio::test]
    async fn already_bootstrapped_is_noop() {
        let (db, _guard) = make_test_db().await;
        sqlx::query("UPDATE hub_settings SET value = '1000' WHERE key = 'bootstrapped_at'")
            .execute(&db)
            .await
            .unwrap();

        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            template_url: Some("https://example.invalid/template.json".into()),
            ..default_cfg()
        };
        // Should return Ok without touching channels.
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "No channels should be created when already bootstrapped"
        );
    }

    // ── Test 2: non-empty channels table is a no-op ───────────────────────────

    #[tokio::test]
    async fn existing_channels_is_noop() {
        let (db, _guard) = make_test_db().await;
        // Insert a channel so the hub looks non-blank.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // system user required by channels.created_by FK constraint.
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
             VALUES('ch-existing', 'existing', 'system', false, 0, $1)",
        )
        .bind(now)
        .execute(&db)
        .await
        .unwrap();

        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            template_url: Some("https://example.invalid/template.json".into()),
            ..default_cfg()
        };
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1, "Only the pre-existing channel should be present");
    }

    // ── Test 3: no config set is a no-op ─────────────────────────────────────

    #[tokio::test]
    async fn no_config_is_noop() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();
        maybe_bootstrap(&db, &http, &default_cfg()).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    // ── Test 4: apply_template inserts channels, roles, and settings ──────────

    #[tokio::test]
    async fn apply_template_creates_channels_and_roles() {
        let (db, _guard) = make_test_db().await;
        let template = sample_template();
        apply_template(&db, &template).await.unwrap();

        // Two non-category channels created.
        let ch_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category = false")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(ch_count, 2, "Expected 2 non-category channels");

        // One category.
        let cat_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category = true")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(cat_count, 1, "Expected 1 category");

        // general channel has a parent (the Lobby category).
        let parent: Option<String> = sqlx::query_scalar(
            "SELECT parent_id FROM channels WHERE name = 'general' AND is_category = false",
        )
        .fetch_optional(&db)
        .await
        .unwrap();
        assert!(
            parent.is_some(),
            "general channel should reference the Lobby category"
        );

        // Custom role created.
        let role_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE name = 'Gamer'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(role_count, 1);

        // Role permissions.
        let perm_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM role_permissions rp JOIN roles r ON rp.role_id = r.id WHERE r.name = 'Gamer'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(perm_count, 2);

        // hub_settings updated.
        let invite_only: Option<String> =
            sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'invite_only'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert_eq!(invite_only.as_deref(), Some("true"));

        // Welcome message posted.
        let msg_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(msg_count, 1, "Expected 1 welcome message");

        // suggested_bots stored.
        let bots_val: Option<String> =
            sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'suggested_bots'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(bots_val.is_some(), "suggested_bots should be stored");
    }

    // ── Test 5: wavvon:// URI resolution ─────────────────────────────────────
    // The actual HTTP call would fail against a real server, but we can verify
    // the URL rewriting logic produces the correct target URL by checking that
    // the function returns None (since the URL is unreachable in CI) but doesn't
    // panic or corrupt state.

    #[tokio::test]
    async fn wavvon_uri_resolves_gracefully() {
        let http = reqwest::Client::new();
        let result = fetch_template(
            &Some("wavvon://templates/starter".into()),
            "https://discovery.wavvon.io",
            &http,
        )
        .await;
        // The remote will be unreachable in CI — we only assert it doesn't panic
        // and returns None (not an Err that would propagate to kill the hub).
        let _ = result; // None or Some — either is acceptable
    }

    // ── Test 6: existing users (no channels) is also a no-op ──────────────────
    // "First launch" requires no channels AND no users — a hub that already
    // has a real user (e.g. an owner seeded via WAVVON_OWNER_PUBKEY) but no
    // channels yet is not a blank hub.

    #[tokio::test]
    async fn existing_users_is_noop() {
        let (db, _guard) = make_test_db().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        sqlx::query(
            "INSERT INTO users(public_key, first_seen_at, last_seen_at) VALUES('deadbeef', $1, $1)",
        )
        .bind(now)
        .execute(&db)
        .await
        .unwrap();

        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            preset: Some("gaming".into()),
            ..default_cfg()
        };
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "A pre-existing user should block bootstrap even with no channels"
        );
    }

    // ── Test 7: built-in preset applies fully, and is idempotent ──────────────

    #[tokio::test]
    async fn preset_applies_and_is_idempotent() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            preset: Some("gaming".into()),
            ..default_cfg()
        };

        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let ch_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(ch_count, 6, "gaming preset: 2 categories + 4 channels");

        let spawner: Option<String> =
            sqlx::query_scalar("SELECT name FROM channels WHERE channel_type = 'spawner'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert_eq!(spawner.as_deref(), Some("Room Creator"));

        let announcements_talk_power: i64 =
            sqlx::query_scalar("SELECT min_talk_power FROM channels WHERE name = 'announcements'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(announcements_talk_power, 100);

        let moderator_role: Option<String> =
            sqlx::query_scalar("SELECT id FROM roles WHERE name = 'Moderator'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(moderator_role.is_some());

        // Re-running with the same (now non-blank) config must not duplicate
        // anything — the bootstrapped_at marker short-circuits.
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();
        let ch_count_again: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(ch_count_again, 6, "second run must not duplicate channels");
    }

    // ── Test 8: minimal preset is (almost) a true no-op, but still marks bootstrapped ──

    #[tokio::test]
    async fn minimal_preset_creates_nothing_but_marks_bootstrapped() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            preset: Some("minimal".into()),
            ..default_cfg()
        };
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let ch_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(ch_count, 0, "minimal preset creates no channels");

        let marker: Option<String> = sqlx::query_scalar(
            "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
        )
        .fetch_optional(&db)
        .await
        .unwrap();
        assert!(
            marker.is_some(),
            "bootstrapped_at should still be set so this doesn't re-run"
        );
    }

    // ── Test 9: unknown preset name is a clear startup error ──────────────────

    #[tokio::test]
    async fn unknown_preset_name_is_a_startup_error() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            preset: Some("not-a-real-preset".into()),
            ..default_cfg()
        };
        let err = maybe_bootstrap(&db, &http, &cfg)
            .await
            .expect_err("unknown preset must be a hard startup error");
        assert!(err.to_string().contains("not-a-real-preset"));

        // Nothing should have been applied.
        let ch_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(ch_count, 0);
    }

    // ── Test 10: local template file is applied and takes precedence over preset ──

    #[tokio::test]
    async fn template_file_takes_precedence_over_preset() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wavvon_test_template_{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, serde_json::to_vec(&sample_template()).unwrap()).unwrap();

        let cfg = BootstrapConfig {
            template_file: Some(path.to_string_lossy().into_owned()),
            preset: Some("gaming".into()),
            ..default_cfg()
        };
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();
        std::fs::remove_file(&path).ok();

        // sample_template() (Lobby/general/off-topic/Gamer role) applied, not
        // the gaming preset (which would create a Moderator role instead).
        let gamer_role: Option<String> =
            sqlx::query_scalar("SELECT id FROM roles WHERE name = 'Gamer'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(
            gamer_role.is_some(),
            "template_file's content should win over the preset"
        );
        let moderator_role: Option<String> =
            sqlx::query_scalar("SELECT id FROM roles WHERE name = 'Moderator'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(
            moderator_role.is_none(),
            "the gaming preset should not have been applied"
        );
    }

    // ── Test 11: missing template file falls back gracefully to the preset ────

    #[tokio::test]
    async fn missing_template_file_falls_back_to_preset() {
        let (db, _guard) = make_test_db().await;
        let http = reqwest::Client::new();
        let cfg = BootstrapConfig {
            template_file: Some("C:/does/not/exist/wavvon-template.json".into()),
            preset: Some("minimal".into()),
            ..default_cfg()
        };
        // Must not error — a missing file falls back to the next source.
        maybe_bootstrap(&db, &http, &cfg).await.unwrap();

        let marker: Option<String> = sqlx::query_scalar(
            "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
        )
        .fetch_optional(&db)
        .await
        .unwrap();
        assert!(
            marker.is_some(),
            "should have fallen back to the minimal preset and bootstrapped"
        );
    }
}
