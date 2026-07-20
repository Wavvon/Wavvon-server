use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::models::{generate_token, hash_token};
use super::models::{
    AuditLogEntry, AuditLogQuery, AuditLogResponse, BotAdminInfo, BotCreatedResponse,
    BotDetailResponse, BotRow, CapabilitiesReadResponse, CapabilitiesResponse,
    ChannelScopeResponse, CreateBotRequest, SetCapabilitiesRequest, SetChannelScopeRequest,
    SetWebhookRequest, SlashCommandInfo, SlashCommandRow,
};

/// POST /admin/bots  — create a bot (any authenticated hub member)
pub async fn admin_create_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateBotRequest>,
) -> Result<(StatusCode, Json<BotCreatedResponse>), (StatusCode, String)> {
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "display_name cannot be empty".to_string(),
        ));
    }

    let public_key = format!("bot_{}", Uuid::new_v4().simple());
    let token = generate_token();
    let token_hash = hash_token(&token);
    let now = crate::auth::handlers::unix_timestamp();

    // Insert into users so messages and member listing work with the existing FK.
    sqlx::query(
        "INSERT INTO users (public_key, display_name, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES ($1, $2, $3, $4, 'approved', TRUE)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO bots (public_key, display_name, created_by, token_hash, mini_app_url, requires_camera, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(&user.public_key)
    .bind(&token_hash)
    .bind(&req.mini_app_url)
    .bind(req.requires_camera)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(BotCreatedResponse {
            public_key,
            display_name,
            created_by: user.public_key,
            created_at: now,
            token,
            mini_app_url: req.mini_app_url,
            requires_camera: req.requires_camera,
        }),
    ))
}

/// GET /admin/bots  — list all bots (no token)
pub async fn admin_list_bots(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<BotAdminInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url, mini_app_url, requires_camera
         FROM bots ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BotAdminInfo {
                public_key: r.public_key,
                display_name: r.display_name,
                created_by: r.created_by,
                created_at: r.created_at,
                webhook_url: r.webhook_url,
            })
            .collect(),
    ))
}

/// GET /admin/bots/:pubkey  — bot detail with slash commands
pub async fn admin_get_bot(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<BotDetailResponse>, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url, mini_app_url, requires_camera
         FROM bots WHERE public_key = $1",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    let cmds = sqlx::query_as::<_, SlashCommandRow>(
        "SELECT command, description FROM bot_slash_commands WHERE bot_pubkey = $1 ORDER BY command",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(BotDetailResponse {
        public_key: bot.public_key,
        display_name: bot.display_name,
        created_by: bot.created_by,
        created_at: bot.created_at,
        webhook_url: bot.webhook_url,
        mini_app_url: bot.mini_app_url,
        requires_camera: bot.requires_camera,
        commands: cmds
            .into_iter()
            .map(|c| SlashCommandInfo {
                command: c.command,
                description: c.description,
            })
            .collect(),
    }))
}

/// DELETE /admin/bots/:pubkey  — delete bot (creator or admin)
pub async fn admin_delete_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url, mini_app_url, requires_camera
         FROM bots WHERE public_key = $1",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    // Creator can delete; admin can delete anyone's bot.
    if bot.created_by != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    // Cascade deletes slash_commands and event_queue via FK.
    sqlx::query("DELETE FROM bots WHERE public_key = $1")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Clean up the users row so the bot disappears from member lists.
    sqlx::query("DELETE FROM users WHERE public_key = $1")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// PUT /admin/bots/:pubkey/webhook  — set or clear webhook (creator or admin)
pub async fn admin_set_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<SetWebhookRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url, mini_app_url, requires_camera
         FROM bots WHERE public_key = $1",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    if bot.created_by != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    sqlx::query("UPDATE bots SET webhook_url = $1 WHERE public_key = $2")
        .bind(&req.webhook_url)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// PUT /admin/bots/:pubkey/capabilities
// ---------------------------------------------------------------------------

/// Admin-only: atomically replaces the granted capability set for a bot
/// (bot-capability-layer.md §1, §6 Phase 1 item 2). `pubkey` may name either
/// an external bot (`users.is_bot=1`) or a self-service bot (`bots` table) --
/// the grants table is keyed on the bare pubkey and doesn't care which.
///
/// The gate a runtime actually checks is requested ∩ granted
/// (`bots::capabilities::effective_capabilities`), so granting a capability
/// an external bot never requested is inert until the bot also declares it;
/// this route only writes the "granted" side.
pub async fn admin_set_bot_capabilities(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<SetCapabilitiesRequest>,
) -> Result<Json<CapabilitiesResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE
            UNION
            SELECT 1 FROM bots WHERE public_key = $1
         )",
    )
    .bind(&pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if !known_bot {
        return Err((StatusCode::NOT_FOUND, "Bot not found".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM bot_capability_grants WHERE bot_pubkey = $1")
        .bind(&pubkey)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for cap in &req.capabilities {
        sqlx::query(
            "INSERT INTO bot_capability_grants (bot_pubkey, capability, granted_by, granted_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&pubkey)
        .bind(cap)
        .bind(&user.public_key)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Audit stream.
    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let target = pubkey.clone();
        let caps = req.capabilities.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "bot.capabilities_changed",
                Some(&actor),
                Some(&target),
                None,
                serde_json::json!({ "capabilities": caps }),
            )
            .await;
        });
    }

    // Push directly to the bot's live WS session(s) (bot-capability-layer.md
    // §1 consent flow step 4) so it can stop advertising something it can no
    // longer run without waiting for a reconnect.
    {
        let sessions = state.bot_sessions.read().await;
        if let Some(per_bot) = sessions.get(&pubkey) {
            let msg = serde_json::json!({
                "type": "capabilities_changed",
                "capabilities": req.capabilities,
            })
            .to_string();
            for tx in per_bot.values() {
                let _ = tx.try_send(msg.clone());
            }
        }
    }

    Ok(Json(CapabilitiesResponse {
        bot_pubkey: pubkey,
        capabilities: req.capabilities,
    }))
}

// ---------------------------------------------------------------------------
// GET /admin/bots/:pubkey/capabilities
// ---------------------------------------------------------------------------

/// Admin-only: stable read contract for the admin panel (bot-capability-
/// layer.md §1, §6 Phase 1 item 2 follow-up). Not just the write endpoint's
/// echo -- `requested` and `effective` aren't observable from
/// `PUT .../capabilities`'s response at all.
pub async fn admin_get_bot_capabilities(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<CapabilitiesReadResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE
            UNION
            SELECT 1 FROM bots WHERE public_key = $1
         )",
    )
    .bind(&pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if !known_bot {
        return Err((StatusCode::NOT_FOUND, "Bot not found".to_string()));
    }

    let requested_json: Option<String> =
        sqlx::query_scalar("SELECT capabilities FROM bot_profiles WHERE pubkey = $1")
            .bind(&pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();
    let requested: Vec<String> = requested_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let granted: Vec<String> = sqlx::query_scalar(
        "SELECT capability FROM bot_capability_grants WHERE bot_pubkey = $1 ORDER BY capability",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut effective: Vec<String> =
        crate::bots::capabilities::effective_capabilities(&state.db, &pubkey)
            .await
            .into_iter()
            .collect();
    effective.sort();

    Ok(Json(CapabilitiesReadResponse {
        requested,
        granted,
        effective,
    }))
}

// ---------------------------------------------------------------------------
// PUT /admin/bots/:pubkey/channels
// ---------------------------------------------------------------------------

/// Admin-only: atomically replaces a bot's channel scope (bots.md §14).
/// `channel_ids` empty (or an empty/omitted body) resets to hub-wide access.
/// Same "either an external bot or a self-service bot" pubkey resolution as
/// `admin_set_bot_capabilities` -- `bot_channel_scope` is keyed on the bare
/// pubkey and the enforcement in `bots/dispatch.rs` and `bots/events.rs`
/// doesn't care which kind of bot row it is.
pub async fn admin_set_bot_channel_scope(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<SetChannelScopeRequest>,
) -> Result<Json<ChannelScopeResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE
            UNION
            SELECT 1 FROM bots WHERE public_key = $1
         )",
    )
    .bind(&pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if !known_bot {
        return Err((StatusCode::NOT_FOUND, "Bot not found".to_string()));
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM bot_channel_scope WHERE bot_pubkey = $1")
        .bind(&pubkey)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for channel_id in &req.channel_ids {
        sqlx::query(
            "INSERT INTO bot_channel_scope (bot_pubkey, channel_id) VALUES ($1, $2)
             ON CONFLICT (bot_pubkey, channel_id) DO NOTHING",
        )
        .bind(&pubkey)
        .bind(channel_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(ChannelScopeResponse {
        bot_pubkey: pubkey,
        channel_ids: req.channel_ids,
    }))
}

// ---------------------------------------------------------------------------
// GET /admin/bots/:pubkey/channels
// ---------------------------------------------------------------------------

/// Admin-only: current channel scope for a bot (bots.md §14). Empty list
/// means hub-wide access. Same pubkey resolution and response shape as
/// `admin_set_bot_channel_scope`.
pub async fn admin_get_bot_channel_scope(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<ChannelScopeResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE
            UNION
            SELECT 1 FROM bots WHERE public_key = $1
         )",
    )
    .bind(&pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if !known_bot {
        return Err((StatusCode::NOT_FOUND, "Bot not found".to_string()));
    }

    let channel_ids: Vec<String> = sqlx::query_scalar(
        "SELECT channel_id FROM bot_channel_scope WHERE bot_pubkey = $1 ORDER BY channel_id",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(ChannelScopeResponse {
        bot_pubkey: pubkey,
        channel_ids,
    }))
}

// ---------------------------------------------------------------------------
// GET /admin/audit-log
// ---------------------------------------------------------------------------

/// Cursor-paginated view of `hub_audit_log`. Admin only.
pub async fn admin_audit_log(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    // We fetch limit+1 to detect whether there's a next page.
    let fetch_limit = limit + 1;

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        seq: i64,
        event_type: String,
        at: i64,
        actor_pubkey: Option<String>,
        target_pubkey: Option<String>,
        channel_id: Option<String>,
        payload_json: String,
    }

    // Build query dynamically from optional filters.
    // SQLite doesn't support named params easily with sqlx, so we use a flag
    // approach: always bind all params, use 0/MAX for disabled ranges.
    let cursor_seq = params.cursor.unwrap_or(0);
    let since = params.since.unwrap_or(0);
    let until = params.until.unwrap_or(i64::MAX);
    let event_type_filter = params.event_type.as_deref().unwrap_or("");

    let rows: Vec<AuditRow> = if event_type_filter.is_empty() {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > $1 AND at >= $2 AND at <= $3
             ORDER BY seq ASC
             LIMIT $4",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > $1 AND at >= $2 AND at <= $3 AND event_type = $4
             ORDER BY seq ASC
             LIMIT $5",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(event_type_filter)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<AuditLogEntry> = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| AuditLogEntry {
            seq: r.seq,
            event_type: r.event_type,
            at: r.at,
            actor_pubkey: r.actor_pubkey,
            target_pubkey: r.target_pubkey,
            channel_id: r.channel_id,
            payload: serde_json::from_str(&r.payload_json).unwrap_or(serde_json::Value::Null),
        })
        .collect();

    let next_cursor = if has_more {
        entries.last().map(|e| e.seq)
    } else {
        None
    };

    Ok(Json(AuditLogResponse {
        entries,
        next_cursor,
    }))
}
