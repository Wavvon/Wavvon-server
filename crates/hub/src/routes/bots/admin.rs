use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::models::{
    AuditLogEntry, AuditLogQuery, AuditLogResponse, CapabilitiesReadResponse, CapabilitiesResponse,
    ChannelScopeResponse, SetCapabilitiesRequest, SetChannelScopeRequest,
};

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
    perms.require(permissions::BOTS_CAPABILITIES)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE)",
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
    perms.require(permissions::BOTS_CAPABILITIES)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE)",
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
    perms.require(permissions::BOTS_CAPABILITIES)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE)",
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
    perms.require(permissions::BOTS_CAPABILITIES)?;

    let known_bot: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE public_key = $1 AND is_bot = TRUE)",
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
    perms.require(permissions::BOTS_AUDIT_READ)?;

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
