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
    BotDetailResponse, BotRow, CreateBotRequest, SetWebhookRequest, SlashCommandInfo,
    SlashCommandRow,
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
         VALUES (?, ?, ?, ?, 'approved', 1)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO bots (public_key, display_name, created_by, token_hash, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&public_key)
    .bind(&display_name)
    .bind(&user.public_key)
    .bind(&token_hash)
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
        }),
    ))
}

/// GET /admin/bots  — list all bots (no token)
pub async fn admin_list_bots(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<BotAdminInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
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
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot not found".to_string()))?;

    let cmds = sqlx::query_as::<_, SlashCommandRow>(
        "SELECT command, description FROM bot_slash_commands WHERE bot_pubkey = ? ORDER BY command",
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
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
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
    sqlx::query("DELETE FROM bots WHERE public_key = ?")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Clean up the users row so the bot disappears from member lists.
    sqlx::query("DELETE FROM users WHERE public_key = ?")
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
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE public_key = ?",
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

    sqlx::query("UPDATE bots SET webhook_url = ? WHERE public_key = ?")
        .bind(&req.webhook_url)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
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
             WHERE seq > ? AND at >= ? AND at <= ?
             ORDER BY seq ASC
             LIMIT ?",
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
             WHERE seq > ? AND at >= ? AND at <= ? AND event_type = ?
             ORDER BY seq ASC
             LIMIT ?",
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
