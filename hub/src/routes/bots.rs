use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

fn generate_token() -> String {
    hex::encode(Uuid::new_v4().as_bytes()) + &hex::encode(Uuid::new_v4().as_bytes())
}

/// Authenticate a bot request via `Authorization: Bearer <token>` and return
/// the matching bot row.
async fn authenticate_bot(
    db: &sqlx::SqlitePool,
    headers: &HeaderMap,
) -> Result<BotRow, (StatusCode, String)> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Missing bot token".to_string()))?;

    let hash = hash_token(raw);

    sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url
         FROM bots WHERE token_hash = ?",
    )
    .bind(&hash)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid bot token".to_string()))
}

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct BotRow {
    public_key: String,
    display_name: String,
    created_by: String,
    created_at: i64,
    webhook_url: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SlashCommandRow {
    command: String,
    description: String,
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: String,
    event_type: String,
    payload: String,
    created_at: i64,
}

// ---------------------------------------------------------------------------
// Admin request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateBotRequest {
    pub display_name: String,
}

#[derive(Serialize)]
pub struct BotAdminInfo {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

#[derive(Serialize)]
pub struct BotCreatedResponse {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    pub token: String,
}

#[derive(Serialize)]
pub struct SlashCommandInfo {
    pub command: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct BotDetailResponse {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub commands: Vec<SlashCommandInfo>,
}

#[derive(Deserialize)]
pub struct SetWebhookRequest {
    pub webhook_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Bot API request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetCommandsRequest {
    pub commands: Vec<CommandInput>,
}

#[derive(Deserialize)]
pub struct CommandInput {
    pub command: String,
    pub description: String,
}

#[derive(Deserialize)]
pub struct BotSendRequest {
    pub channel_id: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct PollQuery {
    pub since: Option<i64>,
}

#[derive(Serialize)]
pub struct EventInfo {
    pub id: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct AckRequest {
    pub ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

/// POST /admin/bots  — create a bot (any authenticated hub member)
pub async fn admin_create_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateBotRequest>,
) -> Result<(StatusCode, Json<BotCreatedResponse>), (StatusCode, String)> {
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "display_name cannot be empty".to_string()));
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
// Bot API handlers  (token auth via Authorization: Bearer header)
// ---------------------------------------------------------------------------

/// PUT /bot/commands  — replace slash command list
pub async fn bot_set_commands(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM bot_slash_commands WHERE bot_pubkey = ?")
        .bind(&bot.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    for cmd in &req.commands {
        let cmd_word = cmd.command.trim().to_lowercase();
        if cmd_word.is_empty() {
            continue;
        }
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO bot_slash_commands (id, bot_pubkey, command, description, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&bot.public_key)
        .bind(&cmd_word)
        .bind(cmd.description.trim())
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

/// POST /bot/send  — post a message as the bot
pub async fn bot_send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BotSendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Verify channel exists.
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.channel_id)
    .bind(&bot.public_key)
    .bind(&req.content)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Broadcast via the chat channel so connected WS clients see it.
    use crate::routes::chat_models::{ChatEvent, MessageResponse};
    let message = MessageResponse {
        id,
        channel_id: req.channel_id.clone(),
        sender: bot.public_key,
        sender_name: Some(bot.display_name),
        content: req.content,
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
    };
    let _ = state.chat_tx.send(ChatEvent::New {
        channel_id: req.channel_id,
        message,
    });

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /bot/poll  — poll undelivered events
pub async fn bot_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PollQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    let rows = if let Some(since) = params.since {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = ? AND delivered = 0 AND created_at > ?
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .bind(since)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = ? AND delivered = 0
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let events: Vec<EventInfo> = rows
        .into_iter()
        .map(|r| EventInfo {
            id: r.id,
            event_type: r.event_type,
            payload: r.payload,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "events": events })))
}

/// DELETE /bot/events  — acknowledge events as delivered
pub async fn bot_ack_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    for id in &req.ids {
        let _ = sqlx::query(
            "UPDATE bot_event_queue SET delivered = 1
             WHERE id = ? AND bot_pubkey = ?",
        )
        .bind(id)
        .bind(&bot.public_key)
        .execute(&state.db)
        .await;
    }

    Ok(StatusCode::OK)
}
