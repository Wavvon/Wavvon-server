use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::routes::bot_models::{BotCommandDef, BotMeta, BotSubscription};

// ---------------------------------------------------------------------------
// Audit log route types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub event_type: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub seq: i64,
    pub event_type: String,
    pub at: i64,
    pub actor_pubkey: Option<String>,
    pub target_pubkey: Option<String>,
    pub channel_id: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogEntry>,
    pub next_cursor: Option<i64>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn generate_token() -> String {
    hex::encode(Uuid::new_v4().as_bytes()) + &hex::encode(Uuid::new_v4().as_bytes())
}

/// Authenticate a bot request via `Authorization: Bearer <token>` and return
/// the matching bot row.
pub async fn authenticate_bot(
    db: &sqlx::PgPool,
    headers: &HeaderMap,
) -> Result<BotRow, (StatusCode, String)> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Missing bot token".to_string()))?;

    let hash = hash_token(raw);

    sqlx::query_as::<_, BotRow>(
        "SELECT public_key, display_name, created_by, created_at, webhook_url, mini_app_url, requires_camera
         FROM bots WHERE token_hash = $1",
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
pub struct BotRow {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub created_at: i64,
    pub webhook_url: Option<String>,
    pub mini_app_url: Option<String>,
    pub requires_camera: bool,
}

#[derive(sqlx::FromRow)]
pub struct SlashCommandRow {
    pub command: String,
    pub description: String,
}

#[derive(sqlx::FromRow)]
pub struct EventRow {
    pub id: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Admin request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateBotRequest {
    pub display_name: String,
    #[serde(default)]
    pub mini_app_url: Option<String>,
    #[serde(default)]
    pub requires_camera: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mini_app_url: Option<String>,
    pub requires_camera: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mini_app_url: Option<String>,
    pub requires_camera: bool,
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
// External bot system types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InviteBotRequest {
    pub pubkey: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct InviteBotResponse {
    pub invite_token: String,
}

#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    pub pubkey: String,
    pub signature_over_token: String,
    pub bot_meta: BotMeta,
}

#[derive(Serialize)]
pub struct AcceptInviteResponse {
    pub status: String,
}

#[derive(Serialize)]
pub struct BotListEntry {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub commands: Vec<BotCommandSummary>,
}

#[derive(Serialize)]
pub struct BotCommandSummary {
    pub name: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct BotMeResponse {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    pub capabilities: Vec<String>,
    pub commands: Vec<BotCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateCommandsRequest {
    pub commands: Vec<BotCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateSubscriptionsRequest {
    pub subscriptions: Vec<BotSubscription>,
}

#[derive(Serialize)]
pub struct SetSubscriptionsResponse {
    pub count: usize,
}

// ---------------------------------------------------------------------------
// External bot DB row helpers
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub struct BotProfileRow {
    pub pubkey: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub description: Option<String>,
    pub webhook_url: Option<String>,
    pub homepage_url: Option<String>,
    pub capabilities: String,
}

#[derive(sqlx::FromRow)]
pub struct BotCommandRow {
    pub name: String,
    pub description: String,
    pub args: Option<String>,
    pub scope: String,
    pub privileged: bool,
    pub cooldown_seconds: i64,
}
