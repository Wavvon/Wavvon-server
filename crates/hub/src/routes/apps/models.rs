use serde::{Deserialize, Serialize};

use crate::routes::app_models::{AppCommandDef, AppSubscription};

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
// DB row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub struct EventRow {
    pub id: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub struct AppProfileRow {
    pub pubkey: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub description: Option<String>,
    pub webhook_url: Option<String>,
    pub homepage_url: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct AppCommandRow {
    pub name: String,
    pub description: String,
    pub args: Option<String>,
    pub scope: String,
    pub privileged: bool,
    pub cooldown_seconds: i64,
}

// ---------------------------------------------------------------------------
// Event transport request / response types
// ---------------------------------------------------------------------------

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
// App registration request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AppMeResponse {
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
    pub commands: Vec<AppCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateCommandsRequest {
    pub commands: Vec<AppCommandDef>,
}

#[derive(Deserialize)]
pub struct UpdateSubscriptionsRequest {
    pub subscriptions: Vec<AppSubscription>,
}

#[derive(Serialize)]
pub struct SetSubscriptionsResponse {
    pub count: usize,
}
