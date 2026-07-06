//! Wire types for the outgoing-webhooks feature: DB row shapes and the 8
//! admin route request/response DTOs (see `docs/docs/outgoing-webhooks.md` §9).
//!
//! Not to be confused with `routes::bot_models::BotSubscription` — the JSON
//! shape is intentionally identical (`{ "event": ..., "channels": [...] }`)
//! so the admin UI can reuse the same subscription editor component, but
//! outgoing webhooks persist to their own tables.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DB row shapes
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct OutgoingWebhook {
    pub id: String,
    pub url: String,
    pub display_name: Option<String>,
    /// Hex-encoded HKDF-SHA256 output. Never the raw secret shown to the admin.
    pub signing_key: String,
    pub created_by_pubkey: String,
    pub active: bool,
    pub failure_count: i64,
    pub last_delivery_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub created_at: i64,
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct WebhookSubscriptionRow {
    pub webhook_id: String,
    pub event_type: String,
    /// `''` sentinel = hub-scope (no channel filter), matching the
    /// `bot_subscriptions` convention.
    pub channel_id: String,
}

#[derive(sqlx::FromRow, Clone, Debug, Serialize)]
pub struct DeliveryRecord {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub event_seq: Option<i64>,
    pub attempted_at: i64,
    pub attempt_number: i64,
    pub status_code: Option<i64>,
    pub success: bool,
    pub error_msg: Option<String>,
}

// ---------------------------------------------------------------------------
// Wire envelope posted to the receiver (doc §3)
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct WebhookEventEnvelope {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub event: String,
    pub hub_url: String,
    pub webhook_id: String,
    pub at: i64,
    pub seq: Option<i64>,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// Subscription DTO (shared shape with bots)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WebhookSubscriptionDto {
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Route request / response DTOs (doc §9)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateOutgoingWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct CreateOutgoingWebhookResponse {
    pub id: String,
    pub url: String,
    pub display_name: Option<String>,
    /// Shown once. Never persisted or returned again.
    pub secret: String,
}

#[derive(Serialize)]
pub struct OutgoingWebhookSummary {
    pub id: String,
    pub url: String,
    pub display_name: Option<String>,
    pub active: bool,
    pub failure_count: i64,
    pub last_delivery_at: Option<i64>,
    pub last_failure_at: Option<i64>,
    pub created_at: i64,
    pub created_by_pubkey: String,
    pub subscription_count: i64,
}

#[derive(Deserialize, Default)]
pub struct UpdateOutgoingWebhookRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
}

#[derive(Deserialize)]
pub struct ReplaceSubscriptionsRequest {
    pub subscriptions: Vec<WebhookSubscriptionDto>,
}

#[derive(Serialize)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<WebhookSubscriptionDto>,
}

#[derive(Serialize)]
pub struct ReplaceSubscriptionsResponse {
    pub count: usize,
}

#[derive(Serialize)]
pub struct RotateSecretResponse {
    /// Shown once. Never persisted or returned again.
    pub secret: String,
}

#[derive(Deserialize, Default)]
pub struct ListDeliveriesQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub success: Option<bool>,
}
