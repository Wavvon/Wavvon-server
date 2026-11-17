//! Web Push subscriptions (push.rs delivers). One row per identity and
//! browser endpoint; the client sends its notify modes for this hub with it,
//! since they live on the client and the hub must honour them while the
//! client is closed.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::push::{b64url_decode, vapid_key, vapid_public, NotifyPrefs};
use crate::state::AppState;

/// Browsers (and accounts sharing one) a single identity may register.
const MAX_SUBSCRIPTIONS: i64 = 20;
const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_NOTIFY_CHANNELS: usize = 2000;

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

#[derive(Serialize)]
pub struct VapidKeyResponse {
    pub public_key: String,
}

/// GET /push/vapid-key — the application server key to subscribe with.
pub async fn get_vapid_key(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<VapidKeyResponse>, (StatusCode, String)> {
    let key = vapid_key(&state.db).await.map_err(db_err)?;
    Ok(Json(VapidKeyResponse {
        public_key: vapid_public(&key),
    }))
}

#[derive(Deserialize)]
pub struct SubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

#[derive(Deserialize)]
pub struct PutSubscriptionRequest {
    pub endpoint: String,
    pub keys: SubscriptionKeys,
    #[serde(default)]
    pub notify: NotifyPrefs,
}

/// PUT /push/subscriptions — add this browser, or update its keys and notify
/// modes. Keyed by endpoint per identity.
pub async fn put_subscription(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PutSubscriptionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    if req.endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(bad("endpoint too long"));
    }
    if req.notify.channels.len() > MAX_NOTIFY_CHANNELS
        || req.notify.channels_until.len() > MAX_NOTIFY_CHANNELS
    {
        return Err(bad("too many channels in notify"));
    }
    b64url_decode(&req.keys.p256dh)
        .and_then(|b| p256::PublicKey::from_sec1_bytes(&b).ok())
        .ok_or_else(|| bad("keys.p256dh is not a P-256 point"))?;
    b64url_decode(&req.keys.auth)
        .filter(|a| a.len() == 16)
        .ok_or_else(|| bad("keys.auth is not 16 bytes"))?;
    // The endpoint is the browser's to choose, and the hub will POST to it.
    crate::webhook_url::validate_webhook_url(&req.endpoint, state.allow_private_webhooks).await?;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_subscriptions WHERE user_pubkey = $1 AND endpoint <> $2",
    )
    .bind(&user.public_key)
    .bind(&req.endpoint)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    if count >= MAX_SUBSCRIPTIONS {
        return Err((
            StatusCode::CONFLICT,
            "too many push subscriptions".to_string(),
        ));
    }

    let notify = serde_json::to_string(&req.notify).unwrap_or_else(|_| "{}".into());
    sqlx::query(
        "INSERT INTO push_subscriptions (user_pubkey, endpoint, p256dh, auth, notify, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_pubkey, endpoint) DO UPDATE
         SET p256dh = excluded.p256dh, auth = excluded.auth, notify = excluded.notify",
    )
    .bind(&user.public_key)
    .bind(&req.endpoint)
    .bind(&req.keys.p256dh)
    .bind(&req.keys.auth)
    .bind(notify)
    .bind(crate::auth::handlers::unix_timestamp_ms())
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct DeleteSubscriptionRequest {
    pub endpoint: String,
}

/// DELETE /push/subscriptions — forget this browser for the caller.
pub async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<DeleteSubscriptionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM push_subscriptions WHERE user_pubkey = $1 AND endpoint = $2")
        .bind(&user.public_key)
        .bind(&req.endpoint)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}
