//! The 9 `/admin/outgoing-webhooks` routes (doc §9). All gated by
//! `permissions::ADMIN`, matching the `create_webhook`/`delete_webhook`
//! pattern in `routes::webhooks` (incoming webhooks).

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use url::Url;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::models::{
    CreateOutgoingWebhookRequest, CreateOutgoingWebhookResponse, DeliveryRecord,
    ListDeliveriesQuery, ListSubscriptionsResponse, OutgoingWebhookSummary,
    ReplaceSubscriptionsRequest, ReplaceSubscriptionsResponse, RotateSecretResponse,
    UpdateOutgoingWebhookRequest, WebhookSubscriptionDto,
};
use super::worker::new_webhook_id;

/// HKDF salt for deriving the persisted signing key from the one-time secret
/// (doc §4).
const HKDF_SALT: &[u8] = b"wavvon-webhook-signing";

// ---------------------------------------------------------------------------
// URL validation — same rule as bot `webhook_url` (doc §1, §7): https only,
// reject private/loopback ranges. `routes::preview` owns the canonical
// private-IP-range check; we reuse it here rather than duplicating the list.
// ---------------------------------------------------------------------------

fn validate_webhook_url(raw: &str) -> Result<(), (StatusCode, String)> {
    let parsed =
        Url::parse(raw).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid URL".to_string()))?;

    if parsed.scheme() != "https" {
        return Err((StatusCode::BAD_REQUEST, "URL must use https://".to_string()));
    }

    let host = parsed
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "URL must have a host".to_string()))?;

    // Reject bare "localhost" outright (matches the redirect-guard rule in
    // routes::preview).
    if host.eq_ignore_ascii_case("localhost") {
        return Err((
            StatusCode::BAD_REQUEST,
            "URL host must not be a private or loopback address".to_string(),
        ));
    }

    // If the host is a literal IP, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if crate::routes::preview::is_private_ip(ip) {
            return Err((
                StatusCode::BAD_REQUEST,
                "URL host must not be a private or loopback address".to_string(),
            ));
        }
        return Ok(());
    }

    // Otherwise resolve the hostname and reject if any resolved address is
    // private/loopback. Best-effort: DNS failure here is a validation error,
    // not a delivery-time concern.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = (host, port).to_socket_addrs().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Could not resolve host".to_string(),
        )
    })?;

    let mut any = false;
    for addr in addrs {
        any = true;
        if crate::routes::preview::is_private_ip(addr.ip()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "URL host must not be a private or loopback address".to_string(),
            ));
        }
    }
    if !any {
        return Err((
            StatusCode::BAD_REQUEST,
            "Could not resolve host".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Secret generation
// ---------------------------------------------------------------------------

/// Generate a fresh 32-byte secret (base64url, shown once) and its derived
/// hex-encoded HKDF-SHA256 signing key (persisted).
fn generate_secret_and_key() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &raw);
    let mut signing_key = [0u8; 32];
    // `expand` only fails if the requested length is too large for the hash
    // (max 255 * hash_len); 32 bytes is always valid, so this cannot fail.
    hk.expand(b"", &mut signing_key)
        .expect("HKDF expand with a 32-byte output cannot fail");

    (secret, hex::encode(signing_key))
}

// ---------------------------------------------------------------------------
// POST /admin/outgoing-webhooks
// ---------------------------------------------------------------------------

pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateOutgoingWebhookRequest>,
) -> Result<(StatusCode, Json<CreateOutgoingWebhookResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    validate_webhook_url(&req.url)?;

    let id = new_webhook_id();
    let now = crate::auth::handlers::unix_timestamp();
    let (secret, signing_key) = generate_secret_and_key();

    sqlx::query(
        "INSERT INTO outgoing_webhooks
            (id, url, display_name, signing_key, created_by_pubkey, active, failure_count, created_at)
         VALUES ($1,$2,$3,$4,$5,TRUE,0,$6)",
    )
    .bind(&id)
    .bind(&req.url)
    .bind(&req.display_name)
    .bind(&signing_key)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateOutgoingWebhookResponse {
            id,
            url: req.url,
            display_name: req.display_name,
            secret,
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /admin/outgoing-webhooks
// ---------------------------------------------------------------------------

pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<OutgoingWebhookSummary>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        url: String,
        display_name: Option<String>,
        active: bool,
        failure_count: i64,
        last_delivery_at: Option<i64>,
        last_failure_at: Option<i64>,
        created_at: i64,
        created_by_pubkey: String,
        subscription_count: i64,
    }

    let rows: Vec<Row> = sqlx::query_as::<_, Row>(
        "SELECT ow.id, ow.url, ow.display_name, ow.active, ow.failure_count,
                ow.last_delivery_at, ow.last_failure_at, ow.created_at, ow.created_by_pubkey,
                (SELECT COUNT(*) FROM outgoing_webhook_subscriptions ows WHERE ows.webhook_id = ow.id) AS subscription_count
         FROM outgoing_webhooks ow
         ORDER BY ow.created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| OutgoingWebhookSummary {
                id: r.id,
                url: r.url,
                display_name: r.display_name,
                active: r.active,
                failure_count: r.failure_count,
                last_delivery_at: r.last_delivery_at,
                last_failure_at: r.last_failure_at,
                created_at: r.created_at,
                created_by_pubkey: r.created_by_pubkey,
                subscription_count: r.subscription_count,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// PATCH /admin/outgoing-webhooks/:id
// ---------------------------------------------------------------------------

pub async fn update_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateOutgoingWebhookRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM outgoing_webhooks WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    if let Some(url) = &req.url {
        validate_webhook_url(url)?;
        sqlx::query("UPDATE outgoing_webhooks SET url = $1 WHERE id = $2")
            .bind(url)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(display_name) = &req.display_name {
        sqlx::query("UPDATE outgoing_webhooks SET display_name = $1 WHERE id = $2")
            .bind(display_name)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(active) = req.active {
        sqlx::query("UPDATE outgoing_webhooks SET active = $1 WHERE id = $2")
            .bind(active)
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// DELETE /admin/outgoing-webhooks/:id
// ---------------------------------------------------------------------------

pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let rows = super::worker::delete_webhook_cascade(&state.db, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /admin/outgoing-webhooks/:id/subscriptions
// ---------------------------------------------------------------------------

pub async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ListSubscriptionsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM outgoing_webhooks WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    #[derive(sqlx::FromRow)]
    struct Row {
        event_type: String,
        channel_id: String,
    }

    let rows: Vec<Row> = sqlx::query_as::<_, Row>(
        "SELECT event_type, channel_id FROM outgoing_webhook_subscriptions
         WHERE webhook_id = $1
         ORDER BY event_type, channel_id",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Group by event_type: '' channel_id rows mean hub-scope (no channels
    // key); any real channel_id rows accumulate into a `channels` list.
    let mut subscriptions: Vec<WebhookSubscriptionDto> = Vec::new();
    for row in rows {
        if row.channel_id.is_empty() {
            subscriptions.push(WebhookSubscriptionDto {
                event: row.event_type,
                channels: None,
            });
            continue;
        }
        if let Some(existing) = subscriptions
            .iter_mut()
            .find(|s| s.event == row.event_type && s.channels.is_some())
        {
            existing
                .channels
                .get_or_insert_with(Vec::new)
                .push(row.channel_id);
        } else {
            subscriptions.push(WebhookSubscriptionDto {
                event: row.event_type,
                channels: Some(vec![row.channel_id]),
            });
        }
    }

    Ok(Json(ListSubscriptionsResponse { subscriptions }))
}

// ---------------------------------------------------------------------------
// PUT /admin/outgoing-webhooks/:id/subscriptions
// ---------------------------------------------------------------------------

pub async fn replace_subscriptions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ReplaceSubscriptionsRequest>,
) -> Result<Json<ReplaceSubscriptionsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM outgoing_webhooks WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    // Same privacy gate as bot subscriptions (doc §2): message.* events
    // require an explicit channels list.
    for sub in &req.subscriptions {
        let is_message_event =
            sub.event.starts_with("message.") && sub.event != "message.mention_bot";
        if is_message_event && sub.channels.as_ref().is_none_or(|v| v.is_empty()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Subscription '{}' requires an explicit channels list",
                    sub.event
                ),
            ));
        }
    }

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM outgoing_webhook_subscriptions WHERE webhook_id = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut count = 0usize;
    for sub in &req.subscriptions {
        match &sub.channels {
            Some(channels) if !channels.is_empty() => {
                for channel_id in channels {
                    sqlx::query(
                        "INSERT INTO outgoing_webhook_subscriptions(webhook_id, event_type, channel_id)
                         VALUES($1,$2,$3) ON CONFLICT (webhook_id, event_type, channel_id) DO NOTHING",
                    )
                    .bind(&id)
                    .bind(&sub.event)
                    .bind(channel_id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                    count += 1;
                }
            }
            _ => {
                sqlx::query(
                    "INSERT INTO outgoing_webhook_subscriptions(webhook_id, event_type, channel_id)
                     VALUES($1,$2,'') ON CONFLICT (webhook_id, event_type, channel_id) DO NOTHING",
                )
                .bind(&id)
                .bind(&sub.event)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                count += 1;
            }
        }
    }

    Ok(Json(ReplaceSubscriptionsResponse { count }))
}

// ---------------------------------------------------------------------------
// POST /admin/outgoing-webhooks/:id/rotate-secret
// ---------------------------------------------------------------------------

pub async fn rotate_secret(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<RotateSecretResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let (secret, signing_key) = generate_secret_and_key();

    let rows = sqlx::query("UPDATE outgoing_webhooks SET signing_key = $1 WHERE id = $2")
        .bind(&signing_key)
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    Ok(Json(RotateSecretResponse { secret }))
}

// ---------------------------------------------------------------------------
// POST /admin/outgoing-webhooks/:id/enable
// ---------------------------------------------------------------------------

pub async fn enable_webhook(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let rows =
        sqlx::query("UPDATE outgoing_webhooks SET active = TRUE, failure_count = 0 WHERE id = $1")
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// GET /admin/outgoing-webhooks/:id/deliveries
// ---------------------------------------------------------------------------

pub async fn list_deliveries(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<ListDeliveriesQuery>,
) -> Result<Json<Vec<DeliveryRecord>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM outgoing_webhooks WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows: Vec<DeliveryRecord> = sqlx::query_as::<_, DeliveryRecord>(
        "SELECT id, webhook_id, event_type, event_seq, attempted_at, attempt_number,
                status_code, success, error_msg
         FROM outgoing_webhook_deliveries
         WHERE webhook_id = $1
           AND ($2::TEXT IS NULL OR event_type = $2)
           AND ($3::BOOLEAN IS NULL OR success = $3)
         ORDER BY attempted_at DESC
         LIMIT $4 OFFSET $5",
    )
    .bind(&id)
    .bind(&q.event_type)
    .bind(q.success)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(rows))
}
