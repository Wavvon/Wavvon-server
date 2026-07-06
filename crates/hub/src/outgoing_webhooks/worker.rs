//! Event dispatch: matches a hub event against `outgoing_webhook_subscriptions`
//! and spawns a delivery task per matching, active webhook.
//!
//! Called directly from `bots::events::publish_hub_event` (this codebase does
//! not have a `tokio::sync::broadcast` channel for hub events — see the
//! module doc on `bots::events` — so dispatch is a plain async call rather
//! than a subscriber loop).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

use super::delivery;
use super::models::{OutgoingWebhook, WebhookEventEnvelope};
use crate::state::AppState;

/// Internal cross-webhook throughput cap (doc §5/§7): 50 events/s combined.
const RATE_LIMIT_PER_SEC: f64 = 50.0;
const RATE_BURST: f64 = 50.0;

/// Max payload size before truncation (doc §7).
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Retry schedule: 3 retries at 5s, 30s, 5min after the first immediate
/// attempt (4 attempts total, doc §5).
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(300),
];

/// Queue depth above which we log a warning (doc §7).
const QUEUE_DEPTH_WARN_THRESHOLD: i64 = 1000;

/// Simple token bucket shared across all outgoing-webhook deliveries in this
/// process. A `Mutex<f64>` would work too, but atomics avoid lock contention
/// on the hot event-publish path.
struct TokenBucket {
    tokens: std::sync::Mutex<(f64, std::time::Instant)>,
    in_flight: AtomicI64,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: std::sync::Mutex::new((RATE_BURST, std::time::Instant::now())),
            in_flight: AtomicI64::new(0),
        }
    }

    /// Try to take one token. Returns `true` if allowed.
    fn try_take(&self) -> bool {
        let mut guard = self.tokens.lock().unwrap();
        let (tokens, last) = &mut *guard;
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * RATE_LIMIT_PER_SEC).min(RATE_BURST);
        *last = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

static BUCKET: LazyLock<TokenBucket> = LazyLock::new(TokenBucket::new);

/// Dispatch a hub event to all active, subscribed outgoing webhooks.
///
/// `payload` should be the same JSON value used for the bot WS `hub_event`
/// envelope. Errors are logged and swallowed — outgoing webhook delivery is
/// best-effort and must never block `publish_hub_event`.
pub async fn dispatch_event(
    state: &Arc<AppState>,
    event_type: &str,
    channel_id: Option<&str>,
    seq: i64,
    now: i64,
    payload: &serde_json::Value,
) {
    #[derive(sqlx::FromRow)]
    struct SubRow {
        webhook_id: String,
    }

    let subs: Vec<SubRow> = sqlx::query_as::<_, SubRow>(
        "SELECT DISTINCT ows.webhook_id
         FROM outgoing_webhook_subscriptions ows
         JOIN outgoing_webhooks ow ON ow.id = ows.webhook_id
         WHERE ows.event_type = $1
           AND (ows.channel_id = '' OR ows.channel_id = $2)
           AND ow.active = TRUE",
    )
    .bind(event_type)
    .bind(channel_id.unwrap_or(""))
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if subs.is_empty() {
        return;
    }

    let hub_url = crate::bots::dispatch::hub_url_public(state).await;
    let hub_pubkey = state.hub_identity.public_key_hex();

    for sub in subs {
        let webhook: Option<OutgoingWebhook> = sqlx::query_as::<_, OutgoingWebhook>(
            "SELECT id, url, display_name, signing_key, created_by_pubkey, active,
                    failure_count, last_delivery_at, last_failure_at, created_at
             FROM outgoing_webhooks WHERE id = $1 AND active = TRUE",
        )
        .bind(&sub.webhook_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

        let Some(webhook) = webhook else { continue };

        if !BUCKET.try_take() {
            let depth = BUCKET.in_flight.load(Ordering::Relaxed);
            if depth > QUEUE_DEPTH_WARN_THRESHOLD {
                tracing::warn!(
                    depth,
                    "outgoing_webhooks: in-flight delivery queue depth exceeds {QUEUE_DEPTH_WARN_THRESHOLD}"
                );
            }
            tracing::debug!(
                webhook_id = %webhook.id,
                event_type,
                "outgoing_webhooks: rate cap hit, dropping event for this webhook"
            );
            continue;
        }

        let (envelope_payload, truncated) = truncate_if_needed(payload.clone());

        let envelope = WebhookEventEnvelope {
            kind: "hub_event",
            event: event_type.to_string(),
            hub_url: hub_url.clone(),
            webhook_id: webhook.id.clone(),
            at: now,
            seq: Some(seq),
            payload: envelope_payload,
            truncated,
        };

        let state = state.clone();
        let hub_pubkey = hub_pubkey.clone();
        let event_type = event_type.to_string();

        BUCKET.in_flight.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            deliver_with_retries(&state, &hub_pubkey, webhook, envelope, seq, &event_type).await;
            BUCKET.in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Truncate `payload` to `MAX_PAYLOAD_BYTES` if its serialized size exceeds
/// the cap (doc §7). Returns `(payload, truncated)`.
fn truncate_if_needed(payload: serde_json::Value) -> (serde_json::Value, bool) {
    let size = serde_json::to_string(&payload)
        .map(|s| s.len())
        .unwrap_or(0);
    if size <= MAX_PAYLOAD_BYTES {
        return (payload, false);
    }
    (serde_json::Value::Null, true)
}

/// Run the full retry schedule for one event delivery to one webhook:
/// immediate attempt, then 5s/30s/5min retries on failure (doc §5). Logs
/// each attempt and applies failure-count / auto-disable bookkeeping.
async fn deliver_with_retries(
    state: &Arc<AppState>,
    hub_pubkey: &str,
    webhook: OutgoingWebhook,
    envelope: WebhookEventEnvelope,
    seq: i64,
    event_type: &str,
) {
    let mut attempt_number: i64 = 1;

    loop {
        let result =
            delivery::attempt_delivery(&state.http_client, hub_pubkey, &webhook, &envelope).await;

        delivery::record_delivery(
            &state.db,
            &webhook.id,
            event_type,
            Some(seq),
            attempt_number,
            &result,
        )
        .await;

        if result.success {
            delivery::apply_outcome(&state.db, &webhook.id, true).await;
            return;
        }

        let retry_idx = (attempt_number - 1) as usize;
        if retry_idx >= RETRY_DELAYS.len() {
            // All attempts exhausted — permanent failure for this event.
            let disabled = delivery::apply_outcome(&state.db, &webhook.id, false).await;
            if disabled {
                notify_webhook_disabled(state, &webhook.id, result.error_msg.as_deref()).await;
            }
            return;
        }

        tokio::time::sleep(RETRY_DELAYS[retry_idx]).await;
        attempt_number += 1;
    }
}

/// Broadcast a `webhook_disabled` event hub-wide (doc §5). There is no
/// admin-only WS channel in this codebase; the admin settings UI is the
/// intended consumer and other clients ignore the unknown event type.
async fn notify_webhook_disabled(
    state: &Arc<AppState>,
    webhook_id: &str,
    last_error: Option<&str>,
) {
    let ws_msg = crate::routes::chat_models::WsServerMessage::WebhookDisabled {
        webhook_id: webhook_id.to_string(),
        reason: "consecutive_failures".to_string(),
        last_error: last_error.map(|s| s.to_string()),
    };
    let json: Arc<str> = match serde_json::to_string(&ws_msg) {
        Ok(j) => Arc::from(j.as_str()),
        Err(_) => return,
    };
    let _ = state.chat_tx.send((
        crate::routes::chat_models::ChatEvent::WebhookDisabled {
            webhook_id: webhook_id.to_string(),
            reason: "consecutive_failures".to_string(),
            last_error: last_error.map(|s| s.to_string()),
        },
        json,
    ));
}

/// Delete a webhook and all rows that reference it. Exposed here (rather
/// than only in `routes.rs`) so a future replay/cleanup worker can reuse it.
pub async fn delete_webhook_cascade(db: &PgPool, webhook_id: &str) -> Result<u64, sqlx::Error> {
    let rows = sqlx::query("DELETE FROM outgoing_webhooks WHERE id = $1")
        .bind(webhook_id)
        .execute(db)
        .await?
        .rows_affected();
    Ok(rows)
}

/// Generate a fresh nanoid-style identifier for a new webhook. Uses UUIDv4
/// like the rest of the codebase (see `routes::webhooks::create_webhook`)
/// rather than introducing a `nanoid` dependency for a single call site.
pub fn new_webhook_id() -> String {
    format!("wh_{}", Uuid::new_v4().simple())
}
