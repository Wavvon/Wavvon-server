//! Single-attempt delivery: sign, POST, log, update failure bookkeeping.
//!
//! Retry scheduling across attempts lives in `worker.rs`; this module only
//! knows how to make one HTTP attempt and record its outcome.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use super::models::{OutgoingWebhook, WebhookEventEnvelope};

type HmacSha256 = Hmac<Sha256>;

/// Per-request timeout (doc §5).
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Delivery log rows retained per webhook (doc §6).
const DELIVERY_LOG_RETENTION: i64 = 200;

/// Threshold at which a webhook is auto-disabled (doc §5).
pub const AUTO_DISABLE_THRESHOLD: i64 = 5;

pub struct DeliveryResult {
    pub success: bool,
    pub status_code: Option<i64>,
    pub error_msg: Option<String>,
}

/// Sign `body` with `signing_key_hex` (hex-decoded HKDF output) using
/// HMAC-SHA256, returning the hex-encoded signature.
pub fn sign_body(signing_key_hex: &str, body: &[u8]) -> Result<String, String> {
    let key_bytes = hex::decode(signing_key_hex).map_err(|e| format!("bad signing key: {e}"))?;
    let mut mac =
        HmacSha256::new_from_slice(&key_bytes).map_err(|e| format!("bad HMAC key: {e}"))?;
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Make a single HTTP delivery attempt: sign the envelope, POST it, and
/// return the outcome. Does not write to the DB — callers log the attempt.
pub async fn attempt_delivery(
    http_client: &reqwest::Client,
    hub_pubkey_hex: &str,
    webhook: &OutgoingWebhook,
    envelope: &WebhookEventEnvelope,
) -> DeliveryResult {
    let body_json = match serde_json::to_string(envelope) {
        Ok(j) => j,
        Err(e) => {
            return DeliveryResult {
                success: false,
                status_code: None,
                error_msg: Some(format!("serialize error: {e}")),
            }
        }
    };

    let signature = match sign_body(&webhook.signing_key, body_json.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            return DeliveryResult {
                success: false,
                status_code: None,
                error_msg: Some(e),
            }
        }
    };

    let timestamp = crate::auth::handlers::unix_timestamp();

    let resp = http_client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Wavvon-Hub-Pubkey", hub_pubkey_hex)
        .header("X-Wavvon-Signature", &signature)
        .header("X-Wavvon-Timestamp", timestamp.to_string())
        .header("X-Wavvon-Webhook-Id", &webhook.id)
        .body(body_json)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status = r.status();
            if status.is_success() {
                DeliveryResult {
                    success: true,
                    status_code: Some(status.as_u16() as i64),
                    error_msg: None,
                }
            } else {
                DeliveryResult {
                    success: false,
                    status_code: Some(status.as_u16() as i64),
                    error_msg: Some(format!("non-2xx status: {status}")),
                }
            }
        }
        Err(e) => DeliveryResult {
            success: false,
            status_code: None,
            error_msg: Some(e.to_string()),
        },
    }
}

/// Write a delivery log row, then prune older rows beyond the retention
/// window for this webhook (doc §6).
pub async fn record_delivery(
    db: &PgPool,
    webhook_id: &str,
    event_type: &str,
    event_seq: Option<i64>,
    attempt_number: i64,
    result: &DeliveryResult,
) {
    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    if let Err(e) = sqlx::query(
        "INSERT INTO outgoing_webhook_deliveries
            (id, webhook_id, event_type, event_seq, attempted_at, attempt_number, status_code, success, error_msg)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&id)
    .bind(webhook_id)
    .bind(event_type)
    .bind(event_seq)
    .bind(now)
    .bind(attempt_number)
    .bind(result.status_code)
    .bind(result.success)
    .bind(&result.error_msg)
    .execute(db)
    .await
    {
        tracing::warn!("outgoing_webhooks: failed to write delivery log row: {e}");
        return;
    }

    // Prune to the last DELIVERY_LOG_RETENTION rows for this webhook.
    if let Err(e) = sqlx::query(
        "DELETE FROM outgoing_webhook_deliveries
         WHERE webhook_id = $1
           AND id NOT IN (
             SELECT id FROM outgoing_webhook_deliveries
             WHERE webhook_id = $1
             ORDER BY attempted_at DESC
             LIMIT $2
           )",
    )
    .bind(webhook_id)
    .bind(DELIVERY_LOG_RETENTION)
    .execute(db)
    .await
    {
        tracing::warn!("outgoing_webhooks: failed to prune delivery log: {e}");
    }
}

/// Apply the post-attempt bookkeeping to `outgoing_webhooks`: on success,
/// reset `failure_count` and stamp `last_delivery_at`; on final failure,
/// increment `failure_count`, stamp `last_failure_at`, and auto-disable if
/// the threshold is reached.
///
/// Returns `true` if this call caused the webhook to be auto-disabled.
pub async fn apply_outcome(db: &PgPool, webhook_id: &str, success: bool) -> bool {
    let now = crate::auth::handlers::unix_timestamp();

    if success {
        let _ = sqlx::query(
            "UPDATE outgoing_webhooks SET failure_count = 0, last_delivery_at = $1 WHERE id = $2",
        )
        .bind(now)
        .bind(webhook_id)
        .execute(db)
        .await;
        return false;
    }

    let new_count: Option<i64> = sqlx::query_scalar(
        "UPDATE outgoing_webhooks
         SET failure_count = failure_count + 1, last_failure_at = $1
         WHERE id = $2
         RETURNING failure_count",
    )
    .bind(now)
    .bind(webhook_id)
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    let Some(count) = new_count else {
        return false;
    };

    if count >= AUTO_DISABLE_THRESHOLD {
        let _ = sqlx::query("UPDATE outgoing_webhooks SET active = FALSE WHERE id = $1")
            .bind(webhook_id)
            .execute(db)
            .await;
        true
    } else {
        false
    }
}
