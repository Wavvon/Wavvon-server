//! Background worker that retries pending DM deliveries in `dm_outbox`.
//!
//! A row lands in the outbox when `send_dm` can't reach the recipient's hub
//! synchronously. The worker wakes on a fixed interval, reconstructs the
//! envelope from `dm_messages` + `conversation_members`, and re-attempts
//! delivery with exponential backoff. After the final attempt we mark the
//! row bounced instead of deleting it, so the UI can surface failures later.

use std::sync::Arc;
use std::time::Duration;

use crate::routes::dm_models::FederatedDmRequest;
use crate::state::AppState;

/// Backoff schedule, in seconds. Index = attempt count (0 = first retry).
/// After the last entry we mark the row bounced.
const BACKOFF_SECS: &[i64] = &[10, 60, 300, 1800, 3600, 21600, 86400];

/// How often the worker wakes to look for due deliveries.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("DM outbox tick failed: {e}");
            }
        }
    });
}

/// Run a single pass over the outbox. Public so tests can drive it directly.
pub async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::auth::handlers::unix_timestamp();

    let due: Vec<OutboxRow> = sqlx::query_as::<_, OutboxRow>(
        "SELECT message_id, recipient_hub_url, attempts
         FROM dm_outbox
         WHERE bounced_at IS NULL AND next_attempt_at <= ?
         LIMIT 100",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    for row in due {
        let Some(envelope) = load_envelope(state, &row.message_id).await? else {
            // Message was deleted from dm_messages — drop the orphan.
            sqlx::query("DELETE FROM dm_outbox WHERE message_id = ? AND recipient_hub_url = ?")
                .bind(&row.message_id)
                .bind(&row.recipient_hub_url)
                .execute(&state.db)
                .await?;
            continue;
        };

        match super::routes::dms::deliver_federated_dm_public(state, &row.recipient_hub_url, &envelope).await {
            Ok(()) => {
                sqlx::query("DELETE FROM dm_outbox WHERE message_id = ? AND recipient_hub_url = ?")
                    .bind(&row.message_id)
                    .bind(&row.recipient_hub_url)
                    .execute(&state.db)
                    .await?;
                tracing::info!(
                    "DM {} delivered to {} after {} retries",
                    &row.message_id[..8],
                    row.recipient_hub_url,
                    row.attempts
                );
            }
            Err(err) => {
                let next_attempts = row.attempts + 1;
                let backoff_idx = row.attempts as usize;
                if backoff_idx >= BACKOFF_SECS.len() {
                    sqlx::query(
                        "UPDATE dm_outbox SET attempts = ?, last_error = ?, bounced_at = ?
                         WHERE message_id = ? AND recipient_hub_url = ?",
                    )
                    .bind(next_attempts)
                    .bind(&err)
                    .bind(now)
                    .bind(&row.message_id)
                    .bind(&row.recipient_hub_url)
                    .execute(&state.db)
                    .await?;
                    tracing::warn!(
                        "DM {} bounced after {} attempts: {err}",
                        &row.message_id[..8],
                        next_attempts
                    );
                } else {
                    let next_at = now + BACKOFF_SECS[backoff_idx];
                    sqlx::query(
                        "UPDATE dm_outbox SET attempts = ?, next_attempt_at = ?, last_error = ?
                         WHERE message_id = ? AND recipient_hub_url = ?",
                    )
                    .bind(next_attempts)
                    .bind(next_at)
                    .bind(&err)
                    .bind(&row.message_id)
                    .bind(&row.recipient_hub_url)
                    .execute(&state.db)
                    .await?;
                }
            }
        }
    }
    Ok(())
}

async fn load_envelope(
    state: &AppState,
    message_id: &str,
) -> Result<Option<FederatedDmRequest>, sqlx::Error> {
    use crate::routes::dm_models::EncryptedDmEnvelope;

    let Some(msg): Option<(String, String, String, Option<String>, Option<String>, Option<String>, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, conversation_id, sender, content, attachments, signature, created_at,
                COALESCE(is_encrypted, 0), ciphertext_json
         FROM dm_messages WHERE id = ?",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?
    else {
        return Ok(None);
    };

    let conv_type: String =
        sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = ?")
            .bind(&msg.1)
            .fetch_one(&state.db)
            .await?;

    let members: Vec<String> =
        sqlx::query_scalar("SELECT public_key FROM conversation_members WHERE conversation_id = ?")
            .bind(&msg.1)
            .fetch_all(&state.db)
            .await?;

    let attachments = msg
        .4
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let is_encrypted = msg.7 != 0;
    let encrypted_envelope = if is_encrypted {
        msg.8
            .as_deref()
            .and_then(|s| serde_json::from_str::<EncryptedDmEnvelope>(s).ok())
    } else {
        None
    };

    Ok(Some(FederatedDmRequest {
        message_id: msg.0,
        conversation_id: msg.1,
        conv_type,
        sender: msg.2,
        members,
        content: msg.3,
        attachments,
        signature: msg.5,
        created_at: msg.6,
        encrypted_envelope,
    }))
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
    message_id: String,
    recipient_hub_url: String,
    attempts: i64,
}
