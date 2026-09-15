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
        "SELECT message_id, recipient_hub_url, attempts, COALESCE(mirror, FALSE) AS mirror
         FROM dm_outbox
         WHERE bounced_at IS NULL AND next_attempt_at <= $1
         LIMIT 100",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    for row in due {
        let loaded = match load_envelope(state, &row.message_id).await {
            Ok(v) => v,
            // One unreadable row must not take the queue with it: propagating
            // here aborts the whole batch and the next tick starts on the same
            // row, so every other queued DM waits behind it forever. Bounce it
            // with the reason recorded, exactly like a delivery that kept
            // failing, and carry on.
            Err(LoadEnvelopeError::Unreadable(why)) => {
                sqlx::query(
                    "UPDATE dm_outbox SET last_error = $1, bounced_at = $2
                     WHERE message_id = $3 AND recipient_hub_url = $4",
                )
                .bind(&why)
                .bind(now)
                .bind(&row.message_id)
                .bind(&row.recipient_hub_url)
                .execute(&state.db)
                .await?;
                tracing::error!("DM {} bounced unsent: {why}", &row.message_id[..8]);
                continue;
            }
            Err(LoadEnvelopeError::Db(e)) => return Err(e),
        };
        let Some(mut envelope) = loaded else {
            // Message was deleted from dm_messages — drop the orphan.
            sqlx::query("DELETE FROM dm_outbox WHERE message_id = $1 AND recipient_hub_url = $2")
                .bind(&row.message_id)
                .bind(&row.recipient_hub_url)
                .execute(&state.db)
                .await?;
            continue;
        };

        // A copy stays a copy across retries — see the `mirror` column.
        envelope.mirror = row.mirror;

        match super::routes::dms::deliver_federated_dm_public(
            state,
            &row.recipient_hub_url,
            &envelope,
        )
        .await
        {
            Ok(()) => {
                sqlx::query(
                    "DELETE FROM dm_outbox WHERE message_id = $1 AND recipient_hub_url = $2",
                )
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
                        "UPDATE dm_outbox SET attempts = $1, last_error = $2, bounced_at = $3
                         WHERE message_id = $4 AND recipient_hub_url = $5",
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
                        "UPDATE dm_outbox SET attempts = $1, next_attempt_at = $2, last_error = $3
                         WHERE message_id = $4 AND recipient_hub_url = $5",
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

/// A row that cannot be rebuilt is not the same failure as a database that
/// cannot be read: one is about this message, the other about every message.
enum LoadEnvelopeError {
    Db(sqlx::Error),
    Unreadable(String),
}

impl From<sqlx::Error> for LoadEnvelopeError {
    fn from(e: sqlx::Error) -> Self {
        LoadEnvelopeError::Db(e)
    }
}

async fn load_envelope(
    state: &AppState,
    message_id: &str,
) -> Result<Option<FederatedDmRequest>, LoadEnvelopeError> {
    use crate::routes::dm_models::{EncryptedDmEnvelope, GroupEncryptedEnvelope};

    #[allow(clippy::type_complexity)]
    let Some(msg): Option<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        bool,
        Option<String>,
        bool,
    )> = sqlx::query_as(
        "SELECT id, conversation_id, sender, content, attachments, signature, created_at,
                COALESCE(is_encrypted, FALSE), ciphertext_json,
                COALESCE(is_group_encrypted, FALSE)
         FROM dm_messages WHERE id = $1",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?
    else {
        return Ok(None);
    };

    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = $1")
        .bind(&msg.1)
        .fetch_one(&state.db)
        .await?;

    let members: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM conversation_members WHERE conversation_id = $1",
    )
    .bind(&msg.1)
    .fetch_all(&state.db)
    .await?;

    let attachments = msg
        .4
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let is_encrypted = msg.7;
    let is_group_encrypted = msg.9;

    // A row that says "encrypted" whose stored envelope will not parse used to
    // be delivered anyway — an encrypted DM carrying nothing, which at the far
    // end is what a tampered message looks like, recorded here as a success.
    // Nothing has been seen to produce it (this code wrote the JSON on send),
    // but this is the crate that changes envelope formats without migrating
    // what is already queued, which is exactly that shape. It now refuses,
    // and the caller bounces the row with the reason on it.
    let envelope_json = |flag: bool, kind: &str| -> Result<Option<&str>, LoadEnvelopeError> {
        if !flag {
            return Ok(None);
        }
        msg.8.as_deref().map(Some).ok_or_else(|| {
            LoadEnvelopeError::Unreadable(format!("{kind} is set but ciphertext_json is NULL"))
        })
    };

    let encrypted_envelope = match envelope_json(is_encrypted, "is_encrypted")? {
        Some(s) => Some(serde_json::from_str::<EncryptedDmEnvelope>(s).map_err(|e| {
            LoadEnvelopeError::Unreadable(format!("unparsable EncryptedDmEnvelope: {e}"))
        })?),
        None => None,
    };

    let group_encrypted_envelope = match envelope_json(is_group_encrypted, "is_group_encrypted")? {
        Some(s) => Some(
            serde_json::from_str::<GroupEncryptedEnvelope>(s).map_err(|e| {
                LoadEnvelopeError::Unreadable(format!("unparsable GroupEncryptedEnvelope: {e}"))
            })?,
        ),
        None => None,
    };

    // Re-derive the top-level signer_cert from the stored envelope so a
    // retried delivery carries the same cert-chained attribution proof the
    // original send did (see dm_models.rs::FederatedDmRequest::signer_cert).
    let signer_cert = encrypted_envelope
        .as_ref()
        .and_then(|e| e.signer_cert.clone());

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
        group_encrypted_envelope,
        sender_hub_url: None,
        signer_cert,
        // Set per row by the caller: the message is neither an original nor a
        // copy, the *delivery* is.
        mirror: false,
    }))
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
    message_id: String,
    recipient_hub_url: String,
    attempts: i64,
    mirror: bool,
}
