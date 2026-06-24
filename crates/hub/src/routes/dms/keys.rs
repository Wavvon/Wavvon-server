use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::routes::dm_models::{GroupSenderKeyEntry, PushSenderKeyRequest, SenderKeyRecipientBlob};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Signing-bytes helpers — delegate to the identity crate
// ---------------------------------------------------------------------------

pub(super) fn envelope_signing_bytes(
    env: &crate::routes::dm_models::EncryptedDmEnvelope,
) -> Vec<u8> {
    voxply_identity::dm_envelope_signing_bytes(
        &env.conv_id,
        &env.ciphertext_hex,
        &env.nonce_hex,
        &env.dh_pubkey_hex,
    )
}

pub(super) fn group_envelope_signing_bytes(
    conv_id: &str,
    version: u32,
    iteration: u32,
    ciphertext_hex: &str,
    nonce_hex: &str,
) -> Vec<u8> {
    voxply_identity::group_dm_envelope_signing_bytes(
        conv_id,
        version,
        iteration,
        ciphertext_hex,
        nonce_hex,
    )
}

fn sender_key_dist_signing_bytes(
    conv_id: &str,
    version: u32,
    recipients: &[SenderKeyRecipientBlob],
) -> Vec<u8> {
    let pairs: Vec<(String, String)> = recipients
        .iter()
        .map(|r| (r.recipient_pubkey.clone(), r.wrapped_key_hex.clone()))
        .collect();
    voxply_identity::sender_key_dist_signing_bytes(conv_id, version, &pairs)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn push_sender_keys(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Json(req): Json<PushSenderKeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Membership check
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ? AND public_key = ?",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_member == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    // Only group conversations support sender-key distribution
    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = ?")
        .bind(&conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    if conv_type != "group" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Sender-key distribution is only for group conversations".to_string(),
        ));
    }

    // Verify Ed25519 signature over the distribution payload
    let msg =
        sender_key_dist_signing_bytes(&conversation_id, req.sender_key_version, &req.recipients);
    let sig_bytes = hex::decode(&req.signature_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature hex: {e}")))?;
    voxply_identity::verify_signature(&user.public_key, &msg, &sig_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid distribution signature: {e}"),
        )
    })?;

    let now = crate::auth::handlers::unix_timestamp();

    for blob in &req.recipients {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO group_sender_key_distributions
             (id, conv_id, sender_pubkey, recipient_pubkey, sender_key_version, iteration, wrapped_key_hex, wrap_nonce_hex, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(conv_id, sender_pubkey, recipient_pubkey, sender_key_version)
             DO UPDATE SET
               iteration       = excluded.iteration,
               wrapped_key_hex = excluded.wrapped_key_hex,
               wrap_nonce_hex  = excluded.wrap_nonce_hex,
               created_at      = excluded.created_at",
        )
        .bind(&id)
        .bind(&conversation_id)
        .bind(&user.public_key)
        .bind(&blob.recipient_pubkey)
        .bind(req.sender_key_version as i64)
        .bind(blob.iteration as i64)
        .bind(&blob.wrapped_key_hex)
        .bind(&blob.wrap_nonce_hex)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct SenderKeyRow {
    sender_pubkey: String,
    sender_key_version: i64,
    iteration: i64,
    wrapped_key_hex: String,
    wrap_nonce_hex: String,
    created_at: i64,
}

pub async fn get_sender_keys(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<Vec<GroupSenderKeyEntry>>, (StatusCode, String)> {
    // Membership check
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ? AND public_key = ?",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_member == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    let rows = sqlx::query_as::<_, SenderKeyRow>(
        "SELECT sender_pubkey, sender_key_version, iteration, wrapped_key_hex, wrap_nonce_hex, created_at
         FROM group_sender_key_distributions
         WHERE conv_id = ? AND recipient_pubkey = ?
         ORDER BY sender_pubkey, sender_key_version",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let entries = rows
        .into_iter()
        .map(|r| GroupSenderKeyEntry {
            sender_pubkey: r.sender_pubkey,
            sender_key_version: r.sender_key_version as u32,
            iteration: r.iteration as u32,
            wrapped_key_hex: r.wrapped_key_hex,
            wrap_nonce_hex: r.wrap_nonce_hex,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(entries))
}
