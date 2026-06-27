use axum::http::StatusCode;

/// Returns true when the user has an active hub-level ban.
pub async fn is_banned(db: &sqlx::PgPool, public_key: &str) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bans WHERE target_public_key = ?")
        .bind(public_key)
        .fetch_one(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_muted(db: &sqlx::PgPool, public_key: &str) -> Result<bool, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // Check for permanent mute (no expires_at) or active timeout (expires_at > now)
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mutes WHERE target_public_key = ? AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(public_key)
    .bind(now)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_channel_banned(
    db: &sqlx::PgPool,
    channel_id: &str,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_bans WHERE channel_id = ? AND target_public_key = ?",
    )
    .bind(channel_id)
    .bind(public_key)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_voice_muted(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM voice_mutes WHERE target_public_key = ?")
            .bind(public_key)
            .fetch_one(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

pub async fn is_channel_voice_muted(
    db: &sqlx::PgPool,
    channel_id: &str,
    pubkey: &str,
) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_voice_mutes WHERE channel_id = ? AND pubkey = ?",
    )
    .bind(channel_id)
    .bind(pubkey)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(count > 0)
}

pub async fn has_raised_hand(db: &sqlx::PgPool, channel_id: &str, pubkey: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM raise_hand_requests WHERE channel_id = ? AND pubkey = ?",
    )
    .bind(channel_id)
    .bind(pubkey)
    .fetch_one(db)
    .await
    .unwrap_or(0)
        > 0
}

/// Returns true if the user's master key (or canonical pubkey for users with
/// no paired master) appears in `federated_bans`.
///
/// Mirrors the check in `auth/middleware.rs` so the same policy is enforced
/// at the message-submission layer. One indexed query on
/// `idx_federated_bans_target`; no cache needed since federated bans are rare.
pub async fn is_federated_banned(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let master_pk: Option<String> =
        sqlx::query_scalar("SELECT master_pubkey FROM users WHERE public_key = ?")
            .bind(public_key)
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    let check_key = master_pk.as_deref().unwrap_or(public_key);

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM federated_bans WHERE target_master_pubkey = ?")
            .bind(check_key)
            .fetch_one(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(count > 0)
}

// ---- Federated ban list endpoint ----

/// GET /federation/banlist
///
/// Returns this hub's local ban list as a signed JSON payload so subscribing
/// hubs can ingest it via banlist_worker. Unauthenticated — the Ed25519
/// signature is the authority, matching the badge and cert patterns.
pub async fn get_federation_banlist(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::state::AppState>>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let bans: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT target_public_key, reason, created_at FROM bans ORDER BY created_at DESC LIMIT 1000",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let entries: Vec<serde_json::Value> = bans
        .iter()
        .map(|(pubkey, reason, added_at)| {
            serde_json::json!({
                "master_pubkey": pubkey,
                "reason": reason,
                "added_at": added_at,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "issuer_pubkey": state.hub_identity.public_key_hex(),
        "issued_at": now,
        "entries": entries,
    });

    let payload_str = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialise error: {e}"),
            )
                .into_response();
        }
    };

    let sig = state.hub_identity.sign(payload_str.as_bytes());
    let signed = serde_json::json!({
        "payload": payload,
        "signature": hex::encode(sig.to_bytes()),
    });

    axum::Json(signed).into_response()
}
