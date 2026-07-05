use axum::http::StatusCode;

/// Returns true when the user has an active hub-level ban.
pub async fn is_banned(db: &sqlx::PgPool, public_key: &str) -> Result<bool, (StatusCode, String)> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bans WHERE target_public_key = $1")
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
        "SELECT COUNT(*) FROM mutes WHERE target_public_key = $1 AND (expires_at IS NULL OR expires_at > $2)",
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
        "SELECT COUNT(*) FROM channel_bans WHERE channel_id = $1 AND target_public_key = $2",
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
        sqlx::query_scalar("SELECT COUNT(*) FROM voice_mutes WHERE target_public_key = $1")
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
        "SELECT COUNT(*) FROM channel_voice_mutes WHERE channel_id = $1 AND pubkey = $2",
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
        "SELECT COUNT(*) FROM raise_hand_requests WHERE channel_id = $1 AND pubkey = $2",
    )
    .bind(channel_id)
    .bind(pubkey)
    .fetch_one(db)
    .await
    .unwrap_or(0)
        > 0
}

/// The single source of truth for the federated-ban admission policy, given
/// the already-resolved check key (master pubkey, or canonical for users with
/// no paired master):
///
/// 1. Local override `whitelist` → always admit.
/// 2. Local override `blacklist` → always deny.
/// 3. A ban from any `hard-reject` source → deny.
/// 4. A ban from a source not in `federated_ban_sources` (legacy path) → deny.
/// 5. Otherwise (incl. soft-flag-only sources) → admit.
///
/// Every enforcement point (auth verify, farm-token middleware, message
/// submission) must call this — the overrides were once missed at the message
/// layer because the policy was duplicated inline.
pub async fn is_denied_by_federated_policy(
    db: &sqlx::PgPool,
    check_key: &str,
) -> Result<bool, sqlx::Error> {
    let override_type: Option<String> = sqlx::query_scalar(
        "SELECT override_type FROM federated_ban_overrides WHERE target_pubkey = $1",
    )
    .bind(check_key)
    .fetch_optional(db)
    .await?;

    match override_type.as_deref() {
        Some("whitelist") => return Ok(false),
        Some("blacklist") => return Ok(true),
        _ => {}
    }

    let hard_reject_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federated_bans fb
         JOIN federated_ban_sources fbs ON fbs.issuer_pubkey = fb.source_hub_pubkey
         WHERE fb.target_master_pubkey = $1
           AND fbs.policy = 'hard-reject'",
    )
    .bind(check_key)
    .fetch_one(db)
    .await?;
    if hard_reject_count > 0 {
        return Ok(true);
    }

    let legacy_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM federated_bans fb
         WHERE fb.target_master_pubkey = $1
           AND NOT EXISTS (
               SELECT 1 FROM federated_ban_sources fbs
               WHERE fbs.issuer_pubkey = fb.source_hub_pubkey
           )",
    )
    .bind(check_key)
    .fetch_one(db)
    .await?;
    Ok(legacy_count > 0)
}

/// Returns true if the federated-ban policy denies this user, resolving the
/// user's master key first (or canonical pubkey for users with no paired
/// master). Thin wrapper over [`is_denied_by_federated_policy`] for callers
/// that only have the session pubkey.
pub async fn is_federated_banned(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<bool, (StatusCode, String)> {
    let master_pk: Option<String> =
        sqlx::query_scalar("SELECT master_pubkey FROM users WHERE public_key = $1")
            .bind(public_key)
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    let check_key = master_pk.as_deref().unwrap_or(public_key);

    is_denied_by_federated_policy(db, check_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
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
