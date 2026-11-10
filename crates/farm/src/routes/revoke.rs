/// POST /farm/auth/revoke-check — belt-and-braces revocation check for hubs.
///
/// Hubs that want stronger-than-expiry revocation guarantees call this endpoint
/// with the token's `jti` and cache the answer for 60s. The `jti` is not
/// guessable so no auth is required on this endpoint.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::FarmState;

#[derive(Deserialize)]
pub struct RevokeCheckRequest {
    pub jti: String,
}

#[derive(Serialize)]
pub struct RevokeCheckResponse {
    pub revoked: bool,
}

pub async fn revoke_check(
    State(state): State<Arc<FarmState>>,
    Json(req): Json<RevokeCheckRequest>,
) -> Result<Json<RevokeCheckResponse>, (StatusCode, String)> {
    let revoked = !session_is_live(&state.db, &req.jti).await;
    Ok(Json(RevokeCheckResponse { revoked }))
}

/// A session is live when its jti is known, not revoked and not expired. A
/// database error reads as not live: this gates authentication, so it fails
/// closed.
pub(crate) async fn session_is_live(db: &sqlx::PgPool, jti: &str) -> bool {
    let row: Result<Option<(Option<i64>, i64)>, _> =
        sqlx::query_as("SELECT revoked_at, expires_at FROM farm_sessions WHERE jti = $1")
            .bind(jti)
            .fetch_optional(db)
            .await;
    matches!(row, Ok(Some((None, expires_at))) if crate::unix_now() < expires_at)
}

/// POST /farm/revocations — a device revocation a hosted hub learned of.
///
/// Unauthenticated like the hub's own revocation route: the master's
/// signature is the whole proof, and anyone relaying a validly signed
/// revocation is doing the user a favour. On a new one, every farm session
/// that device opened is revoked (a session row records the signing device).
pub async fn receive_revocation(
    State(state): State<Arc<FarmState>>,
    Json(entry): Json<wavvon_identity::RevocationEntry>,
) -> Result<StatusCode, (StatusCode, String)> {
    entry
        .verify()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature: {e}")))?;
    let now = crate::unix_now();
    let inserted = sqlx::query(
        "INSERT INTO farm_subkey_revocations
            (master_pubkey, subkey_pubkey, revoked_at, signature, received_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (master_pubkey, subkey_pubkey) DO NOTHING",
    )
    .bind(&entry.master_pubkey)
    .bind(&entry.subkey_pubkey)
    .bind(entry.revoked_at as i64)
    .bind(&entry.signature)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if inserted.rows_affected() > 0 {
        sqlx::query(
            "UPDATE farm_sessions SET revoked_at = $1
             WHERE public_key = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(&entry.subkey_pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Whether `subkey` is a device `master` has revoked. Fails closed.
pub(crate) async fn device_revoked(db: &sqlx::PgPool, master: &str, subkey: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM farm_subkey_revocations
                        WHERE master_pubkey = $1 AND subkey_pubkey = $2)",
    )
    .bind(master)
    .bind(subkey)
    .fetch_one(db)
    .await
    .unwrap_or(true)
}
