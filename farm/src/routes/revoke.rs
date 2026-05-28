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
    // A session is considered revoked if:
    // - The jti doesn't exist in farm_sessions (unknown token → treat as revoked).
    // - revoked_at IS NOT NULL.
    // - expires_at is in the past.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let row: Option<(Option<i64>, i64)> = sqlx::query_as(
        "SELECT revoked_at, expires_at FROM farm_sessions WHERE jti = ?",
    )
    .bind(&req.jti)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let revoked = match row {
        None => true, // unknown jti
        Some((revoked_at, expires_at)) => revoked_at.is_some() || now >= expires_at,
    };

    Ok(Json(RevokeCheckResponse { revoked }))
}
