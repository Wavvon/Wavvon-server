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
