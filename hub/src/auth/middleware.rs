use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;

use crate::state::AppState;

pub struct AuthUser {
    pub public_key: String,
}

/// Paths that pending (not-yet-approved) users are allowed to hit.
/// They can see their own status at /me and nothing else.
const PENDING_ALLOWED_PATHS: &[&str] = &["/me"];

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization format".to_string()))?;

        // Try sessions first
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT s.public_key, u.approval_status
             FROM sessions s
             INNER JOIN users u ON s.public_key = u.public_key
             WHERE s.token = ?",
        )
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        let (public_key, approval_status) = if let Some(r) = row {
            r
        } else {
            // Try bot tokens
            let bot_key: Option<String> = sqlx::query_scalar(
                "SELECT public_key FROM bot_tokens WHERE token = ?",
            )
            .bind(token)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            match bot_key {
                Some(pk) => (pk, "approved".to_string()),
                None => return Err((StatusCode::UNAUTHORIZED, "Invalid or expired token".to_string())),
            }
        };

        // Reject revoked keys. In the current single-key model public_key == subkey_pubkey;
        // this check is forward-compatible with the master+subkey design.
        let is_revoked: bool = sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM subkey_revocations WHERE subkey_pubkey = ?",
        )
        .bind(&public_key)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false);

        if is_revoked {
            return Err((StatusCode::UNAUTHORIZED, "Key has been revoked".to_string()));
        }

        if approval_status == "pending" {
            let path = parts.uri.path();
            if !PENDING_ALLOWED_PATHS.iter().any(|p| path == *p) {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Account is pending admin approval".to_string(),
                ));
            }
        }

        Ok(AuthUser { public_key })
    }
}
