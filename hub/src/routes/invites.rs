use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MANAGE_CHANNELS};
use crate::routes::invite_models::{CreateInviteRequest, InviteResponse};
use crate::state::AppState;

pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    let code = generate_invite_code();
    let now = crate::auth::handlers::unix_timestamp();
    let expires_at = req.expires_in_seconds.map(|s| now + s);

    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&code)
    .bind(&user.public_key)
    .bind(req.max_uses)
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            code,
            created_by: user.public_key,
            max_uses: req.max_uses,
            uses: 0,
            expires_at,
            created_at: now,
        }),
    ))
}

pub async fn list_invites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<InviteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    let rows = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at FROM invites ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| InviteResponse {
                code: r.code,
                created_by: r.created_by,
                max_uses: r.max_uses,
                uses: r.uses,
                expires_at: r.expires_at,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(code): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    sqlx::query("DELETE FROM invites WHERE code = ?")
        .bind(&code)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Called during auth to validate and consume an invite code.
/// Returns Ok(()) if the code is valid, Err if not.
pub async fn validate_and_use_invite(
    db: &sqlx::SqlitePool,
    code: &str,
) -> Result<(), (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    let invite = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at FROM invites WHERE code = ?",
    )
    .bind(code)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::FORBIDDEN, "Invalid invite code".to_string()))?;

    if let Some(expires_at) = invite.expires_at {
        if now > expires_at {
            return Err((StatusCode::FORBIDDEN, "Invite code has expired".to_string()));
        }
    }

    if let Some(max_uses) = invite.max_uses {
        if invite.uses >= max_uses {
            return Err((StatusCode::FORBIDDEN, "Invite code has been used up".to_string()));
        }
    }

    // Increment usage
    sqlx::query("UPDATE invites SET uses = uses + 1 WHERE code = ?")
        .bind(code)
        .execute(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(())
}

/// Check if the hub requires invites
pub async fn is_invite_only(db: &sqlx::SqlitePool) -> Result<bool, (StatusCode, String)> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'invite_only'",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(value.as_deref() == Some("true"))
}

fn generate_invite_code() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(sqlx::FromRow)]
struct InviteRow {
    code: String,
    created_by: String,
    max_uses: Option<i64>,
    uses: i64,
    expires_at: Option<i64>,
    created_at: i64,
}
