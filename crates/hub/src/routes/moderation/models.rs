use axum::http::StatusCode;

use crate::permissions;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(super) struct BanRow {
    pub target_public_key: String,
    pub banned_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct MuteRow {
    pub target_public_key: String,
    pub muted_by: String,
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct ChannelBanRow {
    pub channel_id: String,
    pub target_public_key: String,
    pub banned_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct VoiceMuteRow {
    pub target_public_key: String,
    pub muted_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

pub(super) async fn require_can_moderate(
    state: &AppState,
    actor_key: &str,
    target_key: &str,
    permission: &str,
) -> Result<(), (StatusCode, String)> {
    let actor_perms = permissions::user_permissions(&state.db, actor_key).await?;
    actor_perms.require(permission)?;

    let target_perms = permissions::user_permissions(&state.db, target_key).await?;
    if target_perms.max_priority >= actor_perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot moderate a user with equal or higher priority".to_string(),
        ));
    }
    Ok(())
}
