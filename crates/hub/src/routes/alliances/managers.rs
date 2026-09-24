//! Who may act on one alliance, beyond the hub-wide permission.
//!
//! `alliances.manage` carries the hub-scoped acts — creating an alliance,
//! accepting or declining an invite, leaving. The acts that belong to one
//! relationship (inviting another hub into it, sharing and unsharing a
//! channel, the per-share policies) are carried by this list instead, so
//! "you handle our federation with that community" does not have to mean
//! "you manage every alliance we have" (decisions.md, "Alliance permissions:
//! one hub permission plus a per-alliance grant list").
//!
//! These are **local** permissions over local rows. A partner hub's roles mean
//! nothing here and nothing in this file crosses a hub boundary.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ALLIANCES_MANAGE, ROLES_MANAGE};
use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct AllianceManagerResponse {
    pub alliance_id: String,
    pub role_id: String,
    pub role_name: String,
    pub granted_by: String,
    pub granted_at: i64,
}

/// May `public_key` act on *this* alliance? The hub-wide permission answers
/// yes for every alliance; the grant list answers for one.
///
/// The owner is covered by `user_permissions`, which short-circuits every
/// check for them.
pub async fn can_manage_alliance(
    state: &AppState,
    public_key: &str,
    alliance_id: &str,
) -> Result<bool, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, public_key).await?;
    if perms.has(ALLIANCES_MANAGE) {
        return Ok(true);
    }

    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM alliance_managers am
             JOIN user_roles ur ON ur.role_id = am.role_id
             WHERE am.alliance_id = $1 AND ur.user_public_key = $2
         )",
    )
    .bind(alliance_id)
    .bind(public_key)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

/// The same question, as the refusal the handlers return.
pub async fn require_alliance_manager(
    state: &AppState,
    public_key: &str,
    alliance_id: &str,
) -> Result<(), (StatusCode, String)> {
    if can_manage_alliance(state, public_key, alliance_id).await? {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        "You do not manage this alliance".to_string(),
    ))
}

/// GET /alliances/:id/managers
pub async fn list_alliance_managers(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<Json<Vec<AllianceManagerResponse>>, (StatusCode, String)> {
    super::models::require_alliance_visibility(&state, &user.public_key, &alliance_id).await?;
    require_alliance_manager(&state, &user.public_key, &alliance_id).await?;

    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT am.role_id, r.name, am.granted_by, am.granted_at
         FROM alliance_managers am
         JOIN roles r ON r.id = am.role_id
         WHERE am.alliance_id = $1
         ORDER BY r.priority DESC, r.name",
    )
    .bind(&alliance_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(role_id, role_name, granted_by, granted_at)| AllianceManagerResponse {
                    alliance_id: alliance_id.clone(),
                    role_id,
                    role_name,
                    granted_by,
                    granted_at,
                },
            )
            .collect(),
    ))
}

/// PUT /alliances/:id/managers/:role_id
///
/// Granting the list is handing out authority, which is `roles.manage`'s job
/// everywhere else on the hub — the design said `admin`, written before the
/// wildcard went away. Deliberately *not* `alliances.manage`: a delegate must
/// not be able to widen their own delegation.
pub async fn grant_alliance_manager(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, role_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ROLES_MANAGE)?;

    let alliance_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM alliances WHERE id = $1")
            .bind(&alliance_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if alliance_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    let role_priority: Option<i64> = sqlx::query_scalar("SELECT priority FROM roles WHERE id = $1")
        .bind(&role_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let Some(role_priority) = role_priority else {
        return Err((StatusCode::NOT_FOUND, "Role not found".to_string()));
    };

    // The escalation ceiling, same as direct role assignment: delegating an
    // alliance to a role above your own hands authority upward.
    if !perms.is_owner && role_priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot delegate an alliance to a role at or above your own priority".to_string(),
        ));
    }

    sqlx::query(
        "INSERT INTO alliance_managers (alliance_id, role_id, granted_by, granted_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (alliance_id, role_id) DO NOTHING",
    )
    .bind(&alliance_id)
    .bind(&role_id)
    .bind(&user.public_key)
    .bind(crate::auth::handlers::unix_timestamp())
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /alliances/:id/managers/:role_id
pub async fn revoke_alliance_manager(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, role_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ROLES_MANAGE)?;

    sqlx::query("DELETE FROM alliance_managers WHERE alliance_id = $1 AND role_id = $2")
        .bind(&alliance_id)
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}
