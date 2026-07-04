//! Admin routes for channel-scoped role permission overwrites.
//! See docs/docs/nested-channels-ux.md §3.6.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN, ALL_PERMISSIONS, MANAGE_ROLES};
use crate::state::AppState;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChannelPermissionsResponse {
    pub channel_id: String,
    pub roles: Vec<RolePermissionsView>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RolePermissionsView {
    pub role_id: String,
    pub role_name: String,
    /// Explicit overwrite rows set on this channel for this role.
    pub overwrites: OverwriteSet,
    /// Resolved effective set from baseline + ancestor cascade, *excluding*
    /// this channel's own explicit rows -- what the role would have here if
    /// nothing were overridden on this exact channel.
    pub inherited: Vec<String>,
    /// Resolved effective set from baseline + ancestor cascade + this
    /// channel's own explicit rows.
    pub effective: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub struct OverwriteSet {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct RoleIdName {
    id: String,
    name: String,
}

async fn require_channel_exists(
    db: &sqlx::PgPool,
    channel_id: &str,
) -> Result<(), (StatusCode, String)> {
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "channel not found".to_string()));
    }
    Ok(())
}

/// Returns the role's (name, priority) if it exists. Priority is needed by
/// the hub-wide-style guard below: a channel-permission manager must not be
/// able to edit overwrites for a role at or above their own rank (mirrors
/// `roles.rs` assign/update/delete).
async fn require_role(
    db: &sqlx::PgPool,
    role_id: &str,
) -> Result<(String, i64), (StatusCode, String)> {
    sqlx::query_as::<_, (String, i64)>("SELECT name, priority FROM roles WHERE id = $1")
        .bind(role_id)
        .fetch_optional(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "role not found".to_string()))
}

/// Builds the resolved view (explicit overwrites + inherited + effective)
/// for one role on one channel.
async fn role_view(
    db: &sqlx::PgPool,
    channel_id: &str,
    role_id: &str,
    role_name: &str,
) -> Result<RolePermissionsView, (StatusCode, String)> {
    let chain = permissions::ancestor_chain(db, channel_id).await?;
    let ancestors = &chain[..chain.len().saturating_sub(1)];

    let baseline: HashSet<String> =
        sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .fetch_all(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .into_iter()
            .collect();

    let role_ids = vec![role_id.to_string()];
    let rows = permissions::fetch_overwrites(db, &chain, &role_ids).await?;

    let mut inherited: Vec<String> = permissions::fold_overwrites(&baseline, ancestors, &rows)
        .into_iter()
        .collect();
    inherited.sort();

    let mut effective: Vec<String> = permissions::fold_overwrites(&baseline, &chain, &rows)
        .into_iter()
        .collect();
    effective.sort();

    let mut overwrites = OverwriteSet::default();
    for row in rows.iter().filter(|r| r.channel_id == channel_id) {
        if row.allow {
            overwrites.allow.push(row.permission.clone());
        } else {
            overwrites.deny.push(row.permission.clone());
        }
    }
    overwrites.allow.sort();
    overwrites.deny.sort();

    Ok(RolePermissionsView {
        role_id: role_id.to_string(),
        role_name: role_name.to_string(),
        overwrites,
        inherited,
        effective,
    })
}

/// GET /channels/:id/permissions
pub async fn get_channel_permissions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<ChannelPermissionsResponse>, (StatusCode, String)> {
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(MANAGE_ROLES)?;

    require_channel_exists(&state.db, &channel_id).await?;

    let roles: Vec<RoleIdName> =
        sqlx::query_as("SELECT id, name FROM roles ORDER BY priority DESC")
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut out = Vec::with_capacity(roles.len());
    for role in roles {
        out.push(role_view(&state.db, &channel_id, &role.id, &role.name).await?);
    }

    Ok(Json(ChannelPermissionsResponse {
        channel_id,
        roles: out,
    }))
}

/// PUT /channels/:id/permissions/:role_id
pub async fn put_channel_permissions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, role_id)): Path<(String, String)>,
    Json(req): Json<OverwriteSet>,
) -> Result<Json<RolePermissionsView>, (StatusCode, String)> {
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(MANAGE_ROLES)?;

    require_channel_exists(&state.db, &channel_id).await?;
    let (role_name, role_priority) = require_role(&state.db, &role_id).await?;

    // Priority guard (mirrors roles.rs assign/update/delete): a channel
    // manager cannot edit overwrites for a role at or above their own rank.
    if role_priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot edit permission overwrites for a role with priority >= your own".to_string(),
        ));
    }

    for p in req.allow.iter().chain(req.deny.iter()) {
        if !ALL_PERMISSIONS.contains(&p.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("unknown permission: {p}")));
        }
    }
    for p in &req.allow {
        if req.deny.contains(p) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("permission '{p}' cannot be both allowed and denied"),
            ));
        }
    }

    // `admin` immunity is code-not-data: it must never be grantable through
    // an overwrite, regardless of the caller's own permissions.
    if req.allow.iter().any(|p| p == ADMIN) {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot grant 'admin' via a channel permission overwrite".to_string(),
        ));
    }

    // Self-grant guard: a caller can only allow permissions they themselves
    // effectively hold on this channel -- prevents delegating powers the
    // caller doesn't have. Denies are unrestricted (removing power is safe).
    for p in &req.allow {
        if !perms.has(p) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Cannot grant permission '{p}' you do not hold on this channel"),
            ));
        }
    }

    let before: Vec<(String, bool)> = sqlx::query_as(
        "SELECT permission, allow FROM channel_permission_overwrites
         WHERE channel_id = $1 AND role_id = $2",
    )
    .bind(&channel_id)
    .bind(&role_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM channel_permission_overwrites WHERE channel_id = $1 AND role_id = $2")
        .bind(&channel_id)
        .bind(&role_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for p in &req.allow {
        sqlx::query(
            "INSERT INTO channel_permission_overwrites (channel_id, role_id, permission, allow, created_at)
             VALUES ($1, $2, $3, TRUE, $4)",
        )
        .bind(&channel_id)
        .bind(&role_id)
        .bind(p)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    for p in &req.deny {
        sqlx::query(
            "INSERT INTO channel_permission_overwrites (channel_id, role_id, permission, allow, created_at)
             VALUES ($1, $2, $3, FALSE, $4)",
        )
        .bind(&channel_id)
        .bind(&role_id)
        .bind(p)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let state_c = state.clone();
        let ch = channel_id.clone();
        let rid = role_id.clone();
        let actor = user.public_key.clone();
        let before_map: HashMap<String, bool> = before.into_iter().collect();
        let after_map: HashMap<String, bool> = req
            .allow
            .iter()
            .map(|p| (p.clone(), true))
            .chain(req.deny.iter().map(|p| (p.clone(), false)))
            .collect();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "channel.permission_overwrite.set",
                Some(&actor),
                None,
                Some(&ch),
                serde_json::json!({
                    "channel_id": ch,
                    "role_id": rid,
                    "before": before_map,
                    "after": after_map,
                }),
            )
            .await;
        });
    }

    let view = role_view(&state.db, &channel_id, &role_id, &role_name).await?;
    Ok(Json(view))
}

/// DELETE /channels/:id/permissions/:role_id
pub async fn delete_channel_permissions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, role_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(MANAGE_ROLES)?;

    require_channel_exists(&state.db, &channel_id).await?;
    let (_, role_priority) = require_role(&state.db, &role_id).await?;

    // Priority guard: can't clear overwrites for a role at or above the
    // caller's own rank either.
    if role_priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot clear permission overwrites for a role with priority >= your own".to_string(),
        ));
    }

    let before: Vec<(String, bool)> = sqlx::query_as(
        "SELECT permission, allow FROM channel_permission_overwrites
         WHERE channel_id = $1 AND role_id = $2",
    )
    .bind(&channel_id)
    .bind(&role_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM channel_permission_overwrites WHERE channel_id = $1 AND role_id = $2")
        .bind(&channel_id)
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let state_c = state.clone();
        let ch = channel_id.clone();
        let rid = role_id.clone();
        let actor = user.public_key.clone();
        let before_map: HashMap<String, bool> = before.into_iter().collect();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "channel.permission_overwrite.cleared",
                Some(&actor),
                None,
                Some(&ch),
                serde_json::json!({
                    "channel_id": ch,
                    "role_id": rid,
                    "before": before_map,
                }),
            )
            .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}
