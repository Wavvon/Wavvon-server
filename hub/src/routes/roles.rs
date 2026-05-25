use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MANAGE_ROLES};
use crate::routes::role_models::{CreateRoleRequest, RoleResponse, UpdateRoleRequest};
use crate::state::AppState;

pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<RoleResponse>>, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, priority, display_separately, created_at FROM roles ORDER BY priority DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for role in roles {
        let perms = role_permissions(&state.db, &role.id).await?;
        result.push(RoleResponse {
            id: role.id,
            name: role.name,
            permissions: perms,
            priority: role.priority,
            display_separately: role.display_separately != 0,
            created_at: role.created_at,
        });
    }

    Ok(Json(result))
}

pub async fn create_role(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    if req.priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot create role with priority >= your own".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO roles (id, name, priority, display_separately, created_at) VALUES (?, ?, ?, ?, ?)",
    )
        .bind(&id)
        .bind(&req.name)
        .bind(req.priority)
        .bind(if req.display_separately { 1i64 } else { 0 })
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("Role '{}' already exists", req.name))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
            }
        })?;

    for perm in &req.permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
            .bind(&id)
            .bind(perm)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(RoleResponse {
            id,
            name: req.name,
            permissions: req.permissions,
            priority: req.priority,
            display_separately: req.display_separately,
            created_at: now,
        }),
    ))
}

pub async fn update_role(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(role_id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {
    require_not_builtin(&role_id)?;

    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    let existing = get_role(&state.db, &role_id).await?;
    if existing.priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot modify role with priority >= your own".to_string(),
        ));
    }

    if let Some(new_priority) = req.priority {
        if new_priority >= perms.max_priority {
            return Err((
                StatusCode::FORBIDDEN,
                "Cannot set priority >= your own".to_string(),
            ));
        }
        sqlx::query("UPDATE roles SET priority = ? WHERE id = ?")
            .bind(new_priority)
            .bind(&role_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(ref name) = req.name {
        sqlx::query("UPDATE roles SET name = ? WHERE id = ?")
            .bind(name)
            .bind(&role_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(ref new_perms) = req.permissions {
        sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
            .bind(&role_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        for perm in new_perms {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
                .bind(&role_id)
                .bind(perm)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }
    }

    if let Some(flag) = req.display_separately {
        sqlx::query("UPDATE roles SET display_separately = ? WHERE id = ?")
            .bind(if flag { 1i64 } else { 0 })
            .bind(&role_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let updated = get_role(&state.db, &role_id).await?;
    let role_perms = role_permissions(&state.db, &role_id).await?;

    Ok(Json(RoleResponse {
        id: updated.id,
        name: updated.name,
        permissions: role_perms,
        priority: updated.priority,
        display_separately: updated.display_separately != 0,
        created_at: updated.created_at,
    }))
}

pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(role_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_not_builtin(&role_id)?;

    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    let existing = get_role(&state.db, &role_id).await?;
    if existing.priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot delete role with priority >= your own".to_string(),
        ));
    }

    sqlx::query("DELETE FROM user_roles WHERE role_id = ?")
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn assign_role(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((public_key, role_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    let role = get_role(&state.db, &role_id).await?;
    if role.priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot assign role with priority >= your own".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT OR IGNORE INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, ?, ?)",
    )
    .bind(&public_key)
    .bind(&role_id)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn remove_role(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((public_key, role_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    if role_id == "builtin-everyone" {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot remove @everyone role".to_string(),
        ));
    }

    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    let role = get_role(&state.db, &role_id).await?;
    if role.priority >= perms.max_priority {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot remove role with priority >= your own".to_string(),
        ));
    }

    // Prevent removing the last owner
    if role_id == "builtin-owner" {
        let owner_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = 'builtin-owner'",
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if owner_count <= 1 {
            return Err((
                StatusCode::FORBIDDEN,
                "Cannot remove the last owner".to_string(),
            ));
        }
    }

    sqlx::query("DELETE FROM user_roles WHERE user_public_key = ? AND role_id = ?")
        .bind(&public_key)
        .bind(&role_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn get_user_roles(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(public_key): Path<String>,
) -> Result<Json<Vec<RoleResponse>>, (StatusCode, String)> {
    fetch_user_roles_response(&state.db, &public_key).await.map(Json)
}

pub async fn list_role_members(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(role_id): Path<String>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    let members: Vec<String> = sqlx::query_scalar(
        "SELECT user_public_key FROM user_roles WHERE role_id = ?",
    )
    .bind(&role_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(members))
}

// Helpers

fn require_not_builtin(role_id: &str) -> Result<(), (StatusCode, String)> {
    if role_id == "builtin-owner" || role_id == "builtin-everyone" {
        Err((
            StatusCode::FORBIDDEN,
            "Cannot modify built-in roles".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn get_role(db: &sqlx::SqlitePool, role_id: &str) -> Result<RoleRow, (StatusCode, String)> {
    sqlx::query_as::<_, RoleRow>(
        "SELECT id, name, priority, display_separately, created_at FROM roles WHERE id = ?",
    )
    .bind(role_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Role not found".to_string()))
}

async fn role_permissions(
    db: &sqlx::SqlitePool,
    role_id: &str,
) -> Result<Vec<String>, (StatusCode, String)> {
    sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_id = ?")
        .bind(role_id)
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

async fn fetch_user_roles_response(
    db: &sqlx::SqlitePool,
    public_key: &str,
) -> Result<Vec<RoleResponse>, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.priority, r.display_separately, r.created_at
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = ?
         ORDER BY r.priority DESC",
    )
    .bind(public_key)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for role in roles {
        let perms = role_permissions(db, &role.id).await?;
        result.push(RoleResponse {
            id: role.id,
            name: role.name,
            permissions: perms,
            priority: role.priority,
            display_separately: role.display_separately != 0,
            created_at: role.created_at,
        });
    }
    Ok(result)
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: String,
    name: String,
    priority: i64,
    display_separately: i64,
    created_at: i64,
}
