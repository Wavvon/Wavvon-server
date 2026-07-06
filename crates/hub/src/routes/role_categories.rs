//! Role category CRUD — display-only grouping containers for roles.
//! Categories carry no permissions (see docs/docs/role-categories.md §1);
//! mutations require hub-wide MANAGE_ROLES since categories have no channel
//! dimension.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MANAGE_ROLES};
use crate::routes::role_models::{
    is_valid_color, is_valid_icon, CreateRoleCategoryRequest, RoleCategoryResponse,
    UpdateRoleCategoryRequest,
};
use crate::state::AppState;

pub async fn list_role_categories(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<RoleCategoryResponse>>, (StatusCode, String)> {
    let categories = sqlx::query_as::<_, RoleCategoryRow>(
        "SELECT id, name, color, icon, position, created_at
         FROM role_categories ORDER BY position ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(categories.into_iter().map(Into::into).collect()))
}

pub async fn create_role_category(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateRoleCategoryRequest>,
) -> Result<(StatusCode, Json<RoleCategoryResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    validate_appearance(req.color.as_deref(), req.icon.as_deref())?;

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let position = req.position.unwrap_or(0);

    sqlx::query(
        "INSERT INTO role_categories (id, name, color, icon, position, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.color)
    .bind(&req.icon)
    .bind(position)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let resp = RoleCategoryResponse {
        id: id.clone(),
        name: req.name,
        color: req.color,
        icon: req.icon,
        position,
        created_at: now,
    };

    let state_c = state.clone();
    let actor = user.public_key.clone();
    let cat_id = id.clone();
    let name = resp.name.clone();
    tokio::spawn(async move {
        crate::bots::events::publish_hub_event(
            &state_c,
            "role_category.created",
            Some(&actor),
            None,
            None,
            serde_json::json!({ "category_id": cat_id, "name": name }),
        )
        .await;
    });

    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn update_role_category(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(category_id): Path<String>,
    Json(req): Json<UpdateRoleCategoryRequest>,
) -> Result<Json<RoleCategoryResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    get_category(&state.db, &category_id).await?;

    validate_appearance(
        req.color.as_ref().and_then(|c| c.as_deref()),
        req.icon.as_ref().and_then(|i| i.as_deref()),
    )?;

    if let Some(ref name) = req.name {
        sqlx::query("UPDATE role_categories SET name = $1 WHERE id = $2")
            .bind(name)
            .bind(&category_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(color) = req.color {
        sqlx::query("UPDATE role_categories SET color = $1 WHERE id = $2")
            .bind(&color)
            .bind(&category_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(icon) = req.icon {
        sqlx::query("UPDATE role_categories SET icon = $1 WHERE id = $2")
            .bind(&icon)
            .bind(&category_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(position) = req.position {
        sqlx::query("UPDATE role_categories SET position = $1 WHERE id = $2")
            .bind(position)
            .bind(&category_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let updated = get_category(&state.db, &category_id).await?;

    let state_c = state.clone();
    let actor = user.public_key.clone();
    let cat_id = category_id.clone();
    tokio::spawn(async move {
        crate::bots::events::publish_hub_event(
            &state_c,
            "role_category.updated",
            Some(&actor),
            None,
            None,
            serde_json::json!({ "category_id": cat_id }),
        )
        .await;
    });

    Ok(Json(updated.into()))
}

pub async fn delete_role_category(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(category_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_ROLES)?;

    get_category(&state.db, &category_id).await?;

    // Roles referencing this category fall back to uncategorized via the
    // `ON DELETE SET NULL` foreign key — no explicit UPDATE needed here.
    sqlx::query("DELETE FROM role_categories WHERE id = $1")
        .bind(&category_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let state_c = state.clone();
    let actor = user.public_key.clone();
    let cat_id = category_id.clone();
    tokio::spawn(async move {
        crate::bots::events::publish_hub_event(
            &state_c,
            "role_category.deleted",
            Some(&actor),
            None,
            None,
            serde_json::json!({ "category_id": cat_id }),
        )
        .await;
    });

    Ok(StatusCode::NO_CONTENT)
}

// Helpers

fn validate_appearance(
    color: Option<&str>,
    icon: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    if let Some(c) = color {
        if !is_valid_color(c) {
            return Err((
                StatusCode::BAD_REQUEST,
                "color must match ^#[0-9a-fA-F]{6}$".to_string(),
            ));
        }
    }
    if let Some(i) = icon {
        if !is_valid_icon(i) {
            return Err((
                StatusCode::BAD_REQUEST,
                "icon must be a single emoji grapheme, max 16 bytes, no whitespace/control chars"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

async fn get_category(
    db: &sqlx::PgPool,
    category_id: &str,
) -> Result<RoleCategoryRow, (StatusCode, String)> {
    sqlx::query_as::<_, RoleCategoryRow>(
        "SELECT id, name, color, icon, position, created_at
         FROM role_categories WHERE id = $1",
    )
    .bind(category_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Role category not found".to_string()))
}

#[derive(sqlx::FromRow)]
struct RoleCategoryRow {
    id: String,
    name: String,
    color: Option<String>,
    icon: Option<String>,
    position: i64,
    created_at: i64,
}

impl From<RoleCategoryRow> for RoleCategoryResponse {
    fn from(row: RoleCategoryRow) -> Self {
        RoleCategoryResponse {
            id: row.id,
            name: row.name,
            color: row.color,
            icon: row.icon,
            position: row.position,
            created_at: row.created_at,
        }
    }
}
