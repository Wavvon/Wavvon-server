use std::sync::Arc;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

const MAX_SVG_BYTES: usize = 50 * 1024;

#[derive(Serialize, Deserialize, Clone)]
pub struct HubIconResponse {
    pub id: String,
    pub name: String,
    pub svg_content: String,
    pub uploaded_by: String,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct CreateIconRequest {
    pub name: String,
    pub svg_content: String,
}

#[derive(Deserialize)]
pub struct RenameIconRequest {
    pub name: String,
}

#[derive(sqlx::FromRow)]
struct IconRow {
    id: String,
    name: String,
    svg_content: String,
    uploaded_by: String,
    created_at: i64,
}

pub async fn list_icons(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<HubIconResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, IconRow>(
        "SELECT id, name, svg_content, uploaded_by, created_at FROM hub_icons ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(rows.into_iter().map(|r| HubIconResponse {
        id: r.id, name: r.name, svg_content: r.svg_content,
        uploaded_by: r.uploaded_by, created_at: r.created_at,
    }).collect()))
}

pub async fn create_icon(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateIconRequest>,
) -> Result<(StatusCode, Json<HubIconResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_HUB_ICONS)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Icon name cannot be empty".into()));
    }
    if req.svg_content.len() > MAX_SVG_BYTES {
        return Err((StatusCode::BAD_REQUEST, "SVG content exceeds 50 KB limit".into()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO hub_icons (id, name, svg_content, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&req.svg_content)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((StatusCode::CREATED, Json(HubIconResponse {
        id, name, svg_content: req.svg_content,
        uploaded_by: user.public_key, created_at: now,
    })))
}

pub async fn rename_icon(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(icon_id): Path<String>,
    Json(req): Json<RenameIconRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_HUB_ICONS)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Name cannot be empty".into()));
    }

    let rows = sqlx::query("UPDATE hub_icons SET name = ? WHERE id = ?")
        .bind(&name)
        .bind(&icon_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if rows.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Icon not found".into()));
    }
    Ok(StatusCode::OK)
}

pub async fn delete_icon(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(icon_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_HUB_ICONS)?;

    let rows = sqlx::query("DELETE FROM hub_icons WHERE id = ?")
        .bind(&icon_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if rows.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Icon not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
