use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

#[derive(Serialize)]
pub struct EmojiInfo {
    pub id: String,
    pub name: String,
    pub url: String,
}

pub async fn list_emojis(State(state): State<Arc<AppState>>) -> Json<Vec<EmojiInfo>> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id, name FROM hub_emojis ORDER BY name")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    Json(
        rows.into_iter()
            .map(|(id, name)| EmojiInfo {
                url: format!("/emojis/{id}/image"),
                id,
                name,
            })
            .collect(),
    )
}

pub async fn get_emoji_image(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT mime, data_b64 FROM hub_emojis WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (mime, data_b64) = row.ok_or((StatusCode::NOT_FOUND, "Not found".into()))?;
    let bytes = STANDARD
        .decode(&data_b64)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "public, max-age=86400".into()),
        ],
        bytes,
    ))
}

#[derive(Deserialize)]
pub struct CreateEmojiRequest {
    pub name: String,
    pub mime: String,
    pub data_b64: String,
}

pub async fn create_emoji(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateEmojiRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    if req.name.is_empty() || req.data_b64.len() > 90_000 {
        return Err((StatusCode::BAD_REQUEST, "Invalid emoji".into()));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        "INSERT INTO hub_emojis(id, name, uploader, mime, data_b64, created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&user.public_key)
    .bind(&req.mime)
    .bind(&req.data_b64)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn delete_emoji(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query("DELETE FROM hub_emojis WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
