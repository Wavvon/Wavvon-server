use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;
use sqlx::Row;

use crate::auth::middleware::AuthUser;
use crate::state::AppState;
use voxply_identity::PublicHubProfile;

fn db_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT profile_json FROM public_hub_profiles WHERE pubkey = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let row = row.ok_or((StatusCode::NOT_FOUND, "No profile".to_string()))?;
    let json_str: String = row.get("profile_json");
    let v: Value = serde_json::from_str(&json_str)
        .map_err(|e| db_err(format!("parse stored profile: {e}")))?;
    Ok(Json(v))
}

pub async fn put_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(body): Json<PublicHubProfile>,
) -> Result<StatusCode, (StatusCode, String)> {
    if pubkey != user.public_key {
        return Err((StatusCode::FORBIDDEN, "Cannot update another user's profile".to_string()));
    }
    if body.pubkey != pubkey {
        return Err((StatusCode::BAD_REQUEST, "pubkey mismatch between URL and body".to_string()));
    }
    body.verify()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let json_str = serde_json::to_string(&body)
        .map_err(|e| db_err(format!("serialize profile: {e}")))?;

    sqlx::query(
        "INSERT INTO public_hub_profiles (pubkey, profile_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(pubkey) DO UPDATE SET
            profile_json = excluded.profile_json,
            updated_at   = excluded.updated_at",
    )
    .bind(&pubkey)
    .bind(&json_str)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}
