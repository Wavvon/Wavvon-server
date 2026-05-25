use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::state::AppState;

pub async fn send_friend_request(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<FriendRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if req.target_public_key == user.public_key {
        return Err((StatusCode::BAD_REQUEST, "Cannot friend yourself".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();

    // Cross-hub adds (hub_url provided) skip the pending state because there's
    // no federated notification path yet — leaving them pending forever would
    // be misleading. Same-hub adds keep the existing accept/reject flow.
    let status = if req.hub_url.is_some() { "accepted" } else { "pending" };

    sqlx::query(
        "INSERT OR IGNORE INTO friends (user_a, user_b, status, created_at, hub_url, display_name)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&user.public_key)
    .bind(&req.target_public_key)
    .bind(status)
    .bind(now)
    .bind(&req.hub_url)
    .bind(&req.display_name)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::CREATED)
}

pub async fn accept_friend_request(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(from_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // The request was from `from_key` → `user.public_key`, update to accepted
    let result = sqlx::query(
        "UPDATE friends SET status = 'accepted' WHERE user_a = ? AND user_b = ? AND status = 'pending'",
    )
    .bind(&from_key)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "No pending request from this user".to_string()));
    }

    Ok(StatusCode::OK)
}

pub async fn remove_friend(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Remove in both directions
    sqlx::query("DELETE FROM friends WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)")
        .bind(&user.public_key)
        .bind(&target_key)
        .bind(&target_key)
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_friends(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<FriendInfo>>, (StatusCode, String)> {
    // Each accepted friendship row gives us either the friend's pubkey
    // (when user is user_a) or the friend's pubkey (when user is user_b),
    // along with the hub_url + display_name cached when the friendship was
    // created. user_a-side and user_b-side rows can carry different cached
    // display_name/hub_url; we surface the row that names *this* user as
    // user_a if both exist.
    let rows = sqlx::query_as::<_, FriendRow>(
        "SELECT
            CASE WHEN user_a = ? THEN user_b ELSE user_a END AS friend_key,
            CASE WHEN user_a = ? THEN hub_url ELSE NULL END AS friend_hub_url,
            CASE WHEN user_a = ? THEN display_name ELSE NULL END AS cached_name,
            created_at
         FROM friends
         WHERE (user_a = ? OR user_b = ?) AND status = 'accepted'",
    )
    .bind(&user.public_key)
    .bind(&user.public_key)
    .bind(&user.public_key)
    .bind(&user.public_key)
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        // Prefer the cached display_name we recorded for cross-hub friends;
        // fall back to the local users table for same-hub friends.
        let display_name = match row.cached_name {
            Some(n) if !n.is_empty() => Some(n),
            _ => sqlx::query_scalar::<_, Option<String>>(
                "SELECT display_name FROM users WHERE public_key = ?",
            )
            .bind(&row.friend_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten(),
        };

        result.push(FriendInfo {
            public_key: row.friend_key,
            display_name,
            hub_url: row.friend_hub_url,
            since: row.created_at,
        });
    }

    Ok(Json(result))
}

pub async fn list_pending_requests(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<FriendInfo>>, (StatusCode, String)> {
    // Requests sent TO this user (they can accept). Cross-hub requests don't
    // appear here because they're created with status='accepted' immediately —
    // see send_friend_request. Pending requests are always same-hub.
    let rows = sqlx::query_as::<_, FriendRow>(
        "SELECT user_a AS friend_key, NULL AS friend_hub_url, NULL AS cached_name, created_at
         FROM friends
         WHERE user_b = ? AND status = 'pending'",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        let display_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(&row.friend_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .flatten();

        result.push(FriendInfo {
            public_key: row.friend_key,
            display_name,
            hub_url: None,
            since: row.created_at,
        });
    }

    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct FriendRequest {
    pub target_public_key: String,
    /// Optional hub URL where the friend is reachable. When provided, marks
    /// this as a cross-hub friend and skips the pending acceptance state.
    #[serde(default)]
    pub hub_url: Option<String>,
    /// Optional display name cached at add time. The friend's hub may rename
    /// them later; we'll resync when we next federate with them.
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct FriendInfo {
    pub public_key: String,
    pub display_name: Option<String>,
    /// NULL for same-hub friends (resolve via local users table).
    pub hub_url: Option<String>,
    pub since: i64,
}

#[derive(sqlx::FromRow)]
struct FriendRow {
    friend_key: String,
    friend_hub_url: Option<String>,
    cached_name: Option<String>,
    created_at: i64,
}
