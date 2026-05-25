use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LobbyStatusResponse {
    pub status: String,
    pub required_level: u32,
    pub current_level: u32,
    pub entered_at: Option<i64>,
    pub welcome_md: Option<String>,
}

#[derive(Serialize)]
pub struct SubmitPowResponse {
    pub promoted: bool,
    pub new_level: u32,
}

#[derive(Serialize)]
pub struct LobbyWelcomeResponse {
    pub welcome_md: String,
    pub hub_name: String,
    pub required_level: u32,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SubmitPowRequest {
    pub pow_proof: String,
}

#[derive(Deserialize)]
pub struct UpdateLobbySettingsRequest {
    pub lobby_enabled: bool,
    #[serde(default)]
    pub welcome_md: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn read_setting(db: &sqlx::SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

async fn upsert_setting(
    db: &sqlx::SqlitePool,
    key: &str,
    value: &str,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = ?",
    )
    .bind(key)
    .bind(value)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /lobby/status
pub async fn get_status(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<LobbyStatusResponse>, (StatusCode, String)> {
    let min_level: u32 = read_setting(&state.db, "min_security_level")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let welcome_md = read_setting(&state.db, "lobby_welcome_md").await;

    let row: Option<(String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT lobby_status, lobby_entered_at, pow_level FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (lobby_status, entered_at, pow_level) = row.unwrap_or_else(|| ("none".to_string(), None, 0));
    let current_level = pow_level as u32;

    // Determine effective status from the user perspective:
    // "member" = fully joined (no lobby system, or already promoted, or pow meets level)
    // "promoted" = passed the lobby gate
    // "lobby" = currently in the lobby waiting room
    let effective_status = if lobby_status == "promoted" || current_level >= min_level || min_level == 0 {
        "member".to_string()
    } else if lobby_status == "lobby" {
        "lobby".to_string()
    } else {
        // none — not in lobby yet; from client perspective show as member if no gate
        if min_level == 0 {
            "member".to_string()
        } else {
            lobby_status
        }
    };

    Ok(Json(LobbyStatusResponse {
        status: effective_status,
        required_level: min_level,
        current_level,
        entered_at,
        welcome_md,
    }))
}

/// POST /lobby/submit-pow
pub async fn submit_pow(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SubmitPowRequest>,
) -> Result<Json<SubmitPowResponse>, (StatusCode, String)> {
    let min_level: u32 = read_setting(&state.db, "min_security_level")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Parse pow_proof as "nonce:level" — matches existing PoW convention used elsewhere.
    // The proof string is "<hex_nonce>:<claimed_level>".
    let parts: Vec<&str> = req.pow_proof.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err((StatusCode::BAD_REQUEST, "Invalid pow_proof format; expected nonce:level".to_string()));
    }
    let nonce: u64 = parts[0]
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid nonce".to_string()))?;
    let claimed_level: u32 = parts[1]
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid level".to_string()))?;

    if !voxply_identity::verify_security_level(&user.public_key, nonce, claimed_level) {
        return Err((StatusCode::BAD_REQUEST, "Invalid proof of work".to_string()));
    }

    // Update pow_level (only increase, never decrease)
    let current_pow: i64 = sqlx::query_scalar(
        "SELECT pow_level FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .unwrap_or(0);

    let new_level = (current_pow as u32).max(claimed_level);
    let promoted = new_level >= min_level && min_level > 0;
    let new_status = if promoted { "promoted" } else { "lobby" };

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "UPDATE users SET pow_level = ?, lobby_status = CASE WHEN lobby_status = 'none' THEN ? ELSE ? END, lobby_entered_at = COALESCE(lobby_entered_at, ?) WHERE public_key = ?",
    )
    .bind(new_level as i64)
    .bind(new_status)   // if transitioning from 'none'
    .bind(new_status)   // if already in lobby
    .bind(now)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(SubmitPowResponse { promoted, new_level }))
}

/// GET /lobby/welcome
pub async fn get_welcome(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<LobbyWelcomeResponse>, (StatusCode, String)> {
    let welcome_md = read_setting(&state.db, "lobby_welcome_md")
        .await
        .unwrap_or_default();

    let hub_name = crate::routes::hub::current_hub_name(&state).await;

    let required_level: u32 = read_setting(&state.db, "min_security_level")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(Json(LobbyWelcomeResponse {
        welcome_md,
        hub_name,
        required_level,
    }))
}

/// PUT /hub/settings/lobby
pub async fn update_lobby_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateLobbySettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    upsert_setting(
        &state.db,
        "lobby_enabled",
        if req.lobby_enabled { "1" } else { "0" },
    )
    .await?;

    if let Some(md) = req.welcome_md.as_deref() {
        upsert_setting(&state.db, "lobby_welcome_md", md).await?;
    }

    Ok(StatusCode::OK)
}
