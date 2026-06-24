/// Farm-level game catalogue routes.
///
/// The farm admin installs games once; each hub on the farm then enables or
/// disables them independently.  The per-user KV store (game_kv) is
/// personal-axis — it follows a user across every hub on the farm that has
/// the game enabled.
///
/// POST   /farm/games                                   — install (farm admin)
/// GET    /farm/games                                   — list all
/// GET    /farm/games/:id                               — get one
/// PATCH  /farm/games/:id                               — update permission_grant
/// DELETE /farm/games/:id                               — uninstall (farm admin)
///
/// GET    /farm/games/:id/kv/:user_pubkey/:key          — read KV (owner or admin)
/// PUT    /farm/games/:id/kv/:user_pubkey/:key          — write KV (owner or admin)
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::FarmState;
use crate::token::verify_token;

// ---------------------------------------------------------------------------
// Auth helpers (mirrored from admin.rs)
// ---------------------------------------------------------------------------

fn require_auth(
    headers: &HeaderMap,
    farm_pubkey: &str,
) -> Result<crate::token::FarmTokenPayload, (StatusCode, Json<serde_json::Value>)> {
    let token_str = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing_token"})),
            )
        })?;

    verify_token(farm_pubkey, token_str).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
    })
}

async fn get_admin_pubkey(db: &sqlx::SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

/// Require a valid farm session whose `sub` matches `farms.admin_pubkey`.
/// Returns the admin pubkey on success.
async fn require_admin(
    headers: &HeaderMap,
    state: &FarmState,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(headers, &farm_pubkey)?;

    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(payload.sub.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }
    Ok(payload.sub)
}

/// Require any valid farm session. Returns the caller's pubkey.
fn require_any_auth(
    headers: &HeaderMap,
    state: &FarmState,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(headers, &farm_pubkey)?;
    Ok(payload.sub)
}

// ---------------------------------------------------------------------------
// Shared timestamp helper
// ---------------------------------------------------------------------------

fn now_str() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InstallGameRequest {
    pub name: String,
    pub entry_url: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub min_players: Option<i64>,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Serialize)]
pub struct GameResponse {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
    pub permission_grant: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct GameRow {
    id: String,
    name: String,
    entry_url: String,
    description: Option<String>,
    thumbnail_url: Option<String>,
    version: String,
    author: Option<String>,
    min_players: i64,
    max_players: i64,
    permission_grant: String,
    installed_by: Option<String>,
    installed_at: Option<String>,
}

impl From<GameRow> for GameResponse {
    fn from(r: GameRow) -> Self {
        let permission_grant: serde_json::Value =
            serde_json::from_str(&r.permission_grant).unwrap_or_else(|_| serde_json::json!([]));
        GameResponse {
            id: r.id,
            name: r.name,
            entry_url: r.entry_url,
            description: r.description,
            thumbnail_url: r.thumbnail_url,
            version: r.version,
            author: r.author,
            min_players: r.min_players,
            max_players: r.max_players,
            permission_grant,
            installed_by: r.installed_by,
            installed_at: r.installed_at,
        }
    }
}

#[derive(Deserialize)]
pub struct PatchGameRequest {
    pub permission_grant: Vec<String>,
}

#[derive(Deserialize)]
pub struct SetKvRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct KvResponse {
    pub game_id: String,
    pub user_pubkey: String,
    pub key: String,
    pub value: Option<String>,
    pub updated_at: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /farm/games
// ---------------------------------------------------------------------------

pub async fn install_game(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<InstallGameRequest>,
) -> Result<(StatusCode, Json<GameResponse>), (StatusCode, Json<serde_json::Value>)> {
    let caller = require_admin(&headers, &state).await?;

    // Derive id from entry_url SHA-256 prefix if not supplied.
    let game_id = req.id.unwrap_or_else(|| {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(req.entry_url.as_bytes());
        format!("game-{}", hex::encode(&hash[..8]))
    });
    let version = req.version.unwrap_or_else(|| "1.0.0".to_string());
    let min_players = req.min_players.unwrap_or(1);
    let max_players = req.max_players.unwrap_or(1);
    let now = now_str();

    sqlx::query(
        "INSERT INTO games
             (id, name, entry_url, description, thumbnail_url, version, author,
              min_players, max_players, permission_grant, installed_by, installed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             name          = excluded.name,
             entry_url     = excluded.entry_url,
             description   = excluded.description,
             thumbnail_url = excluded.thumbnail_url,
             version       = excluded.version,
             author        = excluded.author,
             min_players   = excluded.min_players,
             max_players   = excluded.max_players",
    )
    .bind(&game_id)
    .bind(&req.name)
    .bind(&req.entry_url)
    .bind(&req.description)
    .bind(&req.thumbnail_url)
    .bind(&version)
    .bind(&req.author)
    .bind(min_players)
    .bind(max_players)
    .bind(&caller)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let row: GameRow = sqlx::query_as(
        "SELECT id, name, entry_url, description, thumbnail_url, version, author,
                min_players, max_players, permission_grant, installed_by, installed_at
         FROM games WHERE id = ?",
    )
    .bind(&game_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok((StatusCode::CREATED, Json(GameResponse::from(row))))
}

// ---------------------------------------------------------------------------
// GET /farm/games
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ListGamesResponse {
    pub games: Vec<GameResponse>,
}

pub async fn list_games(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListGamesResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Any authenticated farm user may list games.
    require_any_auth(&headers, &state)?;

    let rows: Vec<GameRow> = sqlx::query_as(
        "SELECT id, name, entry_url, description, thumbnail_url, version, author,
                min_players, max_players, permission_grant, installed_by, installed_at
         FROM games ORDER BY name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(ListGamesResponse {
        games: rows.into_iter().map(GameResponse::from).collect(),
    }))
}

// ---------------------------------------------------------------------------
// GET /farm/games/:id
// ---------------------------------------------------------------------------

pub async fn get_game(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Path(id): Path<String>,
) -> Result<Json<GameResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_any_auth(&headers, &state)?;

    let row: Option<GameRow> = sqlx::query_as(
        "SELECT id, name, entry_url, description, thumbnail_url, version, author,
                min_players, max_players, permission_grant, installed_by, installed_at
         FROM games WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    match row {
        Some(r) => Ok(Json(GameResponse::from(r))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "game_not_found"})),
        )),
    }
}

// ---------------------------------------------------------------------------
// PATCH /farm/games/:id   — update permission_grant (farm admin only)
// ---------------------------------------------------------------------------

pub async fn patch_game(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Path(id): Path<String>,
    Json(req): Json<PatchGameRequest>,
) -> Result<Json<GameResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    // Validate capability strings (closed set defined in the design doc).
    const VALID_CAPS: &[&str] = &["post_message", "read_channel_history", "list_channel_users"];
    for cap in &req.permission_grant {
        if !VALID_CAPS.contains(&cap.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "invalid_capability", "details": format!("unknown capability: {cap}")}),
                ),
            ));
        }
    }

    let grant_json =
        serde_json::to_string(&req.permission_grant).unwrap_or_else(|_| "[]".to_string());

    let rows_affected = sqlx::query("UPDATE games SET permission_grant = ? WHERE id = ?")
        .bind(&grant_json)
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?
        .rows_affected();

    if rows_affected == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "game_not_found"})),
        ));
    }

    let row: GameRow = sqlx::query_as(
        "SELECT id, name, entry_url, description, thumbnail_url, version, author,
                min_players, max_players, permission_grant, installed_by, installed_at
         FROM games WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(GameResponse::from(row)))
}

// ---------------------------------------------------------------------------
// DELETE /farm/games/:id   (farm admin only)
// ---------------------------------------------------------------------------

pub async fn uninstall_game(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    let rows_affected = sqlx::query("DELETE FROM games WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?
        .rows_affected();

    if rows_affected == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "game_not_found"})),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /farm/games/:id/kv/:user_pubkey/:key
// ---------------------------------------------------------------------------

pub async fn get_kv(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Path((game_id, user_pubkey, key)): Path<(String, String, String)>,
) -> Result<Json<KvResponse>, (StatusCode, Json<serde_json::Value>)> {
    let caller = require_any_auth(&headers, &state)?;

    // Only the owner or the farm admin may read a user's KV.
    if caller != user_pubkey {
        let admin = get_admin_pubkey(&state.db).await;
        if admin.as_deref() != Some(caller.as_str()) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "forbidden"})),
            ));
        }
    }

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT value, updated_at FROM game_kv WHERE game_id = ? AND user_pubkey = ? AND key = ?",
    )
    .bind(&game_id)
    .bind(&user_pubkey)
    .bind(&key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let (value, updated_at) = match row {
        Some(r) => (Some(r.0), Some(r.1)),
        None => (None, None),
    };

    Ok(Json(KvResponse {
        game_id,
        user_pubkey,
        key,
        value,
        updated_at,
    }))
}

// ---------------------------------------------------------------------------
// PUT /farm/games/:id/kv/:user_pubkey/:key
// ---------------------------------------------------------------------------

pub async fn put_kv(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Path((game_id, user_pubkey, key)): Path<(String, String, String)>,
    Json(req): Json<SetKvRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let caller = require_any_auth(&headers, &state)?;

    // Only the owner or the farm admin may write a user's KV.
    if caller != user_pubkey {
        let admin = get_admin_pubkey(&state.db).await;
        if admin.as_deref() != Some(caller.as_str()) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "forbidden"})),
            ));
        }
    }

    // Verify game exists.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM games WHERE id = ?")
        .bind(&game_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;
    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "game_not_found"})),
        ));
    }

    let now = now_str();

    sqlx::query(
        "INSERT INTO game_kv (game_id, user_pubkey, key, value, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(game_id, user_pubkey, key) DO UPDATE SET
             value      = excluded.value,
             updated_at = excluded.updated_at",
    )
    .bind(&game_id)
    .bind(&user_pubkey)
    .bind(&key)
    .bind(&req.value)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}
