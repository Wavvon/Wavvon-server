//! Game admin routes: install, enable/disable, list, channel scope, permissions.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::helpers::chrono_now;
use super::models::{
    AdminGameEntry, AdminListGamesResponse, EnabledGameEntry, FarmGameManifest, InstallGameRequest,
    InstalledGameResponse, ListEnabledGamesResponse, SetChannelScopeRequest, SetPermissionsRequest,
};

const VALID_CAPABILITIES: &[&str] = &["post_message", "read_channel_history", "list_channel_users"];

// ---------------------------------------------------------------------------
// POST /admin/games  (Tier 1 minimal install — manage_games required)
// ---------------------------------------------------------------------------
/// Install a game on this hub. Uses the game's `entry_url` to derive a stable
/// `id` if none is supplied (SHA-256 prefix). This is the inline-manifest path
/// described in the design doc; the full manifest-URL fetch and catalog browse
/// paths are deferred Tier 1 work.
pub async fn install_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InstallGameRequest>,
) -> Result<(StatusCode, Json<InstalledGameResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Derive id from entry_url hash if not supplied explicitly.
    let game_id = req.id.unwrap_or_else(|| {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(req.entry_url.as_bytes());
        format!("game-{}", hex::encode(&hash[..8]))
    });
    let version = req.version.unwrap_or_else(|| "1.0.0".to_string());
    let min_players = req.min_players.unwrap_or(1);
    let max_players = req.max_players.unwrap_or(1);
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO hub_games
            (id, name, description, version, entry_url, thumbnail_url, author,
             min_players, max_players, installed_by, installed_at, manifest_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             description = excluded.description,
             version = excluded.version,
             entry_url = excluded.entry_url,
             thumbnail_url = excluded.thumbnail_url,
             author = excluded.author,
             min_players = excluded.min_players,
             max_players = excluded.max_players",
    )
    .bind(&game_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&version)
    .bind(&req.entry_url)
    .bind(&req.thumbnail_url)
    .bind(&req.author)
    .bind(min_players)
    .bind(max_players)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(InstalledGameResponse {
            id: game_id,
            name: req.name,
            entry_url: req.entry_url,
            version,
            description: req.description,
            thumbnail_url: req.thumbnail_url,
            author: req.author,
            min_players,
            max_players,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /games/:id/enable
// ---------------------------------------------------------------------------

pub async fn enable_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Fetch manifest from the farm and cache it into hub_games.
    let manifest: FarmGameManifest = match &state.farm_url {
        None => {
            // Un-farmed hub: the game must already be in hub_games (installed locally).
            let exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM hub_games WHERE id = ?")
                    .bind(&game_id)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if exists.is_none() {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Game not installed on this hub".to_string(),
                ));
            }
            // Synthesise a manifest from the local row so we can skip the upsert below.
            #[allow(clippy::type_complexity)]
            let row: (
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
                i64,
                i64,
            ) = sqlx::query_as(
                "SELECT id, name, entry_url, description, thumbnail_url, version, author, min_players, max_players FROM hub_games WHERE id = ?",
            )
            .bind(&game_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            FarmGameManifest {
                id: row.0,
                name: row.1,
                entry_url: row.2,
                description: row.3,
                thumbnail_url: row.4,
                version: row.5,
                author: row.6,
                min_players: row.7,
                max_players: row.8,
            }
        }
        Some(farm_url) => {
            let url = format!("{farm_url}/farm/games/{game_id}");
            let resp = state
                .http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Farm unreachable: {e}")))?;
            if resp.status().as_u16() == 404 {
                return Err((StatusCode::NOT_FOUND, "Game not found on farm".to_string()));
            }
            if !resp.status().is_success() {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("Farm returned {}", resp.status()),
                ));
            }
            resp.json::<FarmGameManifest>().await.map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Invalid farm response: {e}"),
                )
            })?
        }
    };

    let now = chrono_now();

    // Upsert into hub_games (cache from farm).
    sqlx::query(
        "INSERT INTO hub_games
             (id, name, description, version, entry_url, thumbnail_url, author,
              min_players, max_players, installed_by, installed_at, manifest_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
         ON CONFLICT(id) DO UPDATE SET
             name          = excluded.name,
             description   = excluded.description,
             version       = excluded.version,
             entry_url     = excluded.entry_url,
             thumbnail_url = excluded.thumbnail_url,
             author        = excluded.author,
             min_players   = excluded.min_players,
             max_players   = excluded.max_players",
    )
    .bind(&manifest.id)
    .bind(&manifest.name)
    .bind(&manifest.description)
    .bind(&manifest.version)
    .bind(&manifest.entry_url)
    .bind(&manifest.thumbnail_url)
    .bind(&manifest.author)
    .bind(manifest.min_players)
    .bind(manifest.max_players)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Upsert enabled_games row.
    sqlx::query(
        "INSERT INTO enabled_games (game_id, enabled_at, enabled_by)
         VALUES (?, ?, ?)
         ON CONFLICT(game_id) DO UPDATE SET
             enabled_at = excluded.enabled_at,
             enabled_by = excluded.enabled_by",
    )
    .bind(&game_id)
    .bind(&now)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /games/:id/enable
// ---------------------------------------------------------------------------

pub async fn disable_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    let rows = sqlx::query("DELETE FROM enabled_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Game not enabled on this hub".to_string(),
        ));
    }

    // Remove per-channel scope entries for this game too.
    let _ = sqlx::query("DELETE FROM channel_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /games  (player-facing — enabled + channel-scoped)
// ---------------------------------------------------------------------------

pub async fn list_enabled_games(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<ListEnabledGamesResponse>, (StatusCode, String)> {
    // Return all hub-enabled games. Channel-scoped filtering is done client-side
    // (the client knows which channel is open and can call with a channel_id param
    // in the future; for now we return the full enabled list and let the client
    // apply the channel restriction using the /admin/games/:id/channels data).
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        i64,
        i64,
    )> = sqlx::query_as(
        "SELECT g.id, g.name, g.entry_url, g.description, g.thumbnail_url, g.version, g.author,
                g.min_players, g.max_players
         FROM hub_games g
         INNER JOIN enabled_games e ON e.game_id = g.id
         ORDER BY g.name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let games = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                entry_url,
                description,
                thumbnail_url,
                version,
                author,
                min_players,
                max_players,
            )| {
                EnabledGameEntry {
                    id,
                    name,
                    entry_url,
                    description,
                    thumbnail_url,
                    version,
                    author,
                    min_players,
                    max_players,
                }
            },
        )
        .collect();

    Ok(Json(ListEnabledGamesResponse { games }))
}

// ---------------------------------------------------------------------------
// PUT /admin/games/:id/permissions   body: { capabilities: [String] }
// ---------------------------------------------------------------------------

pub async fn set_game_permissions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
    Json(req): Json<SetPermissionsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Only recognise the Tier 1 closed capability set.
    let sanitised: Vec<&str> = req
        .capabilities
        .iter()
        .filter_map(|c| {
            VALID_CAPABILITIES
                .iter()
                .find(|&&v| v == c.as_str())
                .copied()
        })
        .collect();
    let json = serde_json::to_string(&sanitised)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?;

    sqlx::query("UPDATE hub_games SET capabilities = ? WHERE id = ?")
        .bind(&json)
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// PUT /admin/games/:id/channels
// ---------------------------------------------------------------------------

pub async fn set_game_channels(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
    Json(req): Json<SetChannelScopeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Game must be enabled on this hub.
    let enabled: Option<String> =
        sqlx::query_scalar("SELECT game_id FROM enabled_games WHERE game_id = ?")
            .bind(&game_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if enabled.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Game not enabled on this hub".to_string(),
        ));
    }

    // Replace channel scope atomically: delete old rows, insert new ones.
    sqlx::query("DELETE FROM channel_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for channel_id in &req.channel_ids {
        sqlx::query(
            "INSERT INTO channel_games (channel_id, game_id) VALUES (?, ?) ON CONFLICT (channel_id, game_id) DO NOTHING",
        )
        .bind(channel_id)
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /admin/games  (manage_games — full inventory with channel scope)
// ---------------------------------------------------------------------------

pub async fn admin_list_games(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<AdminListGamesResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT g.id, g.name, g.entry_url, g.description, g.thumbnail_url, g.version, g.author,
                g.min_players, g.max_players,
                e.enabled_by, e.enabled_at,
                g.capabilities
         FROM hub_games g
         LEFT JOIN enabled_games e ON e.game_id = g.id
         ORDER BY g.name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut games = Vec::with_capacity(rows.len());
    for (
        id,
        name,
        entry_url,
        description,
        thumbnail_url,
        version,
        author,
        min_players,
        max_players,
        enabled_by,
        enabled_at,
        capabilities_json,
    ) in rows
    {
        let enabled = enabled_by.is_some();
        let channel_scope: Vec<String> = sqlx::query_scalar(
            "SELECT channel_id FROM channel_games WHERE game_id = ? ORDER BY channel_id",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        let capabilities: Vec<String> =
            serde_json::from_str(&capabilities_json).unwrap_or_default();

        games.push(AdminGameEntry {
            id,
            name,
            entry_url,
            description,
            thumbnail_url,
            version,
            author,
            min_players,
            max_players,
            enabled,
            enabled_by,
            enabled_at,
            channel_scope,
            capabilities,
        });
    }

    Ok(Json(AdminListGamesResponse { games }))
}
