/// Farm-side hub management routes.
///
/// GET  /farm/hubs               — list hubs (public → public-only; authed → owned + public)
/// POST /farm/hubs               — create a hub (authenticated)
/// GET  /farm/hubs/:hub_id       — single hub info
/// PATCH /farm/hubs/:hub_id/suspend — suspend/unsuspend (farm admin)
/// POST  /farm/hubs/:hub_id/restart — force an immediate restart (farm admin)
/// DELETE /farm/hubs/:hub_id     — delete (farm admin or owner)
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::state::FarmState;
use crate::token::verify_token;
use crate::unix_now;

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

/// Extract and verify a Bearer farm token. Returns the `sub` (canonical pubkey) on success.
pub(crate) fn require_auth(
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

/// Returns the admin pubkey stored in the `farms` singleton row, or `None`.
pub(crate) async fn get_admin_pubkey(db: &sqlx::PgPool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

fn generate_hub_id() -> String {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Shared response shape
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HubEntry {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub visibility: String,
    /// Absent until the hub has claimed its row on first heartbeat — see
    /// `hub_url`. Clients must treat absence as "not routable yet", never
    /// concatenate it blindly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_url: Option<String>,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<i64>,
}

/// The address a client can actually reach this hub on.
///
/// This used to be `{farm}/hub/{hub_id}`, which resolves to nothing: the proxy
/// resolves a segment as either a 64-hex pubkey or a slug, and a hub id is 8 hex
/// characters, so it is neither. Every client that followed the URL the farm
/// handed it got a 404 — including the web client's farm admin view, which
/// fetches `{hub_url}/info` directly.
///
/// The same rule `slugs::hub_address_by_pubkey` already applied: canonical slug
/// if the hub has one, otherwise its pubkey. `None` before the hub's first
/// heartbeat, because until it claims its row there is no address to give — and
/// an absent field a client must handle beats a present one that 404s.
async fn hub_url(
    db: &sqlx::PgPool,
    farm_url: &str,
    hub_id: &str,
    hub_pubkey: Option<&str>,
) -> Option<String> {
    let base = farm_url.trim_end_matches('/');
    if let Some(slug) = crate::routes::slugs::canonical_slug(db, hub_id).await {
        return Some(format!("{base}/hub/{slug}"));
    }
    hub_pubkey.map(|pk| format!("{base}/hub/{pk}"))
}

// ---------------------------------------------------------------------------
// GET /farm/hubs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ListHubsResponse {
    pub hubs: Vec<HubEntry>,
}

pub async fn list_hubs(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListHubsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let authed_sub = require_auth(&headers, &farm_pubkey).ok().map(|p| p.sub);

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        Option<String>,
        String,
        i64,
        Option<i64>,
        String,
        Option<String>,
    )> = if let Some(ref sub) = authed_sub {
        // Authenticated: return public hubs + hubs the user owns.
        sqlx::query_as(
            "SELECT id, name, description, visibility, created_at, suspended_at, owner_pubkey,
                        hub_pubkey
                 FROM hubs
                 WHERE deleted_at IS NULL
                   AND (visibility = 'public' OR owner_pubkey = $1)",
        )
        .bind(sub)
        .fetch_all(&state.db)
        .await
    } else {
        // Unauthenticated: public hubs only (and only if directory_public is set).
        let dir_public: bool =
            sqlx::query_scalar::<_, bool>("SELECT directory_public FROM farms WHERE id = 1")
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .unwrap_or(false);

        if !dir_public {
            return Ok(Json(ListHubsResponse { hubs: vec![] }));
        }

        sqlx::query_as(
            "SELECT id, name, description, visibility, created_at, suspended_at, owner_pubkey,
                        hub_pubkey
                 FROM hubs
                 WHERE deleted_at IS NULL AND visibility = 'public'",
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let mut hubs = Vec::with_capacity(rows.len());
    for (id, name, description, visibility, created_at, suspended_at, _owner, hub_pubkey) in rows {
        hubs.push(HubEntry {
            hub_url: hub_url(&state.db, &state.farm_url, &id, hub_pubkey.as_deref()).await,
            id,
            name,
            description,
            visibility,
            created_at,
            suspended_at,
        });
    }

    Ok(Json(ListHubsResponse { hubs }))
}

// ---------------------------------------------------------------------------
// POST /farm/hubs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateHubRequest {
    pub name: String,
    pub description: Option<String>,
    pub visibility: Option<String>,
    /// Put this hub on a named server. Omitted, the emptiest node takes it
    /// (placement.rs). Named and full, the request is refused rather than
    /// placed elsewhere — see `choose`.
    #[serde(default)]
    pub server_id: Option<String>,
}

#[derive(Serialize)]
pub struct CreateHubResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_url: Option<String>,
}

pub async fn create_hub(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<CreateHubRequest>,
) -> Result<(StatusCode, Json<CreateHubResponse>), (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // -----------------------------------------------------------------------
    // Phase 3A: Enforce creation policy and quota before doing any real work.
    // -----------------------------------------------------------------------
    {
        let policy_row: Option<(String, i64, i64)> = sqlx::query_as(
            "SELECT creation_policy, max_hubs_per_user, max_hubs_total
             FROM farms WHERE id = 1",
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

        if let Some((creation_policy, max_hubs_per_user, max_hubs_total)) = policy_row {
            let admin_pubkey = get_admin_pubkey(&state.db).await;
            let is_admin = admin_pubkey.as_deref() == Some(payload.sub.as_str());

            match creation_policy.as_str() {
                "disabled" => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({"error": "hub_creation_disabled"})),
                    ));
                }
                "admin_only" => {
                    if !is_admin {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "admin_only"})),
                        ));
                    }
                }
                "open" => {
                    // Per-user quota check.
                    if max_hubs_per_user > 0 {
                        let owned: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM hubs WHERE owner_pubkey = $1 AND deleted_at IS NULL",
                        )
                        .bind(&payload.sub)
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"error": format!("db_error: {e}")})),
                            )
                        })?;

                        if owned >= max_hubs_per_user {
                            return Err((
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({"error": "user_quota_exceeded"})),
                            ));
                        }
                    }

                    // Farm-wide quota check.
                    if max_hubs_total > 0 {
                        let total: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM hubs WHERE deleted_at IS NULL",
                        )
                        .fetch_one(&state.db)
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"error": format!("db_error: {e}")})),
                            )
                        })?;

                        if total >= max_hubs_total {
                            return Err((
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({"error": "farm_quota_exceeded"})),
                            ));
                        }
                    }
                }
                _ => {
                    // Unknown policy value — treat as admin_only (safe default).
                    if !is_admin {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "admin_only"})),
                        ));
                    }
                }
            }
        }
        // If the farms row doesn't exist yet (first-start race), fall through and
        // allow creation — the admin can configure policy once the row is seeded.
    }

    // Validate name: 1-64 chars, alphanumeric + spaces + hyphens.
    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_name", "details": "must be 1-64 chars"})),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "invalid_name", "details": "only alphanumeric, spaces, hyphens"}),
            ),
        ));
    }

    let visibility = match req.visibility.as_deref().unwrap_or("private") {
        "public" => "public",
        _ => "private",
    };

    // Generate a unique hub_id.
    let hub_id = loop {
        let candidate = generate_hub_id();
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM hubs WHERE id = $1")
            .bind(&candidate)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;
        if exists.is_none() {
            break candidate;
        }
    };

    let now = unix_now();

    // Decide where this hub goes *before* creating its row (placement.rs).
    // Choosing afterwards counts the hub against its own node's capacity, so a
    // node capped at one would refuse the very first hub placed on it.
    // Refused rather than overflowed: an operator caps a node for a reason we
    // cannot see from here.
    let nodes = collect_nodes(&state).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;
    let chosen = crate::placement::choose(&nodes, req.server_id.as_deref()).map_err(|e| {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": e.code(), "details": e.message()})),
        )
    })?;
    let chosen = chosen.server_id.clone();

    // Determine the DB path from the hubs_dir configured in FarmState.
    let hubs_dir = &state.hubs_dir;
    let db_path = format!("{}/{}.db", hubs_dir.trim_end_matches('/'), hub_id);

    // Ensure the hubs directory exists.
    if let Err(e) = std::fs::create_dir_all(hubs_dir) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("cannot create hubs dir: {e}")})),
        ));
    }

    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, description, visibility, db_path, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&hub_id)
    .bind(&payload.sub)
    .bind(&name)
    .bind(&req.description)
    .bind(visibility)
    .bind(&db_path)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    // This hub's own database, created before anything is spawned. A failure
    // here fails the whole creation: a hub started without one falls back to
    // the shared default and reads another community's data, which is precisely
    // the bug per-hub provisioning replaced.
    let db_url = match state.hub_manager.ensure_db_url(&state.db, &hub_id).await {
        Ok(url) => url,
        Err(e) => {
            let _ = sqlx::query("UPDATE hubs SET deleted_at = $1 WHERE id = $2")
                .bind(now)
                .bind(&hub_id)
                .execute(&state.db)
                .await;
            tracing::error!(hub_id, error = %e, "Hub creation failed: no database");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_provisioning_failed",
                    "details": e.to_string(),
                })),
            ));
        }
    };

    let launched = if let Some(server_id) = chosen {
        let sender = state.agent_senders.read().await.get(&server_id).cloned();
        // `choose` only returns connected agents, so this is belt and braces —
        // but an agent can drop between the two, and silently spawning locally
        // after the operator picked a server would be the wrong repair.
        let Some(sender) = sender else {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "agent_offline"})),
            ));
        };
        let port = state.hub_manager.allocate_port(&state.db).await;
        let voice_port = state.hub_manager.allocate_voice_port(&state.db).await;
        // The node may hold its own PostgreSQL (farm-model.md, "per-node
        // PostgreSQL"), in which case `db_url` — provisioned on the farm's
        // server — is the wrong machine. Send the database *name* and this
        // server's template alongside it and let the agent decide: its own
        // template first, so a node's credentials never have to reach us.
        let db_url_template: Option<String> =
            sqlx::query_scalar("SELECT db_url_template FROM servers WHERE id = $1")
                .bind(&server_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        let cmd = serde_json::json!({
            "type": "spawn_hub",
            "hub_id": hub_id,
            "db_url": db_url,
            "db_name": crate::db::provision::database_name(&hub_id),
            "db_url_template": db_url_template,
            "port": port,
            "voice_port": voice_port,
            "owner_pubkey": payload.sub,
            "farm_url": state.farm_url,
        });
        let _ = sqlx::query("UPDATE hubs SET server_id = $1 WHERE id = $2")
            .bind(&server_id)
            .bind(&hub_id)
            .execute(&state.db)
            .await;
        // try_send: channel is bounded; on a full channel (agent not consuming)
        // we fall through to local spawn rather than blocking or silently dropping.
        sender.try_send(cmd.to_string()).is_ok()
    } else {
        false
    };

    if !launched {
        match state
            .hub_manager
            .allocate_and_spawn(&state.db, &hub_id, &db_url, Some(payload.sub.as_str()))
            .await
        {
            Ok((port, voice_port)) => {
                tracing::info!(hub_id, port, voice_port, "Hub spawned locally")
            }
            Err(e) => tracing::warn!(hub_id, error = %e, "Hub spawn failed"),
        }
    }

    // Freshly created: no heartbeat yet, so there is no address to hand back.
    // The caller polls `GET /farm/hubs/{id}` (or the fleet view) until there is.
    let url = hub_url(&state.db, &state.farm_url, &hub_id, None).await;
    Ok((
        StatusCode::CREATED,
        Json(CreateHubResponse {
            id: hub_id,
            hub_url: url,
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

pub async fn get_hub(
    Path(hub_id): Path<String>,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<HubEntry>, (StatusCode, Json<serde_json::Value>)> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        Option<String>,
        String,
        i64,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT name, description, visibility, created_at, suspended_at, hub_pubkey
         FROM hubs WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let (name, description, visibility, created_at, suspended_at, hub_pubkey) =
        row.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "hub_not_found"})),
            )
        })?;

    Ok(Json(HubEntry {
        hub_url: hub_url(&state.db, &state.farm_url, &hub_id, hub_pubkey.as_deref()).await,
        id: hub_id,
        name,
        description,
        visibility,
        created_at,
        suspended_at,
    }))
}

// ---------------------------------------------------------------------------
// PATCH /farm/hubs/:hub_id/suspend
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct SuspendResponse {
    pub id: String,
    pub suspended_at: Option<i64>,
}

pub async fn suspend_hub(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<SuspendRequest>,
) -> Result<Json<SuspendResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // Only farm admin may suspend.
    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(&payload.sub) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }

    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM hubs WHERE id = $1 AND deleted_at IS NULL")
            .bind(&hub_id)
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
            Json(serde_json::json!({"error": "hub_not_found"})),
        ));
    }

    let now = unix_now();
    sqlx::query("UPDATE hubs SET suspended_at = $1, suspension_reason = $2 WHERE id = $3")
        .bind(now)
        .bind(&req.reason)
        .bind(&hub_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    Ok(Json(SuspendResponse {
        id: hub_id,
        suspended_at: Some(now),
    }))
}

// ---------------------------------------------------------------------------
// POST /farm/hubs/:hub_id/restart
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RestartResponse {
    pub id: String,
    pub restarted_at: i64,
}

/// Admin-triggered immediate restart. Mirrors `suspend_hub`'s auth pattern.
/// Resets `restart_attempts` and re-enables auto-restart supervision (see
/// monitor.rs) — an operator restarting a hub by hand is a fresh start, not
/// another automated attempt.
///
/// Farm-local hubs restart via `HubManager` directly; agent-hosted hubs
/// (`hubs.server_id` set) delegate to the owning agent over its WebSocket
/// (`FarmState::send_restart_to_agent`), returning 503 `agent_offline` if
/// that agent isn't currently connected.
pub async fn force_restart_hub(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<RestartResponse>, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(&payload.sub) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }

    #[allow(clippy::type_complexity)]
    let row: Option<(Option<i32>, Option<i32>, Option<String>, String)> = sqlx::query_as(
        "SELECT process_port, voice_port, server_id, owner_pubkey FROM hubs
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let (process_port, voice_port, server_id, owner_pubkey) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "hub_not_found"})),
        )
    })?;

    let Some(port) = process_port else {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "hub_not_running"})),
        ));
    };

    let voice_port = state.resolve_voice_port(&hub_id, voice_port).await;

    // Provisions on the spot for a hub that predates per-hub databases, so an
    // admin restart is also the repair path.
    let db_url = state
        .hub_manager
        .ensure_db_url(&state.db, &hub_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "database_provisioning_failed",
                    "details": e.to_string(),
                })),
            )
        })?;

    if let Some(server_id) = server_id {
        // Agent-hosted hub — delegate the restart over the agent's WebSocket.
        if state
            .send_restart_to_agent(
                &server_id,
                &hub_id,
                &db_url,
                port as u16,
                voice_port,
                Some(&owner_pubkey),
            )
            .await
            .is_err()
        {
            tracing::warn!(hub_id, server_id, "Force-restart failed — agent offline");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "agent_offline"})),
            ));
        }
    } else {
        // Best-effort, same as `create_hub`'s spawn and `spawn_all_from_db`: a
        // missing/unreachable hub binary shouldn't turn an admin action into a
        // 500 — it's logged, and the fleet view already surfaces online status.
        if let Err(e) = state
            .hub_manager
            .restart_hub(&hub_id, &db_url, port as u16, voice_port)
            .await
        {
            tracing::warn!(hub_id, error = %e, "Force-restart failed to spawn hub process");
        }
    }

    let now = unix_now();
    sqlx::query(
        "UPDATE hubs SET restart_attempts = 0, last_restart_at = $1, auto_restart_enabled = TRUE
         WHERE id = $2",
    )
    .bind(now)
    .bind(&hub_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(RestartResponse {
        id: hub_id,
        restarted_at: now,
    }))
}

// ---------------------------------------------------------------------------
// DELETE /farm/hubs/:hub_id
// ---------------------------------------------------------------------------

pub async fn delete_hub(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(&headers, &farm_pubkey)?;

    // Admin or owner may delete.
    let admin_pubkey = get_admin_pubkey(&state.db).await;
    let is_admin = admin_pubkey.as_deref() == Some(&payload.sub);

    let row: Option<(String,)> =
        sqlx::query_as("SELECT owner_pubkey FROM hubs WHERE id = $1 AND deleted_at IS NULL")
            .bind(&hub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    let (owner_pubkey,) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "hub_not_found"})),
        )
    })?;

    if !is_admin && payload.sub != owner_pubkey {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "farm_admin_only"})),
        ));
    }

    // Stop the hub process if running.
    if let Err(e) = state.hub_manager.stop_hub(&hub_id).await {
        tracing::warn!(hub_id, error = %e, "Failed to stop hub process on delete (continuing)");
    }

    // Tombstone the row (leave DB file for operator).
    let now = unix_now();
    sqlx::query("UPDATE hubs SET deleted_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&hub_id)
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

// ---------------------------------------------------------------------------
// Helper: the nodes a hub could be placed on, with their current load
// ---------------------------------------------------------------------------

/// Every connected agent plus the farm's own process, each with how many hubs
/// it holds and how many it may.
///
/// Only *connected* agents are listed: a registered server whose agent is
/// offline cannot be handed a spawn command, so offering it as a target would
/// only produce a hub that never starts.
async fn collect_nodes(state: &FarmState) -> Result<Vec<crate::placement::Node>, sqlx::Error> {
    let counts: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT server_id, COUNT(*) FROM hubs WHERE deleted_at IS NULL GROUP BY server_id",
    )
    .fetch_all(&state.db)
    .await?;
    let used: std::collections::HashMap<Option<String>, i64> = counts.into_iter().collect();

    let caps: Vec<(String, Option<i32>)> =
        sqlx::query_as("SELECT id, max_hubs FROM servers WHERE deleted_at IS NULL")
            .fetch_all(&state.db)
            .await?;
    let caps: std::collections::HashMap<String, Option<i32>> = caps.into_iter().collect();

    let local_cap: i64 = sqlx::query_scalar("SELECT max_local_hubs FROM farms WHERE id = 1")
        .fetch_optional(&state.db)
        .await?
        .unwrap_or(0);

    let connected = state.agent_senders.read().await;
    let mut nodes: Vec<crate::placement::Node> = connected
        .keys()
        .map(|id| crate::placement::Node {
            in_use: *used.get(&Some(id.clone())).unwrap_or(&0),
            // A registered server with no cap set is unlimited.
            capacity: caps.get(id).copied().flatten().map(|c| c as i64),
            server_id: Some(id.clone()),
        })
        .collect();

    nodes.push(crate::placement::Node {
        server_id: None,
        in_use: *used.get(&None).unwrap_or(&0),
        // 0 means unlimited, matching max_hubs_per_user.
        capacity: if local_cap > 0 { Some(local_cap) } else { None },
    });

    Ok(nodes)
}
