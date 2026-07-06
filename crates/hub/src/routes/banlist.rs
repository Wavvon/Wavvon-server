//! Admin routes for federated ban list management (ME1).
//!
//! Tables:
//!   `federated_ban_sources`  — per-source URL + policy ('hard-reject' | 'soft-flag')
//!   `federated_ban_overrides` — local whitelist / blacklist overrides
//!   `federated_bans`         — synced ban entries (read-only from here; written by banlist_worker)

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::hub::upsert_setting;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct BanSourceResponse {
    pub url: String,
    pub policy: String,
    pub added_at: i64,
    pub issuer_pubkey: Option<String>,
}

#[derive(sqlx::FromRow)]
struct BanSourceRow {
    url: String,
    policy: String,
    added_at: i64,
    issuer_pubkey: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddSourceRequest {
    pub url: String,
    #[serde(default = "default_policy")]
    pub policy: String,
}

fn default_policy() -> String {
    "hard-reject".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateSourceRequest {
    pub url: String,
    pub policy: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteSourceRequest {
    pub url: String,
}

/// GET /admin/banlist/sources
pub async fn list_sources(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<BanSourceResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, BanSourceRow>(
        "SELECT url, policy, added_at, issuer_pubkey FROM federated_ban_sources ORDER BY added_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BanSourceResponse {
                url: r.url,
                policy: r.policy,
                added_at: r.added_at,
                issuer_pubkey: r.issuer_pubkey,
            })
            .collect(),
    ))
}

/// POST /admin/banlist/sources — add a source and trigger an immediate sync
/// (sync is fire-and-forget; the route returns after the DB insert).
pub async fn add_source(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AddSourceRequest>,
) -> Result<(StatusCode, Json<BanSourceResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    validate_policy(&req.policy)?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO federated_ban_sources (url, policy, added_at)
         VALUES ($1, $2, $3)
         ON CONFLICT(url) DO UPDATE SET policy = excluded.policy",
    )
    .bind(&req.url)
    .bind(&req.policy)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Fire immediate sync in background — fail-open if the fetch fails.
    {
        let state_c = state.clone();
        let url_c = req.url.clone();
        tokio::spawn(async move {
            crate::banlist_worker::sync_one_source(&state_c, &url_c).await;
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(BanSourceResponse {
            url: req.url,
            policy: req.policy,
            added_at: now,
            issuer_pubkey: None,
        }),
    ))
}

/// DELETE /admin/banlist/sources — remove a source and its synced ban entries.
pub async fn delete_source(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<DeleteSourceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Look up the issuer_pubkey so we can remove the matching federated_bans rows.
    let issuer: Option<String> =
        sqlx::query_scalar("SELECT issuer_pubkey FROM federated_ban_sources WHERE url = $1")
            .bind(&req.url)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    sqlx::query("DELETE FROM federated_ban_sources WHERE url = $1")
        .bind(&req.url)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if let Some(pubkey) = issuer {
        if !pubkey.is_empty() {
            let _ = sqlx::query("DELETE FROM federated_bans WHERE source_hub_pubkey = $1")
                .bind(&pubkey)
                .execute(&state.db)
                .await;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /admin/banlist/sources — update the policy on an existing source.
pub async fn update_source(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateSourceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    validate_policy(&req.policy)?;

    let updated = sqlx::query("UPDATE federated_ban_sources SET policy = $1 WHERE url = $2")
        .bind(&req.policy)
        .bind(&req.url)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if updated.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Source not found".to_string()));
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EntryFilter {
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FederatedBanEntryResponse {
    pub source_hub_pubkey: String,
    pub target_master_pubkey: String,
    pub reason: Option<String>,
    pub added_at: i64,
    pub synced_at: i64,
}

#[derive(sqlx::FromRow)]
struct FederatedBanRow {
    source_hub_pubkey: String,
    target_master_pubkey: String,
    reason: Option<String>,
    added_at: i64,
    synced_at: i64,
}

/// GET /admin/banlist/entries?source=<hub_pubkey>
pub async fn list_entries(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(filter): Query<EntryFilter>,
) -> Result<Json<Vec<FederatedBanEntryResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = if let Some(src) = filter.source.as_deref() {
        sqlx::query_as::<_, FederatedBanRow>(
            "SELECT source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at
             FROM federated_bans WHERE source_hub_pubkey = $1
             ORDER BY synced_at DESC LIMIT 1000",
        )
        .bind(src)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, FederatedBanRow>(
            "SELECT source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at
             FROM federated_bans
             ORDER BY synced_at DESC LIMIT 1000",
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| FederatedBanEntryResponse {
                source_hub_pubkey: r.source_hub_pubkey,
                target_master_pubkey: r.target_master_pubkey,
                reason: r.reason,
                added_at: r.added_at,
                synced_at: r.synced_at,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Overrides
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct BanOverrideResponse {
    pub target_pubkey: String,
    pub override_type: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
struct BanOverrideRow {
    target_pubkey: String,
    override_type: String,
    reason: Option<String>,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct AddOverrideRequest {
    pub target_pubkey: String,
    pub override_type: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /admin/banlist/overrides
pub async fn add_override(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AddOverrideRequest>,
) -> Result<(StatusCode, Json<BanOverrideResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    if req.override_type != "whitelist" && req.override_type != "blacklist" {
        return Err((
            StatusCode::BAD_REQUEST,
            "override_type must be 'whitelist' or 'blacklist'".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO federated_ban_overrides (target_pubkey, override_type, reason, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT(target_pubkey) DO UPDATE
            SET override_type = excluded.override_type,
                reason = excluded.reason,
                created_at = excluded.created_at",
    )
    .bind(&req.target_pubkey)
    .bind(&req.override_type)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(BanOverrideResponse {
            target_pubkey: req.target_pubkey,
            override_type: req.override_type,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

/// DELETE /admin/banlist/overrides/:pubkey
pub async fn delete_override(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query("DELETE FROM federated_ban_overrides WHERE target_pubkey = $1")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/banlist/overrides
pub async fn list_overrides(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<BanOverrideResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, BanOverrideRow>(
        "SELECT target_pubkey, override_type, reason, created_at
         FROM federated_ban_overrides ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BanOverrideResponse {
                target_pubkey: r.target_pubkey,
                override_type: r.override_type,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Publish-banlist setting
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct BanlistSettingsResponse {
    pub publish_banlist: bool,
    pub sources: Vec<BanSourceResponse>,
}

#[derive(Debug, Deserialize)]
pub struct PatchBanlistSettingsRequest {
    pub publish_banlist: bool,
}

/// PATCH /admin/settings/banlist
pub async fn patch_banlist_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PatchBanlistSettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    upsert_setting(
        &state.db,
        "publish_banlist",
        if req.publish_banlist { "true" } else { "false" },
    )
    .await?;

    Ok(StatusCode::OK)
}

/// GET /admin/settings/banlist
pub async fn get_banlist_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<BanlistSettingsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let publish_banlist: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'publish_banlist'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|v| v == "true")
    .unwrap_or(false);

    let rows = sqlx::query_as::<_, BanSourceRow>(
        "SELECT url, policy, added_at, issuer_pubkey FROM federated_ban_sources ORDER BY added_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let sources = rows
        .into_iter()
        .map(|r| BanSourceResponse {
            url: r.url,
            policy: r.policy,
            added_at: r.added_at,
            issuer_pubkey: r.issuer_pubkey,
        })
        .collect();

    Ok(Json(BanlistSettingsResponse {
        publish_banlist,
        sources,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_policy(policy: &str) -> Result<(), (StatusCode, String)> {
    if policy == "hard-reject" || policy == "soft-flag" {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "policy must be 'hard-reject' or 'soft-flag'".to_string(),
        ))
    }
}
