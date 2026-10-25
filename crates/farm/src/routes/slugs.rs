//! Hub slug management — the addresses an owner chooses for their hub.
//!
//! GET    /farm/hubs/{hub_id}/slugs                  — list live + released
//! POST   /farm/hubs/{hub_id}/slugs                  — claim one
//! DELETE /farm/hubs/{hub_id}/slugs/{slug}           — release one
//! PUT    /farm/hubs/{hub_id}/slugs/{slug}/canonical — promote to canonical
//!
//! Every route is hub-owner or farm-admin. See `crate::slug` for why a slug is
//! an alias and never an identity, and for the normalisation rules.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::hubs::{get_admin_pubkey, require_auth};
use crate::slug;
use crate::state::FarmState;
use crate::unix_now;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, code: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": code })))
}

fn err_detail(status: StatusCode, code: &str, details: String) -> ApiError {
    (
        status,
        Json(serde_json::json!({ "error": code, "details": details })),
    )
}

fn db_err(e: sqlx::Error) -> ApiError {
    err_detail(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())
}

/// Owner of the hub, or the farm admin. Returns the hub id on success.
async fn require_hub_control(
    headers: &HeaderMap,
    state: &FarmState,
    hub_id: &str,
) -> Result<(), ApiError> {
    let farm_pubkey = state.public_key_hex();
    let payload = require_auth(headers, &farm_pubkey)?;

    let owner: Option<(String,)> =
        sqlx::query_as("SELECT owner_pubkey FROM hubs WHERE id = $1 AND deleted_at IS NULL")
            .bind(hub_id)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    let owner = owner
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "hub_not_found"))?
        .0;

    let is_admin = get_admin_pubkey(&state.db).await.as_deref() == Some(&payload.sub);
    if owner == payload.sub || is_admin {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "not_hub_owner"))
    }
}

async fn farm_limits(db: &sqlx::PgPool) -> (i64, i64) {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT max_slugs_per_hub, slug_cooloff_days FROM farms WHERE id = 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or((5, 60))
}

// ---------------------------------------------------------------------------
// GET /farm/hubs/{hub_id}/slugs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SlugEntry {
    pub slug: String,
    /// The capitalisation the owner typed. Routing is case-insensitive; this
    /// is only for showing the name back to them.
    pub display_slug: String,
    pub is_canonical: bool,
    pub created_at: i64,
    /// Set when released. A released slug stops resolving immediately.
    pub released_at: Option<i64>,
    /// Until this moment only this hub may reclaim it; afterwards it returns
    /// to the pool. Absent on live slugs.
    pub reclaimable_until: Option<i64>,
    pub last_resolved_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct SlugRow {
    slug: String,
    display_slug: String,
    is_canonical: bool,
    created_at: i64,
    released_at: Option<i64>,
    last_resolved_at: Option<i64>,
}

#[derive(Serialize)]
pub struct ListSlugsResponse {
    pub slugs: Vec<SlugEntry>,
    /// Live slugs this hub may hold at once (farm policy).
    pub max_slugs: i64,
    /// How many of those are in use.
    pub used: i64,
}

pub async fn list_slugs(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListSlugsResponse>, ApiError> {
    require_hub_control(&headers, &state, &hub_id).await?;
    let (max_slugs, cooloff_days) = farm_limits(&state.db).await;

    let rows: Vec<SlugRow> = sqlx::query_as(
        "SELECT slug, display_slug, is_canonical, created_at, released_at, last_resolved_at
         FROM hub_slugs WHERE hub_id = $1 ORDER BY released_at NULLS FIRST, created_at",
    )
    .bind(&hub_id)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;

    let used = rows.iter().filter(|r| r.released_at.is_none()).count() as i64;
    let slugs = rows
        .into_iter()
        .map(|r| SlugEntry {
            reclaimable_until: r.released_at.map(|t| t + cooloff_days * 86_400),
            slug: r.slug,
            display_slug: r.display_slug,
            is_canonical: r.is_canonical,
            created_at: r.created_at,
            released_at: r.released_at,
            last_resolved_at: r.last_resolved_at,
        })
        .collect();

    Ok(Json(ListSlugsResponse {
        slugs,
        max_slugs,
        used,
    }))
}

// ---------------------------------------------------------------------------
// POST /farm/hubs/{hub_id}/slugs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ClaimSlugRequest {
    pub slug: String,
    /// Make this the address the hub publishes. The first slug a hub takes
    /// becomes canonical regardless — a hub with slugs but no canonical one
    /// would have no address to advertise.
    #[serde(default)]
    pub canonical: bool,
}

/// Claim a slug for a hub.
///
/// The availability rules, in the order they are checked:
///
/// - free (no row at all) → taken;
/// - released by **this** hub → reclaimed, whenever, no waiting;
/// - released by another hub, cooling-off elapsed → taken;
/// - released by another hub, still cooling off → 409 `slug_reserved`;
/// - live → 409 `slug_taken`.
///
/// The cooling-off exists because releasing a slug is exactly when inheriting
/// its inbound links is worth most. It is farm policy and may be set to 0.
pub async fn claim_slug(
    Path(hub_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<ClaimSlugRequest>,
) -> Result<(StatusCode, Json<SlugEntry>), ApiError> {
    require_hub_control(&headers, &state, &hub_id).await?;

    let normalized = slug::normalize(&req.slug)
        .map_err(|e| err_detail(StatusCode::BAD_REQUEST, "invalid_slug", e.message()))?;
    let display = req.slug.trim().to_string();
    let (max_slugs, cooloff_days) = farm_limits(&state.db).await;
    let now = unix_now();

    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hub_slugs WHERE hub_id = $1 AND released_at IS NULL",
    )
    .bind(&hub_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;

    if live >= max_slugs {
        return Err(err_detail(
            StatusCode::CONFLICT,
            "slug_quota_reached",
            format!("this hub already holds {live} of {max_slugs} addresses — release one first"),
        ));
    }

    let existing: Option<(String, Option<i64>)> =
        sqlx::query_as("SELECT hub_id, released_at FROM hub_slugs WHERE slug = $1")
            .bind(&normalized)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;

    match existing {
        Some((_, None)) => return Err(err(StatusCode::CONFLICT, "slug_taken")),
        Some((holder, Some(released_at))) => {
            let reclaimable_at = released_at + cooloff_days * 86_400;
            if holder != hub_id && now < reclaimable_at {
                return Err(err_detail(
                    StatusCode::CONFLICT,
                    "slug_reserved",
                    format!("released recently; available again after {reclaimable_at}"),
                ));
            }
            sqlx::query(
                "UPDATE hub_slugs
                 SET hub_id = $1, display_slug = $2, released_at = NULL,
                     is_canonical = FALSE, created_at = $3
                 WHERE slug = $4",
            )
            .bind(&hub_id)
            .bind(&display)
            .bind(now)
            .bind(&normalized)
            .execute(&state.db)
            .await
            .map_err(db_err)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO hub_slugs (slug, display_slug, hub_id, is_canonical, created_at)
                 VALUES ($1, $2, $3, FALSE, $4)",
            )
            .bind(&normalized)
            .bind(&display)
            .bind(&hub_id)
            .bind(now)
            .execute(&state.db)
            .await
            // A concurrent claim of the same slug loses the unique-key race
            // here rather than silently overwriting.
            .map_err(|_| err(StatusCode::CONFLICT, "slug_taken"))?;
        }
    }

    // First slug always becomes canonical: slugs with no canonical among them
    // would leave the hub advertising its pubkey URL while perfectly good
    // names sit unused.
    if req.canonical || live == 0 {
        set_canonical(&state, &hub_id, &normalized).await?;
    }

    Ok((
        StatusCode::CREATED,
        Json(SlugEntry {
            slug: normalized,
            display_slug: display,
            is_canonical: req.canonical || live == 0,
            created_at: now,
            released_at: None,
            reclaimable_until: None,
            last_resolved_at: None,
        }),
    ))
}

async fn set_canonical(state: &FarmState, hub_id: &str, slug: &str) -> Result<(), ApiError> {
    let mut tx = state.db.begin().await.map_err(db_err)?;
    sqlx::query("UPDATE hub_slugs SET is_canonical = FALSE WHERE hub_id = $1 AND is_canonical")
        .bind(hub_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "UPDATE hub_slugs SET is_canonical = TRUE
         WHERE slug = $1 AND hub_id = $2 AND released_at IS NULL",
    )
    .bind(slug)
    .bind(hub_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PUT /farm/hubs/{hub_id}/slugs/{slug}/canonical
// ---------------------------------------------------------------------------

pub async fn promote_slug(
    Path((hub_id, slug_param)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<StatusCode, ApiError> {
    require_hub_control(&headers, &state, &hub_id).await?;
    let lowered = slug_param.to_ascii_lowercase();

    let live: Option<(String,)> = sqlx::query_as(
        "SELECT slug FROM hub_slugs WHERE slug = $1 AND hub_id = $2 AND released_at IS NULL",
    )
    .bind(&lowered)
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    if live.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "slug_not_found"));
    }

    set_canonical(&state, &hub_id, &lowered).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /farm/hubs/{hub_id}/slugs/{slug}
// ---------------------------------------------------------------------------

/// Release a slug: it stops resolving and frees a quota slot, but the row
/// stays so the cooling-off window can be enforced.
///
/// Releasing the canonical one promotes the oldest remaining live slug rather
/// than refusing — an automatic choice cannot leave the hub in a state where
/// it holds names but advertises none. When nothing is left, the hub falls
/// back to its pubkey address, which always works.
pub async fn release_slug(
    Path((hub_id, slug_param)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<StatusCode, ApiError> {
    require_hub_control(&headers, &state, &hub_id).await?;
    let lowered = slug_param.to_ascii_lowercase();

    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT is_canonical FROM hub_slugs
         WHERE slug = $1 AND hub_id = $2 AND released_at IS NULL",
    )
    .bind(&lowered)
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    let was_canonical = row
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "slug_not_found"))?
        .0;

    sqlx::query("UPDATE hub_slugs SET released_at = $1, is_canonical = FALSE WHERE slug = $2")
        .bind(unix_now())
        .bind(&lowered)
        .execute(&state.db)
        .await
        .map_err(db_err)?;

    if was_canonical {
        let next: Option<(String,)> = sqlx::query_as(
            "SELECT slug FROM hub_slugs
             WHERE hub_id = $1 AND released_at IS NULL ORDER BY created_at LIMIT 1",
        )
        .bind(&hub_id)
        .fetch_optional(&state.db)
        .await
        .map_err(db_err)?;
        if let Some((next_slug,)) = next {
            set_canonical(&state, &hub_id, &next_slug).await?;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /farm/hubs/by-pubkey/{pubkey}
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HubAddressResponse {
    pub hub_url: String,
}

/// Where a hub lives now, looked up by the one thing about it that never
/// changes.
///
/// The safety net under renaming. A client normally learns a new address from
/// the hub itself (`/info.canonical_url`), but one that was closed while the
/// rename happened comes back to a URL that no longer resolves and has no way
/// to ask the hub anything. It does still hold the pubkey, so it asks the farm.
///
/// Unauthenticated on purpose: a client in this position may hold no valid
/// token for that hub, and the answer is not a secret — the same mapping is
/// what the public proxy resolves on every request.
pub async fn hub_address_by_pubkey(
    Path(pubkey): Path<String>,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<HubAddressResponse>, ApiError> {
    let hub_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM hubs WHERE hub_pubkey = $1 AND deleted_at IS NULL")
            .bind(&pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    let hub_id = hub_id.ok_or_else(|| err(StatusCode::NOT_FOUND, "hub_not_found"))?;

    // No slug gives the pubkey form, which is what the caller already had.
    // Still worth answering — it confirms the hub exists and was not renamed,
    // which is different information from a 404.
    let hub_url = crate::routes::hubs::hub_url(&state.db, &state.farm_url, &hub_id, Some(&pubkey))
        .await
        .unwrap_or_default();

    Ok(Json(HubAddressResponse { hub_url }))
}

/// The address a hub should advertise: its canonical slug when it has one,
/// otherwise `None` and the caller falls back to the pubkey form.
///
/// Used by the heartbeat response, which is how a hub learns its own public
/// name — it cannot be passed at spawn, because a rename must reach a running
/// hub without restarting it.
pub async fn canonical_slug(db: &sqlx::PgPool, hub_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT slug FROM hub_slugs
         WHERE hub_id = $1 AND is_canonical AND released_at IS NULL",
    )
    .bind(hub_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}
