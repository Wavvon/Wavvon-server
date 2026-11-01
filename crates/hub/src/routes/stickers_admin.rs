//! The stored-sticker admin page (stickers.md §5): everything this hub holds,
//! both budgets against their caps, and delete / block / unblock under
//! `stickers.moderate`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, STICKERS_MODERATE};
use crate::routes::paging::{DEFAULT_LIMIT, MAX_LIMIT};
use crate::routes::stickers::{read_settings, valid_sha256};
use crate::state::AppState;

type ApiErr = (StatusCode, String);

fn db_err(e: sqlx::Error) -> ApiErr {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

async fn require_moderate(state: &AppState, user: &AuthUser) -> Result<(), ApiErr> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(STICKERS_MODERATE)
}

/// Spelled out rather than flattening `PageQuery`: see the paging note in
/// CLAUDE.md (`serde_urlencoded` and flatten).
#[derive(Deserialize, Default)]
pub struct ListQuery {
    /// `ok`, `removed`, `evicted`, or absent for all.
    pub state: Option<String>,
    pub uploader: Option<String>,
    /// `created` (default), `used` or `size`, newest or largest first.
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AdminSticker {
    pub id: String,
    pub sha256: String,
    pub name: String,
    pub size_bytes: i64,
    pub width: i32,
    pub height: i32,
    pub pack_id: Option<String>,
    pub uploader: String,
    pub origin_hub_url: Option<String>,
    pub origin_hub_name: Option<String>,
    pub created_at: i64,
    pub last_used_at: i64,
    pub state: String,
    pub message_count: i64,
}

/// GET /admin/stickers
pub async fn list_stickers(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<AdminSticker>>, ApiErr> {
    require_moderate(&state, &user).await?;
    let key = match q.sort.as_deref().unwrap_or("created") {
        "created" => "created_at",
        "used" => "last_used_at",
        "size" => "size_bytes",
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "sort must be created, used or size".into(),
            ))
        }
    };
    if let Some(s) = q.state.as_deref() {
        if !matches!(s, "ok" | "removed" | "evicted") {
            return Err((
                StatusCode::BAD_REQUEST,
                "state must be ok, removed or evicted".into(),
            ));
        }
    }
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    // Filters belong before LIMIT; `key` comes from the whitelist above.
    let sql = format!(
        "SELECT * FROM (
            SELECT s.id, s.sha256, s.name, s.size_bytes, s.width, s.height, s.pack_id,
                   s.uploader, s.origin_hub_url, s.origin_hub_name, s.created_at,
                   s.last_used_at,
                   CASE WHEN s.removed_at IS NOT NULL THEN 'removed'
                        WHEN s.evicted_at IS NOT NULL THEN 'evicted' ELSE 'ok' END AS state,
                   (SELECT COUNT(*) FROM messages m WHERE m.sticker_id = s.id) AS message_count
            FROM stickers s
         ) t
         WHERE ($1::text IS NULL OR t.state = $1)
           AND ($2::text IS NULL OR t.uploader = $2)
           AND ($3::text IS NULL OR (t.{key}, t.id) <
                ((SELECT x.{key} FROM stickers x WHERE x.id = $3), $3))
         ORDER BY t.{key} DESC, t.id DESC LIMIT $4"
    );
    let rows: Vec<AdminSticker> = sqlx::query_as(&sql)
        .bind(q.state.as_deref())
        .bind(q.uploader.as_deref())
        .bind(q.cursor.as_deref())
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(db_err)?;
    Ok(Json(rows))
}

#[derive(Serialize)]
pub struct Budget {
    pub count: i64,
    pub bytes: i64,
    pub cap_bytes: i64,
}

#[derive(Serialize)]
pub struct Usage {
    pub packs: Budget,
    /// Packs are at or past `stickers_packs_warn_percent` of their cap.
    pub packs_warning: bool,
    pub copies: Budget,
    /// Copies whose bytes were dropped for space and that have not come back.
    pub evictions: i64,
}

/// GET /admin/stickers/usage
pub async fn usage(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Usage>, ApiErr> {
    require_moderate(&state, &user).await?;
    let s = read_settings(&state.db).await;
    let (pc, pb, cc, cb, ev): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) FILTER (WHERE pack_id IS NOT NULL AND removed_at IS NULL),
            COALESCE(SUM(size_bytes) FILTER (WHERE pack_id IS NOT NULL AND removed_at IS NULL), 0)::BIGINT,
            COUNT(*) FILTER (WHERE pack_id IS NULL AND removed_at IS NULL AND evicted_at IS NULL),
            COALESCE(SUM(size_bytes) FILTER (WHERE pack_id IS NULL AND removed_at IS NULL AND evicted_at IS NULL), 0)::BIGINT,
            COUNT(*) FILTER (WHERE evicted_at IS NOT NULL AND removed_at IS NULL)
         FROM stickers",
    )
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    let packs_cap = s.stickers_packs_cap_bytes as i64;
    Ok(Json(Usage {
        packs: Budget {
            count: pc,
            bytes: pb,
            cap_bytes: packs_cap,
        },
        packs_warning: pb as i128 * 100
            >= packs_cap as i128 * s.stickers_packs_warn_percent as i128,
        copies: Budget {
            count: cc,
            bytes: cb,
            cap_bytes: s.stickers_copies_cap_bytes as i64,
        },
        evictions: ev,
    }))
}

#[derive(Deserialize, Default)]
pub struct DeleteQuery {
    #[serde(default)]
    pub block: bool,
    pub reason: Option<String>,
}

/// DELETE /admin/stickers/{id}?block=true -- the bytes go, the row stays as the
/// "sticker removed" tombstone messages render, and with `block` the hash is
/// refused at every later ingest.
pub async fn delete_sticker(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<StatusCode, ApiErr> {
    require_moderate(&state, &user).await?;
    let now = crate::auth::handlers::unix_timestamp();
    let sha: Option<String> = sqlx::query_scalar(
        "UPDATE stickers SET removed_at = COALESCE(removed_at, $2), pack_id = NULL
         WHERE id = $1 RETURNING sha256",
    )
    .bind(&id)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;
    let sha = sha.ok_or((StatusCode::NOT_FOUND, "Sticker not found".to_string()))?;
    crate::routes::stickers::remove_file(&sha).await;
    if q.block {
        sqlx::query(
            "INSERT INTO sticker_blocklist (sha256, blocked_by, reason, created_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (sha256) DO NOTHING",
        )
        .bind(&sha)
        .bind(&user.public_key)
        .bind(q.reason.as_deref())
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
pub struct BlocklistQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct BlockedSticker {
    pub sha256: String,
    pub blocked_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

/// GET /admin/stickers/blocklist -- newest first; the cursor is the last hash.
pub async fn list_blocklist(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<BlocklistQuery>,
) -> Result<Json<Vec<BlockedSticker>>, ApiErr> {
    require_moderate(&state, &user).await?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let rows = sqlx::query_as(
        "SELECT sha256, blocked_by, reason, created_at FROM sticker_blocklist
         WHERE ($1::text IS NULL OR (created_at, sha256) <
                ((SELECT created_at FROM sticker_blocklist WHERE sha256 = $1), $1))
         ORDER BY created_at DESC, sha256 DESC LIMIT $2",
    )
    .bind(q.cursor.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    Ok(Json(rows))
}

/// DELETE /admin/stickers/blocklist/{sha256}
pub async fn unblock(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(sha): Path<String>,
) -> Result<StatusCode, ApiErr> {
    require_moderate(&state, &user).await?;
    if !valid_sha256(&sha) {
        return Err((StatusCode::BAD_REQUEST, "invalid sha256".into()));
    }
    let done = sqlx::query("DELETE FROM sticker_blocklist WHERE sha256 = $1")
        .bind(&sha)
        .execute(&state.db)
        .await
        .map_err(db_err)?
        .rows_affected();
    if done == 0 {
        return Err((StatusCode::NOT_FOUND, "Not on the blocklist".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
