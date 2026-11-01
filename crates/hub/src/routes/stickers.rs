//! Stickers (stickers.md, sticker-storage.md): hub packs, copies fetched from
//! the hub that published them, and the shared ingest every byte goes through.
//!
//! A message references a sticker row **this hub** holds. A sticker from
//! another hub is fetched once from its origin, normalized, hashed here and
//! stored under that hash, so the second send costs nothing and the hub that
//! shows the image is the hub that can delete it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{FromRequest, Multipart, Path, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, STICKERS_EXTERNAL, STICKERS_PACKS_MANAGE};
use crate::routes::hub::{read_setting, upsert_setting};
use crate::state::AppState;
use crate::sticker_image::{self, IngestError};

type ApiErr = (StatusCode, String);

fn db_err(e: sqlx::Error) -> ApiErr {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, msg.to_string())
}

// ── Settings ────────────────────────────────────────────────────────────

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

/// (key, default, floor, ceiling). Out-of-range stored values fall back to the
/// default, like `max_attachment_bytes`.
const LIMITS: [(&str, u64, u64, u64); 7] = [
    ("stickers_max_file_bytes", 512 * KB, 64 * KB, 4 * MB),
    ("stickers_packs_cap_bytes", 512 * MB, 16 * MB, 100 * GB),
    ("stickers_packs_warn_percent", 90, 50, 99),
    ("stickers_copies_cap_bytes", GB, 64 * MB, 1024 * GB),
    ("stickers_per_pack", 60, 1, 500),
    ("sticker_packs_per_hub", 20, 1, 200),
    ("stickers_orphan_gc_days", 30, 1, 365),
];

/// The largest file a sticker route may receive, plus multipart framing.
pub const BODY_LIMIT: usize = 4 * 1024 * 1024 + 256 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct StickerSettings {
    pub stickers_max_file_bytes: u64,
    pub stickers_packs_cap_bytes: u64,
    pub stickers_packs_warn_percent: u64,
    pub stickers_copies_cap_bytes: u64,
    pub stickers_per_pack: u64,
    pub sticker_packs_per_hub: u64,
    pub stickers_orphan_gc_days: u64,
    pub stickers_export: bool,
}

impl Default for StickerSettings {
    fn default() -> Self {
        let d = |i: usize| LIMITS[i].1;
        StickerSettings {
            stickers_max_file_bytes: d(0),
            stickers_packs_cap_bytes: d(1),
            stickers_packs_warn_percent: d(2),
            stickers_copies_cap_bytes: d(3),
            stickers_per_pack: d(4),
            sticker_packs_per_hub: d(5),
            stickers_orphan_gc_days: d(6),
            stickers_export: true,
        }
    }
}

/// The sticker part of `PATCH /hub`: every field optional, validated against
/// the floors and ceilings in [`LIMITS`].
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct StickerSettingsPatch {
    pub stickers_max_file_bytes: Option<u64>,
    pub stickers_packs_cap_bytes: Option<u64>,
    pub stickers_packs_warn_percent: Option<u64>,
    pub stickers_copies_cap_bytes: Option<u64>,
    pub stickers_per_pack: Option<u64>,
    pub sticker_packs_per_hub: Option<u64>,
    pub stickers_orphan_gc_days: Option<u64>,
    pub stickers_export: Option<bool>,
}

impl StickerSettingsPatch {
    pub async fn apply(&self, db: &sqlx::PgPool) -> Result<(), ApiErr> {
        let values = [
            self.stickers_max_file_bytes,
            self.stickers_packs_cap_bytes,
            self.stickers_packs_warn_percent,
            self.stickers_copies_cap_bytes,
            self.stickers_per_pack,
            self.sticker_packs_per_hub,
            self.stickers_orphan_gc_days,
        ];
        // Validate everything before writing anything.
        for (v, (key, _, min, max)) in values.iter().zip(LIMITS) {
            if let Some(v) = v {
                if !(min..=max).contains(v) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("{key} must be between {min} and {max}"),
                    ));
                }
            }
        }
        for (v, (key, ..)) in values.iter().zip(LIMITS) {
            if let Some(v) = v {
                upsert_setting(db, key, &v.to_string()).await?;
            }
        }
        if let Some(on) = self.stickers_export {
            upsert_setting(db, "stickers_export", if on { "true" } else { "false" }).await?;
        }
        Ok(())
    }
}

pub async fn read_settings(db: &sqlx::PgPool) -> StickerSettings {
    let mut vals = [0u64; 7];
    for (i, (key, default, min, max)) in LIMITS.iter().enumerate() {
        vals[i] = read_setting(db, key)
            .await
            .and_then(|v| v.parse().ok())
            .filter(|v| (*min..=*max).contains(v))
            .unwrap_or(*default);
    }
    let export = read_setting(db, "stickers_export")
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    StickerSettings {
        stickers_max_file_bytes: vals[0],
        stickers_packs_cap_bytes: vals[1],
        stickers_packs_warn_percent: vals[2],
        stickers_copies_cap_bytes: vals[3],
        stickers_per_pack: vals[4],
        sticker_packs_per_hub: vals[5],
        stickers_orphan_gc_days: vals[6],
        stickers_export: export,
    }
}

// ── Rows and wire shapes ────────────────────────────────────────────────

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct StickerRow {
    pub id: String,
    pub sha256: String,
    pub name: String,
    pub mime: String,
    pub size_bytes: i64,
    pub width: i32,
    pub height: i32,
    pub pack_id: Option<String>,
    pub origin_hub_url: Option<String>,
    pub origin_hub_name: Option<String>,
    pub uploader: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub removed_at: Option<i64>,
    pub evicted_at: Option<i64>,
}

const COLUMNS: &str =
    "id, sha256, name, mime, size_bytes, width, height, pack_id, origin_hub_url, \
     origin_hub_name, uploader, created_at, last_used_at, removed_at, evicted_at";

impl StickerRow {
    fn state(&self) -> &'static str {
        if self.removed_at.is_some() {
            "removed"
        } else if self.evicted_at.is_some() {
            "evicted"
        } else {
            "ok"
        }
    }
}

/// What a message and every sticker route carry. `url` is relative to the hub
/// that holds the message, which is the only hub a reader fetches from.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StickerRef {
    pub id: String,
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub width: i32,
    pub height: i32,
    pub origin_hub_url: Option<String>,
    pub origin_hub_name: Option<String>,
    /// `ok`, `removed` (a moderator deleted it) or `evicted` (space was needed).
    pub state: String,
}

impl From<&StickerRow> for StickerRef {
    fn from(r: &StickerRow) -> Self {
        StickerRef {
            id: r.id.clone(),
            name: r.name.clone(),
            url: format!("/stickers/{}", r.sha256),
            sha256: r.sha256.clone(),
            width: r.width,
            height: r.height,
            origin_hub_url: r.origin_hub_url.clone(),
            origin_hub_name: r.origin_hub_name.clone(),
            state: r.state().to_string(),
        }
    }
}

/// The stickers messages reference, by id, for a page of messages at once.
pub async fn load_refs(
    db: &sqlx::PgPool,
    ids: &[String],
) -> Result<HashMap<String, StickerRef>, ApiErr> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<StickerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM stickers WHERE id = ANY($1)"
    ))
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows
        .iter()
        .map(|r| (r.id.clone(), StickerRef::from(r)))
        .collect())
}

pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sticker_path(sha: &str) -> String {
    format!(
        "{}/sticker_{sha}.webp",
        crate::routes::uploads::uploads_dir().trim_end_matches('/')
    )
}

async fn write_file(sha: &str, bytes: &[u8]) -> Result<(), ApiErr> {
    let dir = crate::routes::uploads::uploads_dir();
    tokio::fs::create_dir_all(dir.trim_end_matches('/'))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}")))?;
    tokio::fs::write(sticker_path(sha), bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Write error: {e}"),
            )
        })
}

pub(crate) async fn remove_file(sha: &str) {
    let _ = tokio::fs::remove_file(sticker_path(sha)).await;
}

fn clean_name(raw: &str) -> String {
    let n: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(32)
        .collect::<String>()
        .trim()
        .to_string();
    if n.is_empty() {
        "sticker".to_string()
    } else {
        n
    }
}

// ── Ingest ──────────────────────────────────────────────────────────────

pub struct Origin {
    pub url: String,
    pub name: Option<String>,
}

pub struct Target<'a> {
    pub name: &'a str,
    pub uploader: &'a str,
    /// A pack upload (counted against the packs budget) when set, a copy when not.
    pub pack_id: Option<&'a str>,
    pub origin: Option<Origin>,
}

/// The one way bytes enter: normalize, hash here, check the blocklist, dedup on
/// the exact hash, store. `expect_hash` is a fetched copy's requested hash: the
/// bytes must hash to it and come out of normalization unchanged.
///
/// Returns the row and whether it was created now.
pub async fn ingest(
    state: &AppState,
    input: Vec<u8>,
    t: Target<'_>,
    expect_hash: Option<&str>,
) -> Result<(StickerRow, bool), ApiErr> {
    let db = &state.db;
    let s = read_settings(db).await;
    if let Some(want) = expect_hash {
        if sha256_hex(&input) != want {
            return Err(err(StatusCode::BAD_GATEWAY, "origin_hash_mismatch"));
        }
    }
    let canon = sticker_image::canonicalize(input, s.stickers_max_file_bytes as usize)
        .await
        .map_err(|e| match e {
            IngestError::TooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m),
            IngestError::NotAnImage(m) => (StatusCode::BAD_REQUEST, m),
        })?;
    let sha = sha256_hex(&canon.bytes);
    if expect_hash.is_some_and(|want| want != sha) {
        return Err(err(StatusCode::BAD_GATEWAY, "origin_not_canonical"));
    }

    let blocked: Option<String> =
        sqlx::query_scalar("SELECT sha256 FROM sticker_blocklist WHERE sha256 = $1")
            .bind(&sha)
            .fetch_optional(db)
            .await
            .map_err(db_err)?;
    if blocked.is_some() {
        return Err(err(StatusCode::FORBIDDEN, "sticker_blocked"));
    }

    let now = crate::auth::handlers::unix_timestamp();
    let size = canon.bytes.len() as i64;
    let existing = find_by_sha(db, &sha).await?;

    if let Some(row) = existing {
        if row.removed_at.is_some() {
            return Err(err(StatusCode::FORBIDDEN, "sticker_removed"));
        }
        if let Some(pack) = t.pack_id {
            if row.pack_id.is_some() {
                return Err(err(StatusCode::CONFLICT, "already_in_a_pack"));
            }
            check_pack_room(db, &s, pack, row.size_bytes).await?;
        }
        if row.evicted_at.is_some() {
            if t.pack_id.is_none() {
                make_room(db, s.stickers_copies_cap_bytes as i64, size, &row.id).await?;
            }
            write_file(&sha, &canon.bytes).await?;
        }
        // Dedup hit: nothing is stored again. Joining a pack makes it this
        // hub's own, so its old origin label goes.
        let updated: StickerRow = sqlx::query_as(&format!(
            "UPDATE stickers SET
                evicted_at = NULL, last_used_at = $2,
                pack_id = COALESCE($3, pack_id),
                name = CASE WHEN $3 IS NULL THEN name ELSE $4 END,
                origin_hub_url = CASE WHEN $3 IS NOT NULL THEN NULL
                                      ELSE COALESCE($5, origin_hub_url) END,
                origin_hub_name = CASE WHEN $3 IS NOT NULL THEN NULL
                                       ELSE COALESCE($6, origin_hub_name) END
             WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(&row.id)
        .bind(now)
        .bind(t.pack_id)
        .bind(clean_name(t.name))
        .bind(t.origin.as_ref().map(|o| o.url.clone()))
        .bind(t.origin.as_ref().and_then(|o| o.name.clone()))
        .fetch_one(db)
        .await
        .map_err(db_err)?;
        return Ok((updated, false));
    }

    match t.pack_id {
        Some(pack) => check_pack_room(db, &s, pack, size).await?,
        // ponytail: concurrent ingests can each see room and overshoot the
        // copies cap briefly; the next ingest evicts back under it.
        None => make_room(db, s.stickers_copies_cap_bytes as i64, size, "").await?,
    }
    write_file(&sha, &canon.bytes).await?;
    let id = Uuid::new_v4().to_string();
    let inserted: Option<StickerRow> = sqlx::query_as(&format!(
        "INSERT INTO stickers (id, sha256, name, mime, size_bytes, width, height, pack_id,
            origin_hub_url, origin_hub_name, uploader, created_at, last_used_at)
         VALUES ($1, $2, $3, 'image/webp', $4, $5, $6, $7, $8, $9, $10, $11, $11)
         ON CONFLICT (sha256) DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind(&id)
    .bind(&sha)
    .bind(clean_name(t.name))
    .bind(size)
    .bind(canon.width as i32)
    .bind(canon.height as i32)
    .bind(t.pack_id)
    .bind(t.origin.as_ref().map(|o| o.url.clone()))
    .bind(t.origin.as_ref().and_then(|o| o.name.clone()))
    .bind(t.uploader)
    .bind(now)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    match inserted {
        Some(row) => Ok((row, true)),
        // Lost a race with the same image: the row that won is the answer.
        None => find_by_sha(db, &sha)
            .await?
            .map(|r| (r, false))
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "sticker vanished")),
    }
}

async fn find_by_sha(db: &sqlx::PgPool, sha: &str) -> Result<Option<StickerRow>, ApiErr> {
    sqlx::query_as(&format!("SELECT {COLUMNS} FROM stickers WHERE sha256 = $1"))
        .bind(sha)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

async fn check_pack_room(
    db: &sqlx::PgPool,
    s: &StickerSettings,
    pack_id: &str,
    add_bytes: i64,
) -> Result<(), ApiErr> {
    let in_pack: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM stickers WHERE pack_id = $1 AND removed_at IS NULL",
    )
    .bind(pack_id)
    .fetch_one(db)
    .await
    .map_err(db_err)?;
    if in_pack >= s.stickers_per_pack as i64 {
        return Err(err(StatusCode::CONFLICT, "pack_full"));
    }
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM stickers
         WHERE pack_id IS NOT NULL AND removed_at IS NULL",
    )
    .fetch_one(db)
    .await
    .map_err(db_err)?;
    if used + add_bytes > s.stickers_packs_cap_bytes as i64 {
        return Err(err(StatusCode::CONFLICT, "packs_full"));
    }
    Ok(())
}

async fn evict(db: &sqlx::PgPool, id: &str, sha: &str) -> Result<(), ApiErr> {
    remove_file(sha).await;
    sqlx::query("UPDATE stickers SET evicted_at = $2 WHERE id = $1")
        .bind(id)
        .bind(crate::auth::handlers::unix_timestamp())
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Evicts copies until `incoming` more bytes fit under `cap`: orphans first
/// (no message, no pack), then the least recently used. Never refuses.
async fn make_room(
    db: &sqlx::PgPool,
    cap: i64,
    incoming: i64,
    keep_id: &str,
) -> Result<(), ApiErr> {
    loop {
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM stickers
             WHERE pack_id IS NULL AND evicted_at IS NULL AND removed_at IS NULL AND id <> $1",
        )
        .bind(keep_id)
        .fetch_one(db)
        .await
        .map_err(db_err)?;
        if used + incoming <= cap {
            return Ok(());
        }
        let victim: Option<(String, String)> = sqlx::query_as(
            "SELECT s.id, s.sha256 FROM stickers s
             WHERE s.pack_id IS NULL AND s.evicted_at IS NULL AND s.removed_at IS NULL
               AND s.id <> $1
             ORDER BY EXISTS (SELECT 1 FROM messages m WHERE m.sticker_id = s.id) ASC,
                      s.last_used_at ASC, s.id ASC
             LIMIT 1",
        )
        .bind(keep_id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
        match victim {
            Some((id, sha)) => evict(db, &id, &sha).await?,
            None => return Ok(()),
        }
    }
}

// ── Public bytes and the federation route ───────────────────────────────

fn webp_response(bytes: Vec<u8>) -> Response {
    let mut resp = Response::new(axum::body::Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/webp"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn read_live(state: &AppState, sha: &str, pack_only: bool) -> Result<Response, ApiErr> {
    let not_found = || err(StatusCode::NOT_FOUND, "Sticker not found");
    if !valid_sha256(sha) {
        return Err(not_found());
    }
    let row = find_by_sha(&state.db, sha).await?.ok_or_else(not_found)?;
    if row.removed_at.is_some() || row.evicted_at.is_some() || (pack_only && row.pack_id.is_none())
    {
        return Err(not_found());
    }
    let bytes = tokio::fs::read(sticker_path(sha)).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            not_found()
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}"))
        }
    })?;
    Ok(webp_response(bytes))
}

/// GET /stickers/{sha256} -- public: an `<img>` sends no token, and the bytes
/// are addressed by their own hash.
pub async fn serve_sticker(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, ApiErr> {
    read_live(&state, &sha, false).await
}

/// GET /federation/stickers/{sha256} -- another hub fetching a sticker this hub
/// published. Own pack stickers only, so removing one or turning export off is
/// enforceable. Unauthenticated on purpose (the bytes are public already and any
/// key can claim to be a hub); the router rate-limits it per IP.
pub async fn federation_sticker(
    State(state): State<Arc<AppState>>,
    Path(sha): Path<String>,
) -> Result<Response, ApiErr> {
    if !read_settings(&state.db).await.stickers_export {
        return Err(err(StatusCode::FORBIDDEN, "stickers_export_off"));
    }
    read_live(&state, &sha, true).await
}

// ── POST /channels/{id}/stickers: make this hub hold a sticker ──────────

#[derive(Deserialize)]
pub struct EnsureRequest {
    pub sha256: String,
    pub origin_hub_url: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// `https://host[:port][/prefix]`, no credentials, query or fragment, no
/// trailing slash. The URL comes from a member, so it only ever reaches the
/// SSRF-checked fetcher.
fn normalize_origin(raw: &str) -> Result<String, ApiErr> {
    let bad = || err(StatusCode::BAD_REQUEST, "invalid origin_hub_url");
    let mut u = url::Url::parse(raw.trim()).map_err(|_| bad())?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err(bad());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad());
    }
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.as_str().trim_end_matches('/').to_string())
}

pub async fn ensure_sticker(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<EnsureRequest>,
) -> Result<(StatusCode, Json<StickerRef>), ApiErr> {
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MESSAGES_SEND)?;
    if !valid_sha256(&req.sha256) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid sha256"));
    }
    let db = &state.db;
    let existing = find_by_sha(db, &req.sha256).await?;
    if let Some(row) = &existing {
        if row.removed_at.is_some() {
            return Err(err(StatusCode::FORBIDDEN, "sticker_removed"));
        }
        // This hub's own pack stickers need no permission to send.
        if row.pack_id.is_none() {
            perms.require(STICKERS_EXTERNAL)?;
        }
        if row.evicted_at.is_none() {
            let now = crate::auth::handlers::unix_timestamp();
            sqlx::query("UPDATE stickers SET last_used_at = $2 WHERE id = $1")
                .bind(&row.id)
                .bind(now)
                .execute(db)
                .await
                .map_err(db_err)?;
            return Ok((StatusCode::OK, Json(StickerRef::from(row))));
        }
    }
    perms.require(STICKERS_EXTERNAL)?;

    let blocked: Option<String> =
        sqlx::query_scalar("SELECT sha256 FROM sticker_blocklist WHERE sha256 = $1")
            .bind(&req.sha256)
            .fetch_optional(db)
            .await
            .map_err(db_err)?;
    if blocked.is_some() {
        return Err(err(StatusCode::FORBIDDEN, "sticker_blocked"));
    }

    let origin = normalize_origin(&req.origin_hub_url)?;
    crate::routes::preview::check_fetch_rate(&state, &user.public_key)?;
    let max = read_settings(db).await.stickers_max_file_bytes as usize;
    let unavailable = |m: &str| err(StatusCode::BAD_GATEWAY, m);

    // One byte past the cap tells "exactly at the cap" from "over it".
    let (bytes, _) = crate::routes::preview::fetch_capped_opts(
        &format!("{origin}/federation/stickers/{}", req.sha256),
        max + 1,
        state.allow_private_webhooks,
    )
    .await
    .map_err(|_| unavailable("origin_unavailable"))?;
    if bytes.len() > max {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "origin_file_too_large"));
    }

    let origin_name = fetch_hub_name(&state, &origin).await;
    let name = req.name.as_deref().unwrap_or("sticker");
    let (row, created) = ingest(
        &state,
        bytes,
        Target {
            name,
            uploader: &user.public_key,
            pack_id: None,
            origin: Some(Origin {
                url: origin,
                name: origin_name,
            }),
        },
        Some(&req.sha256),
    )
    .await
    .map_err(|(status, msg)| {
        // A bad body from the origin is the origin's failure, not the caller's.
        if status == StatusCode::BAD_REQUEST {
            (
                StatusCode::BAD_GATEWAY,
                format!("origin_sent_invalid_image: {msg}"),
            )
        } else {
            (status, msg)
        }
    })?;
    let code = if created || existing.is_some() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((code, Json(StickerRef::from(&row))))
}

async fn fetch_hub_name(state: &AppState, origin: &str) -> Option<String> {
    let (body, _) = crate::routes::preview::fetch_capped_opts(
        &format!("{origin}/info"),
        64 * 1024,
        state.allow_private_webhooks,
    )
    .await
    .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let name: String = v.get("name")?.as_str()?.chars().take(64).collect();
    (!name.trim().is_empty()).then_some(name)
}

// ── Packs ───────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct PackRow {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct PackResponse {
    #[serde(flatten)]
    pub pack: PackRow,
    pub stickers: Vec<StickerRef>,
}

/// GET /stickers/packs -- every pack with its stickers. Bounded by
/// `sticker_packs_per_hub` x `stickers_per_pack`, so it does not page.
pub async fn list_packs(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<PackResponse>>, ApiErr> {
    let packs: Vec<PackRow> = sqlx::query_as(
        "SELECT id, name, created_by, created_at FROM sticker_packs ORDER BY created_at, id",
    )
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    let rows: Vec<StickerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM stickers
         WHERE pack_id IS NOT NULL AND removed_at IS NULL ORDER BY created_at, id"
    ))
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    let mut by_pack: HashMap<String, Vec<StickerRef>> = HashMap::new();
    for r in &rows {
        if let Some(p) = &r.pack_id {
            by_pack.entry(p.clone()).or_default().push(r.into());
        }
    }
    Ok(Json(
        packs
            .into_iter()
            .map(|p| PackResponse {
                stickers: by_pack.remove(&p.id).unwrap_or_default(),
                pack: p,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct PackNameRequest {
    pub name: String,
}

fn pack_name(raw: &str) -> Result<String, ApiErr> {
    let n = raw.trim();
    if n.is_empty() || n.chars().count() > 64 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "pack name must be 1 to 64 characters",
        ));
    }
    Ok(n.to_string())
}

async fn require(state: &AppState, user: &AuthUser, perm: &str) -> Result<(), ApiErr> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(perm)
}

pub async fn create_pack(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PackNameRequest>,
) -> Result<(StatusCode, Json<PackResponse>), ApiErr> {
    require(&state, &user, STICKERS_PACKS_MANAGE).await?;
    let name = pack_name(&req.name)?;
    let s = read_settings(&state.db).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sticker_packs")
        .fetch_one(&state.db)
        .await
        .map_err(db_err)?;
    if count >= s.sticker_packs_per_hub as i64 {
        return Err(err(StatusCode::CONFLICT, "too_many_packs"));
    }
    let pack: PackRow = sqlx::query_as(
        "INSERT INTO sticker_packs (id, name, created_by, created_at) VALUES ($1, $2, $3, $4)
         RETURNING id, name, created_by, created_at",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(name)
    .bind(&user.public_key)
    .bind(crate::auth::handlers::unix_timestamp())
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    Ok((
        StatusCode::CREATED,
        Json(PackResponse {
            pack,
            stickers: Vec::new(),
        }),
    ))
}

pub async fn rename_pack(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pack_id): Path<String>,
    Json(req): Json<PackNameRequest>,
) -> Result<StatusCode, ApiErr> {
    require(&state, &user, STICKERS_PACKS_MANAGE).await?;
    let done = sqlx::query("UPDATE sticker_packs SET name = $2 WHERE id = $1")
        .bind(&pack_id)
        .bind(pack_name(&req.name)?)
        .execute(&state.db)
        .await
        .map_err(db_err)?
        .rows_affected();
    if done == 0 {
        return Err(err(StatusCode::NOT_FOUND, "Pack not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /stickers/packs/{id} -- its stickers become copies (the FK sets
/// `pack_id` NULL), which the cache can then evict.
pub async fn delete_pack(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pack_id): Path<String>,
) -> Result<StatusCode, ApiErr> {
    require(&state, &user, STICKERS_PACKS_MANAGE).await?;
    let done = sqlx::query("DELETE FROM sticker_packs WHERE id = $1")
        .bind(&pack_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?
        .rows_affected();
    if done == 0 {
        return Err(err(StatusCode::NOT_FOUND, "Pack not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AddBySha {
    sha256: String,
    #[serde(default)]
    name: Option<String>,
}

/// POST /stickers/packs/{id}/stickers -- multipart (`file`, optional `name`),
/// or JSON `{sha256}` for a copy this hub already holds, which then counts as
/// its own.
pub async fn add_pack_sticker(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pack_id): Path<String>,
    req: Request,
) -> Result<(StatusCode, Json<StickerRef>), ApiErr> {
    require(&state, &user, STICKERS_PACKS_MANAGE).await?;
    let pack: Option<String> = sqlx::query_scalar("SELECT id FROM sticker_packs WHERE id = $1")
        .bind(&pack_id)
        .fetch_optional(&state.db)
        .await
        .map_err(db_err)?;
    if pack.is_none() {
        return Err(err(StatusCode::NOT_FOUND, "Pack not found"));
    }

    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("multipart/form-data"));

    let (bytes, name) = if is_multipart {
        let mut mp = Multipart::from_request(req, &state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?;
        let (mut bytes, mut name, mut file_name) = (None, None, None);
        while let Some(field) = mp.next_field().await.map_err(|e| {
            if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                err(StatusCode::PAYLOAD_TOO_LARGE, "file too large")
            } else {
                (StatusCode::BAD_REQUEST, format!("Multipart error: {e}"))
            }
        })? {
            match field.name().unwrap_or("") {
                "name" => name = field.text().await.ok(),
                "file" => {
                    file_name = field.file_name().map(|f| {
                        f.rsplit_once('.')
                            .map(|(stem, _)| stem)
                            .unwrap_or(f)
                            .to_string()
                    });
                    bytes = Some(field.bytes().await.map_err(|e| {
                        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                            err(StatusCode::PAYLOAD_TOO_LARGE, "file too large")
                        } else {
                            (StatusCode::BAD_REQUEST, format!("Read error: {e}"))
                        }
                    })?);
                }
                _ => {}
            }
        }
        let bytes =
            bytes.ok_or_else(|| err(StatusCode::BAD_REQUEST, "No 'file' field in upload"))?;
        (
            Some(bytes.to_vec()),
            name.or(file_name).unwrap_or_else(|| "sticker".to_string()),
        )
    } else {
        let Json(body) = Json::<AddBySha>::from_request(req, &state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.body_text()))?;
        if !valid_sha256(&body.sha256) {
            return Err(err(StatusCode::BAD_REQUEST, "invalid sha256"));
        }
        let row = find_by_sha(&state.db, &body.sha256)
            .await?
            .filter(|r| r.removed_at.is_none() && r.evicted_at.is_none())
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "Sticker not found"))?;
        if row.pack_id.is_some() {
            return Err(err(StatusCode::CONFLICT, "already_in_a_pack"));
        }
        let s = read_settings(&state.db).await;
        check_pack_room(&state.db, &s, &pack_id, row.size_bytes).await?;
        let updated: StickerRow = sqlx::query_as(&format!(
            "UPDATE stickers SET pack_id = $2, name = $3, origin_hub_url = NULL,
                origin_hub_name = NULL WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(&row.id)
        .bind(&pack_id)
        .bind(clean_name(body.name.as_deref().unwrap_or(&row.name)))
        .fetch_one(&state.db)
        .await
        .map_err(db_err)?;
        return Ok((StatusCode::CREATED, Json(StickerRef::from(&updated))));
    };

    let (row, _) = ingest(
        &state,
        bytes.unwrap_or_default(),
        Target {
            name: &name,
            uploader: &user.public_key,
            pack_id: Some(&pack_id),
            origin: None,
        },
        None,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(StickerRef::from(&row))))
}

/// DELETE /stickers/packs/{id}/stickers/{sticker_id} -- the sticker leaves the
/// pack and becomes a copy; messages that used it keep working.
pub async fn remove_pack_sticker(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((pack_id, sticker_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiErr> {
    require(&state, &user, STICKERS_PACKS_MANAGE).await?;
    let done = sqlx::query("UPDATE stickers SET pack_id = NULL WHERE id = $1 AND pack_id = $2")
        .bind(&sticker_id)
        .bind(&pack_id)
        .execute(&state.db)
        .await
        .map_err(db_err)?
        .rows_affected();
    if done == 0 {
        return Err(err(StatusCode::NOT_FOUND, "Sticker not in this pack"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Sending: the checks send_message_with makes ─────────────────────────

/// Validates `sticker_id` for a message in a channel whose effective
/// permissions are `perms`, bumps `last_used_at`, and returns the reference to
/// embed in the response.
pub async fn check_for_send(
    db: &sqlx::PgPool,
    sticker_id: &str,
    perms: &permissions::UserPermissions,
) -> Result<StickerRef, ApiErr> {
    let row: StickerRow = sqlx::query_as(&format!("SELECT {COLUMNS} FROM stickers WHERE id = $1"))
        .bind(sticker_id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Sticker not found"))?;
    if row.removed_at.is_some() {
        return Err(err(StatusCode::GONE, "sticker_removed"));
    }
    if row.evicted_at.is_some() {
        return Err(err(StatusCode::GONE, "sticker_evicted"));
    }
    if row.pack_id.is_none() {
        perms.require(STICKERS_EXTERNAL)?;
    }
    sqlx::query("UPDATE stickers SET last_used_at = $2 WHERE id = $1")
        .bind(&row.id)
        .bind(crate::auth::handlers::unix_timestamp())
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(StickerRef::from(&row))
}

// ── Orphan GC ───────────────────────────────────────────────────────────

/// Deletes copies nothing references (no message, no pack) once unused for
/// `stickers_orphan_gc_days`, so a quiet hub does not sit at its cap.
pub async fn gc_orphans(state: &AppState) -> usize {
    let days = read_settings(&state.db).await.stickers_orphan_gc_days as i64;
    let cutoff = crate::auth::handlers::unix_timestamp() - days * 86400;
    let gone: Vec<String> = sqlx::query_scalar(
        "DELETE FROM stickers s
         WHERE s.pack_id IS NULL AND s.last_used_at < $1
           AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.sticker_id = s.id)
         RETURNING s.sha256",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for sha in &gone {
        remove_file(sha).await;
    }
    gone.len()
}

pub fn spawn_gc(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.tick().await;
        loop {
            interval.tick().await;
            let n = gc_orphans(&state).await;
            if n > 0 {
                tracing::info!(n, "Deleted orphaned stickers");
            }
        }
    });
}
