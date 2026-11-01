//! Message attachments on disk (attachments.md): one blob per distinct stored
//! file, one row per upload, a disk budget that expires the oldest rather than
//! refusing a member.
//!
//! Every path that deletes a blob takes [`LOCK`], and so does the ingest that
//! may add one, so "is there room" and "is this blob still wanted" are each
//! answered once and cannot change under the asker.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};

use crate::routes::hub::{read_setting, upsert_setting};
use crate::sticker_image::{self, IngestError};

type ApiErr = (StatusCode, String);

fn db_err(e: sqlx::Error) -> ApiErr {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, msg.to_string())
}

/// An upload that no message, post or reply claimed within this long is
/// deleted. A cleanup delay, not a setting.
pub const ORPHAN_AFTER_SECS: i64 = 24 * 3600;

const MB: u64 = 1024 * 1024;
const GB: u64 = 1024 * MB;

/// (key, default, floor, ceiling). Out-of-range stored values fall back to the
/// default. The cap's floor exceeds two maximum files, so eviction can always
/// make room.
const LIMITS: [(&str, u64, u64, u64); 4] = [
    ("max_attachments_per_message", 10, 1, 25),
    ("attachments_cap_bytes", 10 * GB, 64 * MB, 10 * 1024 * GB),
    ("attachments_warn_percent", 90, 50, 99),
    ("attachments_retention_days", 0, 0, 3650),
];

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AttachmentSettings {
    pub max_attachments_per_message: u64,
    pub attachments_cap_bytes: u64,
    pub attachments_warn_percent: u64,
    /// 0 = attachments never expire by age.
    pub attachments_retention_days: u64,
}

impl Default for AttachmentSettings {
    fn default() -> Self {
        let d = |i: usize| LIMITS[i].1;
        AttachmentSettings {
            max_attachments_per_message: d(0),
            attachments_cap_bytes: d(1),
            attachments_warn_percent: d(2),
            attachments_retention_days: d(3),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct AttachmentSettingsPatch {
    pub max_attachments_per_message: Option<u64>,
    pub attachments_cap_bytes: Option<u64>,
    pub attachments_warn_percent: Option<u64>,
    pub attachments_retention_days: Option<u64>,
}

impl AttachmentSettingsPatch {
    pub async fn apply(&self, db: &PgPool) -> Result<(), ApiErr> {
        let values = [
            self.max_attachments_per_message,
            self.attachments_cap_bytes,
            self.attachments_warn_percent,
            self.attachments_retention_days,
        ];
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
        Ok(())
    }
}

pub async fn read_settings(db: &PgPool) -> AttachmentSettings {
    let mut vals = [0u64; 4];
    for (i, (key, default, min, max)) in LIMITS.iter().enumerate() {
        vals[i] = read_setting(db, key)
            .await
            .and_then(|v| v.parse().ok())
            .filter(|v| (*min..=*max).contains(v))
            .unwrap_or(*default);
    }
    AttachmentSettings {
        max_attachments_per_message: vals[0],
        attachments_cap_bytes: vals[1],
        attachments_warn_percent: vals[2],
        attachments_retention_days: vals[3],
    }
}

// ── Usage ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Usage {
    pub used_bytes: i64,
    pub cap_bytes: u64,
    pub warning: bool,
    /// Blobs evicted for space since this process started.
    pub evictions: u64,
}

static EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub fn evictions() -> u64 {
    EVICTIONS.load(Ordering::Relaxed)
}

async fn used_bytes(db: &PgPool) -> Result<i64, ApiErr> {
    sqlx::query_scalar("SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM attachment_blobs")
        .fetch_one(db)
        .await
        .map_err(db_err)
}

pub async fn usage(db: &PgPool) -> Usage {
    let s = read_settings(db).await;
    let used = used_bytes(db).await.unwrap_or(0);
    Usage {
        used_bytes: used,
        cap_bytes: s.attachments_cap_bytes,
        warning: used as i128 * 100
            >= s.attachments_cap_bytes as i128 * s.attachments_warn_percent as i128,
        evictions: evictions(),
    }
}

// ── Sniffing ────────────────────────────────────────────────────────────

/// What the bytes are. Coarser than a mime type on purpose: it is what an
/// extension is allowed to disagree with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    Raster,
    Svg,
    Pdf,
    Mp4,
    Zip,
    Pe,
    Text,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub struct Sniffed {
    pub mime: &'static str,
    pub family: Family,
}

fn s(mime: &'static str, family: Family) -> Sniffed {
    Sniffed { mime, family }
}

/// The declared type never decides; the first bytes do.
pub fn sniff(b: &[u8]) -> Sniffed {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return s("image/png", Family::Raster);
    }
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return s("image/jpeg", Family::Raster);
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return s("image/gif", Family::Raster);
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" {
        match &b[8..12] {
            b"WEBP" => return s("image/webp", Family::Raster),
            b"WAVE" => return s("audio/wav", Family::Other),
            _ => {}
        }
    }
    if b.starts_with(b"%PDF-") {
        return s("application/pdf", Family::Pdf);
    }
    if b.starts_with(b"MZ") {
        return s("application/vnd.microsoft.portable-executable", Family::Pe);
    }
    if b.starts_with(b"\x7fELF") {
        return s("application/x-elf", Family::Other);
    }
    if b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || b.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
        return s("application/x-mach-binary", Family::Other);
    }
    if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        return s("application/zip", Family::Zip);
    }
    if b.starts_with(&[0x1F, 0x8B]) {
        return s("application/gzip", Family::Other);
    }
    if b.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return s("application/x-7z-compressed", Family::Other);
    }
    if b.starts_with(b"Rar!\x1a\x07") {
        return s("application/vnd.rar", Family::Other);
    }
    if b.starts_with(b"OggS") {
        return s("audio/ogg", Family::Other);
    }
    if b.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return s("video/webm", Family::Other);
    }
    if b.starts_with(b"ID3") {
        return s("audio/mpeg", Family::Other);
    }
    if b.len() >= 12 && &b[4..8] == b"ftyp" {
        // HEIC and AVIF are files here (no pure-Rust decoder), not video.
        return match &b[8..12] {
            b"heic" | b"heix" | b"mif1" | b"msf1" => s("image/heic", Family::Other),
            b"avif" | b"avis" => s("image/avif", Family::Other),
            _ => s("video/mp4", Family::Mp4),
        };
    }
    let head = &b[..b.len().min(8192)];
    if let Ok(text) = std::str::from_utf8(head) {
        let t = text.trim_start_matches('\u{feff}').trim_start();
        if t.starts_with("<svg") || (t.starts_with("<?xml") && text.contains("<svg")) {
            return s("image/svg+xml", Family::Svg);
        }
        if !head.contains(&0) {
            return s("text/plain", Family::Text);
        }
    } else if head.len() == 8192 {
        // A cut in the middle of a character is still text; anything else is not.
        if let Err(e) = std::str::from_utf8(head) {
            if e.error_len().is_none() && !head.contains(&0) {
                return s("text/plain", Family::Text);
            }
        }
    }
    s("application/octet-stream", Family::Other)
}

fn extension_family(name: &str) -> Option<Family> {
    let (_, ext) = name.rsplit_once('.')?;
    Some(match ext.to_ascii_lowercase().as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" => Family::Raster,
        "svg" => Family::Svg,
        "pdf" => Family::Pdf,
        "mp4" | "m4v" => Family::Mp4,
        "zip" | "jar" | "docx" | "xlsx" | "pptx" | "apk" => Family::Zip,
        "exe" | "dll" | "scr" => Family::Pe,
        "txt" | "md" | "csv" | "json" | "log" => Family::Text,
        _ => return None,
    })
}

/// 415 only when the name claims one kind of file and the bytes are another.
/// A raster named as a different raster is harmless (it is re-encoded) and
/// common (a browser saves a WebP as `.jpg`), so it passes.
pub fn check_extension(name: &str, sniffed: &Sniffed) -> Result<(), ApiErr> {
    match extension_family(name) {
        Some(want) if want != sniffed.family => Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("'{name}' does not match its contents ({})", sniffed.mime),
        )),
        _ => Ok(()),
    }
}

/// The last path segment without control characters, at most 255 characters.
pub fn clean_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let n: String = base.chars().filter(|c| !c.is_control()).take(255).collect();
    let n = n.trim().to_string();
    if n.is_empty() {
        "file".to_string()
    } else {
        n
    }
}

/// RFC 8187 `filename*` value.
pub fn encode_filename(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ── Wire shape ──────────────────────────────────────────────────────────

/// One attachment as messages, posts and replies carry it. `url` is relative
/// to the hub that holds the message.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttachmentRef {
    pub id: String,
    pub url: String,
    pub name: String,
    pub mime: String,
    /// `image` renders inline; `file` is only ever downloaded.
    pub kind: String,
    pub size: i64,
    #[serde(default)]
    pub width: Option<i32>,
    #[serde(default)]
    pub height: Option<i32>,
    /// `ok`, `removed` (a moderator) or `expired` (retention or the budget).
    pub state: String,
}

impl AttachmentRef {
    /// A reader's hub points the client at itself, which streams the file from
    /// the hub that holds it, so the client never contacts a hub it did not
    /// choose.
    pub fn via_alliance(&mut self, alliance_id: &str) {
        self.url = format!("/alliances/{alliance_id}/uploads/{}", self.id);
    }
}

#[derive(Clone, Copy)]
pub enum Owner {
    Message,
    Post,
    Reply,
}

impl Owner {
    fn column(self) -> &'static str {
        match self {
            Owner::Message => "message_id",
            Owner::Post => "post_id",
            Owner::Reply => "reply_id",
        }
    }
}

#[derive(sqlx::FromRow)]
struct RefRow {
    owner_id: String,
    id: String,
    name: String,
    as_file: bool,
    removed_at: Option<i64>,
    expired_at: Option<i64>,
    sha256: Option<String>,
    kind: Option<String>,
    mime: Option<String>,
    size_bytes: Option<i64>,
    width: Option<i32>,
    height: Option<i32>,
}

impl RefRow {
    fn into_ref(self) -> AttachmentRef {
        let state = if self.removed_at.is_some() {
            "removed"
        } else if self.expired_at.is_some() || self.sha256.is_none() || self.kind.is_none() {
            "expired"
        } else {
            "ok"
        };
        let live = state == "ok";
        let inline = live && self.kind.as_deref() == Some("image") && !self.as_file;
        AttachmentRef {
            url: format!("/uploads/{}", self.id),
            id: self.id,
            name: self.name,
            mime: if live {
                self.mime.unwrap_or_default()
            } else {
                "application/octet-stream".to_string()
            },
            kind: if inline { "image" } else { "file" }.to_string(),
            size: if live {
                self.size_bytes.unwrap_or(0)
            } else {
                0
            },
            width: if live { self.width } else { None },
            height: if live { self.height } else { None },
            state: state.to_string(),
        }
    }
}

/// The attachments of each owner id, in the order they were sent.
pub async fn load(
    db: &PgPool,
    owner: Owner,
    owner_ids: &[String],
) -> Result<HashMap<String, Vec<AttachmentRef>>, ApiErr> {
    let mut out: HashMap<String, Vec<AttachmentRef>> = HashMap::new();
    if owner_ids.is_empty() {
        return Ok(out);
    }
    let col = owner.column();
    let sql = format!(
        "SELECT a.{col} AS owner_id, a.id, a.name, a.as_file, a.removed_at, a.expired_at,
                a.sha256, b.kind, b.mime, b.size_bytes, b.width, b.height
         FROM attachments a LEFT JOIN attachment_blobs b ON b.sha256 = a.sha256
         WHERE a.{col} = ANY($1)
         ORDER BY a.position, a.created_at, a.id"
    );
    let rows: Vec<RefRow> = sqlx::query_as(&sql)
        .bind(owner_ids)
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    for r in rows {
        out.entry(r.owner_id.clone())
            .or_default()
            .push(r.into_ref());
    }
    Ok(out)
}

pub async fn load_one(db: &PgPool, owner: Owner, id: &str) -> Result<Vec<AttachmentRef>, ApiErr> {
    Ok(load(db, owner, &[id.to_string()])
        .await?
        .remove(id)
        .unwrap_or_default())
}

// ── Linking ─────────────────────────────────────────────────────────────

/// Checks, before anything is written, that `ids` may be attached by
/// `uploader` in `channel_id`. One answer for "not yours" and "not there", so
/// the ids of other people's uploads are not probeable.
pub async fn check_ids(
    db: &PgPool,
    ids: &[String],
    uploader: &str,
    channel_id: &str,
) -> Result<(), ApiErr> {
    if ids.is_empty() {
        return Ok(());
    }
    let max = read_settings(db).await.max_attachments_per_message as usize;
    if ids.len() > max {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("too_many_attachments: at most {max} per message"),
        ));
    }
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return Err(err(StatusCode::BAD_REQUEST, "duplicate_attachment"));
    }
    let rows: Vec<(String, bool, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT id, (message_id IS NOT NULL OR post_id IS NOT NULL OR reply_id IS NOT NULL),
                removed_at, expired_at
         FROM attachments WHERE id = ANY($1) AND uploader = $2 AND channel_id = $3",
    )
    .bind(ids)
    .bind(uploader)
    .bind(channel_id)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    if rows.len() != ids.len() {
        return Err(err(StatusCode::BAD_REQUEST, "attachment_not_found"));
    }
    for (_, linked, removed, expired) in rows {
        if removed.is_some() || expired.is_some() {
            return Err(err(StatusCode::GONE, "attachment_gone"));
        }
        if linked {
            return Err(err(StatusCode::CONFLICT, "attachment_already_linked"));
        }
    }
    Ok(())
}

/// Attaches `ids` to one owner inside the caller's transaction. The UPDATE
/// repeats the conditions of [`check_ids`], so a concurrent send or an
/// eviction between the two fails the whole write rather than half of it.
pub async fn link(
    tx: &mut PgConnection,
    owner: Owner,
    owner_id: &str,
    ids: &[String],
) -> Result<(), ApiErr> {
    if ids.is_empty() {
        return Ok(());
    }
    let sql = format!(
        "UPDATE attachments SET {} = $1, position = $2
         WHERE id = $3 AND message_id IS NULL AND post_id IS NULL AND reply_id IS NULL
           AND removed_at IS NULL AND expired_at IS NULL",
        owner.column()
    );
    for (pos, id) in ids.iter().enumerate() {
        let n = sqlx::query(&sql)
            .bind(owner_id)
            .bind(pos as i32)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?
            .rows_affected();
        if n != 1 {
            return Err(err(StatusCode::CONFLICT, "attachment_unavailable"));
        }
    }
    sqlx::query(
        "UPDATE attachment_blobs SET last_linked_at = $1
         WHERE sha256 IN (SELECT sha256 FROM attachments WHERE id = ANY($2))",
    )
    .bind(crate::auth::handlers::unix_timestamp())
    .bind(ids)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// A legacy client sending inline `attachments` or outside URLs gets a
/// sentence, not a message that quietly lost them.
pub fn reject_legacy(present: bool) -> Result<(), ApiErr> {
    if present {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "inline attachments are gone: upload through POST /channels/{id}/upload and send attachment_ids",
        ));
    }
    Ok(())
}

// ── Disk ────────────────────────────────────────────────────────────────

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn blob_dir() -> String {
    format!(
        "{}/attachments",
        crate::routes::uploads::uploads_dir().trim_end_matches('/')
    )
}

pub fn blob_path(sha: &str) -> String {
    format!("{}/{sha}", blob_dir())
}

async fn remove_file(sha: &str) {
    let _ = tokio::fs::remove_file(blob_path(sha)).await;
}

fn is_out_of_space(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::StorageFull
}

async fn write_blob(sha: &str, bytes: &[u8]) -> std::io::Result<()> {
    tokio::fs::create_dir_all(blob_dir()).await?;
    let tmp = format!("{}.tmp", blob_path(sha));
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, blob_path(sha)).await
}

/// Orphans past the delay, then blobs no live row wants. Returns bytes freed.
async fn drop_unused(db: &PgPool, now: i64) -> Result<i64, ApiErr> {
    sqlx::query(
        "DELETE FROM attachments a
         WHERE a.message_id IS NULL AND a.post_id IS NULL AND a.reply_id IS NULL
           AND a.created_at < $1
           AND NOT EXISTS (SELECT 1 FROM channels c WHERE c.banner_file_id = a.id)",
    )
    .bind(now - ORPHAN_AFTER_SECS)
    .execute(db)
    .await
    .map_err(db_err)?;
    let gone: Vec<(String, i64)> = sqlx::query_as(
        "DELETE FROM attachment_blobs b
         WHERE NOT EXISTS (SELECT 1 FROM attachments a
                           WHERE a.sha256 = b.sha256
                             AND a.removed_at IS NULL AND a.expired_at IS NULL)
         RETURNING b.sha256, b.size_bytes",
    )
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    for (sha, _) in &gone {
        remove_file(sha).await;
    }
    Ok(gone.iter().map(|(_, n)| n).sum())
}

/// Whole blobs, least recently linked first, banners excepted, until `want`
/// bytes are freed. Every row on an evicted blob becomes "expired".
async fn evict_oldest(db: &PgPool, want: i64, now: i64) -> Result<i64, ApiErr> {
    let mut freed = 0i64;
    while freed < want {
        let batch: Vec<(String, i64)> = sqlx::query_as(
            "SELECT b.sha256, b.size_bytes FROM attachment_blobs b
             WHERE NOT EXISTS (SELECT 1 FROM attachments a
                               JOIN channels c ON c.banner_file_id = a.id
                               WHERE a.sha256 = b.sha256)
             ORDER BY b.last_linked_at, b.sha256 LIMIT 32",
        )
        .fetch_all(db)
        .await
        .map_err(db_err)?;
        if batch.is_empty() {
            break;
        }
        for (sha, size) in batch {
            sqlx::query(
                "UPDATE attachments SET expired_at = $2
                 WHERE sha256 = $1 AND expired_at IS NULL AND removed_at IS NULL",
            )
            .bind(&sha)
            .bind(now)
            .execute(db)
            .await
            .map_err(db_err)?;
            sqlx::query("DELETE FROM attachment_blobs WHERE sha256 = $1")
                .bind(&sha)
                .execute(db)
                .await
                .map_err(db_err)?;
            remove_file(&sha).await;
            EVICTIONS.fetch_add(1, Ordering::Relaxed);
            freed += size;
            if freed >= want {
                break;
            }
        }
    }
    Ok(freed)
}

/// Frees room for `need` more bytes: first what nothing wants, then the
/// oldest. If only banners are left it gives up quietly: the upload still
/// succeeds, a little over the cap.
async fn ensure_room(db: &PgPool, need: i64, now: i64) -> Result<(), ApiErr> {
    let cap = read_settings(db).await.attachments_cap_bytes as i64;
    let over = used_bytes(db).await? + need - cap;
    if over <= 0 {
        return Ok(());
    }
    let over = over - drop_unused(db, now).await?;
    if over > 0 {
        evict_oldest(db, over, now).await?;
    }
    Ok(())
}

// ── Ingest ──────────────────────────────────────────────────────────────

pub struct Upload {
    pub channel_id: String,
    pub uploader: String,
    pub name: String,
    pub bytes: Vec<u8>,
    pub as_file: bool,
    /// A banner is always an image and always re-encoded.
    pub banner: bool,
}

fn ingest_err(e: IngestError) -> ApiErr {
    match e {
        IngestError::TooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m),
        IngestError::NotAnImage(m) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, m),
    }
}

/// The caller has already checked the input against the upload cap; the
/// re-encoded output is not capped (a lossless WebP of a large PNG can grow)
/// and counts against the disk budget instead.
pub async fn ingest(db: &PgPool, up: Upload) -> Result<AttachmentRef, ApiErr> {
    let name = clean_name(&up.name);
    let sniffed = sniff(&up.bytes);
    check_extension(&name, &sniffed)?;
    let raster = sniffed.family == Family::Raster;
    if up.banner && !raster {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Banner images must be PNG, JPEG, GIF, or WebP".to_string(),
        ));
    }

    let (bytes, mime, kind, width, height, as_file) = if raster && (up.banner || !up.as_file) {
        let c = sticker_image::canonicalize_with(up.bytes, usize::MAX, sticker_image::ATTACHMENT)
            .await
            .map_err(ingest_err)?;
        (
            c.bytes,
            c.mime,
            "image",
            Some(c.width as i32),
            Some(c.height as i32),
            false,
        )
    } else {
        (
            up.bytes,
            sniffed.mime,
            "file",
            None,
            None,
            up.as_file && raster,
        )
    };

    let sha = hex::encode(Sha256::digest(&bytes));
    let size = bytes.len() as i64;
    let now = crate::auth::handlers::unix_timestamp();
    let id = uuid::Uuid::new_v4().to_string();

    let _guard = LOCK.lock().await;
    let held: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attachment_blobs WHERE sha256 = $1)")
            .bind(&sha)
            .fetch_one(db)
            .await
            .map_err(db_err)?;
    let on_disk = held
        && tokio::fs::try_exists(blob_path(&sha))
            .await
            .unwrap_or(false);
    if !on_disk {
        ensure_room(db, size, now).await?;
        if let Err(first) = write_blob(&sha, &bytes).await {
            if !is_out_of_space(&first) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Write error: {first}"),
                ));
            }
            // The cap was above the free disk: expire once more, retry once.
            evict_oldest(db, size, now).await?;
            if let Err(second) = write_blob(&sha, &bytes).await {
                tracing::error!("attachments: disk full and nothing left to evict: {second}");
                return Err(err(StatusCode::INSUFFICIENT_STORAGE, "storage_full"));
            }
        }
    }
    sqlx::query(
        "INSERT INTO attachment_blobs (sha256, kind, mime, size_bytes, width, height, created_at, last_linked_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
         ON CONFLICT (sha256) DO UPDATE SET
            last_linked_at = EXCLUDED.last_linked_at,
            kind = CASE WHEN EXCLUDED.kind = 'image' THEN 'image' ELSE attachment_blobs.kind END,
            width = COALESCE(attachment_blobs.width, EXCLUDED.width),
            height = COALESCE(attachment_blobs.height, EXCLUDED.height)",
    )
    .bind(&sha)
    .bind(kind)
    .bind(mime)
    .bind(size)
    .bind(width)
    .bind(height)
    .bind(now)
    .execute(db)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO attachments (id, sha256, name, uploader, channel_id, as_file, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&sha)
    .bind(&name)
    .bind(&up.uploader)
    .bind(&up.channel_id)
    .bind(as_file)
    .bind(now)
    .execute(db)
    .await
    .map_err(db_err)?;
    drop(_guard);

    Ok(RefRow {
        owner_id: String::new(),
        id,
        name,
        as_file,
        removed_at: None,
        expired_at: None,
        sha256: Some(sha),
        kind: Some(kind.to_string()),
        mime: Some(mime.to_string()),
        size_bytes: Some(size),
        width,
        height,
    }
    .into_ref())
}

// ── Serving and removal ─────────────────────────────────────────────────

pub struct Served {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub name: String,
    pub inline: bool,
}

/// `Err(GONE)` for a tombstone, 404 for an id nobody holds.
pub async fn read_for_serving(db: &PgPool, id: &str) -> Result<Served, ApiErr> {
    let row: Option<RefRow> = sqlx::query_as(
        "SELECT a.id AS owner_id, a.id, a.name, a.as_file, a.removed_at, a.expired_at,
                a.sha256, b.kind, b.mime, b.size_bytes, b.width, b.height
         FROM attachments a LEFT JOIN attachment_blobs b ON b.sha256 = a.sha256
         WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    let row = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "File not found"))?;
    let sha = row.sha256.clone();
    let a = row.into_ref();
    match a.state.as_str() {
        "removed" => return Err(err(StatusCode::GONE, "attachment removed")),
        "expired" => return Err(err(StatusCode::GONE, "attachment expired")),
        _ => {}
    }
    let sha = sha.unwrap_or_default();
    let bytes = tokio::fs::read(blob_path(&sha)).await.map_err(|e| {
        tracing::warn!("attachment {id}: blob {sha} unreadable: {e}");
        err(StatusCode::NOT_FOUND, "File not found")
    })?;
    Ok(Served {
        bytes,
        mime: a.mime,
        name: a.name,
        inline: a.kind == "image",
    })
}

/// The channel an attachment belongs to, for the permission check of a
/// moderator's removal.
pub async fn channel_of(db: &PgPool, id: &str) -> Result<String, ApiErr> {
    sqlx::query_scalar("SELECT channel_id FROM attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "File not found"))
}

/// Tombstones one attachment and drops its bytes if nothing else wants them.
pub async fn remove(db: &PgPool, id: &str) -> Result<(), ApiErr> {
    let _guard = LOCK.lock().await;
    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "UPDATE attachments SET removed_at = COALESCE(removed_at, $2), sha256 = NULL WHERE id = $1",
    )
    .bind(id)
    .bind(now)
    .execute(db)
    .await
    .map_err(db_err)?;
    drop_unused(db, now).await?;
    Ok(())
}

// ── Retention ───────────────────────────────────────────────────────────

/// The retention worker's pass: age, orphans, blobs nothing wants.
pub async fn sweep(db: &PgPool, now: i64) {
    let _guard = LOCK.lock().await;
    let days = read_settings(db).await.attachments_retention_days as i64;
    if days > 0 {
        let r = sqlx::query(
            "UPDATE attachments a SET expired_at = $1
             WHERE a.expired_at IS NULL AND a.removed_at IS NULL AND a.created_at < $2
               AND NOT EXISTS (SELECT 1 FROM channels c WHERE c.banner_file_id = a.id)",
        )
        .bind(now)
        .bind(now - days * 86400)
        .execute(db)
        .await;
        if let Err(e) = r {
            tracing::warn!("attachment retention: {e}");
        }
    }
    if let Err((_, e)) = drop_unused(db, now).await {
        tracing::warn!("attachment sweep: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_decide_not_the_name() {
        let pe = sniff(b"MZ\x90\x00\x03\x00\x00\x00");
        assert_eq!(pe.family, Family::Pe);
        let e = check_extension("holiday.png", &pe).unwrap_err();
        assert_eq!(e.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(check_extension("setup.exe", &pe).is_ok());
        let webp = sniff(b"RIFF\x10\x00\x00\x00WEBPVP8L");
        assert!(check_extension("photo.jpg", &webp).is_ok());
        assert!(check_extension("data.bin", &pe).is_ok());
    }

    #[test]
    fn svg_and_text_are_files() {
        assert_eq!(sniff(b"<svg xmlns='x'></svg>").mime, "image/svg+xml");
        assert_eq!(sniff(b"<?xml version='1.0'?><svg/>").family, Family::Svg);
        assert_eq!(sniff(b"hello\n").family, Family::Text);
        assert_eq!(sniff(&[0, 1, 2, 3]).mime, "application/octet-stream");
    }

    #[test]
    fn names_are_cleaned_and_encoded() {
        assert_eq!(clean_name("..\\..\\a/b/pic\n.png"), "pic.png");
        assert_eq!(clean_name("  "), "file");
        assert_eq!(encode_filename("a b\u{e9}.txt"), "a%20b%C3%A9.txt");
    }
}
