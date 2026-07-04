//! Per-hub soundboard clip library (soundboard.md §1).
//!
//! Clips are short (≤10s, ≤512KB) Opus-in-Ogg files members can trigger in
//! voice. The clip is mixed client-side into the triggering user's own
//! outgoing stream -- the hub never touches the audio itself. `POST
//! /soundboard/:id/played` is attribution UX only: it broadcasts a
//! `soundboard_played` WS event so listeners see a "🔊 X played *name*"
//! chip, gated by the same channel-scoped `use_soundboard` permission that
//! is the actual enforcement (see Decisions in the design doc).

use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MANAGE_SOUNDBOARD, USE_SOUNDBOARD};
use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::AppState;

/// Hard caps (soundboard.md §1 Decisions). Hub-configurable caps are a
/// documented follow-up, not implemented here.
const MAX_CLIP_BYTES: usize = 512 * 1024;
const MAX_CLIP_DURATION_MS: i64 = 10_000;
const MAX_CLIPS_PER_HUB: i64 = 50;

/// Audio bytes live under the same directory as attachment uploads
/// (`uploads.rs`), keyed by clip id rather than a random filename since the
/// `soundboard_clips` schema carries no filename column of its own.
fn soundboard_dir() -> String {
    std::env::var("WAVVON_UPLOADS_DIR").unwrap_or_else(|_| "./uploads/".to_string())
}

fn clip_audio_path(id: &str) -> String {
    format!(
        "{}/soundboard_{}.ogg",
        soundboard_dir().trim_end_matches('/'),
        id
    )
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ClipInfo {
    pub id: String,
    pub name: String,
    pub emoji: Option<String>,
    pub uploader: String,
    pub size_bytes: i64,
    pub duration_ms: i64,
    pub created_at: i64,
}

/// GET /soundboard -- list every clip in the hub's library. Any
/// authenticated member may list; playing one is gated separately by
/// `use_soundboard`.
pub async fn list_clips(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<ClipInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, ClipInfo>(
        "SELECT id, name, emoji, uploader, size_bytes, duration_ms, created_at
         FROM soundboard_clips ORDER BY name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(rows))
}

/// GET /soundboard/:id/audio -- raw clip bytes, cacheable. Clip content is
/// immutable once uploaded (there is no edit-in-place; a re-upload gets a
/// new id), so the response is safe to cache indefinitely.
pub async fn get_clip_audio(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM soundboard_clips WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Clip not found".to_string()));
    }

    let bytes = tokio::fs::read(clip_audio_path(&id))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}")))?;

    Ok((
        [
            (header::CONTENT_TYPE, "audio/ogg".to_string()),
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
        ],
        bytes,
    ))
}

/// POST /soundboard -- multipart upload: `name` (text), optional `emoji`
/// (text), `audio` (Opus-in-Ogg file). Requires `manage_soundboard`.
pub async fn upload_clip(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<ClipInfo>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_SOUNDBOARD)?;

    let clip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soundboard_clips")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if clip_count >= MAX_CLIPS_PER_HUB {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("This hub already has the maximum of {MAX_CLIPS_PER_HUB} soundboard clips"),
        ));
    }

    let mut name: Option<String> = None;
    let mut emoji: Option<String> = None;
    let mut audio_bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "name" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Read error: {e}")))?;
                name = Some(text);
            }
            "emoji" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Read error: {e}")))?;
                if !text.is_empty() {
                    emoji = Some(text);
                }
            }
            "audio" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Read error: {e}")))?;
                if data.len() > MAX_CLIP_BYTES {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Clip exceeds {} KB limit", MAX_CLIP_BYTES / 1024),
                    ));
                }
                audio_bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }

    let name = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'name' field".to_string()))?;
    let bytes = audio_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No 'audio' field in upload".to_string(),
        )
    })?;

    let duration_ms = validate_ogg_opus(&bytes).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    if duration_ms > MAX_CLIP_DURATION_MS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Clip exceeds {}s duration limit",
                MAX_CLIP_DURATION_MS / 1000
            ),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let size = bytes.len() as i64;

    let dir = soundboard_dir();
    tokio::fs::create_dir_all(dir.trim_end_matches('/'))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}")))?;
    tokio::fs::write(clip_audio_path(&id), &bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Write error: {e}"),
            )
        })?;

    sqlx::query(
        "INSERT INTO soundboard_clips (id, name, emoji, uploader, size_bytes, duration_ms, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&emoji)
    .bind(&user.public_key)
    .bind(size)
    .bind(duration_ms)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let clip_id = id.clone();
        let clip_name = name.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "soundboard.clip_uploaded",
                Some(&actor),
                None,
                None,
                serde_json::json!({ "clip_id": clip_id, "name": clip_name }),
            )
            .await;
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(ClipInfo {
            id,
            name,
            emoji,
            uploader: user.public_key,
            size_bytes: size,
            duration_ms,
            created_at: now,
        }),
    ))
}

/// DELETE /soundboard/:id -- requires `manage_soundboard`.
pub async fn delete_clip(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_SOUNDBOARD)?;

    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM soundboard_clips WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if existing.is_none() {
        return Err((StatusCode::NOT_FOUND, "Clip not found".to_string()));
    }

    sqlx::query("DELETE FROM soundboard_clips WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Best-effort file cleanup: a stray file left on disk after the DB row
    // is gone is unreachable via the API and harmless.
    let _ = tokio::fs::remove_file(clip_audio_path(&id)).await;

    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let clip_id = id.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "soundboard.clip_deleted",
                Some(&actor),
                None,
                None,
                serde_json::json!({ "clip_id": clip_id }),
            )
            .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PlayedRequest {
    pub channel_id: String,
}

/// POST /soundboard/:id/played -- attribution event only (soundboard.md §1
/// Decisions). `use_soundboard` is resolved channel-scoped, exactly like
/// `read_messages`, so a channel-level deny (e.g. a serious-meeting channel
/// denying it on @everyone) is respected. The server does not, and cannot,
/// verify the clip was actually mixed into the caller's outgoing audio --
/// the permission check is the enforcement; the WS broadcast is purely UX.
pub async fn mark_played(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<PlayedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms =
        permissions::channel_permissions(&state.db, &user.public_key, &req.channel_id).await?;
    perms.require(USE_SOUNDBOARD)?;

    let clip_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM soundboard_clips WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let clip_name =
        clip_name.ok_or_else(|| (StatusCode::NOT_FOUND, "Clip not found".to_string()))?;

    let ws_msg = WsServerMessage::SoundboardPlayed {
        channel_id: req.channel_id.clone(),
        clip_id: id,
        clip_name,
        public_key: user.public_key,
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((
        ChatEvent::Soundboard {
            channel_id: req.channel_id,
        },
        json,
    ));

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Opus-in-Ogg validation
// ---------------------------------------------------------------------------

/// Validates the container/codec shape and returns the clip duration in
/// milliseconds, derived from the last page's granule position (RFC 7845
/// §4: an Ogg Opus granule position counts PCM samples at a fixed 48 kHz
/// rate). This is a structural check, not a full decode: it verifies the
/// file is a well-formed sequence of Ogg pages whose first page carries an
/// `OpusHead` identification header, but does not validate the Opus packets
/// themselves.
fn validate_ogg_opus(bytes: &[u8]) -> Result<i64, String> {
    if bytes.len() < 4 || &bytes[0..4] != b"OggS" {
        return Err("Not a valid Ogg container".to_string());
    }

    let mut pos = 0usize;
    let mut last_granule: i64 = 0;
    let mut found_opus_head = false;
    let mut page_count = 0u32;

    while pos + 27 <= bytes.len() {
        if &bytes[pos..pos + 4] != b"OggS" {
            break;
        }
        let granule_position = i64::from_le_bytes(
            bytes[pos + 6..pos + 14]
                .try_into()
                .map_err(|_| "Malformed Ogg page header".to_string())?,
        );
        let num_segments = bytes[pos + 26] as usize;
        let seg_table_start = pos + 27;
        if seg_table_start + num_segments > bytes.len() {
            return Err("Truncated Ogg page".to_string());
        }
        let segment_table = &bytes[seg_table_start..seg_table_start + num_segments];
        let payload_len: usize = segment_table.iter().map(|&b| b as usize).sum();
        let payload_start = seg_table_start + num_segments;
        let payload_end = payload_start + payload_len;
        if payload_end > bytes.len() {
            return Err("Truncated Ogg page payload".to_string());
        }

        if page_count == 0 {
            let payload = &bytes[payload_start..payload_end];
            if payload.len() >= 8 && &payload[0..8] == b"OpusHead" {
                found_opus_head = true;
            }
        }

        if granule_position >= 0 {
            last_granule = granule_position;
        }

        page_count += 1;
        pos = payload_end;
    }

    if !found_opus_head {
        return Err("Not a valid Opus stream (missing OpusHead)".to_string());
    }
    if page_count < 2 {
        return Err("Ogg file has no audio pages".to_string());
    }

    Ok((last_granule.max(0) * 1000) / 48_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_ogg() {
        assert!(validate_ogg_opus(b"not ogg data at all").is_err());
    }

    #[test]
    fn rejects_truncated_ogg() {
        assert!(validate_ogg_opus(b"OggS").is_err());
    }
}
