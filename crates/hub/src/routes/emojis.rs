use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, HUB_APPEARANCE};
use crate::state::AppState;

#[derive(Serialize)]
pub struct EmojiInfo {
    pub id: String,
    pub name: String,
    pub url: String,
}

pub async fn list_emojis(State(state): State<Arc<AppState>>) -> Json<Vec<EmojiInfo>> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT id, name FROM hub_emojis ORDER BY name")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    Json(
        rows.into_iter()
            .map(|(id, name)| EmojiInfo {
                url: format!("/emojis/{id}/image"),
                id,
                name,
            })
            .collect(),
    )
}

/// True when `mime` is on the raster allow-list (no SVG: it is a document
/// that can carry script) and the bytes start with that format's signature.
fn signature_matches(mime: &str, bytes: &[u8]) -> bool {
    match mime {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "image/webp" => bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

pub async fn get_emoji_image(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT mime, data_b64 FROM hub_emojis WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (mime, data_b64) = row.ok_or((StatusCode::NOT_FOUND, "Not found".into()))?;
    let bytes = STANDARD
        .decode(&data_b64)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Rows stored before the allow-list may carry any type: never serve those
    // as anything but an opaque download.
    let safe = signature_matches(&mime, &bytes);
    let (mime, disposition) = if safe {
        (mime, "inline")
    } else {
        ("application/octet-stream".to_string(), "attachment")
    };
    Ok((
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "public, max-age=86400".into()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
            (header::CONTENT_DISPOSITION, disposition.into()),
        ],
        bytes,
    ))
}

#[derive(Deserialize)]
pub struct CreateEmojiRequest {
    pub name: String,
    pub mime: String,
    pub data_b64: String,
}

pub async fn create_emoji(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateEmojiRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_APPEARANCE)?;

    if req.name.is_empty() || req.data_b64.len() > 90_000 {
        return Err((StatusCode::BAD_REQUEST, "Invalid emoji".into()));
    }

    let bytes = STANDARD
        .decode(&req.data_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid emoji".to_string()))?;
    if !signature_matches(&req.mime, &bytes) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Emoji must be a PNG, WebP, GIF or JPEG image".into(),
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        "INSERT INTO hub_emojis(id, name, uploader, mime, data_b64, created_at) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&user.public_key)
    .bind(&req.mime)
    .bind(&req.data_b64)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn delete_emoji(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_APPEARANCE)?;

    sqlx::query("DELETE FROM hub_emojis WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::signature_matches as ok;

    #[test]
    fn only_matching_raster_signatures_pass() {
        assert!(ok("image/png", b"\x89PNG\r\n\x1a\nrest"));
        assert!(ok("image/jpeg", &[0xff, 0xd8, 0xff, 0xe0]));
        assert!(ok("image/gif", b"GIF89a..."));
        assert!(ok("image/webp", b"RIFF\0\0\0\0WEBPVP8 "));
        assert!(!ok("image/png", b"GIF89a..."));
        assert!(!ok("image/webp", b"RIFF\0\0\0\0WAVEfmt "));
        assert!(!ok("text/html", b"<html>"));
        assert!(!ok(
            "image/svg+xml",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"
        ));
    }
}
