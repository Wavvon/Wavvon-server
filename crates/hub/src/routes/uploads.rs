use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;

use crate::attachments::AttachmentRef;
use crate::auth::middleware::AuthUser;
use crate::state::AppState;

/// What the router lets this route's body reach: the largest cap an operator
/// can set plus room for the multipart framing, so the check below is the one
/// that answers. Left at axum's 2 MB default, a 3 MB file failed as a
/// multipart parse error.
pub const UPLOAD_BODY_LIMIT: usize =
    crate::routes::hub::MAX_MAX_UPLOAD_BYTES as usize + 1024 * 1024;
const BANNER_MAX_UPLOAD_BYTES: usize = 512 * 1024;

/// Where uploaded attachments live. Public because `backup`/`restore` have to
/// put the same files in the same place — two copies of this default drifting
/// apart is how a backup silently stops containing anything.
pub fn uploads_dir() -> String {
    std::env::var("WAVVON_UPLOADS_DIR").unwrap_or_else(|_| "./uploads/".to_string())
}

/// A body past `UPLOAD_BODY_LIMIT` surfaces as a multipart error, not as a
/// status of its own; keep axum's 413 and say which limit it was.
fn multipart_err(e: axum::extract::multipart::MultipartError, max: usize) -> (StatusCode, String) {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("File exceeds {}MB limit", max / 1024 / 1024),
        );
    }
    (StatusCode::BAD_REQUEST, format!("Multipart error: {e}"))
}

/// POST /channels/:channel_id/upload
///
/// The one way bytes enter: type from the magic bytes, images re-encoded to
/// WebP unless `as_file`, one blob per distinct stored file (attachments.md).
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<AttachmentRef>), (StatusCode, String)> {
    let channel_type: Option<String> =
        sqlx::query_scalar("SELECT channel_type FROM channels WHERE id = $1")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let channel_type =
        channel_type.ok_or_else(|| (StatusCode::NOT_FOUND, "Channel not found".to_string()))?;
    // An upload is an attachment on its way into this channel: the channel's
    // own send permission applies, so it cannot be used to fill the disk
    // through a channel the caller could never post in.
    crate::permissions::channel_permissions(&state.db, &user.public_key, &channel_id)
        .await?
        .require(crate::permissions::MESSAGES_SEND)?;

    let is_banner = channel_type == "banner";
    let effective_max = if is_banner {
        BANNER_MAX_UPLOAD_BYTES
    } else {
        crate::routes::hub::read_upload_cap(&state.db).await as usize
    };

    let mut file: Option<(Vec<u8>, String)> = None;
    let mut as_file = false;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err(e, effective_max))?
    {
        match field.name().unwrap_or("") {
            "file" if file.is_none() => {
                let name = field.file_name().unwrap_or("upload").to_string();
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| multipart_err(e, effective_max))?;
                if data.len() > effective_max {
                    if is_banner {
                        return Err((
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "Banner image exceeds 512 KB limit".to_string(),
                        ));
                    }
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("File exceeds {}MB limit", effective_max / 1024 / 1024),
                    ));
                }
                file = Some((data.to_vec(), name));
            }
            "as_file" => {
                let v = field.text().await.unwrap_or_default();
                as_file = matches!(v.trim(), "true" | "1" | "on");
            }
            _ => {}
        }
    }
    let (bytes, name) = file.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No 'file' field in upload".to_string(),
        )
    })?;

    let stored = crate::attachments::ingest(
        &state.db,
        crate::attachments::Upload {
            channel_id,
            uploader: user.public_key,
            name,
            bytes,
            as_file,
            banner: is_banner,
        },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(stored)))
}

const CSP: &str = "default-src 'none'; sandbox";

/// GET /uploads/:id
/// Public: an `<img>` sends no token, and the id is a random UUID, not a hash,
/// so holding a file does not tell you whether this hub holds it.
pub async fn serve_upload(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    // Masquerade avatars are still plain files under a name derived from their
    // source URL (preview.rs) until they go through ingest too.
    if id.starts_with("remote-") {
        return serve_remote_avatar(&id).await;
    }
    let served = crate::attachments::read_for_serving(&state.db, &id).await?;

    let mut resp = Response::new(axum::body::Body::from(served.bytes));
    let h = resp.headers_mut();
    let (ctype, disposition) = if served.inline {
        (served.mime, "inline".to_string())
    } else {
        let ctype = if served.mime == "text/plain" {
            "text/plain; charset=utf-8".to_string()
        } else {
            served.mime
        };
        (
            ctype,
            format!(
                "attachment; filename*=UTF-8''{}",
                crate::attachments::encode_filename(&served.name)
            ),
        )
    };
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&ctype)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );
    Ok(resp)
}

async fn serve_remote_avatar(filename: &str) -> Result<Response, (StatusCode, String)> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err((StatusCode::BAD_REQUEST, "Invalid filename".to_string()));
    }
    let path = format!("{}/{}", uploads_dir().trim_end_matches('/'), filename);
    let data = tokio::fs::read(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (StatusCode::NOT_FOUND, "File not found".to_string())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}"))
        }
    })?;
    let mime = match filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    };
    let mut resp = Response::new(axum::body::Body::from(data));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    Ok(resp)
}

/// DELETE /uploads/:id -- a moderator's removal. The row stays as the
/// "attachment removed" tombstone; the bytes go unless another upload shares
/// them.
pub async fn delete_upload(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let channel_id = crate::attachments::channel_of(&state.db, &id).await?;
    crate::permissions::channel_permissions(&state.db, &user.public_key, &channel_id)
        .await?
        .require(crate::permissions::MESSAGES_MANAGE)?;
    crate::attachments::remove(&state.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}
