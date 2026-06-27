use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::state::AppState;

// Max upload size: 25 MB in raw bytes
const MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
const BANNER_MAX_UPLOAD_BYTES: usize = 512 * 1024;

/// Allowed mime types for uploads.
/// SVG is intentionally excluded: it can carry script content and must not
/// be served with a content-type that causes browsers to execute it.
/// Previously-uploaded SVG files are still served but with
/// Content-Disposition: attachment so they are downloaded, not rendered.
fn is_allowed_mime(mime: &str) -> bool {
    (mime.starts_with("image/") && mime != "image/svg+xml")
        || mime == "video/mp4"
        || mime == "application/pdf"
        || mime == "text/plain"
}

fn uploads_dir() -> String {
    std::env::var("WAVVON_UPLOADS_DIR").unwrap_or_else(|_| "./uploads/".to_string())
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub id: String,
    pub url: String,
    pub filename: String,
    pub size_bytes: usize,
    pub mime_type: String,
}

/// POST /channels/:channel_id/upload
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), (StatusCode, String)> {
    // Verify channel exists and fetch its type.
    let channel_type: Option<String> =
        sqlx::query_scalar("SELECT channel_type FROM channels WHERE id = $1")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let channel_type =
        channel_type.ok_or_else(|| (StatusCode::NOT_FOUND, "Channel not found".to_string()))?;

    let is_banner = channel_type == "banner";
    let effective_max = if is_banner {
        BANNER_MAX_UPLOAD_BYTES
    } else {
        MAX_UPLOAD_BYTES
    };

    // Extract the "file" field from the multipart body.
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut original_name = String::from("upload");
    let mut content_type = String::from("application/octet-stream");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Multipart error: {e}")))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name != "file" {
            continue;
        }

        if let Some(fname) = field.file_name() {
            original_name = fname.to_string();
        }
        if let Some(ct) = field.content_type() {
            content_type = ct.to_string();
        }

        let data = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Read error: {e}")))?;

        if data.len() > effective_max {
            if is_banner {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Banner image exceeds 512 KB limit".to_string(),
                ));
            }
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("File exceeds {}MB limit", MAX_UPLOAD_BYTES / 1024 / 1024),
            ));
        }

        file_bytes = Some(data.to_vec());
        break;
    }

    let bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "No 'file' field in upload".to_string(),
        )
    })?;

    // Mime type validation.
    if is_banner {
        let allowed_banner_mime = matches!(
            content_type.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        );
        if !allowed_banner_mime {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Banner images must be PNG, JPEG, GIF, or WebP; got '{}'",
                    content_type
                ),
            ));
        }
    } else if !is_allowed_mime(&content_type) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("Mime type '{}' is not allowed", content_type),
        ));
    }

    // Derive extension from original filename or mime type.
    let ext = original_name
        .rsplit('.')
        .next()
        .filter(|e| !e.is_empty() && e.len() <= 10)
        .unwrap_or("bin");

    let stored_filename = format!("{}.{}", Uuid::new_v4(), ext);
    let dir = uploads_dir();

    // Ensure directory exists.
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}")))?;

    let path = format!("{}/{}", dir.trim_end_matches('/'), stored_filename);
    tokio::fs::write(&path, &bytes).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Write error: {e}"),
        )
    })?;

    let size = bytes.len();
    let now = crate::auth::handlers::unix_timestamp();
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO upload_files (id, filename, original_name, mime_type, size_bytes, uploader_pubkey, channel_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&stored_filename)
    .bind(&original_name)
    .bind(&content_type)
    .bind(size as i64)
    .bind(&user.public_key)
    .bind(&channel_id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            id,
            url: format!("/uploads/{}", stored_filename),
            filename: stored_filename,
            size_bytes: size,
            mime_type: content_type,
        }),
    ))
}

/// GET /uploads/:filename
/// Public — no auth needed, filenames are unguessable UUIDs.
pub async fn serve_upload(Path(filename): Path<String>) -> Result<Response, (StatusCode, String)> {
    // Reject path traversal attempts.
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err((StatusCode::BAD_REQUEST, "Invalid filename".to_string()));
    }

    let dir = uploads_dir();
    let path = format!("{}/{}", dir.trim_end_matches('/'), filename);

    let data = tokio::fs::read(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (StatusCode::NOT_FOUND, "File not found".to_string())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("FS error: {e}"))
        }
    })?;

    // Infer content-type from extension.
    let mime = infer_mime_from_ext(&filename);

    let mut resp = Response::new(axum::body::Body::from(data));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_str(mime)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    // Force all uploads to be downloaded rather than rendered inline.
    // This is defence-in-depth: prevents XSS via uploaded HTML/SVG/etc.
    resp.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );

    Ok(resp)
}

fn infer_mime_from_ext(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}
