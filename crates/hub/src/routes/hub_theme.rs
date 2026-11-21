//! The hub's default theme (themes.md §4): one `.wavvontheme` package an
//! admin uploads, checked with the client's own rules, served publicly at a
//! URL carrying its hash so a browser caches it for good.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, HUB_APPEARANCE};
use crate::state::AppState;
use crate::theme_package;

/// Room for the 8 MB package plus framing.
pub const BODY_LIMIT: usize = theme_package::MAX_ZIP_BYTES + 64 * 1024;

/// What `/info` says about the hub theme. The client builds the URLs from the
/// hash: `/hub/theme/{sha256}` and, with a preview, `/hub/theme/{sha256}/preview`.
#[derive(Serialize, Deserialize, Clone)]
pub struct HubThemeInfo {
    pub sha256: String,
    pub has_preview: bool,
}

type ApiError = (StatusCode, String);

fn db_err(e: sqlx::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

pub async fn read_theme_info(db: &sqlx::PgPool) -> Option<HubThemeInfo> {
    sqlx::query_as::<_, (String, bool)>(
        "SELECT sha256, preview IS NOT NULL FROM hub_theme WHERE id = TRUE",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|(sha256, has_preview)| HubThemeInfo {
        sha256,
        has_preview,
    })
}

/// PUT /hub/theme — the raw package as the body. Replaces any earlier one.
pub async fn put_theme(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    body: Bytes,
) -> Result<axum::Json<HubThemeInfo>, ApiError> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_APPEARANCE)?;

    let check = theme_package::validate(&body).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    let sha256 = hex::encode(Sha256::digest(&body));
    let (preview, preview_mime) = match check.preview {
        Some((bytes, mime)) => (Some(bytes), Some(mime)),
        None => (None, None),
    };
    let has_preview = preview.is_some();
    sqlx::query(
        "INSERT INTO hub_theme (id, sha256, package, preview, preview_mime, uploaded_by, uploaded_at)
         VALUES (TRUE, $1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO UPDATE SET sha256 = EXCLUDED.sha256, package = EXCLUDED.package,
           preview = EXCLUDED.preview, preview_mime = EXCLUDED.preview_mime,
           uploaded_by = EXCLUDED.uploaded_by, uploaded_at = EXCLUDED.uploaded_at",
    )
    .bind(&sha256)
    .bind(body.as_ref())
    .bind(preview)
    .bind(preview_mime)
    .bind(&user.public_key)
    .bind(crate::auth::handlers::unix_timestamp())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(axum::Json(HubThemeInfo {
        sha256,
        has_preview,
    }))
}

/// DELETE /hub/theme
pub async fn delete_theme(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<StatusCode, ApiError> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(HUB_APPEARANCE)?;
    let rows = sqlx::query("DELETE FROM hub_theme")
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    if rows.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "No hub theme".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn immutable(mime: &str, bytes: Vec<u8>) -> Result<Response, ApiError> {
    Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        )
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(bytes))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn not_found() -> ApiError {
    (StatusCode::NOT_FOUND, "No hub theme with that hash".into())
}

/// GET /hub/theme/{sha256} — public. Only the current theme's hash answers:
/// a replaced theme is gone, and its old URL with it.
pub async fn get_theme(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    let package: Vec<u8> = sqlx::query_scalar("SELECT package FROM hub_theme WHERE sha256 = $1")
        .bind(&sha256)
        .fetch_optional(&state.db)
        .await
        .map_err(db_err)?
        .ok_or_else(not_found)?;
    immutable("application/zip", package)
}

/// GET /hub/theme/{sha256}/preview — public; the image a directory listing shows.
pub async fn get_theme_preview(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    let (bytes, mime): (Vec<u8>, String) = sqlx::query_as(
        "SELECT preview, preview_mime FROM hub_theme
         WHERE sha256 = $1 AND preview IS NOT NULL",
    )
    .bind(&sha256)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or_else(not_found)?;
    immutable(&mime, bytes)
}
