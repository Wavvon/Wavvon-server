//! The hub's language packs and default language (language-packs.md §3):
//! `.wavvonlang` packages the owner uploads, one per language code, listed
//! publicly and served at a URL carrying their hash.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::middleware::AuthUser;
use crate::lang_package;
use crate::permissions;
use crate::state::AppState;

/// Room for a stored 512 KB manifest plus zip framing.
pub const BODY_LIMIT: usize = lang_package::MAX_LANG_BYTES as usize + 64 * 1024;
const DEFAULT_KEY: &str = "default_language";

#[derive(Serialize, Deserialize, Clone)]
pub struct HubLanguagePack {
    pub code: String,
    pub name: String,
    /// The package is at `/hub/languages/{sha256}`.
    pub sha256: String,
}

/// `GET /hub/languages`, and `languages` on `/info`.
#[derive(Serialize, Deserialize, Clone)]
pub struct HubLanguages {
    /// A language code: a pack's, or one the client ships. None = no default.
    pub default: Option<String>,
    pub packs: Vec<HubLanguagePack>,
}

type ApiError = (StatusCode, String);

fn db_err(e: sqlx::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

pub async fn read_languages(db: &sqlx::PgPool) -> Result<HubLanguages, ApiError> {
    let packs = sqlx::query_as::<_, (String, String, String)>(
        "SELECT code, name, sha256 FROM hub_languages ORDER BY code",
    )
    .fetch_all(db)
    .await
    .map_err(db_err)?
    .into_iter()
    .map(|(code, name, sha256)| HubLanguagePack { code, name, sha256 })
    .collect();
    Ok(HubLanguages {
        default: crate::routes::hub::read_setting(db, DEFAULT_KEY).await,
        packs,
    })
}

/// For `/info`: absent while the hub offers nothing.
pub async fn info_languages(db: &sqlx::PgPool) -> Option<HubLanguages> {
    read_languages(db)
        .await
        .ok()
        .filter(|l| l.default.is_some() || !l.packs.is_empty())
}

/// GET /hub/languages — public.
pub async fn list_languages(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HubLanguages>, ApiError> {
    Ok(Json(read_languages(&state.db).await?))
}

/// PUT /hub/languages — the raw package as the body. Replaces the pack with
/// the same code, if any.
pub async fn put_language(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    body: Bytes,
) -> Result<Json<HubLanguagePack>, ApiError> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require_owner("manage the hub's languages")?;

    let check = lang_package::validate(&body).map_err(|m| (StatusCode::BAD_REQUEST, m))?;
    let sha256 = hex::encode(Sha256::digest(&body));
    sqlx::query(
        "INSERT INTO hub_languages (code, name, sha256, package, uploaded_by, uploaded_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, sha256 = EXCLUDED.sha256,
           package = EXCLUDED.package, uploaded_by = EXCLUDED.uploaded_by,
           uploaded_at = EXCLUDED.uploaded_at",
    )
    .bind(&check.code)
    .bind(&check.name)
    .bind(&sha256)
    .bind(body.as_ref())
    .bind(&user.public_key)
    .bind(crate::auth::handlers::unix_timestamp())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(Json(HubLanguagePack {
        code: check.code,
        name: check.name,
        sha256,
    }))
}

/// DELETE /hub/languages/{sha256}
pub async fn delete_language(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(sha256): Path<String>,
) -> Result<StatusCode, ApiError> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require_owner("manage the hub's languages")?;
    let rows = sqlx::query("DELETE FROM hub_languages WHERE sha256 = $1")
        .bind(&sha256)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    if rows.rows_affected() == 0 {
        return Err(not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct DefaultBody {
    pub code: Option<String>,
}

/// PUT /hub/languages/default — `{ "code": "sc" }`, or null to clear.
pub async fn put_default(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<DefaultBody>,
) -> Result<Json<HubLanguages>, ApiError> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require_owner("manage the hub's languages")?;
    match body.code {
        Some(raw) => {
            let code = lang_package::canonical_code(&raw).ok_or((
                StatusCode::BAD_REQUEST,
                "Invalid code (must be a BCP-47 language tag)".to_string(),
            ))?;
            sqlx::query(
                "INSERT INTO hub_settings (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(DEFAULT_KEY)
            .bind(code)
            .execute(&state.db)
            .await
            .map_err(db_err)?;
        }
        None => {
            sqlx::query("DELETE FROM hub_settings WHERE key = $1")
                .bind(DEFAULT_KEY)
                .execute(&state.db)
                .await
                .map_err(db_err)?;
        }
    }
    Ok(Json(read_languages(&state.db).await?))
}

fn not_found() -> ApiError {
    (
        StatusCode::NOT_FOUND,
        "No hub language with that hash".into(),
    )
}

/// GET /hub/languages/{sha256} — public. A replaced pack's old URL is gone.
pub async fn get_language(
    State(state): State<Arc<AppState>>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiError> {
    let package: Vec<u8> =
        sqlx::query_scalar("SELECT package FROM hub_languages WHERE sha256 = $1")
            .bind(&sha256)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?
            .ok_or_else(not_found)?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        )
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(package))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}
