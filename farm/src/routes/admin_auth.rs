/// TOTP 2FA routes for the farm admin account.
///
/// POST /farm/admin/totp/setup   — generate a new TOTP secret (not saved yet)
/// POST /farm/admin/totp/confirm — verify and persist the TOTP secret
/// POST /farm/admin/totp/disable — verify current code then clear TOTP
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::routes::admin::require_admin_pub;
use crate::state::FarmState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a TOTP instance from a base32 secret string.
fn totp_from_base32(secret_b32: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| format!("invalid base32 secret: {e}"))?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "voxply-farm".to_string())
        .map_err(|e| format!("totp construction failed: {e}"))
}

/// Verify a 6-digit TOTP code against a base32 secret. Returns true if valid.
fn verify_totp(secret_b32: &str, code: &str) -> bool {
    match totp_from_base32(secret_b32) {
        Ok(totp) => totp.check_current(code).unwrap_or(false),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// POST /farm/admin/totp/setup
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_url: String,
}

pub async fn totp_setup(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<TotpSetupResponse>, (StatusCode, Json<serde_json::Value>)> {
    let admin_sub = require_admin_pub(&headers, &state).await?;

    // Generate a fresh random TOTP secret (20 bytes = 160-bit, standard for SHA1 TOTP).
    let secret_bytes = {
        use rand::RngCore;
        let mut bytes = vec![0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    };
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Voxply Farm".to_string()),
        admin_sub.clone(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("totp init failed: {e}")})),
        )
    })?;

    let secret_b32 = totp.get_secret_base32();
    let qr_url = totp.get_url();

    // Do not persist yet — the caller must confirm with a valid code first.
    Ok(Json(TotpSetupResponse {
        secret: secret_b32,
        qr_url,
    }))
}

// ---------------------------------------------------------------------------
// POST /farm/admin/totp/confirm
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TotpConfirmRequest {
    pub secret: String,
    pub code: String,
}

pub async fn totp_confirm(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<TotpConfirmRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    if !verify_totp(&req.secret, &req.code) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_totp"})),
        ));
    }

    sqlx::query("UPDATE farms SET totp_secret = ?, totp_enabled = 1 WHERE id = 1")
        .bind(&req.secret)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    Ok(Json(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// POST /farm/admin/totp/disable
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TotpDisableRequest {
    pub code: String,
}

pub async fn totp_disable(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<TotpDisableRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    // Load current TOTP state.
    let row: Option<(Option<String>, i64)> =
        sqlx::query_as("SELECT totp_secret, totp_enabled FROM farms WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    let (totp_secret, totp_enabled) = row.unwrap_or((None, 0));

    if totp_enabled != 0 {
        let secret = totp_secret.ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "totp_secret_missing"})),
            )
        })?;

        if !verify_totp(&secret, &req.code) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_totp"})),
            ));
        }
    }

    sqlx::query("UPDATE farms SET totp_secret = NULL, totp_enabled = 0 WHERE id = 1")
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db_error: {e}")})),
            )
        })?;

    Ok(Json(serde_json::json!({})))
}
