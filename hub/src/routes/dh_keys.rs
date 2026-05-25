use std::sync::Arc;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use voxply_identity::DhKeyRecord;
use crate::auth::middleware::AuthUser;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct PublishDhKeyRequest {
    pub dh_pubkey_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize)]
pub struct DhKeyResponse {
    pub dh_pubkey_hex: String,
    pub signature_hex: String,
    pub published_at: i64,
}

pub async fn put_dh_key(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
    Json(req): Json<PublishDhKeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if pubkey != user.public_key {
        return Err((StatusCode::FORBIDDEN, "Can only publish your own DH key".to_string()));
    }

    let record = DhKeyRecord {
        pubkey: pubkey.clone(),
        dh_pubkey_hex: req.dh_pubkey_hex.clone(),
        signature_hex: req.signature_hex.clone(),
        published_at: 0, // validated only; actual timestamp set below
    };
    record.verify()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid signature: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO dh_keys (pubkey, dh_pubkey_hex, signature_hex, published_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(pubkey) DO UPDATE SET dh_pubkey_hex = ?, signature_hex = ?, published_at = ?",
    )
    .bind(&pubkey)
    .bind(&req.dh_pubkey_hex)
    .bind(&req.signature_hex)
    .bind(now)
    .bind(&req.dh_pubkey_hex)
    .bind(&req.signature_hex)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn get_dh_key(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> Result<Json<DhKeyResponse>, (StatusCode, String)> {
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT dh_pubkey_hex, signature_hex, published_at FROM dh_keys WHERE pubkey = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        Some((dh, sig, ts)) => Ok(Json(DhKeyResponse {
            dh_pubkey_hex: dh,
            signature_hex: sig,
            published_at: ts,
        })),
        None => Err((StatusCode::NOT_FOUND, "No DH key published".to_string())),
    }
}
