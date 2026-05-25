use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use voxply_identity::{
    PairingClaim, PairingComplete, PairingOffer, PairingStatus, SubkeyCert,
};

use crate::state::AppState;

const MAX_OFFER_LIFETIME_SECS: u64 = 300;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn bad(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

fn db_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

async fn prune_expired(pool: &sqlx::SqlitePool) {
    let _ = sqlx::query("DELETE FROM pairing_offers WHERE expires_at < ?")
        .bind(now_secs())
        .execute(pool)
        .await;
}

pub async fn post_offer(
    State(state): State<Arc<AppState>>,
    Json(offer): Json<PairingOffer>,
) -> Result<StatusCode, (StatusCode, String)> {
    offer.verify().map_err(|e| bad(format!("Bad signature: {e}")))?;

    if offer.expires_at <= offer.issued_at {
        return Err(bad("expires_at must exceed issued_at"));
    }
    if offer.expires_at.saturating_sub(offer.issued_at) > MAX_OFFER_LIFETIME_SECS {
        return Err(bad("offer lifetime exceeds 5 minutes"));
    }
    let now = now_secs() as u64;
    if offer.expires_at <= now {
        return Err(bad("offer is already expired"));
    }
    if offer.pairing_token.len() < 32 {
        return Err(bad("pairing_token too short"));
    }

    prune_expired(&state.db).await;

    let home_hubs_json = serde_json::to_string(&offer.home_hubs)
        .map_err(|e| db_err(format!("serialize home_hubs: {e}")))?;

    sqlx::query(
        "INSERT INTO pairing_offers
            (pairing_token, master_pubkey, home_hubs_json, issued_at, expires_at,
             offer_signature, state, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
         ON CONFLICT(pairing_token) DO NOTHING",
    )
    .bind(&offer.pairing_token)
    .bind(&offer.master_pubkey)
    .bind(&home_hubs_json)
    .bind(offer.issued_at as i64)
    .bind(offer.expires_at as i64)
    .bind(&offer.signature)
    .bind(now_secs())
    .bind(now_secs())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}

pub async fn post_claim(
    State(state): State<Arc<AppState>>,
    Json(claim): Json<PairingClaim>,
) -> Result<StatusCode, (StatusCode, String)> {
    claim.verify().map_err(|e| bad(format!("Bad proof: {e}")))?;

    prune_expired(&state.db).await;

    let row = sqlx::query(
        "SELECT state, expires_at FROM pairing_offers WHERE pairing_token = ?",
    )
    .bind(&claim.pairing_token)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "Unknown or expired token".to_string()))?;

    let current_state: String = row.get("state");
    let expires_at: i64 = row.get("expires_at");
    if expires_at < now_secs() {
        return Err((StatusCode::GONE, "Token expired".to_string()));
    }
    if current_state != "pending" {
        return Err((
            StatusCode::CONFLICT,
            format!("Offer already in state '{current_state}'"),
        ));
    }

    sqlx::query(
        "UPDATE pairing_offers SET
            state = 'claimed',
            subkey_pubkey = ?,
            device_label = ?,
            claim_proof = ?,
            updated_at = ?
         WHERE pairing_token = ? AND state = 'pending'",
    )
    .bind(&claim.subkey_pubkey)
    .bind(&claim.device_label)
    .bind(&claim.proof)
    .bind(now_secs())
    .bind(&claim.pairing_token)
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}

pub async fn post_complete(
    State(state): State<Arc<AppState>>,
    Json(complete): Json<PairingComplete>,
) -> Result<StatusCode, (StatusCode, String)> {
    complete
        .cert
        .verify()
        .map_err(|e| bad(format!("Bad cert signature: {e}")))?;

    prune_expired(&state.db).await;

    let row = sqlx::query(
        "SELECT state, master_pubkey, subkey_pubkey, expires_at
         FROM pairing_offers WHERE pairing_token = ?",
    )
    .bind(&complete.pairing_token)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?
    .ok_or((StatusCode::NOT_FOUND, "Unknown or expired token".to_string()))?;

    let current_state: String = row.get("state");
    let offer_master: String = row.get("master_pubkey");
    let claimed_subkey: Option<String> = row.get("subkey_pubkey");
    let expires_at: i64 = row.get("expires_at");

    if expires_at < now_secs() {
        return Err((StatusCode::GONE, "Token expired".to_string()));
    }
    if current_state != "claimed" {
        return Err((
            StatusCode::CONFLICT,
            format!("Offer not in 'claimed' state (current: '{current_state}')"),
        ));
    }

    if complete.cert.master_pubkey != offer_master {
        return Err(bad("cert master_pubkey doesn't match offer"));
    }
    if Some(&complete.cert.subkey_pubkey) != claimed_subkey.as_ref() {
        return Err(bad("cert subkey_pubkey doesn't match claim"));
    }

    let cert_json = serde_json::to_string(&complete.cert)
        .map_err(|e| db_err(format!("serialize cert: {e}")))?;
    let fallback_json = serde_json::to_string(&complete.cert.fallback_hubs)
        .map_err(|e| db_err(format!("serialize fallback_hubs: {e}")))?;

    let mut tx = state.db.begin().await.map_err(db_err)?;

    sqlx::query(
        "INSERT INTO subkey_certs
            (master_pubkey, subkey_pubkey, device_label, issued_at,
             not_after, fallback_hubs_json, signature, registered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(master_pubkey, subkey_pubkey) DO UPDATE SET
            device_label = excluded.device_label,
            issued_at = excluded.issued_at,
            not_after = excluded.not_after,
            fallback_hubs_json = excluded.fallback_hubs_json,
            signature = excluded.signature",
    )
    .bind(&complete.cert.master_pubkey)
    .bind(&complete.cert.subkey_pubkey)
    .bind(&complete.cert.device_label)
    .bind(complete.cert.issued_at as i64)
    .bind(complete.cert.not_after.map(|t| t as i64))
    .bind(&fallback_json)
    .bind(&complete.cert.signature)
    .bind(now_secs())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    sqlx::query(
        "UPDATE pairing_offers SET
            state = 'complete',
            cert_json = ?,
            wrapped_key_hex = ?,
            updated_at = ?
         WHERE pairing_token = ? AND state = 'claimed'",
    )
    .bind(&cert_json)
    .bind(&complete.wrapped_blob_key_hex)
    .bind(now_secs())
    .bind(&complete.pairing_token)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;

    Ok(StatusCode::OK)
}

pub async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<Json<PairingStatus>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT state, expires_at, subkey_pubkey, device_label, cert_json, wrapped_key_hex
         FROM pairing_offers WHERE pairing_token = ?",
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let row = row.ok_or((StatusCode::NOT_FOUND, "Unknown token".to_string()))?;

    let expires_at: i64 = row.get("expires_at");
    if expires_at < now_secs() {
        return Ok(Json(PairingStatus::Expired));
    }

    let state_str: String = row.get("state");
    let status = match state_str.as_str() {
        "pending" => PairingStatus::Pending,
        "claimed" => {
            let subkey_pubkey: String = row.get("subkey_pubkey");
            let device_label: String = row.get("device_label");
            PairingStatus::Claimed { subkey_pubkey, device_label }
        }
        "complete" => {
            let cert_json: String = row.get("cert_json");
            let wrapped_blob_key_hex: String = row.get("wrapped_key_hex");
            let cert: SubkeyCert = serde_json::from_str(&cert_json)
                .map_err(|e| db_err(format!("parse cert_json: {e}")))?;
            PairingStatus::Complete { cert, wrapped_blob_key_hex }
        }
        other => {
            return Err(db_err(format!("unknown state: {other}")));
        }
    };

    Ok(Json(status))
}
