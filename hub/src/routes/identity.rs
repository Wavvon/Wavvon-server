use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use voxply_identity::{HomeHubList, RevocationEntry, SignedPrefsBlob, SubkeyCert};

use crate::state::AppState;

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

// --- Designation (HomeHubList) ---

pub async fn get_designation(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
) -> Result<Json<HomeHubList>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT master_pubkey, hubs_json, issued_at, sequence, signature
         FROM home_hub_designations WHERE master_pubkey = ?",
    )
    .bind(&master)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let row = row.ok_or((StatusCode::NOT_FOUND, "No designation".to_string()))?;
    let hubs_json: String = row.get("hubs_json");
    let hubs: Vec<String> =
        serde_json::from_str(&hubs_json).map_err(|e| db_err(format!("hubs_json: {e}")))?;

    Ok(Json(HomeHubList {
        master_pubkey: row.get("master_pubkey"),
        hubs,
        issued_at: row.get::<i64, _>("issued_at") as u64,
        sequence: row.get::<i64, _>("sequence") as u64,
        signature: row.get("signature"),
    }))
}

pub async fn put_designation(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
    Json(body): Json<HomeHubList>,
) -> Result<StatusCode, (StatusCode, String)> {
    if body.master_pubkey != master {
        return Err(bad("master_pubkey mismatch between URL and body"));
    }
    body.verify().map_err(|e| bad(format!("Bad signature: {e}")))?;

    let current: Option<i64> =
        sqlx::query_scalar("SELECT sequence FROM home_hub_designations WHERE master_pubkey = ?")
            .bind(&master)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;

    if let Some(seq) = current {
        if (body.sequence as i64) <= seq {
            return Err((
                StatusCode::CONFLICT,
                format!("sequence must exceed current ({seq})"),
            ));
        }
    }

    let hubs_json = serde_json::to_string(&body.hubs)
        .map_err(|e| db_err(format!("serialize hubs: {e}")))?;

    sqlx::query(
        "INSERT INTO home_hub_designations
            (master_pubkey, hubs_json, issued_at, sequence, signature, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(master_pubkey) DO UPDATE SET
            hubs_json = excluded.hubs_json,
            issued_at = excluded.issued_at,
            sequence  = excluded.sequence,
            signature = excluded.signature,
            updated_at = excluded.updated_at",
    )
    .bind(&master)
    .bind(&hubs_json)
    .bind(body.issued_at as i64)
    .bind(body.sequence as i64)
    .bind(&body.signature)
    .bind(now_secs())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}

// --- Device registry (subkey certs) ---

pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
) -> Result<Json<Vec<SubkeyCert>>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT master_pubkey, subkey_pubkey, device_label, issued_at,
                not_after, fallback_hubs_json, signature
         FROM subkey_certs WHERE master_pubkey = ?
         ORDER BY issued_at",
    )
    .bind(&master)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let fallback_json: String = row.get("fallback_hubs_json");
        let fallback_hubs: Vec<String> = serde_json::from_str(&fallback_json)
            .map_err(|e| db_err(format!("fallback_hubs_json: {e}")))?;
        let not_after: Option<i64> = row.get("not_after");
        out.push(SubkeyCert {
            master_pubkey: row.get("master_pubkey"),
            subkey_pubkey: row.get("subkey_pubkey"),
            device_label: row.get("device_label"),
            issued_at: row.get::<i64, _>("issued_at") as u64,
            not_after: not_after.map(|t| t as u64),
            fallback_hubs,
            signature: row.get("signature"),
        });
    }
    Ok(Json(out))
}

pub async fn post_device(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
    Json(cert): Json<SubkeyCert>,
) -> Result<StatusCode, (StatusCode, String)> {
    if cert.master_pubkey != master {
        return Err(bad("master_pubkey mismatch between URL and body"));
    }
    cert.verify().map_err(|e| bad(format!("Bad signature: {e}")))?;

    let fallback_json = serde_json::to_string(&cert.fallback_hubs)
        .map_err(|e| db_err(format!("serialize fallback_hubs: {e}")))?;

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
    .bind(&cert.master_pubkey)
    .bind(&cert.subkey_pubkey)
    .bind(&cert.device_label)
    .bind(cert.issued_at as i64)
    .bind(cert.not_after.map(|t| t as i64))
    .bind(&fallback_json)
    .bind(&cert.signature)
    .bind(now_secs())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}

// --- Revocations ---

pub async fn list_revocations(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
) -> Result<Json<Vec<RevocationEntry>>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT master_pubkey, subkey_pubkey, revoked_at, signature
         FROM subkey_revocations WHERE master_pubkey = ?
         ORDER BY revoked_at",
    )
    .bind(&master)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;

    let out = rows
        .into_iter()
        .map(|row| RevocationEntry {
            master_pubkey: row.get("master_pubkey"),
            subkey_pubkey: row.get("subkey_pubkey"),
            revoked_at: row.get::<i64, _>("revoked_at") as u64,
            signature: row.get("signature"),
        })
        .collect();
    Ok(Json(out))
}

pub async fn post_revocation(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
    Json(entry): Json<RevocationEntry>,
) -> Result<StatusCode, (StatusCode, String)> {
    if entry.master_pubkey != master {
        return Err(bad("master_pubkey mismatch between URL and body"));
    }
    entry.verify().map_err(|e| bad(format!("Bad signature: {e}")))?;

    sqlx::query(
        "INSERT INTO subkey_revocations
            (master_pubkey, subkey_pubkey, revoked_at, signature, registered_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(master_pubkey, subkey_pubkey) DO NOTHING",
    )
    .bind(&entry.master_pubkey)
    .bind(&entry.subkey_pubkey)
    .bind(entry.revoked_at as i64)
    .bind(&entry.signature)
    .bind(now_secs())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}

// --- Prefs blob ---

pub async fn get_prefs(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
) -> Result<Json<SignedPrefsBlob>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT master_pubkey, blob_version, ciphertext_hex, signature
         FROM prefs_blobs WHERE master_pubkey = ?",
    )
    .bind(&master)
    .fetch_optional(&state.db)
    .await
    .map_err(db_err)?;

    let row = row.ok_or((StatusCode::NOT_FOUND, "No prefs blob".to_string()))?;
    Ok(Json(SignedPrefsBlob {
        master_pubkey: row.get("master_pubkey"),
        blob_version: row.get::<i64, _>("blob_version") as u64,
        ciphertext_hex: row.get("ciphertext_hex"),
        signature: row.get("signature"),
    }))
}

pub async fn put_prefs(
    State(state): State<Arc<AppState>>,
    Path(master): Path<String>,
    Json(blob): Json<SignedPrefsBlob>,
) -> Result<StatusCode, (StatusCode, String)> {
    if blob.master_pubkey != master {
        return Err(bad("master_pubkey mismatch between URL and body"));
    }
    blob.verify().map_err(|e| bad(format!("Bad signature: {e}")))?;

    let current: Option<i64> =
        sqlx::query_scalar("SELECT blob_version FROM prefs_blobs WHERE master_pubkey = ?")
            .bind(&master)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;

    if let Some(v) = current {
        if (blob.blob_version as i64) <= v {
            return Err((
                StatusCode::CONFLICT,
                format!("blob_version must exceed current ({v})"),
            ));
        }
    }

    sqlx::query(
        "INSERT INTO prefs_blobs
            (master_pubkey, blob_version, ciphertext_hex, signature, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(master_pubkey) DO UPDATE SET
            blob_version = excluded.blob_version,
            ciphertext_hex = excluded.ciphertext_hex,
            signature = excluded.signature,
            updated_at = excluded.updated_at",
    )
    .bind(&blob.master_pubkey)
    .bind(blob.blob_version as i64)
    .bind(&blob.ciphertext_hex)
    .bind(&blob.signature)
    .bind(now_secs())
    .execute(&state.db)
    .await
    .map_err(db_err)?;

    Ok(StatusCode::OK)
}
