/// Farm heartbeat routes.
///
/// POST /farm/heartbeat          — hub pushes stats every 60 s (unauthenticated by hub pubkey match)
/// GET  /farm/admin/fleet        — farm admin reads online/offline status of all hubs
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Serialize;
use sqlx::Row;

use crate::routes::admin::require_admin_pub;
use crate::state::FarmState;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// POST /farm/heartbeat
// ---------------------------------------------------------------------------

pub async fn receive_heartbeat(
    State(state): State<Arc<FarmState>>,
    Json(payload): Json<serde_json::Value>,
) -> StatusCode {
    let hub_pubkey = match payload.get("hub_pubkey").and_then(|v| v.as_str()) {
        Some(pk) if !pk.is_empty() => pk.to_string(),
        _ => return StatusCode::BAD_REQUEST,
    };
    let online_users = payload
        .get("online_users")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let storage_bytes = payload
        .get("storage_bytes")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let uptime_seconds = payload
        .get("uptime_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let now = unix_now();

    // Only accept heartbeats from hubs we recognise (hub_pubkey in hubs table).
    let known_count: Result<i64, _> =
        sqlx::query_scalar("SELECT COUNT(*) FROM hubs WHERE hub_pubkey = ? AND deleted_at IS NULL")
            .bind(&hub_pubkey)
            .fetch_one(&state.db)
            .await;

    match known_count {
        Ok(0) => return StatusCode::FORBIDDEN,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
        Ok(_) => {}
    }

    let _ = sqlx::query(
        "INSERT OR REPLACE INTO hub_heartbeats
             (hub_pubkey, online_users, storage_bytes, uptime_seconds, last_seen_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&hub_pubkey)
    .bind(online_users)
    .bind(storage_bytes)
    .bind(uptime_seconds)
    .bind(now)
    .execute(&state.db)
    .await;

    StatusCode::OK
}

// ---------------------------------------------------------------------------
// GET /farm/admin/fleet
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FleetEntry {
    pub id: String,
    pub name: String,
    pub hub_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_pubkey: Option<String>,
    pub online: bool,
    pub online_users: i64,
    pub storage_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
}

pub async fn get_fleet(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<Vec<FleetEntry>>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    let now = unix_now();
    // 3 missed 60-second heartbeats = 180 seconds.
    let offline_threshold = now - 180;

    let rows = sqlx::query(
        "SELECT h.id, h.name, h.hub_pubkey,
                hb.online_users, hb.storage_bytes, hb.last_seen_at,
                CASE WHEN hb.last_seen_at IS NULL OR hb.last_seen_at < ? THEN 0 ELSE 1 END AS online,
                h.created_at
         FROM hubs h
         LEFT JOIN hub_heartbeats hb ON hb.hub_pubkey = h.hub_pubkey
         WHERE h.deleted_at IS NULL
         ORDER BY h.created_at",
    )
    .bind(offline_threshold)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let farm_url = state.farm_url.trim_end_matches('/');

    let fleet: Vec<FleetEntry> = rows
        .iter()
        .map(|r| {
            let id: String = r.get("id");
            let hub_url = format!("{}/hub/{}", farm_url, id);
            FleetEntry {
                hub_url,
                id,
                name: r.get("name"),
                hub_pubkey: r.get("hub_pubkey"),
                online: r.get::<i64, _>("online") == 1,
                online_users: r.get::<Option<i64>, _>("online_users").unwrap_or(0),
                storage_bytes: r.get::<Option<i64>, _>("storage_bytes").unwrap_or(0),
                last_seen_at: r.get("last_seen_at"),
                created_at: r.get("created_at"),
            }
        })
        .collect();

    Ok(Json(fleet))
}
