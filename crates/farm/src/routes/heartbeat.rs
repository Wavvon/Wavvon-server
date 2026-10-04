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

use crate::routes::admin::require_admin;
use crate::routes::hubs::hub_url;
use crate::state::FarmState;
use crate::unix_now;

// ---------------------------------------------------------------------------
// POST /farm/heartbeat
// ---------------------------------------------------------------------------

/// What the farm tells a hub in reply to its heartbeat.
///
/// The heartbeat is the only standing farm→hub channel, so it is where a hub
/// learns its own public address. It cannot come from the environment: a
/// rename has to reach a *running* hub, and an env var is fixed at spawn.
/// Within one heartbeat interval every hub knows its current name.
#[derive(Serialize, Default)]
pub struct HeartbeatResponse {
    /// Absolute URL this hub should advertise as its own — its canonical slug
    /// when it has one, otherwise the pubkey form. Absent when the farm cannot
    /// work it out (no public farm URL configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_url: Option<String>,
    /// The other hubs on this farm.
    ///
    /// Offered, not imposed. A hub uses these to subscribe to its siblings'
    /// ban lists in `soft-flag` (history, never a block) and to trust them as
    /// certification issuers, so somebody vouched for on one hub of a farm is
    /// not a stranger on the next — the anti-bot story, built out of the
    /// federation primitives that already exist rather than a farm-level
    /// reputation store, which is a thing this project has said it will not
    /// build.
    ///
    /// A hub wires each sibling in **once**. If its owner later unsubscribes,
    /// it stays unsubscribed: a compromised sibling has to be cuttable, and an
    /// admin decision the farm silently reverts every minute is not a decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siblings: Vec<Sibling>,
}

#[derive(Serialize)]
pub struct Sibling {
    pub hub_pubkey: String,
    pub hub_url: String,
}

pub async fn receive_heartbeat(
    State(state): State<Arc<FarmState>>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<HeartbeatResponse>) {
    let hub_pubkey = match payload.get("hub_pubkey").and_then(|v| v.as_str()) {
        Some(pk) if !pk.is_empty() => pk.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(HeartbeatResponse::default())),
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

    // First contact: bind the row to the pubkey ("claiming the serial").
    //
    // The farm allocates a `hubs` row before the process exists, so it cannot
    // know the hub's Ed25519 key — that is generated on the hub's first boot.
    // The hub reports back the id we handed it at spawn (WAVVON_FARM_HUB_ID)
    // and we record its pubkey against that row, once.
    //
    // Nothing did this, and `hubs.hub_pubkey` stayed NULL forever. Every
    // consequence was silent: the proxy resolves `/hub/<serial>` against that
    // column, so every farm-routed request 404'd; the recognition check below
    // rejected every heartbeat; and the monitor, reading liveness from those
    // heartbeats, concluded each hub was down, restarted it on a backoff, and
    // eventually disabled its own auto-restart.
    //
    // `WHERE hub_pubkey IS NULL` makes it strictly one-shot: a hub can take an
    // unclaimed row, never another hub's. A row already bound to a different
    // key is left alone and the mismatch is logged — that is either a hub
    // restored from another hub's backup or a misconfigured spawn, and both
    // want an operator, not a silent rebind.
    if let Some(hub_id) = payload.get("hub_id").and_then(|v| v.as_str()) {
        let claimed = sqlx::query(
            "UPDATE hubs SET hub_pubkey = $1
             WHERE id = $2 AND hub_pubkey IS NULL AND deleted_at IS NULL",
        )
        .bind(&hub_pubkey)
        .bind(hub_id)
        .execute(&state.db)
        .await;

        match claimed {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(hub_id, hub_pubkey, "Hub claimed its row — routable now");
            }
            Ok(_) => {
                // Either already bound to us (the normal steady state, every
                // 60s) or bound to someone else (worth saying out loud).
                let existing: Option<Option<String>> =
                    sqlx::query_scalar("SELECT hub_pubkey FROM hubs WHERE id = $1")
                        .bind(hub_id)
                        .fetch_optional(&state.db)
                        .await
                        .ok()
                        .flatten();
                if let Some(Some(bound)) = existing {
                    if bound != hub_pubkey {
                        tracing::warn!(
                            hub_id,
                            bound_pubkey = bound,
                            reporting_pubkey = hub_pubkey,
                            "Heartbeat claims a hub row already bound to a different \
                             pubkey — ignoring the claim. Check for a duplicated \
                             WAVVON_FARM_HUB_ID or a restored hub identity."
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(hub_id, error = %e, "Failed to claim hub row"),
        }
    }

    // Only accept heartbeats from hubs we recognise (hub_pubkey in hubs table).
    let known_count: Result<i64, _> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hubs WHERE hub_pubkey = $1 AND deleted_at IS NULL",
    )
    .bind(&hub_pubkey)
    .fetch_one(&state.db)
    .await;

    match known_count {
        Ok(0) => return (StatusCode::FORBIDDEN, Json(HeartbeatResponse::default())),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(HeartbeatResponse::default()),
            )
        }
        Ok(_) => {}
    }

    let _ = sqlx::query(
        "INSERT INTO hub_heartbeats
             (hub_pubkey, online_users, storage_bytes, uptime_seconds, last_seen_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (hub_pubkey) DO UPDATE SET
             online_users   = EXCLUDED.online_users,
             storage_bytes  = EXCLUDED.storage_bytes,
             uptime_seconds = EXCLUDED.uptime_seconds,
             last_seen_at   = EXCLUDED.last_seen_at",
    )
    .bind(&hub_pubkey)
    .bind(online_users)
    .bind(storage_bytes)
    .bind(uptime_seconds)
    .bind(now)
    .execute(&state.db)
    .await;

    // Hub is confirmed online — zero out any accrued auto-restart attempts
    // (see monitor.rs) so a hub that recovers on its own, or after a manual
    // force-restart, gets a clean backoff slate.
    let _ = sqlx::query(
        "UPDATE hubs SET restart_attempts = 0
         WHERE hub_pubkey = $1 AND restart_attempts > 0",
    )
    .bind(&hub_pubkey)
    .execute(&state.db)
    .await;

    // Tell the hub where it currently lives. Its canonical slug if it has one,
    // otherwise the pubkey form — which always resolves and needs no lookup.
    let canonical_url = {
        let hub_id: Option<String> =
            sqlx::query_scalar("SELECT id FROM hubs WHERE hub_pubkey = $1 AND deleted_at IS NULL")
                .bind(&hub_pubkey)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        match hub_id {
            Some(id) => hub_url(&state.db, &state.farm_url, &id, Some(&hub_pubkey)).await,
            None => None,
        }
    };

    // Every other live hub on this farm, addressed by its canonical slug so
    // the URL survives a rename. Only hubs that have claimed a serial: one
    // without a pubkey cannot be verified as a ban-list issuer or a cert
    // issuer, which is the whole basis for trusting it.
    let siblings = {
        let base = state.farm_url.trim_end_matches('/');
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT h.id, h.hub_pubkey, s.slug
             FROM hubs h
             LEFT JOIN hub_slugs s
                    ON s.hub_id = h.id AND s.is_canonical AND s.released_at IS NULL
             WHERE h.hub_pubkey IS NOT NULL
               AND h.hub_pubkey <> $1
               AND h.deleted_at IS NULL
               AND h.suspended_at IS NULL",
        )
        .bind(&hub_pubkey)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|(_, pubkey, slug)| {
                let address = slug.unwrap_or_else(|| pubkey.clone());
                Sibling {
                    hub_url: format!("{base}/hub/{address}"),
                    hub_pubkey: pubkey,
                }
            })
            .collect()
    };

    (
        StatusCode::OK,
        Json(HeartbeatResponse {
            canonical_url,
            siblings,
        }),
    )
}

// ---------------------------------------------------------------------------
// GET /farm/admin/fleet
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FleetEntry {
    pub id: String,
    pub name: String,
    /// Absent until the hub has claimed its row; see `hubs::hub_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_pubkey: Option<String>,
    pub online: bool,
    pub online_users: i64,
    pub storage_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    pub created_at: i64,
    pub auto_restart_enabled: bool,
    pub restart_attempts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_restart_at: Option<i64>,
}

pub async fn get_fleet(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<Vec<FleetEntry>>, (StatusCode, Json<serde_json::Value>)> {
    require_admin(&headers, &state).await?;

    let now = unix_now();
    // 3 missed 60-second heartbeats = 180 seconds.
    let offline_threshold = now - 180;

    let rows = sqlx::query(
        "SELECT h.id, h.name, h.hub_pubkey,
                hb.online_users, hb.storage_bytes, hb.last_seen_at,
                (hb.last_seen_at IS NOT NULL AND hb.last_seen_at >= $1) AS online,
                h.created_at, h.auto_restart_enabled, h.restart_attempts, h.last_restart_at
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

    let mut fleet = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: String = r.get("id");
        let hub_pubkey: Option<String> = r.get("hub_pubkey");
        fleet.push(FleetEntry {
            hub_url: hub_url(&state.db, &state.farm_url, &id, hub_pubkey.as_deref()).await,
            id,
            name: r.get("name"),
            hub_pubkey,
            online: r.get::<bool, _>("online"),
            online_users: r.get::<Option<i64>, _>("online_users").unwrap_or(0),
            storage_bytes: r.get::<Option<i64>, _>("storage_bytes").unwrap_or(0),
            last_seen_at: r.get("last_seen_at"),
            created_at: r.get("created_at"),
            auto_restart_enabled: r.get("auto_restart_enabled"),
            restart_attempts: r.get("restart_attempts"),
            last_restart_at: r.get("last_restart_at"),
        });
    }

    Ok(Json(fleet))
}
