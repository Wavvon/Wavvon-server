use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::models::{AuditLogEntry, AuditLogQuery};

// ---------------------------------------------------------------------------
// GET /admin/audit-log
// ---------------------------------------------------------------------------

/// `hub_audit_log` for a person reading it: newest first, each page older
/// than `cursor`. Admin only. Apps replaying the same log read it forwards
/// through `GET /me/events`, so the two readers do not share an order.
pub async fn admin_audit_log(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLogEntry>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::AUDIT_READ)?;

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        seq: i64,
        event_type: String,
        at: i64,
        actor_pubkey: Option<String>,
        target_pubkey: Option<String>,
        channel_id: Option<String>,
        payload_json: String,
    }

    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
         FROM hub_audit_log
         WHERE ($1::bigint IS NULL OR seq < $1)
           AND at >= $2 AND at <= $3
           AND ($4::text IS NULL OR event_type = $4)
           AND ($5::text IS NULL OR actor_pubkey = $5)
         ORDER BY seq DESC
         LIMIT $6",
    )
    .bind(params.cursor)
    .bind(params.since.unwrap_or(0))
    .bind(params.until.unwrap_or(i64::MAX))
    .bind(params.event_type.as_deref().filter(|s| !s.is_empty()))
    .bind(params.actor.as_deref().filter(|s| !s.is_empty()))
    .bind(params.limit.unwrap_or(50).clamp(1, 200))
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AuditLogEntry {
                seq: r.seq,
                event_type: r.event_type,
                at: r.at,
                actor_pubkey: r.actor_pubkey,
                target_pubkey: r.target_pubkey,
                channel_id: r.channel_id,
                payload: serde_json::from_str(&r.payload_json).unwrap_or(serde_json::Value::Null),
            })
            .collect(),
    ))
}
