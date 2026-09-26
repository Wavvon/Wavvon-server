use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

use super::models::{AuditLogEntry, AuditLogQuery, AuditLogResponse};

// ---------------------------------------------------------------------------
// GET /admin/audit-log
// ---------------------------------------------------------------------------

/// Cursor-paginated view of `hub_audit_log`. Admin only.
pub async fn admin_audit_log(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::AUDIT_READ)?;

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    // We fetch limit+1 to detect whether there's a next page.
    let fetch_limit = limit + 1;

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

    // Build query dynamically from optional filters.
    // SQLite doesn't support named params easily with sqlx, so we use a flag
    // approach: always bind all params, use 0/MAX for disabled ranges.
    let cursor_seq = params.cursor.unwrap_or(0);
    let since = params.since.unwrap_or(0);
    let until = params.until.unwrap_or(i64::MAX);
    let event_type_filter = params.event_type.as_deref().unwrap_or("");

    let rows: Vec<AuditRow> = if event_type_filter.is_empty() {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > $1 AND at >= $2 AND at <= $3
             ORDER BY seq ASC
             LIMIT $4",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, AuditRow>(
            "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
             FROM hub_audit_log
             WHERE seq > $1 AND at >= $2 AND at <= $3 AND event_type = $4
             ORDER BY seq ASC
             LIMIT $5",
        )
        .bind(cursor_seq)
        .bind(since)
        .bind(until)
        .bind(event_type_filter)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<AuditLogEntry> = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| AuditLogEntry {
            seq: r.seq,
            event_type: r.event_type,
            at: r.at,
            actor_pubkey: r.actor_pubkey,
            target_pubkey: r.target_pubkey,
            channel_id: r.channel_id,
            payload: serde_json::from_str(&r.payload_json).unwrap_or(serde_json::Value::Null),
        })
        .collect();

    let next_cursor = if has_more {
        entries.last().map(|e| e.seq)
    } else {
        None
    };

    Ok(Json(AuditLogResponse {
        entries,
        next_cursor,
    }))
}
