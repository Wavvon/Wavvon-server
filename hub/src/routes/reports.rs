use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ReportRequest {
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ReportAction {
    pub action: String,
    pub note: Option<String>,
}
// action: "dismiss" | "delete_message" | "ban_user"

#[derive(Deserialize)]
pub struct ReportsQuery {
    pub status: Option<String>,
}

pub async fn report_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<ReportRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let id = uuid::Uuid::new_v4().to_string();
    let result = sqlx::query(
        "INSERT INTO message_reports(id, message_id, reporter_pubkey, reason, reported_at, status)
         VALUES(?,?,?,?,?,'pending') ON CONFLICT (message_id, reporter_pubkey) DO NOTHING",
    )
    .bind(&id)
    .bind(&message_id)
    .bind(&user.public_key)
    .bind(req.reason.unwrap_or_default())
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Already reported".into()));
    }
    Ok(StatusCode::OK)
}

pub async fn list_reports(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ReportsQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let status = q.status.unwrap_or_else(|| "pending".into());
    let rows = sqlx::query(
        "SELECT r.id, r.message_id, m.content as message_content, m.channel_id,
                r.reporter_pubkey, r.reason, r.reported_at, r.status
         FROM message_reports r
         JOIN messages m ON m.id = r.message_id
         WHERE r.status = ?
         ORDER BY r.reported_at DESC LIMIT 50",
    )
    .bind(&status)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    use sqlx::Row;
    let results: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<String, _>("id"),
                "message_id": r.get::<String, _>("message_id"),
                "message_content": r.get::<Option<String>, _>("message_content"),
                "channel_id": r.get::<String, _>("channel_id"),
                "reporter_pubkey": r.get::<String, _>("reporter_pubkey"),
                "reason": r.get::<String, _>("reason"),
                "reported_at": r.get::<i64, _>("reported_at"),
                "status": r.get::<String, _>("status"),
            })
        })
        .collect();

    Ok(Json(results))
}

pub async fn review_report(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(report_id): Path<String>,
    Json(req): Json<ReportAction>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let row = sqlx::query("SELECT message_id, reporter_pubkey FROM message_reports WHERE id = ?")
        .bind(&report_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Report not found".into()))?;

    use sqlx::Row;
    let message_id: String = row.get("message_id");

    match req.action.as_str() {
        "delete_message" => {
            sqlx::query("UPDATE messages SET content = '[deleted]' WHERE id = ?")
                .bind(&message_id)
                .execute(&state.db)
                .await
                .ok();
        }
        "ban_user" => {
            let sender: Option<String> =
                sqlx::query_scalar("SELECT sender FROM messages WHERE id = ?")
                    .bind(&message_id)
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten();
            if let Some(pk) = sender {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                sqlx::query(
                    "INSERT INTO bans(target_public_key, banned_by, reason, created_at)
                     VALUES(?,?,?,?) ON CONFLICT (target_public_key) DO NOTHING",
                )
                .bind(&pk)
                .bind(&user.public_key)
                .bind("Report action")
                .bind(now)
                .execute(&state.db)
                .await
                .ok();
            }
        }
        _ => {} // "dismiss" — just update the status below
    }

    sqlx::query(
        "UPDATE message_reports SET status='reviewed', reviewed_by=?, review_note=? WHERE id=?",
    )
    .bind(&user.public_key)
    .bind(req.note.as_deref())
    .bind(&report_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}
