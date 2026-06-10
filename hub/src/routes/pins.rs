use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct PinResponse {
    pub message_id: String,
    pub pinned_by: String,
    pub pinned_at: i64,
    pub message: PinnedMessage,
}

#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct PinnedMessage {
    pub id: String,
    pub content: String,
    pub sender: String,
    #[sqlx(default)]
    pub sender_name: Option<String>,
    pub created_at: i64,
}

/// POST /channels/:channel_id/pins/:message_id
pub async fn pin_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Require manage_messages or admin.
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_MESSAGES)?;

    // Verify message belongs to this channel.
    let msg_channel: Option<String> =
        sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = ?")
            .bind(&message_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match msg_channel {
        None => return Err((StatusCode::NOT_FOUND, "Message not found".to_string())),
        Some(c) if c != channel_id => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Message is not in this channel".to_string(),
            ))
        }
        _ => {}
    }

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO channel_pins (channel_id, message_id, pinned_by, pinned_at)
         VALUES (?, ?, ?, ?) ON CONFLICT (channel_id, message_id) DO NOTHING",
    )
    .bind(&channel_id)
    .bind(&message_id)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Broadcast WS event.
    let ws_msg = WsServerMessage::MessagePinned {
        channel_id: channel_id.clone(),
        message_id: message_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state
        .chat_tx
        .send((ChatEvent::MessagePinned { channel_id }, json));

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /channels/:channel_id/pins/:message_id
pub async fn unpin_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_MESSAGES)?;

    sqlx::query("DELETE FROM channel_pins WHERE channel_id = ? AND message_id = ?")
        .bind(&channel_id)
        .bind(&message_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let ws_msg = WsServerMessage::MessageUnpinned {
        channel_id: channel_id.clone(),
        message_id: message_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state
        .chat_tx
        .send((ChatEvent::MessageUnpinned { channel_id }, json));

    Ok(StatusCode::NO_CONTENT)
}

/// GET /channels/:channel_id/pins
pub async fn list_pins(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<PinResponse>>, (StatusCode, String)> {
    // Verify channel exists.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    #[derive(sqlx::FromRow)]
    struct PinRow {
        message_id: String,
        pinned_by: String,
        pinned_at: i64,
        // message fields
        content: String,
        sender: String,
        sender_name: Option<String>,
        created_at: i64,
    }

    let rows: Vec<PinRow> = sqlx::query_as(
        "SELECT cp.message_id, cp.pinned_by, cp.pinned_at,
                m.content, m.sender,
                u.display_name as sender_name,
                m.created_at
         FROM channel_pins cp
         INNER JOIN messages m ON m.id = cp.message_id
         LEFT JOIN users u ON u.public_key = m.sender
         WHERE cp.channel_id = ?
         ORDER BY cp.pinned_at DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let result = rows
        .into_iter()
        .map(|r| PinResponse {
            message_id: r.message_id.clone(),
            pinned_by: r.pinned_by,
            pinned_at: r.pinned_at,
            message: PinnedMessage {
                id: r.message_id,
                content: r.content,
                sender: r.sender,
                sender_name: r.sender_name,
                created_at: r.created_at,
            },
        })
        .collect();

    Ok(Json(result))
}
