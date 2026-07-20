use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

use crate::state::AppState;

use super::models::{authenticate_bot, AckRequest, BotSendRequest, EventInfo, EventRow, PollQuery};

/// PUT /bot/commands  — replace slash command list
pub async fn bot_set_commands(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<super::models::SetCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM bot_slash_commands WHERE bot_pubkey = $1")
        .bind(&bot.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();
    for cmd in &req.commands {
        let cmd_word = cmd.command.trim().to_lowercase();
        if cmd_word.is_empty() {
            continue;
        }
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO bot_slash_commands (id, bot_pubkey, command, description, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(&bot.public_key)
        .bind(&cmd_word)
        .bind(cmd.description.trim())
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

/// POST /bot/send  — post a message as the bot
pub async fn bot_send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BotSendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Verify channel exists.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&req.channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&req.channel_id)
    .bind(&bot.public_key)
    .bind(&req.content)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Broadcast via the chat channel so connected WS clients see it.
    use crate::routes::chat_models::{ChatEvent, MessageResponse, WsServerMessage};
    let message = MessageResponse {
        id,
        channel_id: req.channel_id.clone(),
        sender: bot.public_key,
        sender_name: Some(bot.display_name),
        content: req.content,
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: None,
        reply_count: 0,
        embeds: None,
        game: None,
    };
    {
        let ws_msg = WsServerMessage::ChatMessage {
            channel_id: req.channel_id.clone(),
            message: message.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::New {
                channel_id: req.channel_id,
                message,
            },
            json,
        ));
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /bot/poll  — poll undelivered events
pub async fn bot_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PollQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    let rows = if let Some(since) = params.since {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = $1 AND delivered = FALSE AND created_at > $2
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .bind(since)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM bot_event_queue
             WHERE bot_pubkey = $1 AND delivered = FALSE
             ORDER BY created_at ASC LIMIT 100",
        )
        .bind(&bot.public_key)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let events: Vec<EventInfo> = rows
        .into_iter()
        .map(|r| EventInfo {
            id: r.id,
            event_type: r.event_type,
            payload: r.payload,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "events": events })))
}

/// DELETE /bot/events  — acknowledge events as delivered
pub async fn bot_ack_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    for id in &req.ids {
        let _ = sqlx::query(
            "UPDATE bot_event_queue SET delivered = TRUE
             WHERE id = $1 AND bot_pubkey = $2",
        )
        .bind(id)
        .bind(&bot.public_key)
        .execute(&state.db)
        .await;
    }

    Ok(StatusCode::OK)
}
