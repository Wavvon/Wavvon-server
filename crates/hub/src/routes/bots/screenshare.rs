use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::{ActiveShare, AppState, ScreenStreamMeta};

use super::models::authenticate_bot;

#[derive(Deserialize)]
pub struct ScreenshareStartRequest {
    pub channel_id: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default = "default_mime")]
    pub mime: String,
    #[serde(default)]
    pub has_audio: bool,
}

fn default_kind() -> String {
    "screen".into()
}
fn default_mime() -> String {
    "video/webm".into()
}

#[derive(Serialize)]
pub struct ScreenshareStartResponse {
    pub stream_id: String,
    pub channel_id: String,
}

/// POST /bots/{id}/screenshare/start
///
/// Registers a new video stream for a bot in the given channel. The bot must
/// authenticate as itself via `Authorization: Bearer <bot_token>` and the
/// `{id}` path parameter must match its own public key.
///
/// Returns a `stream_id` that the bot should use when pushing
/// `ScreenShareChunk` frames over its WS connection.
pub async fn bot_screenshare_start(
    Path(bot_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScreenshareStartRequest>,
) -> Result<Json<ScreenshareStartResponse>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Caller must be the bot identified by the path parameter.
    if bot.public_key != bot_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the bot itself may call this".into(),
        ));
    }

    // Verify channel exists and is not a category.
    let channel_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ? AND is_category = 0")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if channel_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".into()));
    }

    let stream_id = Uuid::new_v4().to_string();

    // Register the stream in screen_shares.
    {
        let mut shares = state.screen_shares.write().await;
        let active = shares
            .entry((req.channel_id.clone(), bot_id.clone()))
            .or_insert_with(|| ActiveShare {
                streams: HashMap::new(),
                viewers: HashSet::new(),
                cross_channel_subscribers: HashSet::new(),
            });
        active.streams.insert(
            stream_id.clone(),
            ScreenStreamMeta {
                kind: req.kind.clone(),
                mime: req.mime.clone(),
                has_audio: req.has_audio,
                sharer_pubkey: bot_id.clone(),
                session_id: "bot-rest".to_string(),
                init_chunk: None,
                started_at: std::time::Instant::now(),
            },
        );
    }

    // Broadcast ScreenShareStarted to all WS subscribers.
    let ev = ChatEvent::ScreenShareStarted {
        channel_id: req.channel_id.clone(),
        stream_id: stream_id.clone(),
        sharer_pubkey: bot_id.clone(),
        kind: req.kind.clone(),
        mime: req.mime.clone(),
        has_audio: req.has_audio,
    };
    let ws_msg = WsServerMessage::ScreenShareStarted {
        channel_id: req.channel_id.clone(),
        stream_id: stream_id.clone(),
        sharer_pubkey: bot_id.clone(),
        kind: req.kind.clone(),
        mime: req.mime.clone(),
        has_audio: req.has_audio,
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));

    Ok(Json(ScreenshareStartResponse {
        stream_id,
        channel_id: req.channel_id,
    }))
}

#[derive(Deserialize)]
pub struct ScreenshareStopRequest {
    pub channel_id: String,
    pub stream_id: String,
}

/// DELETE /bots/{id}/screenshare/stop
///
/// Deregisters a previously started video stream. Broadcasts `ScreenShareStopped`
/// to all WS subscribers and returns 204 No Content. Idempotent — calling it
/// when the stream is already gone is a no-op (still 204).
pub async fn bot_screenshare_stop(
    Path(bot_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScreenshareStopRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Caller must be the bot identified by the path parameter.
    if bot.public_key != bot_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the bot itself may call this".into(),
        ));
    }

    // Remove the stream from screen_shares, mirroring handle_screen_share_stop.
    let cross_subscribers: Vec<String> = {
        let mut shares = state.screen_shares.write().await;
        let key = (req.channel_id.clone(), bot_id.clone());
        let mut subs = Vec::new();
        if let Some(active) = shares.get_mut(&key) {
            subs = active.cross_channel_subscribers.iter().cloned().collect();
            active.streams.remove(&req.stream_id);
            if active.streams.is_empty() {
                shares.remove(&key);
            }
        }
        subs
    };

    // Broadcast ScreenShareStopped.
    {
        let ev = ChatEvent::ScreenShareStopped {
            channel_id: req.channel_id.clone(),
            stream_id: req.stream_id.clone(),
            sharer_pubkey: bot_id.clone(),
        };
        let ws_msg = WsServerMessage::ScreenShareStopped {
            channel_id: req.channel_id.clone(),
            stream_id: req.stream_id.clone(),
            sharer_pubkey: bot_id.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }

    // Notify any cross-channel subscribers that their subscription ended.
    for subscriber_pubkey in cross_subscribers {
        let ev = ChatEvent::StreamSubscriptionEnded {
            to_pubkey: subscriber_pubkey.clone(),
            source_channel_id: req.channel_id.clone(),
            stream_id: req.stream_id.clone(),
        };
        let ws_msg = WsServerMessage::StreamSubscriptionEnded {
            source_channel_id: req.channel_id.clone(),
            stream_id: req.stream_id.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }

    Ok(StatusCode::NO_CONTENT)
}
