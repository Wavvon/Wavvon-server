use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::{ActiveShare, AppState, ScreenStreamMeta};

/// Stands in for the WS session id on a stream started over HTTP, where there
/// is no socket to name. Session-scoped teardown matches on it, so it has to
/// be a value no real session id can collide with.
const HTTP_SESSION_ID: &str = "http";

use crate::auth::middleware::AuthUser;

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

/// POST /screenshare/start
///
/// Registers a video stream for the calling identity in the given channel,
/// for a client that pushes frames without going through the WS start
/// handshake in `ws::handlers::screen`. Returns the `stream_id` to send
/// `ScreenShareChunk` frames under.
pub async fn screenshare_start(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ScreenshareStartRequest>,
) -> Result<Json<ScreenshareStartResponse>, (StatusCode, String)> {
    let sharer = user.public_key.clone();

    // Verify channel exists and is not a category.
    let channel_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = $1 AND is_category = false")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if channel_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".into()));
    }

    // Same channel gate the WS path applies, because it is the same act.
    let perms = crate::permissions::channel_permissions(&state.db, &sharer, &req.channel_id)
        .await
        .map_err(|_| (StatusCode::FORBIDDEN, "You cannot share here".to_string()))?;
    if !perms.has(crate::permissions::VOICE_JOIN) {
        return Err((
            StatusCode::FORBIDDEN,
            "You cannot share into this channel".into(),
        ));
    }

    // Hub-wide cap on streams started this way. A person clicking Share holds
    // a socket and goes through the WS path; this one is for the unattended
    // pushers, and it is the one worth bounding.
    {
        let active_http_streams = state
            .screen_shares
            .read()
            .await
            .values()
            .flat_map(|active| active.streams.values())
            .filter(|meta| meta.via_http)
            .count();
        if active_http_streams >= state.http_video_stream_budget {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Hub-wide video stream budget exceeded".into(),
            ));
        }
    }

    let stream_id = Uuid::new_v4().to_string();

    // Register the stream in screen_shares.
    {
        let mut shares = state.screen_shares.write().await;
        let active = shares
            .entry((req.channel_id.clone(), sharer.clone()))
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
                sharer_pubkey: sharer.clone(),
                via_http: true,
                session_id: HTTP_SESSION_ID.to_string(),
                init_chunk: None,
                started_at: std::time::Instant::now(),
            },
        );
    }

    // Broadcast ScreenShareStarted to all WS subscribers.
    let ev = ChatEvent::ScreenShareStarted {
        channel_id: req.channel_id.clone(),
        stream_id: stream_id.clone(),
        sharer_pubkey: sharer.clone(),
        kind: req.kind.clone(),
        mime: req.mime.clone(),
        has_audio: req.has_audio,
    };
    let ws_msg = WsServerMessage::ScreenShareStarted {
        channel_id: req.channel_id.clone(),
        stream_id: stream_id.clone(),
        sharer_pubkey: sharer.clone(),
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

/// DELETE /screenshare/stop
///
/// Deregisters a previously started video stream. Broadcasts `ScreenShareStopped`
/// to all WS subscribers and returns 204 No Content. Idempotent — calling it
/// when the stream is already gone is a no-op (still 204).
pub async fn screenshare_stop(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ScreenshareStopRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let sharer = user.public_key.clone();

    // Remove the stream from screen_shares, mirroring handle_screen_share_stop.
    let cross_subscribers: Vec<String> = {
        let mut shares = state.screen_shares.write().await;
        let key = (req.channel_id.clone(), sharer.clone());
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
            sharer_pubkey: sharer.clone(),
        };
        let ws_msg = WsServerMessage::ScreenShareStopped {
            channel_id: req.channel_id.clone(),
            stream_id: req.stream_id.clone(),
            sharer_pubkey: sharer.clone(),
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
