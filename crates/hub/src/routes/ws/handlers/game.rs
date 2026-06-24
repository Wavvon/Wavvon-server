use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;

use crate::routes::chat_models::{WsClientMessage, WsServerMessage};
use crate::state::AppState;

use crate::routes::ws::conn_state::{ConnState, DispatchResult};

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

pub(in crate::routes::ws) async fn handle_game_send(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (session_id, payload, to) = match msg {
        WsClientMessage::GameSend {
            session_id,
            payload,
            to,
        } => (session_id, payload, to),
        _ => return DispatchResult::Continue,
    };

    enum Outcome {
        NotFound,
        NotInSession,
        Ok {
            channel_id: String,
            roster: Vec<String>,
        },
    }

    let outcome = {
        let sessions = state.active_game_sessions.lock().unwrap();
        match sessions.get(&session_id) {
            None => Outcome::NotFound,
            Some(s) if !s.players.contains(&cs.public_key) => Outcome::NotInSession,
            Some(s) => Outcome::Ok {
                channel_id: s.channel_id.clone(),
                roster: s.players.iter().cloned().collect(),
            },
        }
    };

    let (channel_id, roster) = match outcome {
        Outcome::NotFound => {
            let err = WsServerMessage::Error {
                context: "game_send".to_string(),
                message: "Session not found".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::NotInSession => {
            let err = WsServerMessage::Error {
                context: "game_send".to_string(),
                message: "Not in session".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::Ok { channel_id, roster } => (channel_id, roster),
    };

    // Update last_event_at under lock (no await inside).
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.last_event_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
        }
    }

    let game_event = WsServerMessage::GameEvent {
        session_id: session_id.clone(),
        from_pubkey: cs.public_key.clone(),
        payload,
    };

    let should_send = if let Some(ref target) = to {
        roster.contains(target)
    } else {
        true
    };
    if should_send {
        let ev = crate::routes::chat_models::ChatEvent::Game {
            channel_id: channel_id.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&game_event).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_game_set_status(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (session_id, status) = match msg {
        WsClientMessage::GameSetStatus { session_id, status } => (session_id, status),
        _ => return DispatchResult::Continue,
    };

    enum Outcome {
        NotFound,
        NotHost,
        Ok(String),
    }

    let outcome = {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        match sessions.get_mut(&session_id) {
            None => Outcome::NotFound,
            Some(s) if s.host_pubkey != cs.public_key => Outcome::NotHost,
            Some(s) => {
                s.status = status.clone();
                s.last_event_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                Outcome::Ok(s.channel_id.clone())
            }
        }
    };

    let channel_id = match outcome {
        Outcome::NotFound => {
            let err = WsServerMessage::Error {
                context: "game_set_status".to_string(),
                message: "Session not found".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::NotHost => {
            let err = WsServerMessage::Error {
                context: "game_set_status".to_string(),
                message: "Only the host can change session status".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::Ok(ch) => ch,
    };

    let ev = crate::routes::chat_models::ChatEvent::Game { channel_id };
    let status_msg = WsServerMessage::GameEvent {
        session_id: session_id.clone(),
        from_pubkey: cs.public_key.clone(),
        payload: serde_json::json!({ "type": "status_changed", "status": status }),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&status_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_game_snapshot(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (session_id, blob) = match msg {
        WsClientMessage::GameSnapshot { session_id, blob } => (session_id, blob),
        _ => return DispatchResult::Continue,
    };

    let in_session = {
        let sessions = state.active_game_sessions.lock().unwrap();
        sessions
            .get(&session_id)
            .map(|s| s.players.contains(&cs.public_key))
            .unwrap_or(false)
    };
    if !in_session {
        return DispatchResult::Continue;
    }

    let blob_bytes = bytes::Bytes::from(blob.into_bytes());
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.snapshot = Some(blob_bytes.clone());
            s.last_event_at = now_ts;
        }
    }

    let state_c = state.clone();
    let sid = session_id.clone();
    let blob_vec = blob_bytes.to_vec();
    tokio::spawn(async move {
        let _ = sqlx::query("UPDATE game_sessions SET snapshot = ?, updated_at = ? WHERE id = ?")
            .bind(blob_vec.as_slice())
            .bind(now_ts)
            .bind(&sid)
            .execute(&state_c.db)
            .await;
    });
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_game_end(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (session_id, result) = match msg {
        WsClientMessage::GameEnd { session_id, result } => (session_id, result),
        _ => return DispatchResult::Continue,
    };

    enum Outcome {
        NotFound,
        NotHost,
        Ok(String),
    }

    let outcome = {
        let sessions = state.active_game_sessions.lock().unwrap();
        match sessions.get(&session_id) {
            None => Outcome::NotFound,
            Some(s) if s.host_pubkey != cs.public_key => Outcome::NotHost,
            Some(s) => Outcome::Ok(s.channel_id.clone()),
        }
    };

    let channel_id = match outcome {
        Outcome::NotFound => {
            let err = WsServerMessage::Error {
                context: "game_end".to_string(),
                message: "Session not found".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::NotHost => {
            let err = WsServerMessage::Error {
                context: "game_end".to_string(),
                message: "Only the host can end the session".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Outcome::Ok(ch) => ch,
    };

    state
        .active_game_sessions
        .lock()
        .unwrap()
        .remove(&session_id);

    let state_c = state.clone();
    let sid = session_id.clone();
    tokio::spawn(async move {
        let now_str = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let _ = sqlx::query("UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?")
            .bind(&now_str)
            .bind(&sid)
            .execute(&state_c.db)
            .await;
    });

    let end_msg = WsServerMessage::GameSessionEnded {
        session_id: session_id.clone(),
        reason: Some("ended".to_string()),
        result,
    };
    let ev = crate::routes::chat_models::ChatEvent::Game { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&end_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}
