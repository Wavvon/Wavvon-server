use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::Message;
use futures_util::SinkExt;

use crate::routes::chat_models::{WsClientMessage, WsServerMessage};
use crate::state::AppState;

use crate::routes::ws::conn_state::{ConnState, DispatchResult};

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

pub(in crate::routes::ws) async fn handle_typing(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, typing) = match msg {
        WsClientMessage::Typing { channel_id, typing } => (channel_id, typing),
        _ => return DispatchResult::Continue,
    };

    // Silently drop typing events from users who are not subscribed to the
    // channel or who have been banned from it.
    if !cs.subscribed.contains(&channel_id) {
        return DispatchResult::Continue;
    }
    if crate::routes::moderation::is_channel_banned(&state.db, &channel_id, &cs.public_key)
        .await
        .unwrap_or(false)
    {
        return DispatchResult::Continue;
    }

    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
            .bind(&cs.public_key)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let ev = crate::routes::chat_models::ChatEvent::Typing {
        channel_id: channel_id.clone(),
        public_key: cs.public_key.clone(),
        display_name: display_name.clone(),
        typing,
    };
    let ws_msg = WsServerMessage::Typing {
        channel_id,
        public_key: cs.public_key.clone(),
        display_name,
        typing,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_dm_typing(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (conversation_id, typing) = match msg {
        WsClientMessage::DmTyping {
            conversation_id,
            typing,
        } => (conversation_id, typing),
        _ => return DispatchResult::Continue,
    };
    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
            .bind(&cs.public_key)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let _ = state.dm_tx.send(crate::state::DmEvent::Typing {
        conversation_id,
        sender: cs.public_key.clone(),
        sender_name: display_name,
        typing,
    });
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_component_interaction(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (message_id, custom_id, values) = match msg {
        WsClientMessage::ComponentInteraction {
            message_id,
            custom_id,
            values,
        } => (message_id, custom_id, values),
        _ => return DispatchResult::Continue,
    };

    let rl_key = (cs.public_key.clone(), custom_id.clone());
    let now_inst = Instant::now();
    if let Some(last) = cs.component_rate_limit.get(&rl_key) {
        if now_inst.duration_since(*last) < Duration::from_secs(3) {
            let err = WsServerMessage::Error {
                context: "component_interaction".to_string(),
                message: "Please wait before interacting again.".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
    }
    cs.component_rate_limit.insert(rl_key, now_inst);
    // Opportunistic cleanup so the map doesn't grow forever.
    if cs.component_rate_limit.len() > 500 {
        cs.component_rate_limit
            .retain(|_, t| now_inst.duration_since(*t) < Duration::from_secs(60));
    }

    let state_c = state.clone();
    let pk = cs.public_key.clone();
    tokio::spawn(async move {
        crate::bots::dispatch::dispatch_component(&state_c, &message_id, &custom_id, &values, &pk)
            .await;
    });
    DispatchResult::Continue
}
