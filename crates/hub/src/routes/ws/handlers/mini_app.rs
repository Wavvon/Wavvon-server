use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;
use rand::RngCore;

use crate::routes::chat_models::{ChatEvent, WsClientMessage, WsServerMessage};
use crate::routes::ws::conn_state::{ConnState, DispatchResult};
use crate::state::AppState;

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

/// Bot → hub → channel: fan out a mini-app launch card.
pub(in crate::routes::ws) async fn handle_bot_app_announce(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (title, description, channel_id) = match msg {
        WsClientMessage::BotAppAnnounce {
            title,
            description,
            channel_id,
        } => (title, description, channel_id),
        _ => return DispatchResult::Continue,
    };

    // Only bots may announce.
    if !cs.is_bot {
        return DispatchResult::Continue;
    }

    let server_msg = WsServerMessage::BotAppLaunch {
        bot_id: cs.public_key.clone(),
        title,
        description,
        channel_id: channel_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&server_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ChatEvent::BotApp { channel_id }, json));

    DispatchResult::Continue
}

/// Client → hub: join a mini-app session. Mint scoped token, send BotAppOpen.
pub(in crate::routes::ws) async fn handle_bot_app_join(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (bot_id, channel_id) = match msg {
        WsClientMessage::BotAppJoin { bot_id, channel_id } => (bot_id, channel_id),
        _ => return DispatchResult::Continue,
    };

    // Look up the bot's mini_app_url.
    let mini_app_url: Option<String> =
        sqlx::query_scalar("SELECT mini_app_url FROM bots WHERE public_key = ?")
            .bind(&bot_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .flatten();

    let mini_app_url = match mini_app_url {
        Some(url) => url,
        None => return DispatchResult::Continue, // bot not found or no mini_app_url
    };

    // Mint a 4-hour scoped session token for the joining user.
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(&bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + 4 * 3600;

    let insert_ok = sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(&cs.public_key)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .is_ok();

    if !insert_ok {
        return DispatchResult::Continue;
    }

    let reply = WsServerMessage::BotAppOpen {
        bot_id,
        channel_id,
        mini_app_url,
        session_token: token,
    };
    let json = serde_json::to_string(&reply).unwrap();
    if ws_tx.send(Message::Text(json.into())).await.is_err() {
        return DispatchResult::Break;
    }

    DispatchResult::Continue
}

/// Bot → hub → channel: fan out session close, clients dismiss webviews.
pub(in crate::routes::ws) async fn handle_bot_app_dismiss(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::BotAppDismiss { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    if !cs.is_bot {
        return DispatchResult::Continue;
    }

    let server_msg = WsServerMessage::BotAppClose {
        bot_id: cs.public_key.clone(),
        channel_id: channel_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&server_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ChatEvent::BotApp { channel_id }, json));

    DispatchResult::Continue
}
