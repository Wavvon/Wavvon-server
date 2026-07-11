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

    // Look up the bot's mini_app_url and requires_camera flag.
    #[derive(sqlx::FromRow)]
    struct BotAppRow {
        mini_app_url: Option<String>,
        requires_camera: bool,
    }
    let bot_row: Option<BotAppRow> =
        sqlx::query_as("SELECT mini_app_url, requires_camera FROM bots WHERE public_key = $1")
            .bind(&bot_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let (mini_app_url, requires_camera) = match bot_row {
        Some(r) => match r.mini_app_url {
            Some(url) => (url, r.requires_camera),
            None => return DispatchResult::Continue,
        },
        None => return DispatchResult::Continue,
    };

    // Gate: camera is only granted when operator allows it hub-wide.
    let grant_camera = requires_camera && state.bots_allow_camera;

    // Mint a 4-hour scoped session token for the joining user.
    //
    // `scope = 'mini_app'` (not 'member' — see auth::middleware) is the fix
    // for the security finding this closes: this token used to be a plain
    // full-access session row indistinguishable from the user's own login,
    // which meant a mini-app webview holding it could call every REST route
    // the user's roles allowed, including admin and federation endpoints.
    // `mini_app_channel_id` / `mini_app_bot_id` record the binding
    // bot-mini-apps.md's "Scoped session token" section documents ("Bound to
    // one channel and one bot ID"); the WS layer uses the channel id to
    // confine auto-subscription to just this channel.
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(&bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + 4 * 3600;

    let insert_ok = sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at, scope, mini_app_channel_id, mini_app_bot_id)
         VALUES ($1, $2, $3, $4, 'mini_app', $5, $6)",
    )
    .bind(&token)
    .bind(&cs.public_key)
    .bind(now)
    .bind(expires_at)
    .bind(&channel_id)
    .bind(&bot_id)
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
        requires_camera: grant_camera,
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
