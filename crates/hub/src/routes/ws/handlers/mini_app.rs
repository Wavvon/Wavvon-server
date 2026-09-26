use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;
use rand::RngCore;

use crate::routes::chat_models::{ChatEvent, WsClientMessage, WsServerMessage};
use crate::routes::ws::conn_state::{ConnState, DispatchResult};
use crate::state::AppState;

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

/// Bot → hub → channel: fan out a mini-app launch card.
pub(in crate::routes::ws) async fn handle_app_announce(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (title, description, channel_id) = match msg {
        WsClientMessage::AppAnnounce {
            title,
            description,
            channel_id,
        } => (title, description, channel_id),
        _ => return DispatchResult::Continue,
    };

    // Only the identity hosting the app may announce it.
    if !cs.is_app {
        return DispatchResult::Continue;
    }

    let server_msg = WsServerMessage::AppLaunch {
        app_id: cs.public_key.clone(),
        title,
        description,
        channel_id: channel_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&server_msg).unwrap().as_str());
    let _ = state
        .chat_tx
        .send((ChatEvent::AppModal { channel_id }, json));

    DispatchResult::Continue
}

/// Client → hub: join a mini-app session. Mint scoped token, send BotAppOpen.
pub(in crate::routes::ws) async fn handle_app_join(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (app_id, channel_id) = match msg {
        WsClientMessage::BotAppJoin { app_id, channel_id } => (app_id, channel_id),
        _ => return DispatchResult::Continue,
    };

    // Look up the bot's mini_app_url and requires_camera flag. Two bot
    // systems can register a mini-app (bots/capabilities.rs doc comment):
    // external bots self-declare it in `app_profiles` (mini-apps.md,
    // apps.md-- added alongside `webhook_url`/`capabilities`, since an
    // external bot is the only kind with slash commands and a live WS
    // session to actually own game state); self-service bots set it at
    // `POST /admin/bots` time in the `bots` table. Try external first.
    #[derive(sqlx::FromRow)]
    struct BotAppRow {
        mini_app_url: Option<String>,
        requires_camera: bool,
    }
    let app_row: Option<BotAppRow> =
        sqlx::query_as("SELECT mini_app_url, requires_camera FROM app_profiles WHERE pubkey = $1")
            .bind(&app_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    // `app_profiles` is the only source now — the second lookup that used to
    // fall back to the self-service `bots` table went with that system
    // (decisions.md, "Every bot is an external bot").
    let (mini_app_url, requires_camera) = match app_row {
        Some(r) => match r.mini_app_url {
            Some(url) => (url, r.requires_camera),
            None => return DispatchResult::Continue,
        },
        None => return DispatchResult::Continue,
    };

    // Gate: the identity hosting the modal must still hold `apps.register`.
    // Resolved per join rather than trusted from the profile row, so losing
    // the role stops new sessions immediately instead of when the row is
    // next rewritten.
    match crate::permissions::user_permissions(&state.db, &app_id).await {
        Ok(perms) if perms.has(crate::permissions::APPS_REGISTER) => {}
        _ => return DispatchResult::Continue,
    }

    // Gate: camera is only granted when operator allows it hub-wide.
    let grant_camera = requires_camera && state.apps_allow_camera;

    // Mint a 4-hour scoped session token for the joining user.
    //
    // `scope = 'mini_app'` (not 'member' — see auth::middleware) is the fix
    // for the security finding this closes: this token used to be a plain
    // full-access session row indistinguishable from the user's own login,
    // which meant a mini-app webview holding it could call every REST route
    // the user's roles allowed, including admin and federation endpoints.
    // `mini_app_channel_id` / `mini_app_host` record the binding
    // mini-apps.md's "Scoped session token" section documents ("Bound to
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
        "INSERT INTO sessions (token, public_key, created_at, expires_at, scope, mini_app_channel_id, mini_app_host)
         VALUES ($1, $2, $3, $4, 'mini_app', $5, $6)",
    )
    .bind(&token)
    .bind(&cs.public_key)
    .bind(now)
    .bind(expires_at)
    .bind(&channel_id)
    .bind(&app_id)
    .execute(&state.db)
    .await
    .is_ok();

    if !insert_ok {
        return DispatchResult::Continue;
    }

    let reply = WsServerMessage::BotAppOpen {
        app_id,
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
pub(in crate::routes::ws) async fn handle_app_dismiss(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::AppDismiss { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    if !cs.is_app {
        return DispatchResult::Continue;
    }

    let server_msg = WsServerMessage::AppClose {
        app_id: cs.public_key.clone(),
        channel_id: channel_id.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&server_msg).unwrap().as_str());
    let _ = state
        .chat_tx
        .send((ChatEvent::AppModal { channel_id }, json));

    DispatchResult::Continue
}

/// Generic mini-app <-> bot relay (mini-apps.md "exchanges messages ...
/// through the normal WS relay"). No wire type shipped this before this
/// pairing — a mini-app session is confined to `/ws` (`auth::middleware`
/// `MINI_APP_ALLOWED_PATHS` is deliberately empty), so without this the
/// modal webview had no way to reach the bot that owns its game state.
///
/// - Player (mini-app, non-bot) -> bot: forward to every active WS session
///   for `app_id`, tagged with the sender's pubkey.
/// - Bot -> player: `to_pubkey` selects the target; delivered via the
///   per-pubkey targeted sender (`ws_key_senders`, the same mechanism V4
///   voice key distribution uses). Last-registered session for that pubkey
///   wins if the user has more than one connection open — acceptable for a
///   single modal per player.
pub(in crate::routes::ws) async fn handle_mini_app_message(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (app_id, channel_id, payload, to_pubkey) = match msg {
        WsClientMessage::MiniAppMessage {
            app_id,
            channel_id,
            payload,
            to_pubkey,
        } => (app_id, channel_id, payload, to_pubkey),
        _ => return DispatchResult::Continue,
    };

    if cs.is_app {
        let Some(target) = to_pubkey else {
            return DispatchResult::Continue;
        };
        let server_msg = WsServerMessage::MiniAppMessage {
            app_id: cs.public_key.clone(),
            channel_id,
            payload,
            from_pubkey: None,
        };
        // Every session the addressee has open, for the same reason voice
        // keys go to all of them: the hub cannot tell which socket is
        // playing the mini-app.
        state.send_to_user(&target, server_msg).await;
    } else {
        let server_msg = WsServerMessage::MiniAppMessage {
            app_id: app_id.clone(),
            channel_id,
            payload,
            from_pubkey: Some(cs.public_key.clone()),
        };
        let json = serde_json::to_string(&server_msg).unwrap();
        let sessions = state.app_sessions.read().await;
        if let Some(per_app) = sessions.get(&app_id) {
            for tx in per_app.values() {
                let _ = tx.try_send(json.clone());
            }
        }
    }

    DispatchResult::Continue
}
