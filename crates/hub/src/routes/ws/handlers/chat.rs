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

/// Presence status (away/dnd/invisible + optional custom text). Persisted
/// on the users row so it survives reconnects; "online" clears it.
///
/// Broadcast is hub-wide like member_online/member_offline, but "invisible"
/// is never broadcast literally: to every *other* client the user must look
/// like they went offline (they stay connected — DMs/messages/voice are
/// unaffected, only what other members are told changes). The setter's own
/// client tracks its invisible state locally and does not rely on this
/// broadcast to know it's invisible.
pub(in crate::routes::ws) async fn handle_set_status(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (status, custom) = match msg {
        WsClientMessage::SetStatus { status, custom } => (status, custom),
        _ => return DispatchResult::Continue,
    };

    let status = match status.as_str() {
        "online" => None,
        "away" | "dnd" | "invisible" => Some(status),
        // Unknown status value — drop silently, same policy as other
        // malformed ephemeral WS messages.
        _ => return DispatchResult::Continue,
    };
    // Keep custom text short; whitespace-only clears it.
    let custom = custom
        .map(|c| c.trim().chars().take(100).collect::<String>())
        .filter(|c| !c.is_empty());

    // Snapshot the prior status before overwriting it: we need this to know
    // whether this transition is *leaving* invisible (in which case other
    // clients, who were told this user was offline, need to be told they're
    // back online again before the plain status update).
    let was_invisible = crate::routes::users::fetch_presence_status(&state.db, &cs.public_key)
        .await
        .as_deref()
        == Some("invisible");

    if sqlx::query(
        "UPDATE users SET presence_status = $1, presence_custom = $2 WHERE public_key = $3",
    )
    .bind(&status)
    .bind(&custom)
    .bind(&cs.public_key)
    .execute(&state.db)
    .await
    .is_err()
    {
        return DispatchResult::Continue;
    }

    let is_invisible_now = status.as_deref() == Some("invisible");

    // Voice surfaces are presence-gated like the roster (decisions.md
    // 2026-07-12). A mid-call transition into/out of invisible must remove
    // the user from (or restore them to) other members' voice participant
    // lists, which are otherwise only updated by join/leave broadcasts.
    if is_invisible_now != was_invisible {
        let voice_channel: Option<String> = {
            let vc = state.voice_channels.read().await;
            vc.iter()
                .find(|(_, members)| members.contains_key(&cs.public_key))
                .map(|(ch, _)| ch.clone())
        };
        if let Some(ch) = voice_channel {
            if is_invisible_now {
                let _ = state.voice_event_tx.send((
                    ch.clone(),
                    WsServerMessage::VoiceParticipantLeft {
                        channel_id: ch.clone(),
                        public_key: cs.public_key.clone(),
                    },
                ));
            } else {
                let row: Option<(Option<String>, bool)> =
                    sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
                        .bind(&cs.public_key)
                        .fetch_optional(&state.db)
                        .await
                        .ok()
                        .flatten();
                let (display_name, is_bot) = row.unwrap_or((None, false));
                let _ = state.voice_event_tx.send((
                    ch.clone(),
                    WsServerMessage::VoiceParticipantJoined {
                        channel_id: ch.clone(),
                        participant: crate::routes::chat_models::VoiceParticipantInfo {
                            public_key: cs.public_key.clone(),
                            display_name,
                            is_bot,
                        },
                    },
                ));
            }
            // Refresh the sender_id roster too — it is filtered by the same
            // gate (get_voice_roster), and the DB status is already updated.
            let roster = crate::routes::ws::voice::get_voice_roster(state, &ch).await;
            let _ = state.voice_event_tx.send((
                ch.clone(),
                WsServerMessage::VoiceRosterUpdate {
                    channel_id: ch,
                    participants: roster,
                },
            ));
        }
    }

    if is_invisible_now {
        // Presence broadcasts are not per-recipient, so map invisible ->
        // offline in the outgoing broadcast rather than ever sending the
        // literal "invisible" value over the wire to other clients.
        let ev = crate::routes::chat_models::ChatEvent::MemberOffline {
            public_key: cs.public_key.clone(),
        };
        let ws_msg = WsServerMessage::MemberOffline {
            public_key: cs.public_key.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
        return DispatchResult::Continue;
    }

    if was_invisible {
        // Coming back from invisible: other clients believe this user is
        // offline, so re-announce them online before the status details.
        let ev = crate::routes::chat_models::ChatEvent::MemberOnline {
            public_key: cs.public_key.clone(),
        };
        let ws_msg = WsServerMessage::MemberOnline {
            public_key: cs.public_key.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }

    let ev = crate::routes::chat_models::ChatEvent::MemberStatus {
        public_key: cs.public_key.clone(),
    };
    let ws_msg = WsServerMessage::MemberStatus {
        public_key: cs.public_key.clone(),
        status,
        custom,
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
