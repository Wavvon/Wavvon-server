use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::routes::chat_models::{WsClientMessage, WsServerMessage};
use crate::state::AppState;

use super::conn_state::{ConnState, DispatchResult};
use super::handlers::{bot, chat, mini_app, screen, voice};
use super::voice::get_voice_roster;

pub(super) async fn handle_socket(socket: WebSocket, state: Arc<AppState>, public_key: String) {
    // ── Connection setup ─────────────────────────────────────────────────────

    let is_bot: bool =
        sqlx::query_scalar::<_, bool>("SELECT is_bot FROM users WHERE public_key = $1")
            .bind(&public_key)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(false);

    // Increment the online-users refcount for this pubkey.
    {
        let mut online = state.online_users.write().await;
        *online.entry(public_key.clone()).or_insert(0) += 1;
    }

    let (mut ws_tx, mut ws_rx) = socket.split();

    let (bot_tx, mut bot_rx): (mpsc::Sender<String>, mpsc::Receiver<String>) = mpsc::channel(256);

    // Unique id for this specific WS session — used to discriminate
    // bot_sessions entries so a newer session does not overwrite the older
    // sender, and so the first disconnect does not evict the second session.
    let session_id = uuid::Uuid::new_v4().to_string();

    if is_bot {
        state
            .bot_sessions
            .write()
            .await
            .entry(public_key.clone())
            .or_default()
            .insert(session_id.clone(), bot_tx.clone());
    }

    let mut chat_rx = state.chat_tx.subscribe();
    let chat_rx_since = std::time::Instant::now();
    let mut dm_rx = state.dm_tx.subscribe();

    // Notify all clients (including this one, since chat_rx is now subscribed)
    // that this user is online. Only fires on the first session (refcount == 1).
    {
        let online = state.online_users.read().await;
        if online.get(&public_key).copied().unwrap_or(0) == 1 {
            let ws_msg = WsServerMessage::MemberOnline {
                public_key: public_key.clone(),
            };
            let json: std::sync::Arc<str> =
                std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
            let _ = state.chat_tx.send((
                crate::routes::chat_models::ChatEvent::MemberOnline {
                    public_key: public_key.clone(),
                },
                json,
            ));
        }
    }
    let mut voice_rx = state.voice_event_tx.subscribe();
    let mut screen_share_rx = state.screen_share_tx.subscribe();

    // Load DM conversation memberships (once at connect time).
    let my_conversations: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT conversation_id FROM conversation_members WHERE public_key = $1",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Auto-subscribe to non-banned channels.
    let subscribed: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT id FROM channels
         WHERE is_category = false
           AND id NOT IN (
               SELECT channel_id FROM channel_bans WHERE target_public_key = $1
           )",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Send `hello` with live_seq.
    {
        let live_seq = crate::bots::events::current_seq(&state).await;
        let hello = serde_json::json!({ "type": "hello", "live_seq": live_seq });
        let _ = ws_tx.send(Message::Text(hello.to_string().into())).await;
    }

    let mut cs = ConnState::new(
        public_key.clone(),
        is_bot,
        session_id.clone(),
        subscribed,
        my_conversations,
    );

    // Push in-progress screen shares to this client.
    {
        let shares = state.screen_shares.read().await;
        for ((ch_id, _sharer), active) in shares.iter() {
            if !cs.subscribed.contains(ch_id) {
                continue;
            }
            for (stream_id, meta) in &active.streams {
                if meta.started_at >= chat_rx_since {
                    continue;
                }
                let started = WsServerMessage::ScreenShareStarted {
                    channel_id: ch_id.clone(),
                    stream_id: stream_id.clone(),
                    sharer_pubkey: meta.sharer_pubkey.clone(),
                    kind: meta.kind.clone(),
                    mime: meta.mime.clone(),
                    has_audio: meta.has_audio,
                };
                let json = serde_json::to_string(&started).unwrap();
                let _ = ws_tx.send(Message::Text(json.into())).await;
                cs.notified_streams
                    .insert((ch_id.clone(), stream_id.clone()));
                if let Some(init_bytes) = &meta.init_chunk {
                    let chunk_envelope = WsServerMessage::ScreenShareChunkOut {
                        channel_id: ch_id.clone(),
                        stream_id: stream_id.clone(),
                        sharer_pubkey: meta.sharer_pubkey.clone(),
                        seq: 0,
                        is_init: true,
                    };
                    let json = serde_json::to_string(&chunk_envelope).unwrap();
                    let _ = ws_tx.send(Message::Text(json.into())).await;
                    let _ = ws_tx
                        .send(Message::Binary(init_bytes.to_vec().into()))
                        .await;
                }
            }
        }
    }

    // ── Main select! loop ────────────────────────────────────────────────────

    loop {
        tokio::select! {
            // ── Broadcast chat events ─────────────────────────────────────
            result = chat_rx.recv() => {
                match result {
                    Ok((event, pre_json)) => {
                        // Hub-wide events bypass the per-channel subscription filter.
                        if matches!(
                            event,
                            crate::routes::chat_models::ChatEvent::ChannelsUpdated
                                | crate::routes::chat_models::ChatEvent::MemberOnline { .. }
                                | crate::routes::chat_models::ChatEvent::MemberOffline { .. }
                        ) {
                            let json = pre_json.to_string();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        if cs.subscribed.contains(event.channel_id()) {
                            // Typing: filter own events.
                            if let crate::routes::chat_models::ChatEvent::Typing {
                                public_key: sender_key, ..
                            } = &event {
                                if sender_key == &cs.public_key { continue; }
                            }
                            // New message: ephemeral visibility filter.
                            if let crate::routes::chat_models::ChatEvent::New {
                                message: ref m, ..
                            } = &event {
                                if let Some(ref vtp) = m.visible_to_pubkey {
                                    if vtp != &cs.public_key { continue; }
                                }
                            }
                            // v2 signaling: targeted to to_pubkey only.
                            if let crate::routes::chat_models::ChatEvent::ScreenShareSignal {
                                to_pubkey, ..
                            } = &event {
                                if to_pubkey != &cs.public_key { continue; }
                            }
                            // StreamSubscriptionEnded: targeted.
                            if let crate::routes::chat_models::ChatEvent::StreamSubscriptionEnded {
                                to_pubkey, ..
                            } = &event {
                                if to_pubkey != &cs.public_key { continue; }
                            }
                            // Video offer/answer/ice: targeted when to_pubkey present.
                            if let crate::routes::chat_models::ChatEvent::Video { .. } = &event {
                                let val: serde_json::Value =
                                    serde_json::from_str(&pre_json).unwrap_or_default();
                                if let Some(target) =
                                    val.get("to_pubkey").and_then(|v| v.as_str())
                                {
                                    if target != cs.public_key { continue; }
                                }
                            }
                            // WhisperSignal: targeted to specific pubkeys.
                            if let crate::routes::chat_models::ChatEvent::WhisperSignal {
                                to_pubkeys, ..
                            } = &event {
                                if !to_pubkeys.contains(&cs.public_key) { continue; }
                            }

                            let json = pre_json.to_string();
                            // Track when screen_share_started reaches this client
                            // so the chunk-relay arm never races ahead of it.
                            if let crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                channel_id, stream_id, ..
                            } = &event {
                                cs.notified_streams.insert((channel_id.clone(), stream_id.clone()));
                            }
                            if cs.is_replaying {
                                cs.replay_buffer.push(json);
                            } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged, missed {n} messages");
                        let lag_msg = crate::routes::chat_models::WsServerMessage::Lagged { count: n };
                        if let Ok(json) = serde_json::to_string(&lag_msg) {
                            let _ = ws_tx.send(Message::Text(json.into())).await;
                        }
                    }
                    Err(_) => break,
                }
            }

            // ── Bot-targeted push messages ────────────────────────────────
            bot_msg = bot_rx.recv() => {
                match bot_msg {
                    Some(json) => {
                        if cs.is_replaying {
                            cs.replay_buffer.push(json);
                        } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }

            // ── Inbound client frame ──────────────────────────────────────
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Silently ignore unparseable frames (protocol contract).
                        if let Ok(client_msg) = serde_json::from_str::<WsClientMessage>(&text) {
                            let result = dispatch_client_msg(
                                &mut cs,
                                &state,
                                &mut ws_tx,
                                &bot_tx,
                                client_msg,
                            ).await;
                            if matches!(result, DispatchResult::Break) {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        let bytes = bytes::Bytes::from(data.to_vec());
                        let result = screen::handle_binary_chunk(&mut cs, &state, bytes).await;
                        if matches!(result, DispatchResult::Break) {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            // ── Voice channel events ──────────────────────────────────────
            voice_result = voice_rx.recv() => {
                if let Ok((channel_id, msg)) = voice_result {
                    let is_self = match &msg {
                        WsServerMessage::VoiceParticipantSpeaking {
                            public_key: pk, ..
                        } => pk == &cs.public_key,
                        WsServerMessage::VoiceParticipantJoined {
                            participant, ..
                        } => participant.public_key == cs.public_key,
                        WsServerMessage::VoiceParticipantLeft {
                            public_key: pk, ..
                        } => pk == &cs.public_key,
                        _ => false,
                    };
                    // Joined/Left go to every client so sidebar rosters stay
                    // up-to-date even for clients not in any voice channel.
                    // Speaking events stay scoped to same-channel clients only.
                    let is_roster_event = matches!(
                        &msg,
                        WsServerMessage::VoiceParticipantJoined { .. }
                            | WsServerMessage::VoiceParticipantLeft { .. }
                    );
                    let in_same_channel =
                        cs.voice_channel.as_deref() == Some(channel_id.as_str());
                    if (in_same_channel || is_roster_event) && !is_self {
                        let json = serde_json::to_string(&msg).unwrap();
                        if ws_tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }

            // ── DM events ────────────────────────────────────────────────
            dm_result = dm_rx.recv() => {
                if let Ok(dm) = dm_result {
                    if (dm.suppress_echo() && dm.sender() == cs.public_key)
                        || !cs.my_conversations.contains(dm.conversation_id())
                    {
                        continue;
                    }
                    let reply = match dm {
                        crate::state::DmEvent::Message {
                            conversation_id, sender, sender_name, content, timestamp,
                        } => WsServerMessage::DirectMessage {
                            conversation_id, sender, sender_name, content, timestamp,
                        },
                        crate::state::DmEvent::Typing {
                            conversation_id, sender, sender_name, typing,
                        } => WsServerMessage::DmTyping {
                            conversation_id, sender, sender_name, typing,
                        },
                        crate::state::DmEvent::MemberChanged {
                            conversation_id, added, removed, ..
                        } => WsServerMessage::DmMemberChanged {
                            conversation_id, added, removed,
                        },
                    };
                    let json = serde_json::to_string(&reply).unwrap();
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            // ── Screen-share chunk relay ──────────────────────────────────
            chunk_result = screen_share_rx.recv() => {
                match chunk_result {
                    Ok(ev) => {
                        let in_channel =
                            ev.sharer_pubkey != cs.public_key
                            && cs.subscribed.contains(&ev.channel_id);
                        let (is_cross_subscriber, stream_meta) = {
                            let shares = state.screen_shares.read().await;
                            let active = shares.get(&(ev.channel_id.clone(), ev.sharer_pubkey.clone()));
                            let cross = active
                                .map(|a| a.cross_channel_subscribers.contains(&cs.public_key))
                                .unwrap_or(false);
                            let meta = active
                                .and_then(|a| a.streams.get(&ev.stream_id))
                                .map(|m| (m.sharer_pubkey.clone(), m.kind.clone(), m.mime.clone(), m.has_audio));
                            (cross, meta)
                        };
                        if in_channel || is_cross_subscriber {
                            // Guarantee screen_share_started arrives before the
                            // first chunk for this stream, regardless of the order
                            // the hub processes the sharer's messages.
                            let stream_key = (ev.channel_id.clone(), ev.stream_id.clone());
                            if !cs.notified_streams.contains(&stream_key) {
                                if let Some((sharer_pubkey, kind, mime, has_audio)) = stream_meta {
                                    let started = WsServerMessage::ScreenShareStarted {
                                        channel_id: ev.channel_id.clone(),
                                        stream_id: ev.stream_id.clone(),
                                        sharer_pubkey,
                                        kind,
                                        mime,
                                        has_audio,
                                    };
                                    let json = serde_json::to_string(&started).unwrap();
                                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                        break;
                                    }
                                    cs.notified_streams.insert(stream_key);
                                }
                            }
                            let envelope = WsServerMessage::ScreenShareChunkOut {
                                channel_id: ev.channel_id,
                                stream_id: ev.stream_id,
                                sharer_pubkey: ev.sharer_pubkey,
                                seq: ev.seq,
                                is_init: ev.is_init,
                            };
                            let json = serde_json::to_string(&envelope).unwrap();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                            if ws_tx
                                .send(Message::Binary(ev.data.to_vec().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Screen-share client lagged, missed {n} chunks");
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // ── Disconnect cleanup ───────────────────────────────────────────────────

    if let Some(ch_id) = cs.voice_channel {
        leave_voice(&state, &public_key, &ch_id).await;
    }

    {
        let mut shares = state.screen_shares.write().await;

        // Collect (ch_id, stream_id, subscribers) for streams that belong
        // to THIS session — these are the ones we end. Streams started by
        // other concurrent sessions of the same pubkey are left intact.
        let ended_streams: Vec<(String, String, Vec<String>)> = shares
            .iter()
            .filter(|((_, sharer), _)| sharer.as_str() == public_key.as_str())
            .flat_map(|((ch_id, _), active)| {
                active
                    .streams
                    .iter()
                    .filter(|(_, meta)| meta.session_id == session_id)
                    .map(move |(sid, active_meta)| {
                        (
                            ch_id.clone(),
                            sid.clone(),
                            active_meta
                                .init_chunk
                                .as_ref()
                                .map(|_| {
                                    // We just need the subscribers list from
                                    // the ActiveShare — borrow it separately.
                                    vec![]
                                })
                                .unwrap_or_default(),
                        )
                    })
            })
            .collect();

        // Collect cross_channel_subscribers for this session's streams
        // (can't borrow inside the closure above due to the outer iter borrow).
        let ended_with_subs: Vec<(String, String, Vec<String>)> = shares
            .iter()
            .filter(|((_, sharer), _)| sharer.as_str() == public_key.as_str())
            .flat_map(|((ch_id, _), active)| {
                active
                    .streams
                    .iter()
                    .filter(|(_, meta)| meta.session_id == session_id)
                    .map(move |(sid, _)| {
                        (
                            ch_id.clone(),
                            sid.clone(),
                            active
                                .cross_channel_subscribers
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>(),
                        )
                    })
            })
            .collect();
        let _ = ended_streams; // superseded by ended_with_subs

        // Remove only this session's streams from each ActiveShare entry.
        // Drop the entire ActiveShare entry if streams becomes empty.
        shares.retain(|(_, sharer), active| {
            if sharer == &public_key {
                active
                    .streams
                    .retain(|_, meta| meta.session_id != session_id);
                !active.streams.is_empty()
            } else {
                true
            }
        });

        // Remove the disconnecting user as a viewer/subscriber from all
        // remaining shares (they may have been watching someone else's share).
        for active in shares.values_mut() {
            active.viewers.remove(&public_key);
            active.cross_channel_subscribers.remove(&public_key);
        }

        for (ch_id, stream_id, subscribers) in ended_with_subs {
            for subscriber_pubkey in subscribers {
                let ev = crate::routes::chat_models::ChatEvent::StreamSubscriptionEnded {
                    to_pubkey: subscriber_pubkey.clone(),
                    source_channel_id: ch_id.clone(),
                    stream_id: stream_id.clone(),
                };
                let ws_msg = WsServerMessage::StreamSubscriptionEnded {
                    source_channel_id: ch_id.clone(),
                    stream_id: stream_id.clone(),
                };
                let json: std::sync::Arc<str> =
                    std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
                let _ = state.chat_tx.send((ev, json));
            }
        }
    }

    if is_bot {
        let mut sessions = state.bot_sessions.write().await;
        if let Some(per_bot) = sessions.get_mut(&public_key) {
            per_bot.remove(&session_id);
            if per_bot.is_empty() {
                sessions.remove(&public_key);
            }
        }
    }

    // Decrement the online-users refcount; remove the key only when it
    // reaches zero so that other concurrent sessions for the same pubkey
    // are not erroneously marked offline.
    let went_offline = {
        let mut online = state.online_users.write().await;
        if let Some(count) = online.get_mut(&public_key) {
            if *count <= 1 {
                online.remove(&public_key);
                true
            } else {
                *count -= 1;
                false
            }
        } else {
            false
        }
    };

    if went_offline {
        let ws_msg = WsServerMessage::MemberOffline {
            public_key: public_key.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            crate::routes::chat_models::ChatEvent::MemberOffline {
                public_key: public_key.clone(),
            },
            json,
        ));
    }

    tracing::info!(
        "WebSocket disconnected: {}",
        &public_key[..16.min(public_key.len())]
    );
}

// ── Per-message dispatch ─────────────────────────────────────────────────────

async fn dispatch_client_msg(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    bot_tx: &mpsc::Sender<String>,
    msg: WsClientMessage,
) -> DispatchResult {
    match msg {
        // ── Subscriptions ──────────────────────────────────────────────────
        WsClientMessage::Subscribe { .. } => screen::handle_subscribe(cs, state, ws_tx, msg).await,
        WsClientMessage::Unsubscribe { .. } => screen::handle_unsubscribe(cs, msg),

        // ── Chat ───────────────────────────────────────────────────────────
        WsClientMessage::Typing { .. } => chat::handle_typing(cs, state, msg).await,
        WsClientMessage::DmTyping { .. } => chat::handle_dm_typing(cs, state, msg).await,
        WsClientMessage::ComponentInteraction { .. } => {
            chat::handle_component_interaction(cs, state, ws_tx, msg).await
        }

        // ── Voice core ─────────────────────────────────────────────────────
        WsClientMessage::VoiceJoin { .. } => voice::handle_voice_join(cs, state, ws_tx, msg).await,
        WsClientMessage::VoiceWatch { channel_id } => {
            cs.voice_channel = Some(channel_id);
            DispatchResult::Continue
        }
        WsClientMessage::VoiceUnwatch => {
            cs.voice_channel = None;
            DispatchResult::Continue
        }
        WsClientMessage::VoiceLeave { .. } => voice::handle_voice_leave(cs, state, msg).await,
        WsClientMessage::VoiceSpeaking { .. } => voice::handle_voice_speaking(cs, state, msg),
        WsClientMessage::VoiceWhisperStart { .. } => {
            voice::handle_voice_whisper_start(cs, state, msg).await
        }
        WsClientMessage::VoiceWhisperStop => voice::handle_voice_whisper_stop(cs, state).await,

        // ── Proximity voice ────────────────────────────────────────────────
        WsClientMessage::VoiceZoneCreate { .. } => {
            voice::handle_voice_zone_create(cs, state, ws_tx, msg).await
        }
        WsClientMessage::VoiceZoneDestroy { .. } => {
            voice::handle_voice_zone_destroy(cs, state, msg).await
        }
        WsClientMessage::VoicePositionUpdate { .. } => {
            voice::handle_voice_position_update(cs, state, msg).await
        }

        // ── Video signaling ────────────────────────────────────────────────
        WsClientMessage::VideoEnable { .. } => {
            voice::handle_video_enable(cs, state, ws_tx, msg).await
        }
        WsClientMessage::VideoDisable { .. } => voice::handle_video_disable(cs, state, msg).await,
        WsClientMessage::VideoOffer { .. } => voice::handle_video_offer(cs, state, msg),
        WsClientMessage::VideoAnswer { .. } => voice::handle_video_answer(cs, state, msg),
        WsClientMessage::VideoIce { .. } => voice::handle_video_ice(cs, state, msg),

        // ── Screen share ───────────────────────────────────────────────────
        WsClientMessage::ScreenShareStart { .. } => {
            screen::handle_screen_share_start(cs, state, msg).await
        }
        WsClientMessage::ScreenShareChunk { .. } => {
            screen::handle_screen_share_chunk_header(cs, msg)
        }
        WsClientMessage::ScreenShareStop { .. } => {
            screen::handle_screen_share_stop(cs, state, msg).await
        }
        WsClientMessage::ScreenShareViewerJoin { .. } => {
            screen::handle_screen_share_viewer_join(cs, state, ws_tx, msg).await
        }
        WsClientMessage::ScreenShareViewerLeave { .. } => {
            screen::handle_screen_share_viewer_leave(cs, state, msg).await
        }
        WsClientMessage::ScreenShareOffer { .. } => {
            screen::handle_screen_share_offer(cs, state, msg).await
        }
        WsClientMessage::ScreenShareAnswer { .. } => {
            screen::handle_screen_share_answer(cs, state, msg).await
        }
        WsClientMessage::ScreenShareIce { .. } => {
            screen::handle_screen_share_ice(cs, state, msg).await
        }
        WsClientMessage::StreamList => screen::handle_stream_list(cs, state, ws_tx).await,
        WsClientMessage::StreamSubscribe { .. } => {
            screen::handle_stream_subscribe(cs, state, ws_tx, msg).await
        }
        WsClientMessage::StreamUnsubscribe { .. } => {
            screen::handle_stream_unsubscribe(cs, state, msg).await
        }

        // ── Bot mini-apps ──────────────────────────────────────────────────
        WsClientMessage::BotAppAnnounce { .. } => {
            mini_app::handle_bot_app_announce(cs, state, msg).await
        }
        WsClientMessage::BotAppJoin { .. } => {
            mini_app::handle_bot_app_join(cs, state, ws_tx, msg).await
        }
        WsClientMessage::BotAppDismiss { .. } => {
            mini_app::handle_bot_app_dismiss(cs, state, msg).await
        }

        // ── Bots ───────────────────────────────────────────────────────────
        WsClientMessage::Resume { .. } => bot::handle_resume(cs, state, ws_tx, bot_tx, msg).await,
    }
}

// ── Voice helpers (also used by tests) ──────────────────────────────────────

/// Public helper that exposes the leave-voice cleanup path for integration tests.
///
/// Calls `leave_voice` directly so tests can simulate WS disconnect or
/// explicit leave without needing a live WS connection.  Not part of the
/// public HTTP/WS API — only referenced from `tests/voice_relay_flow.rs`.
#[doc(hidden)]
pub async fn leave_voice_for_test(state: &AppState, public_key: &str, channel_id: &str) {
    leave_voice(state, public_key, channel_id).await;
}

pub async fn leave_voice(state: &AppState, public_key: &str, channel_id: &str) {
    let removed_addr = {
        let mut channels = state.voice_channels.write().await;
        let addr = channels
            .get_mut(channel_id)
            .and_then(|participants| participants.remove(public_key));
        if let Some(participants) = channels.get(channel_id) {
            if participants.is_empty() {
                channels.remove(channel_id);
            }
        }
        addr
    };
    // Remove from voice_addr_map if this was a real bound address (not the sentinel 0.0.0.0:0).
    if let Some(addr) = removed_addr {
        let sentinel: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        if addr != sentinel {
            state.voice_addr_map.write().await.remove(&addr);
        }
    }

    // Remove any un-consumed pending bind for this pubkey.
    {
        let mut binds = state.voice_pending_binds.write().await;
        binds.retain(|_, v| v.pubkey != public_key);
    }
    // Remove any consumed-token record whose bound address maps to this pubkey.
    {
        let mut consumed = state.voice_consumed_tokens.write().await;
        consumed.retain(|_, v| v.pubkey != public_key);
    }

    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceParticipantLeft {
            channel_id: channel_id.to_string(),
            public_key: public_key.to_string(),
        },
    ));

    // Remove sender_id mapping.
    {
        let mut sids = state.voice_sender_ids.write().await;
        if let Some(ch_map) = sids.get_mut(channel_id) {
            ch_map.remove(public_key);
            if ch_map.is_empty() {
                sids.remove(channel_id);
            }
        }
    }
    // Clean up counter if channel is now empty.
    {
        let channels = state.voice_channels.read().await;
        if !channels.contains_key(channel_id) {
            state.voice_next_sender_id.write().await.remove(channel_id);
        }
    }
    // Remove this user's position from all voice zones in this channel.
    {
        let mut zones = state.voice_zones.write().await;
        for ((ch, _), zone) in zones.iter_mut() {
            if ch == channel_id {
                zone.positions.remove(public_key);
            }
        }
    }
    // Remove from video_channels if present and broadcast disable to channel.
    {
        let should_broadcast = {
            let mut vc = state.video_channels.write().await;
            if let Some(ch_set) = vc.get_mut(channel_id) {
                if ch_set.remove(public_key) {
                    if ch_set.is_empty() {
                        vc.remove(channel_id);
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if should_broadcast {
            let _ = state.chat_tx.send((
                crate::routes::chat_models::ChatEvent::Video {
                    channel_id: channel_id.to_string(),
                },
                std::sync::Arc::from(
                    serde_json::to_string(&WsServerMessage::VideoParticipantDisabled {
                        channel_id: channel_id.to_string(),
                        pubkey: public_key.to_string(),
                    })
                    .unwrap()
                    .as_str(),
                ),
            ));
        }
    }

    // Clean up the departing user's whisper session.
    state.whisper_targets.write().await.remove(public_key);
    state.whisper_target_defs.write().await.remove(public_key);

    // Revoke the UDP relay slot.
    state.voice_relay_active.write().await.remove(public_key);

    // Broadcast updated roster.
    let roster = get_voice_roster(state, channel_id).await;
    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceRosterUpdate {
            channel_id: channel_id.to_string(),
            participants: roster,
        },
    ));
}
