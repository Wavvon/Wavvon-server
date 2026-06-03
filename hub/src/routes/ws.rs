use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::routes::chat_models::{
    HubStreamInfo, VoiceParticipantInfo, WsClientMessage, WsParams, WsServerMessage,
};
use crate::state::{ActiveShare, AppState, ScreenChunkEvent};

// `bytes` is used for game snapshot storage in the game_snapshot handler.

// ---------------------------------------------------------------------------
// Component interaction rate-limit store (in-memory, no external dep).
// Key: (user_pubkey, custom_id); Value: last interaction instant.
// ---------------------------------------------------------------------------
tokio::task_local! {
    // Not used across tasks; the HashMap is held per WS connection below.
}

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM sessions WHERE token = ?")
            .bind(&params.token)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let public_key = public_key
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;

    let is_revoked: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM subkey_revocations WHERE subkey_pubkey = ?",
    )
    .bind(&public_key)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if is_revoked {
        return Err((StatusCode::UNAUTHORIZED, "Key has been revoked".to_string()));
    }

    tracing::info!("WebSocket connected: {}", &public_key[..16.min(public_key.len())]);

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, public_key)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, public_key: String) {
    // Determine whether this connection belongs to a bot.
    let is_bot: bool = sqlx::query_scalar::<_, i64>(
        "SELECT is_bot FROM users WHERE public_key = ?",
    )
    .bind(&public_key)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0)
        != 0;

    state.online_users.write().await.insert(public_key.clone());

    let (mut ws_tx, mut ws_rx) = socket.split();

    // For bots we use an mpsc channel so that the events module can push
    // hub_event frames without going through the broadcast flood.
    // For regular users we keep the existing broadcast approach.
    let (bot_tx, mut bot_rx): (mpsc::Sender<String>, mpsc::Receiver<String>) =
        mpsc::channel(256);

    if is_bot {
        state.bot_sessions.write().await.insert(public_key.clone(), bot_tx.clone());
    }

    let mut chat_rx = state.chat_tx.subscribe();
    let chat_rx_since = std::time::Instant::now();
    let mut dm_rx = state.dm_tx.subscribe();
    let mut voice_rx = state.voice_event_tx.subscribe();
    let mut screen_share_rx = state.screen_share_tx.subscribe();
    let mut voice_channel: Option<String> = None;
    let mut pending_chunk: Option<(String, String, u32, bool)> = None;

    // Per-connection component interaction rate-limit map.
    // Key: (user_pubkey, custom_id). Value: last interaction instant.
    let mut component_rate_limit: HashMap<(String, String), Instant> = HashMap::new();

    // Load DM conversation memberships.
    let my_conversations: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT conversation_id FROM conversation_members WHERE public_key = ?",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Auto-subscribe to non-banned channels.
    let mut subscribed: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT id FROM channels
         WHERE is_category = 0
           AND id NOT IN (
               SELECT channel_id FROM channel_bans WHERE target_public_key = ?
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
        let hello = serde_json::json!({
            "type": "hello",
            "live_seq": live_seq,
        });
        let _ = ws_tx.send(Message::Text(hello.to_string().into())).await;
    }

    // Push in-progress screen shares to this client.
    {
        let shares = state.screen_shares.read().await;
        for ((ch_id, _sharer), active) in shares.iter() {
            if !subscribed.contains(ch_id) {
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
                    let _ = ws_tx.send(Message::Binary(init_bytes.to_vec().into())).await;
                }
            }
        }
    }

    // Replay buffer: accumulates live events during a bot replay pass.
    let mut replay_buffer: Vec<String> = Vec::new();
    #[allow(unused_assignments)]
    let mut is_replaying = false;

    loop {
        tokio::select! {
            result = chat_rx.recv() => {
                match result {
                    Ok((event, pre_json)) => {
                        if subscribed.contains(event.channel_id()) {
                            if let crate::routes::chat_models::ChatEvent::Typing {
                                public_key: sender_key, ..
                            } = &event
                            {
                                if sender_key == &public_key {
                                    continue;
                                }
                            }
                            if let crate::routes::chat_models::ChatEvent::New { message: ref m, .. } = &event {
                                if let Some(ref vtp) = m.visible_to_pubkey {
                                    if vtp != &public_key {
                                        continue;
                                    }
                                }
                            }
                            // v2 signaling envelopes are targeted: only deliver to to_pubkey.
                            if let crate::routes::chat_models::ChatEvent::ScreenShareSignal {
                                to_pubkey, ..
                            } = &event
                            {
                                if to_pubkey != &public_key {
                                    continue;
                                }
                            }
                            // StreamSubscriptionEnded is targeted to a specific subscriber.
                            if let crate::routes::chat_models::ChatEvent::StreamSubscriptionEnded {
                                to_pubkey, ..
                            } = &event
                            {
                                if to_pubkey != &public_key {
                                    continue;
                                }
                            }
                            let json = pre_json.to_string();
                            if is_replaying {
                                replay_buffer.push(json);
                            } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged, missed {n} messages");
                    }
                    Err(_) => break,
                }
            }

            // Bot-targeted push messages (hub_event, token_expiring_soon, etc.)
            bot_msg = bot_rx.recv() => {
                match bot_msg {
                    Some(json) => {
                        if is_replaying {
                            replay_buffer.push(json);
                        } else if ws_tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }

            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsClientMessage>(&text) {
                            Ok(WsClientMessage::Subscribe { channel_id }) => {
                                let newly_subscribed = subscribed.insert(channel_id.clone());
                                if !newly_subscribed { continue; }
                                let shares = state.screen_shares.read().await;
                                for ((ch_id, _sharer), active) in shares.iter() {
                                    if ch_id != &channel_id {
                                        continue;
                                    }
                                    for (stream_id, meta) in &active.streams {
                                        let started = WsServerMessage::ScreenShareStarted {
                                            channel_id: channel_id.clone(),
                                            stream_id: stream_id.clone(),
                                            sharer_pubkey: meta.sharer_pubkey.clone(),
                                            kind: meta.kind.clone(),
                                            mime: meta.mime.clone(),
                                            has_audio: meta.has_audio,
                                        };
                                        let json = serde_json::to_string(&started).unwrap();
                                        if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                            break;
                                        }
                                        if let Some(init_bytes) = &meta.init_chunk {
                                            let chunk_envelope = WsServerMessage::ScreenShareChunkOut {
                                                channel_id: channel_id.clone(),
                                                stream_id: stream_id.clone(),
                                                sharer_pubkey: meta.sharer_pubkey.clone(),
                                                seq: 0,
                                                is_init: true,
                                            };
                                            let json = serde_json::to_string(&chunk_envelope).unwrap();
                                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                                break;
                                            }
                                            if ws_tx
                                                .send(Message::Binary(init_bytes.to_vec().into()))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(WsClientMessage::Unsubscribe { channel_id }) => {
                                subscribed.remove(&channel_id);
                            }
                            Ok(WsClientMessage::VoiceJoin { channel_id, udp_port }) => {
                                // Hub-wide voice mute check (existing behaviour).
                                let is_hub_muted = crate::routes::moderation::is_voice_muted(
                                    &state.db, &public_key,
                                )
                                .await
                                .unwrap_or(false);
                                if is_hub_muted {
                                    let err = WsServerMessage::Error {
                                        context: "voice_join".to_string(),
                                        message: "You are voice-muted on this hub.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }

                                // Per-channel voice mute check.
                                let is_ch_muted = crate::routes::moderation::is_channel_voice_muted(
                                    &state.db, &channel_id, &public_key,
                                )
                                .await
                                .unwrap_or(false);
                                if is_ch_muted {
                                    let err = WsServerMessage::Error {
                                        context: "voice_join".to_string(),
                                        message: "You are voice-muted in this channel.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }

                                // Talk-power check: read min_talk_power from channels row (new
                                // column) and fall back to channel_settings for older rows.
                                let min_talk_power: i64 = sqlx::query_scalar(
                                    "SELECT COALESCE(min_talk_power, 0) FROM channels WHERE id = ?",
                                )
                                .bind(&channel_id)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| {
                                    // fall back to legacy channel_settings table
                                    0i64
                                });
                                // Also check legacy channel_settings table if channels row gives 0.
                                let min_talk_power = if min_talk_power == 0 {
                                    sqlx::query_scalar::<_, i64>(
                                        "SELECT min_talk_power FROM channel_settings WHERE channel_id = ?",
                                    )
                                    .bind(&channel_id)
                                    .fetch_optional(&state.db)
                                    .await
                                    .ok()
                                    .flatten()
                                    .unwrap_or(0)
                                } else {
                                    min_talk_power
                                };

                                if min_talk_power > 0 {
                                    // Get the user's maximum talk_power from their assigned roles.
                                    let user_talk_power: i64 = sqlx::query_scalar(
                                        "SELECT COALESCE(MAX(r.talk_power), 0)
                                         FROM roles r
                                         INNER JOIN user_roles ur ON r.id = ur.role_id
                                         WHERE ur.user_public_key = ?",
                                    )
                                    .bind(&public_key)
                                    .fetch_optional(&state.db)
                                    .await
                                    .ok()
                                    .flatten()
                                    .unwrap_or(0);

                                    // Also use max_priority as a legacy fallback (owner has 999999).
                                    let user_priority = crate::permissions::user_permissions(
                                        &state.db, &public_key,
                                    )
                                    .await
                                    .as_ref()
                                    .map(|p| p.max_priority)
                                    .unwrap_or(0);

                                    let effective_power = user_talk_power.max(user_priority);

                                    // User passes if their effective power meets the threshold
                                    // OR if they have an active raise-hand request.
                                    let hand_raised = crate::routes::moderation::has_raised_hand(
                                        &state.db, &channel_id, &public_key,
                                    ).await;

                                    if effective_power < min_talk_power && !hand_raised {
                                        let err = WsServerMessage::Error {
                                            context: "voice_join".to_string(),
                                            message: format!(
                                                "This channel requires talk priority {}; you have {}. Raise your hand to request access.",
                                                min_talk_power, effective_power
                                            ),
                                        };
                                        let _ = ws_tx
                                            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                            .await;
                                        continue;
                                    }
                                }

                                let client_addr: SocketAddr =
                                    format!("127.0.0.1:{udp_port}").parse().unwrap();

                                state.voice_channels.write().await
                                    .entry(channel_id.clone())
                                    .or_default()
                                    .insert(public_key.clone(), client_addr);
                                state.voice_addr_map.write().await
                                    .insert(client_addr, (channel_id.clone(), public_key.clone()));

                                voice_channel = Some(channel_id.clone());

                                let participants = get_voice_participants(&state, &channel_id).await;

                                let msg = WsServerMessage::VoiceJoined {
                                    channel_id: channel_id.clone(),
                                    hub_udp_port: state.voice_udp_port,
                                    participants: participants.clone(),
                                };
                                let json = serde_json::to_string(&msg).unwrap();
                                let _ = ws_tx.send(Message::Text(json.into())).await;

                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();

                                let _ = state.voice_event_tx.send((
                                    channel_id.clone(),
                                    WsServerMessage::VoiceParticipantJoined {
                                        channel_id: voice_channel.clone().unwrap(),
                                        participant: VoiceParticipantInfo {
                                            public_key: public_key.clone(),
                                            display_name: display_name.clone(),
                                        },
                                    },
                                ));

                                // Publish member.joined audit event.
                                {
                                    let state_c = state.clone();
                                    let pk = public_key.clone();
                                    let ch = channel_id.clone();
                                    let dn = display_name;
                                    tokio::spawn(async move {
                                        crate::bots::events::publish_hub_event(
                                            &state_c,
                                            "member.joined",
                                            Some(&pk),
                                            None,
                                            Some(&ch),
                                            serde_json::json!({ "display_name": dn }),
                                        ).await;
                                    });
                                }

                                tracing::info!("Voice join: {} in channel", &public_key[..16.min(public_key.len())]);
                            }
                            Ok(WsClientMessage::VoiceLeave { channel_id }) => {
                                leave_voice(&state, &public_key, &channel_id).await;
                                voice_channel = None;
                                // Publish member.left audit event.
                                {
                                    let state_c = state.clone();
                                    let pk = public_key.clone();
                                    let ch = channel_id.clone();
                                    tokio::spawn(async move {
                                        crate::bots::events::publish_hub_event(
                                            &state_c,
                                            "member.left",
                                            Some(&pk),
                                            None,
                                            Some(&ch),
                                            serde_json::json!({}),
                                        ).await;
                                    });
                                }
                                tracing::info!("Voice leave: {}", &public_key[..16.min(public_key.len())]);
                            }
                            Ok(WsClientMessage::VoiceSpeaking { channel_id, speaking }) => {
                                let _ = state.voice_event_tx.send((
                                    channel_id.clone(),
                                    WsServerMessage::VoiceParticipantSpeaking {
                                        channel_id,
                                        public_key: public_key.clone(),
                                        speaking,
                                    },
                                ));
                            }
                            Ok(WsClientMessage::Typing { channel_id, typing }) => {
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();
                                let ev = crate::routes::chat_models::ChatEvent::Typing {
                                    channel_id: channel_id.clone(),
                                    public_key: public_key.clone(),
                                    display_name: display_name.clone(),
                                    typing,
                                };
                                let ws_msg = WsServerMessage::Typing {
                                    channel_id,
                                    public_key: public_key.clone(),
                                    display_name,
                                    typing,
                                };
                                let json: std::sync::Arc<str> = std::sync::Arc::from(
                                    serde_json::to_string(&ws_msg).unwrap().as_str(),
                                );
                                let _ = state.chat_tx.send((ev, json));
                            }
                            Ok(WsClientMessage::DmTyping { conversation_id, typing }) => {
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();
                                let _ = state.dm_tx.send(crate::state::DmEvent::Typing {
                                    conversation_id,
                                    sender: public_key.clone(),
                                    sender_name: display_name,
                                    typing,
                                });
                            }

                            Ok(WsClientMessage::ScreenShareStart { channel_id, stream_id, kind, mime, has_audio, .. }) => {
                                // Multiple concurrent sharers per channel are allowed (multi-stream overlay).
                                // No per-channel cap is enforced here; permission checks (can_screen_share)
                                // gate who can start — that's the right control plane.
                                {
                                    let mut shares = state.screen_shares.write().await;
                                    let active = shares
                                        .entry((channel_id.clone(), public_key.clone()))
                                        .or_insert_with(|| ActiveShare {
                                            streams: std::collections::HashMap::new(),
                                            viewers: std::collections::HashSet::new(),
                                            cross_channel_subscribers: std::collections::HashSet::new(),
                                        });
                                    active.streams.insert(stream_id.clone(), crate::state::ScreenStreamMeta {
                                        kind: kind.clone(),
                                        mime: mime.clone(),
                                        has_audio,
                                        sharer_pubkey: public_key.clone(),
                                        init_chunk: None,
                                        started_at: std::time::Instant::now(),
                                    });
                                }
                                {
                                    let ev = crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: public_key.clone(),
                                        kind: kind.clone(),
                                        mime: mime.clone(),
                                        has_audio,
                                    };
                                    let ws_msg = WsServerMessage::ScreenShareStarted {
                                        channel_id,
                                        stream_id,
                                        sharer_pubkey: public_key.clone(),
                                        kind,
                                        mime,
                                        has_audio,
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&ws_msg).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                            }

                            Ok(WsClientMessage::ScreenShareChunk { channel_id, stream_id, seq, is_init }) => {
                                pending_chunk = Some((channel_id, stream_id, seq, is_init));
                            }

                            Ok(WsClientMessage::ScreenShareStop { channel_id, stream_id }) => {
                                let cross_subscribers: Vec<String> = {
                                    let mut shares = state.screen_shares.write().await;
                                    let key = (channel_id.clone(), public_key.clone());
                                    let mut subs = Vec::new();
                                    if let Some(active) = shares.get_mut(&key) {
                                        // Collect cross-channel subscribers before removing the stream.
                                        subs = active.cross_channel_subscribers.iter().cloned().collect();
                                        active.streams.remove(&stream_id);
                                        if active.streams.is_empty() {
                                            shares.remove(&key);
                                        }
                                    }
                                    subs
                                };
                                {
                                    let ev = crate::routes::chat_models::ChatEvent::ScreenShareStopped {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: public_key.clone(),
                                    };
                                    let ws_msg = WsServerMessage::ScreenShareStopped {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: public_key.clone(),
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&ws_msg).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                                // Notify cross-channel subscribers.
                                for subscriber_pubkey in cross_subscribers {
                                    let ev = crate::routes::chat_models::ChatEvent::StreamSubscriptionEnded {
                                        to_pubkey: subscriber_pubkey.clone(),
                                        source_channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                    };
                                    let ws_msg = WsServerMessage::StreamSubscriptionEnded {
                                        source_channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&ws_msg).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                            }

                            // ---- Screen share v2: WebRTC signaling ----

                            Ok(WsClientMessage::ScreenShareViewerJoin { channel_id, stream_id }) => {
                                // Validate: stream exists.
                                let share_exists = {
                                    let shares = state.screen_shares.read().await;
                                    shares.iter().any(|((ch, _), active)| {
                                        ch == &channel_id && active.streams.contains_key(&stream_id)
                                    })
                                };
                                if !share_exists {
                                    let err = WsServerMessage::Error {
                                        context: "screen_share_viewer_join".to_string(),
                                        message: "No active share with that stream_id in this channel.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }
                                // Record viewer and find sharer.
                                let sharer_pubkey: Option<String> = {
                                    let mut shares = state.screen_shares.write().await;
                                    shares.iter_mut()
                                        .find(|((ch, _), active)| {
                                            ch == &channel_id && active.streams.contains_key(&stream_id)
                                        })
                                        .map(|((_, sharer), active)| {
                                            active.viewers.insert(public_key.clone());
                                            sharer.clone()
                                        })
                                };
                                if let Some(sharer) = sharer_pubkey {
                                    let msg = WsServerMessage::ScreenShareViewerJoined {
                                        channel_id: channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        from_pubkey: public_key.clone(),
                                    };
                                    send_v2_signal(&state, channel_id, sharer, msg);
                                }
                            }

                            Ok(WsClientMessage::ScreenShareViewerLeave { channel_id, stream_id }) => {
                                let sharer_pubkey: Option<String> = {
                                    let mut shares = state.screen_shares.write().await;
                                    shares.iter_mut()
                                        .find(|((ch, _), active)| {
                                            ch == &channel_id && active.streams.contains_key(&stream_id)
                                        })
                                        .map(|((_, sharer), active)| {
                                            active.viewers.remove(&public_key);
                                            sharer.clone()
                                        })
                                };
                                if let Some(sharer) = sharer_pubkey {
                                    send_v2_signal(
                                        &state,
                                        channel_id.clone(),
                                        sharer,
                                        WsServerMessage::ScreenShareViewerLeft {
                                            channel_id,
                                            stream_id,
                                            from_pubkey: public_key.clone(),
                                        },
                                    );
                                }
                            }

                            Ok(WsClientMessage::ScreenShareOffer { channel_id, to_pubkey, stream_id, sdp }) => {
                                // Sender must be the sharer for this stream.
                                let share_exists = {
                                    let shares = state.screen_shares.read().await;
                                    shares.get(&(channel_id.clone(), public_key.clone()))
                                        .map(|a| a.streams.contains_key(&stream_id))
                                        .unwrap_or(false)
                                };
                                if !share_exists { continue; }
                                send_v2_signal(
                                    &state,
                                    channel_id.clone(),
                                    to_pubkey.clone(),
                                    WsServerMessage::ScreenShareOfferIn {
                                        channel_id,
                                        to_pubkey: to_pubkey.clone(),
                                        stream_id,
                                        sdp,
                                        from_pubkey: public_key.clone(),
                                    },
                                );
                            }

                            Ok(WsClientMessage::ScreenShareAnswer { channel_id, to_pubkey, stream_id, sdp }) => {
                                // Sender is a viewer; to_pubkey is the sharer.
                                let share_exists = {
                                    let shares = state.screen_shares.read().await;
                                    shares.get(&(channel_id.clone(), to_pubkey.clone()))
                                        .map(|a| a.streams.contains_key(&stream_id))
                                        .unwrap_or(false)
                                };
                                if !share_exists { continue; }
                                send_v2_signal(
                                    &state,
                                    channel_id.clone(),
                                    to_pubkey.clone(),
                                    WsServerMessage::ScreenShareAnswerIn {
                                        channel_id,
                                        to_pubkey: to_pubkey.clone(),
                                        stream_id,
                                        sdp,
                                        from_pubkey: public_key.clone(),
                                    },
                                );
                            }

                            Ok(WsClientMessage::ScreenShareIce { channel_id, to_pubkey, stream_id, candidate }) => {
                                let share_exists = {
                                    let shares = state.screen_shares.read().await;
                                    shares.get(&(channel_id.clone(), public_key.clone()))
                                        .map(|a| a.streams.contains_key(&stream_id))
                                        .unwrap_or(false)
                                    || shares.get(&(channel_id.clone(), to_pubkey.clone()))
                                        .map(|a| a.streams.contains_key(&stream_id))
                                        .unwrap_or(false)
                                };
                                if !share_exists { continue; }
                                send_v2_signal(
                                    &state,
                                    channel_id.clone(),
                                    to_pubkey.clone(),
                                    WsServerMessage::ScreenShareIceIn {
                                        channel_id,
                                        to_pubkey: to_pubkey.clone(),
                                        stream_id,
                                        candidate,
                                        from_pubkey: public_key.clone(),
                                    },
                                );
                            }

                            Ok(WsClientMessage::StreamList) => {
                                // Return all active streams on channels visible to this user.
                                let shares = state.screen_shares.read().await;
                                let mut stream_list: Vec<HubStreamInfo> = Vec::new();
                                for ((ch_id, _sharer), active) in shares.iter() {
                                    if !subscribed.contains(ch_id) {
                                        continue;
                                    }
                                    for (sid, meta) in &active.streams {
                                        stream_list.push(HubStreamInfo {
                                            channel_id: ch_id.clone(),
                                            stream_id: sid.clone(),
                                            sharer_pubkey: meta.sharer_pubkey.clone(),
                                            kind: meta.kind.clone(),
                                            mime: meta.mime.clone(),
                                            has_audio: meta.has_audio,
                                        });
                                    }
                                }
                                let msg = WsServerMessage::HubStreams { streams: stream_list };
                                let _ = ws_tx
                                    .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
                                    .await;
                            }

                            Ok(WsClientMessage::StreamSubscribe { source_channel_id, stream_id }) => {
                                // Permission: user must have view access to source_channel_id.
                                let can_view: bool = subscribed.contains(&source_channel_id)
                                    || sqlx::query_scalar::<_, i64>(
                                        "SELECT COUNT(*) FROM channels WHERE id = ?",
                                    )
                                    .bind(&source_channel_id)
                                    .fetch_optional(&state.db)
                                    .await
                                    .ok()
                                    .flatten()
                                    .unwrap_or(0)
                                    > 0;

                                if !can_view {
                                    let err = WsServerMessage::Error {
                                        context: "stream_subscribe".to_string(),
                                        message: "Channel not found or access denied.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }

                                // Find the stream and add this user as a cross-channel subscriber.
                                let found: Option<(String, String, String, bool)> = {
                                    let mut shares = state.screen_shares.write().await;
                                    let entry = shares.iter_mut().find(|((ch, _), active)| {
                                        ch == &source_channel_id && active.streams.contains_key(&stream_id)
                                    });
                                    entry.map(|((_, sharer), active)| {
                                        active.cross_channel_subscribers.insert(public_key.clone());
                                        let meta = active.streams.get(&stream_id).unwrap();
                                        (sharer.clone(), meta.kind.clone(), meta.mime.clone(), meta.has_audio)
                                    })
                                };

                                if let Some((sharer_pubkey, kind, mime, has_audio)) = found {
                                    // Acknowledge subscription.
                                    let ack = WsServerMessage::StreamSubscribed {
                                        source_channel_id: source_channel_id.clone(),
                                        stream_id: stream_id.clone(),
                                        sharer_pubkey: sharer_pubkey.clone(),
                                        kind,
                                        mime,
                                        has_audio,
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&ack).unwrap().into()))
                                        .await;

                                    // Replay init chunk if available.
                                    let shares = state.screen_shares.read().await;
                                    if let Some(active) = shares.get(&(source_channel_id.clone(), sharer_pubkey)) {
                                        if let Some(meta) = active.streams.get(&stream_id) {
                                            if let Some(init_bytes) = &meta.init_chunk {
                                                let chunk_env = WsServerMessage::ScreenShareChunkOut {
                                                    channel_id: source_channel_id.clone(),
                                                    stream_id: stream_id.clone(),
                                                    sharer_pubkey: meta.sharer_pubkey.clone(),
                                                    seq: 0,
                                                    is_init: true,
                                                };
                                                let _ = ws_tx
                                                    .send(Message::Text(serde_json::to_string(&chunk_env).unwrap().into()))
                                                    .await;
                                                let _ = ws_tx
                                                    .send(Message::Binary(init_bytes.to_vec().into()))
                                                    .await;
                                            }
                                        }
                                    }
                                } else {
                                    let err = WsServerMessage::Error {
                                        context: "stream_subscribe".to_string(),
                                        message: "No active stream with that ID in the specified channel.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                }
                            }

                            Ok(WsClientMessage::StreamUnsubscribe { source_channel_id, stream_id }) => {
                                let mut shares = state.screen_shares.write().await;
                                if let Some((_, active)) = shares.iter_mut().find(|((ch, _), active)| {
                                    ch == &source_channel_id && active.streams.contains_key(&stream_id)
                                }) {
                                    active.cross_channel_subscribers.remove(&public_key);
                                }
                            }

                            Ok(WsClientMessage::Resume { since_seq }) => {
                                // Only bots can resume (they're the only consumers of hub_event).
                                if !is_bot {
                                    continue;
                                }

                                is_replaying = true;
                                let _ = is_replaying; // suppress lint: read across tokio::select! arms

                                let live_seq = crate::bots::events::current_seq(&state).await;

                                // Clone the bot_tx so replay_events_for_bot can push directly.
                                let replay_tx = bot_tx.clone();
                                let result = crate::bots::events::replay_events_for_bot(
                                    &state,
                                    &public_key,
                                    since_seq,
                                    &replay_tx,
                                ).await;

                                is_replaying = false;

                                match result {
                                    crate::bots::events::ReplayResult::Unavailable {
                                        earliest_seq,
                                        earliest_at,
                                    } => {
                                        let msg = serde_json::json!({
                                            "type": "replay_unavailable",
                                            "earliest_seq": earliest_seq,
                                            "earliest_at": earliest_at,
                                        });
                                        if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                    crate::bots::events::ReplayResult::Complete { replayed } => {
                                        let msg = serde_json::json!({
                                            "type": "replay_complete",
                                            "replayed": replayed,
                                            "live_from_seq": live_seq,
                                        });
                                        if ws_tx.send(Message::Text(msg.to_string().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }

                                // Flush buffered live events that arrived during replay.
                                for buffered in replay_buffer.drain(..) {
                                    if ws_tx.send(Message::Text(buffered.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }

                            // ---- Gaming Tier 2: client → hub game messages ----
                            // All handlers here must drop Mutex locks before any `.await`.

                            Ok(WsClientMessage::GameSend { session_id, payload, to }) => {
                                // Validate: sender must be in the session roster.
                                // We extract all needed data under the lock, then drop it.
                                enum GameSendOutcome {
                                    NotFound,
                                    NotInSession,
                                    Ok { channel_id: String, roster: Vec<String> },
                                }
                                let outcome = {
                                    let sessions = state.active_game_sessions.lock().unwrap();
                                    match sessions.get(&session_id) {
                                        None => GameSendOutcome::NotFound,
                                        Some(s) if !s.players.contains(&public_key) => GameSendOutcome::NotInSession,
                                        Some(s) => GameSendOutcome::Ok {
                                            channel_id: s.channel_id.clone(),
                                            roster: s.players.iter().cloned().collect(),
                                        },
                                    }
                                };
                                let (channel_id, roster) = match outcome {
                                    GameSendOutcome::NotFound => {
                                        let err = WsServerMessage::Error {
                                            context: "game_send".to_string(),
                                            message: "Session not found".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameSendOutcome::NotInSession => {
                                        let err = WsServerMessage::Error {
                                            context: "game_send".to_string(),
                                            message: "Not in session".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameSendOutcome::Ok { channel_id, roster } => (channel_id, roster),
                                };

                                // Update last_event_at (no await in this block).
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
                                    from_pubkey: public_key.clone(),
                                    payload,
                                };

                                // Fan-out: targeted or broadcast.
                                let should_send = if let Some(ref target) = to {
                                    roster.contains(target)
                                } else {
                                    true
                                };
                                if should_send {
                                    let ev = crate::routes::chat_models::ChatEvent::Game {
                                        channel_id: channel_id.clone(),
                                    };
                                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                                        serde_json::to_string(&game_event).unwrap().as_str(),
                                    );
                                    let _ = state.chat_tx.send((ev, json));
                                }
                            }

                            Ok(WsClientMessage::GameSetStatus { session_id, status }) => {
                                enum GameSetStatusOutcome {
                                    NotFound,
                                    NotHost,
                                    Ok(String),
                                }
                                let outcome = {
                                    let mut sessions = state.active_game_sessions.lock().unwrap();
                                    match sessions.get_mut(&session_id) {
                                        None => GameSetStatusOutcome::NotFound,
                                        Some(s) if s.host_pubkey != public_key => GameSetStatusOutcome::NotHost,
                                        Some(s) => {
                                            s.status = status.clone();
                                            s.last_event_at = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs() as i64;
                                            GameSetStatusOutcome::Ok(s.channel_id.clone())
                                        }
                                    }
                                };
                                let channel_id = match outcome {
                                    GameSetStatusOutcome::NotFound => {
                                        let err = WsServerMessage::Error {
                                            context: "game_set_status".to_string(),
                                            message: "Session not found".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameSetStatusOutcome::NotHost => {
                                        let err = WsServerMessage::Error {
                                            context: "game_set_status".to_string(),
                                            message: "Only the host can change session status".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameSetStatusOutcome::Ok(ch) => ch,
                                };

                                let ev = crate::routes::chat_models::ChatEvent::Game { channel_id };
                                let status_msg = WsServerMessage::GameEvent {
                                    session_id: session_id.clone(),
                                    from_pubkey: public_key.clone(),
                                    payload: serde_json::json!({ "type": "status_changed", "status": status }),
                                };
                                let json: std::sync::Arc<str> = std::sync::Arc::from(
                                    serde_json::to_string(&status_msg).unwrap().as_str(),
                                );
                                let _ = state.chat_tx.send((ev, json));
                            }

                            Ok(WsClientMessage::GameSnapshot { session_id, blob }) => {
                                // Validate and extract under lock; no await inside.
                                let in_session = {
                                    let sessions = state.active_game_sessions.lock().unwrap();
                                    sessions.get(&session_id)
                                        .map(|s| s.players.contains(&public_key))
                                        .unwrap_or(false)
                                };
                                if !in_session { continue; }

                                let blob_bytes = bytes::Bytes::from(blob.into_bytes());
                                {
                                    let mut sessions = state.active_game_sessions.lock().unwrap();
                                    if let Some(s) = sessions.get_mut(&session_id) {
                                        s.snapshot = Some(blob_bytes.clone());
                                        s.last_event_at = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs() as i64;
                                    }
                                }

                                // Persist snapshot to DB in a separate task (no await here).
                                let state_c = state.clone();
                                let sid = session_id.clone();
                                let blob_vec = blob_bytes.to_vec();
                                let now_ts = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() as i64;
                                tokio::spawn(async move {
                                    let _ = sqlx::query(
                                        "UPDATE game_sessions SET snapshot = ?, updated_at = ? WHERE id = ?",
                                    )
                                    .bind(blob_vec.as_slice())
                                    .bind(now_ts)
                                    .bind(&sid)
                                    .execute(&state_c.db)
                                    .await;
                                });
                            }

                            Ok(WsClientMessage::GameEnd { session_id, result }) => {
                                enum GameEndOutcome {
                                    NotFound,
                                    NotHost,
                                    Ok(String),
                                }
                                let outcome = {
                                    let sessions = state.active_game_sessions.lock().unwrap();
                                    match sessions.get(&session_id) {
                                        None => GameEndOutcome::NotFound,
                                        Some(s) if s.host_pubkey != public_key => GameEndOutcome::NotHost,
                                        Some(s) => GameEndOutcome::Ok(s.channel_id.clone()),
                                    }
                                };
                                let channel_id = match outcome {
                                    GameEndOutcome::NotFound => {
                                        let err = WsServerMessage::Error {
                                            context: "game_end".to_string(),
                                            message: "Session not found".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameEndOutcome::NotHost => {
                                        let err = WsServerMessage::Error {
                                            context: "game_end".to_string(),
                                            message: "Only the host can end the session".to_string(),
                                        };
                                        let _ = ws_tx.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
                                        continue;
                                    }
                                    GameEndOutcome::Ok(ch) => ch,
                                };

                                state.active_game_sessions.lock().unwrap().remove(&session_id);

                                let state_c = state.clone();
                                let sid = session_id.clone();
                                tokio::spawn(async move {
                                    let now_str = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                        .to_string();
                                    let _ = sqlx::query(
                                        "UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?",
                                    )
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
                                let json: std::sync::Arc<str> = std::sync::Arc::from(
                                    serde_json::to_string(&end_msg).unwrap().as_str(),
                                );
                                let _ = state.chat_tx.send((ev, json));
                            }

                            Ok(WsClientMessage::ComponentInteraction {
                                message_id,
                                custom_id,
                                values,
                            }) => {
                                // Rate-limit: 1 interaction per (user, custom_id) per 3 seconds.
                                let rl_key = (public_key.clone(), custom_id.clone());
                                let now_inst = Instant::now();
                                if let Some(last) = component_rate_limit.get(&rl_key) {
                                    if now_inst.duration_since(*last) < Duration::from_secs(3) {
                                        let err = WsServerMessage::Error {
                                            context: "component_interaction".to_string(),
                                            message: "Please wait before interacting again.".to_string(),
                                        };
                                        let _ = ws_tx
                                            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                            .await;
                                        continue;
                                    }
                                }
                                component_rate_limit.insert(rl_key, now_inst);
                                // Opportunistic cleanup so the map doesn't grow forever.
                                if component_rate_limit.len() > 500 {
                                    component_rate_limit.retain(|_, t| now_inst.duration_since(*t) < Duration::from_secs(60));
                                }

                                let state_c = state.clone();
                                let pk = public_key.clone();
                                tokio::spawn(async move {
                                    crate::bots::dispatch::dispatch_component(
                                        &state_c,
                                        &message_id,
                                        &custom_id,
                                        &values,
                                        &pk,
                                    ).await;
                                });
                            }

                            Err(_) => {}
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if let Some((ch_id, st_id, seq, is_init)) = pending_chunk.take() {
                            let chunk_bytes = bytes::Bytes::from(data.to_vec());
                            if is_init {
                                let mut shares = state.screen_shares.write().await;
                                let key = (ch_id.clone(), public_key.clone());
                                if let Some(active) = shares.get_mut(&key) {
                                    if let Some(meta) = active.streams.get_mut(&st_id) {
                                        meta.init_chunk = Some(chunk_bytes.clone());
                                    }
                                }
                            }
                            let _ = state.screen_share_tx.send(ScreenChunkEvent {
                                channel_id: ch_id,
                                stream_id: st_id,
                                sharer_pubkey: public_key.clone(),
                                seq,
                                is_init,
                                data: chunk_bytes,
                            });
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }

            voice_result = voice_rx.recv() => {
                if let Ok((channel_id, msg)) = voice_result {
                    if voice_channel.as_deref() == Some(channel_id.as_str()) {
                        let is_self = match &msg {
                            WsServerMessage::VoiceParticipantSpeaking { public_key: pk, .. } => pk == &public_key,
                            WsServerMessage::VoiceParticipantJoined { participant, .. } => participant.public_key == public_key,
                            WsServerMessage::VoiceParticipantLeft { public_key: pk, .. } => pk == &public_key,
                            _ => false,
                        };
                        if !is_self {
                            let json = serde_json::to_string(&msg).unwrap();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }

            dm_result = dm_rx.recv() => {
                if let Ok(dm) = dm_result {
                    if dm.sender() == public_key
                        || !my_conversations.contains(dm.conversation_id())
                    {
                        continue;
                    }
                    let msg = match dm {
                        crate::state::DmEvent::Message { conversation_id, sender, sender_name, content, timestamp } => {
                            WsServerMessage::DirectMessage {
                                conversation_id, sender, sender_name, content, timestamp,
                            }
                        }
                        crate::state::DmEvent::Typing { conversation_id, sender, sender_name, typing } => {
                            WsServerMessage::DmTyping {
                                conversation_id, sender, sender_name, typing,
                            }
                        }
                    };
                    let json = serde_json::to_string(&msg).unwrap();
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            chunk_result = screen_share_rx.recv() => {
                match chunk_result {
                    Ok(ev) => {
                        // Deliver to normal channel subscribers (not the sharer themselves).
                        let in_channel = ev.sharer_pubkey != public_key
                            && subscribed.contains(&ev.channel_id);
                        // Deliver to cross-channel subscribers for this specific stream.
                        let is_cross_subscriber = {
                            let shares = state.screen_shares.read().await;
                            shares.get(&(ev.channel_id.clone(), ev.sharer_pubkey.clone()))
                                .map(|a| a.cross_channel_subscribers.contains(&public_key))
                                .unwrap_or(false)
                        };
                        if in_channel || is_cross_subscriber {
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
                            if ws_tx.send(Message::Binary(ev.data.to_vec().into())).await.is_err() {
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

    // Clean up on disconnect.
    if let Some(ch_id) = voice_channel {
        leave_voice(&state, &public_key, &ch_id).await;
    }
    {
        let mut shares = state.screen_shares.write().await;

        // Collect streams this user was sharing so we can notify their cross-channel subscribers.
        let ended_streams: Vec<(String, String, Vec<String>)> = shares
            .iter()
            .filter(|((_, sharer), _)| sharer.as_str() == public_key.as_str())
            .flat_map(|((ch_id, _), active)| {
                active.streams.keys().map(move |sid| {
                    (
                        ch_id.clone(),
                        sid.clone(),
                        active.cross_channel_subscribers.iter().cloned().collect::<Vec<_>>(),
                    )
                })
            })
            .collect();

        // Remove any share keyed by this user as sharer.
        shares.retain(|(_, sharer), _| sharer != &public_key);
        // Also remove this user from any viewer set and cross-channel subscribers.
        for active in shares.values_mut() {
            active.viewers.remove(&public_key);
            active.cross_channel_subscribers.remove(&public_key);
        }

        // Notify cross-channel subscribers about ended streams via chat_tx.
        for (ch_id, stream_id, subscribers) in ended_streams {
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
        state.bot_sessions.write().await.remove(&public_key);
    }
    state.online_users.write().await.remove(&public_key);

    tracing::info!("WebSocket disconnected: {}", &public_key[..16.min(public_key.len())]);
}

async fn leave_voice(state: &AppState, public_key: &str, channel_id: &str) {
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
    if let Some(addr) = removed_addr {
        state.voice_addr_map.write().await.remove(&addr);
    }

    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceParticipantLeft {
            channel_id: channel_id.to_string(),
            public_key: public_key.to_string(),
        },
    ));
}

/// Broadcast a v2 signaling envelope via `chat_tx` using `ChatEvent::ScreenShareSignal`
/// so the WS dispatch loop delivers it only to `to_pubkey`.
fn send_v2_signal(
    state: &AppState,
    channel_id: String,
    to_pubkey: String,
    msg: WsServerMessage,
) {
    let ev = crate::routes::chat_models::ChatEvent::ScreenShareSignal {
        channel_id,
        to_pubkey,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
}

async fn get_voice_participants(state: &AppState, channel_id: &str) -> Vec<VoiceParticipantInfo> {
    let channels = state.voice_channels.read().await;
    let Some(participants) = channels.get(channel_id) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for (pk, _addr) in participants {
        let display_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(pk)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        result.push(VoiceParticipantInfo {
            public_key: pk.clone(),
            display_name,
        });
    }
    result
}
