use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State, WebSocketUpgrade};
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};

use crate::routes::chat_models::{
    VoiceParticipantInfo, WsClientMessage, WsParams, WsServerMessage,
};
use crate::state::{ActiveShare, AppState, ScreenChunkEvent};

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

    tracing::info!("WebSocket connected: {}", &public_key[..16]);

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, public_key)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, public_key: String) {
    // Track online status
    state.online_users.write().await.insert(public_key.clone());

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut chat_rx = state.chat_tx.subscribe();
    // Record the time we subscribed to the broadcast channel. The auto-subscribe
    // push below only sends ScreenShareStarted for streams whose started_at
    // predates this instant — streams started after this instant arrive via
    // the broadcast and don't need an explicit push.
    let chat_rx_since = std::time::Instant::now();
    let mut dm_rx = state.dm_tx.subscribe();
    let mut voice_rx = state.voice_event_tx.subscribe();
    let mut screen_share_rx = state.screen_share_tx.subscribe();
    let mut voice_channel: Option<String> = None;
    // When Some, the next binary WS frame is a screen-share chunk for this stream.
    // (channel_id, stream_id, seq, is_init)
    let mut pending_chunk: Option<(String, String, u32, bool)> = None;

    // Load this user's conversation IDs for DM filtering
    let my_conversations: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT conversation_id FROM conversation_members WHERE public_key = ?",
    )
    .bind(&public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Auto-subscribe to all channels the user is not banned from.
    // Categories (is_category = 1) carry no messages so skip them.
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

    // Push any in-progress screen shares to this client immediately at connect
    // so they don't miss a share that started before they subscribed to the
    // broadcast. Shares started after chat_rx_since will arrive via the
    // broadcast channel and must not be pushed here (would duplicate them).
    {
        let shares = state.screen_shares.read().await;
        for channel_id in &subscribed {
            if let Some(active) = shares.get(channel_id) {
                for (stream_id, meta) in &active.streams {
                    if meta.started_at >= chat_rx_since {
                        continue;
                    }
                    let started = WsServerMessage::ScreenShareStarted {
                        channel_id: channel_id.clone(),
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
                            channel_id: channel_id.clone(),
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
    }

    loop {
        tokio::select! {
            result = chat_rx.recv() => {
                match result {
                    Ok(event) => {
                        if subscribed.contains(event.channel_id()) {
                            // Don't echo typing events back to the originator -- they
                            // already know they're typing.
                            if let crate::routes::chat_models::ChatEvent::Typing {
                                public_key: sender_key, ..
                            } = &event
                            {
                                if sender_key == &public_key {
                                    continue;
                                }
                            }
                            let ws_msg = match event {
                                crate::routes::chat_models::ChatEvent::New { channel_id, message } => {
                                    WsServerMessage::ChatMessage { channel_id, message }
                                }
                                crate::routes::chat_models::ChatEvent::Edited { channel_id, message } => {
                                    WsServerMessage::MessageEdited { channel_id, message }
                                }
                                crate::routes::chat_models::ChatEvent::Deleted { channel_id, message_id } => {
                                    WsServerMessage::MessageDeleted { channel_id, message_id }
                                }
                                crate::routes::chat_models::ChatEvent::ReactionsUpdated { channel_id, message_id, reactions } => {
                                    WsServerMessage::ReactionsUpdated { channel_id, message_id, reactions }
                                }
                                crate::routes::chat_models::ChatEvent::Typing { channel_id, public_key, display_name, typing } => {
                                    WsServerMessage::Typing { channel_id, public_key, display_name, typing }
                                }
                                crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                    channel_id, stream_id, sharer_pubkey, kind, mime, has_audio,
                                } => WsServerMessage::ScreenShareStarted {
                                    channel_id, stream_id, sharer_pubkey, kind, mime, has_audio,
                                },
                                crate::routes::chat_models::ChatEvent::ScreenShareStopped {
                                    channel_id, stream_id, sharer_pubkey,
                                } => WsServerMessage::ScreenShareStopped {
                                    channel_id, stream_id, sharer_pubkey,
                                },
                            };
                            let json = serde_json::to_string(&ws_msg).unwrap();
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
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

            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsClientMessage>(&text) {
                            Ok(WsClientMessage::Subscribe { channel_id }) => {
                                let newly_subscribed = subscribed.insert(channel_id.clone());
                                // Push active screen shares only for channels not already in
                                // the subscribed set. Auto-subscribed channels are handled at
                                // connect time above; re-subscribing would produce duplicates.
                                if !newly_subscribed { continue; }
                                let shares = state.screen_shares.read().await;
                                if let Some(active) = shares.get(&channel_id) {
                                    for (stream_id, meta) in &active.streams {
                                        // Send ScreenShareStarted so the client knows the stream exists.
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
                                        // If we have a cached init chunk, send it as a
                                        // synthetic ScreenShareChunkOut + binary frame.
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
                                // Moderation gates before adding the user to
                                // the voice channel:
                                //   1. Voice mute applies hub-wide.
                                //   2. min_talk_power on the channel requires
                                //      the user's highest role priority to be
                                //      at least that level.
                                let is_muted = crate::routes::moderation::is_voice_muted(
                                    &state.db, &public_key,
                                )
                                .await
                                .unwrap_or(false);
                                if is_muted {
                                    let err = WsServerMessage::Error {
                                        context: "voice_join".to_string(),
                                        message: "You are voice-muted on this hub.".to_string(),
                                    };
                                    let _ = ws_tx
                                        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                        .await;
                                    continue;
                                }

                                let min_talk_power: i64 = sqlx::query_scalar(
                                    "SELECT min_talk_power FROM channel_settings WHERE channel_id = ?",
                                )
                                .bind(&channel_id)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten()
                                .unwrap_or(0);

                                if min_talk_power > 0 {
                                    let perms = crate::permissions::user_permissions(
                                        &state.db, &public_key,
                                    )
                                    .await;
                                    let user_priority = perms
                                        .as_ref()
                                        .map(|p| p.max_priority)
                                        .unwrap_or(0);
                                    if user_priority < min_talk_power {
                                        let err = WsServerMessage::Error {
                                            context: "voice_join".to_string(),
                                            message: format!(
                                                "This channel requires role priority {} to talk; you have {}.",
                                                min_talk_power, user_priority
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

                                // Register participant
                                state.voice_channels.write().await
                                    .entry(channel_id.clone())
                                    .or_default()
                                    .insert(public_key.clone(), client_addr);

                                voice_channel = Some(channel_id.clone());

                                // Get participant list
                                let participants = get_voice_participants(&state, &channel_id).await;

                                // Send confirmation to this client
                                let msg = WsServerMessage::VoiceJoined {
                                    channel_id: channel_id.clone(),
                                    hub_udp_port: state.voice_udp_port,
                                    participants: participants.clone(),
                                };
                                let json = serde_json::to_string(&msg).unwrap();
                                let _ = ws_tx.send(Message::Text(json.into())).await;

                                // Get display name for broadcast
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();

                                // Broadcast to others via chat broadcast (they'll filter)
                                let _ = state.voice_event_tx.send((
                                    channel_id,
                                    WsServerMessage::VoiceParticipantJoined {
                                        channel_id: voice_channel.clone().unwrap(),
                                        participant: VoiceParticipantInfo {
                                            public_key: public_key.clone(),
                                            display_name,
                                        },
                                    },
                                ));

                                tracing::info!("Voice join: {} in channel", &public_key[..16]);
                            }
                            Ok(WsClientMessage::VoiceLeave { channel_id }) => {
                                leave_voice(&state, &public_key, &channel_id).await;
                                voice_channel = None;
                                tracing::info!("Voice leave: {}", &public_key[..16]);
                            }
                            Ok(WsClientMessage::VoiceSpeaking { channel_id, speaking }) => {
                                // Broadcast to other participants of this voice channel
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
                                // Look up display name once -- the broadcast can carry
                                // it so receivers don't need an extra users map lookup.
                                let display_name: Option<String> = sqlx::query_scalar(
                                    "SELECT display_name FROM users WHERE public_key = ?",
                                )
                                .bind(&public_key)
                                .fetch_optional(&state.db)
                                .await
                                .ok()
                                .flatten();
                                let _ = state.chat_tx.send(
                                    crate::routes::chat_models::ChatEvent::Typing {
                                        channel_id,
                                        public_key: public_key.clone(),
                                        display_name,
                                        typing,
                                    },
                                );
                            }
                            Ok(WsClientMessage::DmTyping { conversation_id, typing }) => {
                                // Same shape but routed through the DM
                                // broadcast so it filters to conversation
                                // members on the relay side.
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

                            Ok(WsClientMessage::ScreenShareStart { channel_id, stream_id, kind, mime, has_audio }) => {
                                // At-most-one-sharer-per-channel: reject if a *different* user
                                // is already sharing. The same sharer may add a second stream.
                                {
                                    let shares = state.screen_shares.read().await;
                                    if let Some(active) = shares.get(&channel_id) {
                                        let other_sharer = active.streams.values()
                                            .any(|m| m.sharer_pubkey != public_key);
                                        if other_sharer {
                                            let err = WsServerMessage::Error {
                                                context: "screen_share".to_string(),
                                                message: "Someone else is already sharing in this channel.".to_string(),
                                            };
                                            let _ = ws_tx
                                                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                                                .await;
                                            continue;
                                        }
                                    }
                                }
                                {
                                    let mut shares = state.screen_shares.write().await;
                                    let active = shares.entry(channel_id.clone()).or_insert_with(|| ActiveShare {
                                        streams: std::collections::HashMap::new(),
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
                                let _ = state.chat_tx.send(crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                    channel_id,
                                    stream_id,
                                    sharer_pubkey: public_key.clone(),
                                    kind,
                                    mime,
                                    has_audio,
                                });
                            }

                            Ok(WsClientMessage::ScreenShareChunk { channel_id, stream_id, seq, is_init }) => {
                                // Store metadata; the next binary frame carries the actual data.
                                pending_chunk = Some((channel_id, stream_id, seq, is_init));
                            }

                            Ok(WsClientMessage::ScreenShareStop { channel_id, stream_id }) => {
                                {
                                    let mut shares = state.screen_shares.write().await;
                                    if let Some(active) = shares.get_mut(&channel_id) {
                                        active.streams.remove(&stream_id);
                                        if active.streams.is_empty() {
                                            shares.remove(&channel_id);
                                        }
                                    }
                                }
                                let _ = state.chat_tx.send(crate::routes::chat_models::ChatEvent::ScreenShareStopped {
                                    channel_id,
                                    stream_id,
                                    sharer_pubkey: public_key.clone(),
                                });
                            }

                            Err(_) => {}
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if let Some((ch_id, st_id, seq, is_init)) = pending_chunk.take() {
                            let chunk_bytes = bytes::Bytes::from(data.to_vec());
                            // Cache init chunk so late joiners can catch up.
                            if is_init {
                                let mut shares = state.screen_shares.write().await;
                                if let Some(active) = shares.get_mut(&ch_id) {
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

            // Voice event relay — only forward to clients currently in that voice channel
            voice_result = voice_rx.recv() => {
                if let Ok((channel_id, msg)) = voice_result {
                    if voice_channel.as_deref() == Some(channel_id.as_str()) {
                        // Don't echo our own speaking state back to ourselves
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

            // DM relay
            dm_result = dm_rx.recv() => {
                if let Ok(dm) = dm_result {
                    // Only relay to members of this conversation, and never
                    // back to the sender (they already know they sent /
                    // typed it).
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

            // Screen-share chunk relay
            chunk_result = screen_share_rx.recv() => {
                match chunk_result {
                    Ok(ev) => {
                        // Forward only to subscribers of the channel, never back to the sharer.
                        if ev.sharer_pubkey != public_key
                            && subscribed.contains(&ev.channel_id)
                        {
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

    // Clean up on disconnect
    if let Some(ch_id) = voice_channel {
        leave_voice(&state, &public_key, &ch_id).await;
    }
    // Remove any screen shares owned by this connection.
    {
        let mut shares = state.screen_shares.write().await;
        for active in shares.values_mut() {
            active.streams.retain(|_, meta| meta.sharer_pubkey != public_key);
        }
        shares.retain(|_, active| !active.streams.is_empty());
    }
    state.online_users.write().await.remove(&public_key);

    tracing::info!("WebSocket disconnected: {}", &public_key[..16]);
}

async fn leave_voice(state: &AppState, public_key: &str, channel_id: &str) {
    let mut channels = state.voice_channels.write().await;
    if let Some(participants) = channels.get_mut(channel_id) {
        participants.remove(public_key);
        if participants.is_empty() {
            channels.remove(channel_id);
        }
    }

    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceParticipantLeft {
            channel_id: channel_id.to_string(),
            public_key: public_key.to_string(),
        },
    ));
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
