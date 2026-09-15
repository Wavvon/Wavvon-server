use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::routes::chat_models::{WsClientMessage, WsServerMessage};
use crate::state::AppState;

use super::conn_state::{ConnState, DispatchResult};

/// How often the hub pings an idle socket.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// How long a socket may go without a single inbound frame before it is
/// treated as dead. Three missed pings — generous enough to survive a brief
/// stall, short enough that a phantom voice participant clears in a minute
/// rather than never.
const KEEPALIVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(65);
use super::handlers::{bot, chat, mini_app, screen, voice};
use super::voice::get_voice_roster;

pub(super) async fn handle_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    public_key: String,
    mini_app_channel_id: Option<String>,
    alliance_voice_channel: Option<String>,
) {
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
    // bot_sessions and ws_key_senders entries so a newer session does not
    // overwrite the older sender, and so the first disconnect does not evict
    // the second session.
    let session_id = uuid::Uuid::new_v4().to_string();

    // V4 voice encryption: per-connection unbounded channel for targeted key
    // distribution messages.  Registered in ws_key_senders so other connections
    // can send directly to this one without going through the broadcast bus.
    // Filed under this session's own id, for the reason bot_sessions is: a
    // pubkey with two sockets used to leave one of them registered nowhere,
    // and a voice participant registered nowhere receives no sender key and
    // hears silence (state.rs, `ws_key_senders`).
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<WsServerMessage>();
    state
        .ws_key_senders
        .write()
        .await
        .entry(public_key.clone())
        .or_default()
        .insert(session_id.clone(), key_tx);

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
    // that this user is online. Only fires on the first session (refcount == 1),
    // and never while the user's stored presence is "invisible" — an
    // invisible user must never be broadcast as online to other clients,
    // even though they are (and stay) genuinely connected for delivery.
    {
        let is_invisible = crate::routes::users::fetch_presence_status(&state.db, &public_key)
            .await
            .as_deref()
            == Some("invisible");
        let online = state.online_users.read().await;
        if online.get(&public_key).copied().unwrap_or(0) == 1 && !is_invisible {
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

    // A mini-app session (bot-mini-apps.md "Scoped session token") is bound
    // to exactly one channel and never sees DMs — it's a game/interactive
    // relay for one channel, not a general-purpose login. Skip the normal
    // "every readable channel" auto-subscribe and DM-membership load
    // entirely in that case.
    let is_mini_app = mini_app_channel_id.is_some();

    // Load DM conversation memberships (once at connect time). Never for a
    // mini-app session — see above.
    let my_conversations: std::collections::HashSet<String> = if is_mini_app {
        std::collections::HashSet::new()
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT conversation_id FROM conversation_members WHERE public_key = $1",
        )
        .bind(&public_key)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
    };

    // Read-gating (§3.5): a channel the caller can't effectively read is
    // never auto-subscribed, so no chat/typing/etc. events for it are ever
    // delivered over this connection.
    let readable_channels: std::collections::HashSet<String> =
        crate::permissions::channels_with_permission(
            &state.db,
            &public_key,
            crate::permissions::READ_MESSAGES,
        )
        .await
        .unwrap_or_default();

    // Auto-subscribe to non-banned, readable channels — or, for a mini-app
    // session, to its single bound channel only (still gated by the same
    // ban + read-permission checks; a mini-app session grants no extra
    // visibility beyond what the underlying user already has).
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
    .filter(|id| readable_channels.contains(id))
    .filter(|id| {
        mini_app_channel_id
            .as_deref()
            .is_none_or(|bound| bound == id)
    })
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
        is_mini_app,
        alliance_voice_channel,
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

    // ── Liveness ─────────────────────────────────────────────────────────────
    //
    // Nothing used to notice a client that vanished without closing its socket
    // — a slept laptop, a changed network, a killed tab. The read loop stayed
    // parked on a half-open TCP connection for as long as the OS took to
    // notice, and because the disconnect cleanup below is the *only* thing
    // that calls `leave_voice`, that member sat in the voice roster the whole
    // time. Reconnecting then showed them talking to themselves.
    //
    // WebSocket ping is the right tool: browsers answer at the protocol level,
    // so this needs no client cooperation. Any inbound frame counts as proof
    // of life, pong included.
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_seen = std::time::Instant::now();

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
                                | crate::routes::chat_models::ChatEvent::HubUpdated
                                | crate::routes::chat_models::ChatEvent::MemberOnline { .. }
                                | crate::routes::chat_models::ChatEvent::MemberOffline { .. }
                                | crate::routes::chat_models::ChatEvent::MemberUpdated { .. }
                                | crate::routes::chat_models::ChatEvent::MemberStatus { .. }
                                | crate::routes::chat_models::ChatEvent::WebhookDisabled { .. }
                                | crate::routes::chat_models::ChatEvent::VoiceMove { .. }
                        ) {
                            // VoiceMove is hub-wide-bypass in the sense that it
                            // never depends on channel subscription, but it is
                            // still targeted to exactly one recipient (events.md
                            // §7.1) — filter on pubkey before delivering.
                            if let crate::routes::chat_models::ChatEvent::VoiceMove {
                                to_pubkey,
                            } = &event {
                                if to_pubkey != &cs.public_key { continue; }
                            }
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

                            // If the screen_share_rx arm already sent screen_share_started
                            // proactively (race-guard), suppress the duplicate here.
                            if let crate::routes::chat_models::ChatEvent::ScreenShareStarted {
                                channel_id, stream_id, ..
                            } = &event {
                                let key = (channel_id.clone(), stream_id.clone());
                                if cs.notified_streams.contains(&key) {
                                    continue;
                                }
                                cs.notified_streams.insert(key);
                            }
                            let json = pre_json.to_string();
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

            // ── V4 voice-key targeted delivery ───────────────────────────
            key_msg = key_rx.recv() => {
                if let Some(msg) = key_msg {
                    let json = serde_json::to_string(&msg).unwrap();
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }

            // ── Inbound client frame ──────────────────────────────────────
            // ── Liveness probe ────────────────────────────────────────────
            _ = keepalive.tick() => {
                if last_seen.elapsed() > KEEPALIVE_DEADLINE {
                    // Breaking runs the disconnect cleanup below, which is
                    // what actually frees the voice roster entry.
                    tracing::debug!(
                        "WebSocket liveness timeout, closing: {}",
                        public_key
                    );
                    break;
                }
                if ws_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }

            msg = ws_rx.next() => {
                // Proof of life before anything else: a pong, or a frame this
                // loop ignores, still means the peer is there.
                if matches!(msg, Some(Ok(_))) {
                    last_seen = std::time::Instant::now();
                }
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
                match voice_result {
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Dropped voice events are permanent UI damage (a
                        // missed Joined leaves a participant invisible until
                        // the next roster broadcast) — tell the client to
                        // resync, same as the chat arm.
                        tracing::warn!("WebSocket client lagged on voice events, missed {n}");
                        let lag_msg = crate::routes::chat_models::WsServerMessage::Lagged { count: n };
                        if let Ok(json) = serde_json::to_string(&lag_msg) {
                            let _ = ws_tx.send(Message::Text(json.into())).await;
                        }
                    }
                    Err(_) => break,
                    Ok((channel_id, msg)) => {
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
                    // up-to-date even for clients not in any voice channel —
                    // INCLUDING the actor themselves: suppressing self-echo
                    // here left the actor's own sidebar stale on channel
                    // switch/leave (they never saw their own Left event for
                    // the previous channel). Clients dedupe their own Joined.
                    // Speaking events stay scoped to same-channel clients and
                    // do skip self (that echo is pure noise).
                    let is_roster_event = matches!(
                        &msg,
                        WsServerMessage::VoiceParticipantJoined { .. }
                            | WsServerMessage::VoiceParticipantLeft { .. }
                    );
                    let in_same_channel =
                        cs.voice_channel.as_deref() == Some(channel_id.as_str());
                    if is_roster_event || (in_same_channel && !is_self) {
                        let json = serde_json::to_string(&msg).unwrap();
                        if ws_tx.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    }
                }
            }

            // ── DM events ────────────────────────────────────────────────
            dm_result = dm_rx.recv() => {
                if let Ok(dm) = dm_result {
                    // `my_conversations` is loaded once at connect, so keep it
                    // live from membership events: without this, a conversation
                    // created after this connection opened would be dead air
                    // (every event for it dropped by the gate below) until the
                    // client reconnects. Removal happens after delivery so the
                    // removed member still receives their final MemberChanged.
                    let mut removed_from = None;
                    if let crate::state::DmEvent::MemberChanged { conversation_id, added, removed, .. } = &dm {
                        if added.iter().any(|k| k == &cs.public_key) {
                            cs.my_conversations.insert(conversation_id.clone());
                        }
                        if removed.iter().any(|k| k == &cs.public_key) {
                            removed_from = Some(conversation_id.clone());
                        }
                    }
                    if (dm.suppress_echo() && dm.sender() == cs.public_key)
                        || !cs.my_conversations.contains(dm.conversation_id())
                    {
                        continue;
                    }
                    if let Some(conv_id) = removed_from {
                        cs.my_conversations.remove(&conv_id);
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

    // V4 voice encryption: deregister *this session's* key sender, leaving
    // any concurrent session of the same pubkey registered — removing the
    // whole entry is what used to silence the surviving socket.
    {
        let mut senders = state.ws_key_senders.write().await;
        if let Some(sessions) = senders.get_mut(&public_key) {
            sessions.remove(&session_id);
            if sessions.is_empty() {
                senders.remove(&public_key);
            }
        }
    }

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
        // If the user's current presence is "invisible", other clients were
        // never told they came online in the first place (see connect,
        // above) — or were already told they went offline the moment
        // invisible was set (see handle_set_status) — so skip the redundant
        // member_offline broadcast here.
        let is_invisible = crate::routes::users::fetch_presence_status(&state.db, &public_key)
            .await
            .as_deref()
            == Some("invisible");
        if !is_invisible {
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
    }

    tracing::info!(
        "WebSocket disconnected: {}",
        &public_key[..16.min(public_key.len())]
    );
}

// ── Per-message dispatch ─────────────────────────────────────────────────────

/// The only WS messages an `alliance_voice` visitor may send
/// (alliances.md). Everything a room genuinely needs and nothing else: join,
/// leave, the speaking flag, the E2E key offer, and the latency probe.
///
/// The design also listed `voice_key_request`; there is no such client
/// message. `VoiceKeyRequest` is server->client, part of `WsServerMessage` —
/// the hub asks a sender to re-offer, the client answers with another
/// `voice_key_offer`. Listing it would have been a no-op arm for a variant
/// that cannot arrive.
///
/// Written as an explicit `matches!` over named variants rather than a wildcard
/// so that adding a variant to `WsClientMessage` cannot quietly grant it to
/// visitors.
fn visitor_may_send(msg: &WsClientMessage) -> bool {
    matches!(
        msg,
        WsClientMessage::VoiceJoin { .. }
            | WsClientMessage::VoiceLeave { .. }
            | WsClientMessage::VoiceSpeaking { .. }
            | WsClientMessage::VoiceKeyOffer { .. }
            | WsClientMessage::Ping { .. }
    )
}

/// A short name for the log line above. Only used for diagnostics, so it does
/// not have to be exhaustive — but it does have to say *something*, which is
/// the whole difference from a silent drop.
fn msg_kind(msg: &WsClientMessage) -> &'static str {
    match msg {
        WsClientMessage::Subscribe { .. } => "subscribe",
        WsClientMessage::Unsubscribe { .. } => "unsubscribe",
        WsClientMessage::Typing { .. } => "typing",
        WsClientMessage::SetStatus { .. } => "set_status",
        WsClientMessage::DmTyping { .. } => "dm_typing",
        WsClientMessage::ComponentInteraction { .. } => "component_interaction",
        WsClientMessage::VoiceWatch { .. } => "voice_watch",
        WsClientMessage::VoiceUnwatch => "voice_unwatch",
        _ => "other",
    }
}

async fn dispatch_client_msg(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    bot_tx: &mpsc::Sender<String>,
    msg: WsClientMessage,
) -> DispatchResult {
    // Alliance-voice visitor confinement (alliances.md "Scope enforcement —
    // allowlist, not denylist").
    //
    // An allowlist, so a route added tomorrow is closed by default rather than
    // open by omission. And the refused case *logs* instead of falling into a
    // silent no-op: an `Other => {}` arm on this very enum is how four hub
    // features were absent for months with no symptom, and the server
    // CLAUDE.md names it as the bug class to watch for here.
    if cs.alliance_voice_channel.is_some() && !visitor_may_send(&msg) {
        tracing::info!(
            visitor = %&cs.public_key[..16.min(cs.public_key.len())],
            message = msg_kind(&msg),
            "Dropped WS message outside the alliance_voice allowlist"
        );
        return DispatchResult::Continue;
    }

    match msg {
        // ── Subscriptions ──────────────────────────────────────────────────
        WsClientMessage::Subscribe { .. } => screen::handle_subscribe(cs, state, ws_tx, msg).await,
        WsClientMessage::Unsubscribe { .. } => screen::handle_unsubscribe(cs, msg),

        // ── Chat ───────────────────────────────────────────────────────────
        WsClientMessage::Typing { .. } => chat::handle_typing(cs, state, msg).await,
        WsClientMessage::SetStatus { .. } => chat::handle_set_status(cs, state, msg).await,
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
        // The client still times the round trip itself — the hub keeps no
        // probe table. The loss figure is read from a map the relay maintains
        // anyway, so replying costs one lock and no bookkeeping.
        WsClientMessage::Ping { nonce } => {
            let outbound_loss_pct = crate::voice_loss::loss_percent(
                state.voice_outbound_loss.read().await.get(&cs.public_key),
            );
            let json = serde_json::to_string(&WsServerMessage::Pong {
                nonce,
                outbound_loss_pct,
            })
            .unwrap();
            let _ = ws_tx.send(Message::Text(json.into())).await;
            DispatchResult::Continue
        }
        WsClientMessage::VoiceUnwatch => {
            cs.voice_channel = None;
            DispatchResult::Continue
        }
        WsClientMessage::VoiceLeave { .. } => voice::handle_voice_leave(cs, state, msg).await,
        WsClientMessage::VoiceSpeaking { .. } => voice::handle_voice_speaking(cs, state, msg).await,
        WsClientMessage::VoiceWhisperStart { .. } => {
            voice::handle_voice_whisper_start(cs, state, msg).await
        }
        WsClientMessage::VoiceWhisperStop => voice::handle_voice_whisper_stop(cs, state).await,
        WsClientMessage::VoiceWhisperOptout { .. } => {
            voice::handle_voice_whisper_optout(cs, state, msg).await
        }
        WsClientMessage::VoiceMove { .. } => voice::handle_voice_move(cs, state, ws_tx, msg).await,

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
            screen::handle_screen_share_start(cs, state, ws_tx, msg).await
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
        WsClientMessage::MiniAppMessage { .. } => {
            mini_app::handle_mini_app_message(cs, state, msg).await
        }

        // ── V4 voice encryption ────────────────────────────────────────────
        WsClientMessage::VoiceKeyOffer { .. } => {
            voice::handle_voice_key_offer(cs, state, msg).await
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
    state.voice_last_active.write().await.remove(public_key);
    let (removed_session, became_empty) = {
        let mut channels = state.voice_channels.write().await;
        let session = channels
            .get_mut(channel_id)
            .and_then(|participants| participants.remove(public_key))
            .flatten();
        let mut became_empty = false;
        if let Some(participants) = channels.get(channel_id) {
            if participants.is_empty() {
                became_empty = true;
                channels.remove(channel_id);
            }
        }
        (session, became_empty)
    };

    if became_empty {
        // Stamp temp-channel GC bookkeeping (temp-voice-channels.md §3); a
        // no-op for ordinary channels since the WHERE clause only matches
        // is_temporary rows. `temp_channel_worker` sweeps rooms stamped
        // this way once past the grace period.
        let now = crate::auth::handlers::unix_timestamp();
        let _ = sqlx::query(
            "UPDATE channels SET empty_since = $1 WHERE id = $2 AND is_temporary = TRUE",
        )
        .bind(now)
        .bind(channel_id)
        .execute(&state.db)
        .await;
    }
    // WS leave_voice is authoritative for roster (voice-transport-v2.md):
    // proactively close any still-live WT session rather than leaving it to
    // idle out on its own now that it has no roster entry.
    if let Some(session) = removed_session {
        session.close(wtransport::VarInt::from_u32(0), b"voice_leave");
    }

    // Remove any un-consumed pending bind for this pubkey.
    {
        let mut binds = state.voice_pending_binds.write().await;
        binds.retain(|_, v| v.pubkey != public_key);
    }

    // An invisible participant was never announced as joined, so don't
    // announce them leaving either (a Left for someone who toggled invisible
    // mid-call was already emitted by handle_set_status). Same gate as the
    // join broadcast.
    if !crate::routes::users::is_invisible(&state.db, public_key).await {
        let _ = state.voice_event_tx.send((
            channel_id.to_string(),
            WsServerMessage::VoiceParticipantLeft {
                channel_id: channel_id.to_string(),
                public_key: public_key.to_string(),
            },
        ));
    }

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

    // Clean up the departing user's whisper session (whisper.md: a session
    // is torn down when the whisperer leaves voice). If they were an active
    // whisperer, notify the previously-resolved recipients so their
    // indicators clear -- the hub-routed audio is about to stop too since
    // this pubkey no longer has a voice_channels entry.
    state.whisper_target_defs.write().await.remove(public_key);
    let prev_whisper_pks = state
        .whisper_target_pubkeys
        .write()
        .await
        .remove(public_key);
    if let Some(prev_whisper_pks) = prev_whisper_pks {
        super::voice::send_whisper_notification(
            state,
            public_key,
            channel_id,
            false,
            prev_whisper_pks.into_iter().collect(),
        );
    }

    // Revoke the voice relay slot.
    state.voice_relay_active.write().await.remove(public_key);
    state.voice_outbound_loss.write().await.remove(public_key);

    // events.md §7.4: a voice-only presence grant for this exact
    // (pubkey, channel) pair evaporates on leave -- never persisted, never
    // outlives the voice session. Both WS disconnect and explicit
    // VoiceLeave funnel through this shared teardown.
    {
        let mut grants = state.staging_voice_grants.write().await;
        if let Some(set) = grants.get_mut(public_key) {
            set.remove(channel_id);
            if set.is_empty() {
                grants.remove(public_key);
            }
        }
    }

    // Broadcast updated roster.
    let roster = get_voice_roster(state, channel_id).await;
    let _ = state.voice_event_tx.send((
        channel_id.to_string(),
        WsServerMessage::VoiceRosterUpdate {
            channel_id: channel_id.to_string(),
            participants: roster,
        },
    ));

    // The departing user may be a RECIPIENT in other users' whisper
    // sessions; re-resolve here (not just in the explicit voice-leave
    // handler) so raw WS-disconnect teardown drops them from every
    // resolved target set too.
    super::voice::re_resolve_whisper_sessions(state).await;
}
