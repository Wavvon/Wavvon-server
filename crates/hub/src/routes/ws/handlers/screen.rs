use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;

use crate::routes::chat_models::{HubStreamInfo, WsClientMessage, WsServerMessage};
use crate::state::{ActiveShare, AppState, ScreenChunkEvent};

use crate::routes::ws::conn_state::{ConnState, DispatchResult};
use crate::routes::ws::screen_share::send_v2_signal;

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

pub(in crate::routes::ws) async fn handle_subscribe(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::Subscribe { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    let newly_subscribed = cs.subscribed.insert(channel_id.clone());
    if !newly_subscribed {
        return DispatchResult::Continue;
    }

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
                return DispatchResult::Break;
            }
            cs.notified_streams
                .insert((channel_id.clone(), stream_id.clone()));
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
                    return DispatchResult::Break;
                }
                if ws_tx
                    .send(Message::Binary(init_bytes.to_vec().into()))
                    .await
                    .is_err()
                {
                    return DispatchResult::Break;
                }
            }
        }
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_unsubscribe(
    cs: &mut ConnState,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::Unsubscribe { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };
    cs.subscribed.remove(&channel_id);
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_screen_share_chunk_header(
    cs: &mut ConnState,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id, seq, is_init) = match msg {
        WsClientMessage::ScreenShareChunk {
            channel_id,
            stream_id,
            seq,
            is_init,
        } => (channel_id, stream_id, seq, is_init),
        _ => return DispatchResult::Continue,
    };
    cs.pending_chunk = Some((channel_id, stream_id, seq, is_init));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_binary_chunk(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    data: bytes::Bytes,
) -> DispatchResult {
    if let Some((ch_id, st_id, seq, is_init)) = cs.pending_chunk.take() {
        if is_init {
            let mut shares = state.screen_shares.write().await;
            let key = (ch_id.clone(), cs.public_key.clone());
            if let Some(active) = shares.get_mut(&key) {
                if let Some(meta) = active.streams.get_mut(&st_id) {
                    meta.init_chunk = Some(data.clone());
                }
            }
        }
        let _ = state.screen_share_tx.send(ScreenChunkEvent {
            channel_id: ch_id,
            stream_id: st_id,
            sharer_pubkey: cs.public_key.clone(),
            seq,
            is_init,
            data,
        });
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_start(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id, kind, mime, has_audio) = match msg {
        WsClientMessage::ScreenShareStart {
            channel_id,
            stream_id,
            kind,
            mime,
            has_audio,
            ..
        } => (channel_id, stream_id, kind, mime, has_audio),
        _ => return DispatchResult::Continue,
    };

    {
        let mut shares = state.screen_shares.write().await;
        let active = shares
            .entry((channel_id.clone(), cs.public_key.clone()))
            .or_insert_with(|| ActiveShare {
                streams: std::collections::HashMap::new(),
                viewers: std::collections::HashSet::new(),
                cross_channel_subscribers: std::collections::HashSet::new(),
            });
        active.streams.insert(
            stream_id.clone(),
            crate::state::ScreenStreamMeta {
                kind: kind.clone(),
                mime: mime.clone(),
                has_audio,
                sharer_pubkey: cs.public_key.clone(),
                session_id: cs.session_id.clone(),
                init_chunk: None,
                started_at: std::time::Instant::now(),
            },
        );
    }

    let ev = crate::routes::chat_models::ChatEvent::ScreenShareStarted {
        channel_id: channel_id.clone(),
        stream_id: stream_id.clone(),
        sharer_pubkey: cs.public_key.clone(),
        kind: kind.clone(),
        mime: mime.clone(),
        has_audio,
    };
    let ws_msg = WsServerMessage::ScreenShareStarted {
        channel_id,
        stream_id,
        sharer_pubkey: cs.public_key.clone(),
        kind,
        mime,
        has_audio,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_stop(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id) = match msg {
        WsClientMessage::ScreenShareStop {
            channel_id,
            stream_id,
        } => (channel_id, stream_id),
        _ => return DispatchResult::Continue,
    };

    let cross_subscribers: Vec<String> = {
        let mut shares = state.screen_shares.write().await;
        let key = (channel_id.clone(), cs.public_key.clone());
        let mut subs = Vec::new();
        if let Some(active) = shares.get_mut(&key) {
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
            sharer_pubkey: cs.public_key.clone(),
        };
        let ws_msg = WsServerMessage::ScreenShareStopped {
            channel_id: channel_id.clone(),
            stream_id: stream_id.clone(),
            sharer_pubkey: cs.public_key.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }

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
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_viewer_join(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id) = match msg {
        WsClientMessage::ScreenShareViewerJoin {
            channel_id,
            stream_id,
        } => (channel_id, stream_id),
        _ => return DispatchResult::Continue,
    };

    let share_exists = {
        let shares = state.screen_shares.read().await;
        shares
            .iter()
            .any(|((ch, _), active)| ch == &channel_id && active.streams.contains_key(&stream_id))
    };
    if !share_exists {
        let err = WsServerMessage::Error {
            context: "screen_share_viewer_join".to_string(),
            message: "No active share with that stream_id in this channel.".to_string(),
        };
        let _ = ws_tx
            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
            .await;
        return DispatchResult::Continue;
    }

    let sharer_pubkey: Option<String> = {
        let mut shares = state.screen_shares.write().await;
        shares
            .iter_mut()
            .find(|((ch, _), active)| ch == &channel_id && active.streams.contains_key(&stream_id))
            .map(|((_, sharer), active)| {
                active.viewers.insert(cs.public_key.clone());
                sharer.clone()
            })
    };
    if let Some(sharer) = sharer_pubkey {
        let reply = WsServerMessage::ScreenShareViewerJoined {
            channel_id: channel_id.clone(),
            stream_id: stream_id.clone(),
            from_pubkey: cs.public_key.clone(),
        };
        send_v2_signal(state, channel_id, sharer, reply);
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_viewer_leave(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id) = match msg {
        WsClientMessage::ScreenShareViewerLeave {
            channel_id,
            stream_id,
        } => (channel_id, stream_id),
        _ => return DispatchResult::Continue,
    };

    let sharer_pubkey: Option<String> = {
        let mut shares = state.screen_shares.write().await;
        shares
            .iter_mut()
            .find(|((ch, _), active)| ch == &channel_id && active.streams.contains_key(&stream_id))
            .map(|((_, sharer), active)| {
                active.viewers.remove(&cs.public_key);
                sharer.clone()
            })
    };
    if let Some(sharer) = sharer_pubkey {
        send_v2_signal(
            state,
            channel_id.clone(),
            sharer,
            WsServerMessage::ScreenShareViewerLeft {
                channel_id,
                stream_id,
                from_pubkey: cs.public_key.clone(),
            },
        );
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_offer(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, stream_id, sdp) = match msg {
        WsClientMessage::ScreenShareOffer {
            channel_id,
            to_pubkey,
            stream_id,
            sdp,
        } => (channel_id, to_pubkey, stream_id, sdp),
        _ => return DispatchResult::Continue,
    };

    let share_exists = {
        let shares = state.screen_shares.read().await;
        shares
            .get(&(channel_id.clone(), cs.public_key.clone()))
            .map(|a| a.streams.contains_key(&stream_id))
            .unwrap_or(false)
    };
    if !share_exists {
        return DispatchResult::Continue;
    }
    send_v2_signal(
        state,
        channel_id.clone(),
        to_pubkey.clone(),
        WsServerMessage::ScreenShareOfferIn {
            channel_id,
            to_pubkey: to_pubkey.clone(),
            stream_id,
            sdp,
            from_pubkey: cs.public_key.clone(),
        },
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_answer(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, stream_id, sdp) = match msg {
        WsClientMessage::ScreenShareAnswer {
            channel_id,
            to_pubkey,
            stream_id,
            sdp,
        } => (channel_id, to_pubkey, stream_id, sdp),
        _ => return DispatchResult::Continue,
    };

    let share_exists = {
        let shares = state.screen_shares.read().await;
        shares
            .get(&(channel_id.clone(), to_pubkey.clone()))
            .map(|a| a.streams.contains_key(&stream_id))
            .unwrap_or(false)
    };
    if !share_exists {
        return DispatchResult::Continue;
    }
    send_v2_signal(
        state,
        channel_id.clone(),
        to_pubkey.clone(),
        WsServerMessage::ScreenShareAnswerIn {
            channel_id,
            to_pubkey: to_pubkey.clone(),
            stream_id,
            sdp,
            from_pubkey: cs.public_key.clone(),
        },
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_screen_share_ice(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, stream_id, candidate) = match msg {
        WsClientMessage::ScreenShareIce {
            channel_id,
            to_pubkey,
            stream_id,
            candidate,
        } => (channel_id, to_pubkey, stream_id, candidate),
        _ => return DispatchResult::Continue,
    };

    let share_exists = {
        let shares = state.screen_shares.read().await;
        shares
            .get(&(channel_id.clone(), cs.public_key.clone()))
            .map(|a| a.streams.contains_key(&stream_id))
            .unwrap_or(false)
            || shares
                .get(&(channel_id.clone(), to_pubkey.clone()))
                .map(|a| a.streams.contains_key(&stream_id))
                .unwrap_or(false)
    };
    if !share_exists {
        return DispatchResult::Continue;
    }
    send_v2_signal(
        state,
        channel_id.clone(),
        to_pubkey.clone(),
        WsServerMessage::ScreenShareIceIn {
            channel_id,
            to_pubkey: to_pubkey.clone(),
            stream_id,
            candidate,
            from_pubkey: cs.public_key.clone(),
        },
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_stream_list(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
) -> DispatchResult {
    let shares = state.screen_shares.read().await;
    let mut stream_list: Vec<HubStreamInfo> = Vec::new();
    for ((ch_id, _sharer), active) in shares.iter() {
        if !cs.subscribed.contains(ch_id) {
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
    let msg = WsServerMessage::HubStreams {
        streams: stream_list,
    };
    let _ = ws_tx
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await;
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_stream_subscribe(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (source_channel_id, stream_id) = match msg {
        WsClientMessage::StreamSubscribe {
            source_channel_id,
            stream_id,
        } => (source_channel_id, stream_id),
        _ => return DispatchResult::Continue,
    };

    let can_view: bool = cs.subscribed.contains(&source_channel_id)
        || sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE id = $1")
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
        return DispatchResult::Continue;
    }

    let found: Option<(String, String, String, bool)> = {
        let mut shares = state.screen_shares.write().await;
        let entry = shares.iter_mut().find(|((ch, _), active)| {
            ch == &source_channel_id && active.streams.contains_key(&stream_id)
        });
        entry.and_then(|((_, sharer), active)| {
            active
                .cross_channel_subscribers
                .insert(cs.public_key.clone());
            let meta = active.streams.get(&stream_id)?;
            Some((
                sharer.clone(),
                meta.kind.clone(),
                meta.mime.clone(),
                meta.has_audio,
            ))
        })
    };

    if let Some((sharer_pubkey, kind, mime, has_audio)) = found {
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
                        .send(Message::Text(
                            serde_json::to_string(&chunk_env).unwrap().into(),
                        ))
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
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_stream_unsubscribe(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (source_channel_id, stream_id) = match msg {
        WsClientMessage::StreamUnsubscribe {
            source_channel_id,
            stream_id,
        } => (source_channel_id, stream_id),
        _ => return DispatchResult::Continue,
    };

    let mut shares = state.screen_shares.write().await;
    if let Some((_, active)) = shares.iter_mut().find(|((ch, _), active)| {
        ch == &source_channel_id && active.streams.contains_key(&stream_id)
    }) {
        active.cross_channel_subscribers.remove(&cs.public_key);
    }
    DispatchResult::Continue
}
