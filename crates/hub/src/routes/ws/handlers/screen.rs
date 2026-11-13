use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;

use crate::routes::chat_models::{HubStreamInfo, WsClientMessage, WsServerMessage};
use crate::state::{ActiveShare, AppState, ScreenChunkEvent};

use crate::routes::ws::conn_state::{ConnState, DispatchResult};

use super::{send_error, WsTx};

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

    // Read-gating (§3.5): mirror the auto-subscribe gate in
    // ws/connection.rs -- a channel the caller can't effectively
    // MESSAGES_READ must never be inserted into `subscribed`, or its live
    // messages/edits/typing/reactions/pins would leak over this connection.
    let can_read =
        match crate::permissions::channel_permissions(&state.db, &cs.public_key, &channel_id).await
        {
            Ok(perms) => perms.has(crate::permissions::MESSAGES_READ),
            Err(_) => false,
        };
    if !can_read {
        return send_error(
            ws_tx,
            "subscribe",
            "You do not have access to this channel.".to_string(),
        )
        .await;
    }

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
            if cs.streams_on_request {
                continue;
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

/// How many seconds of the cap a stream may send at once: a keyframe is far
/// larger than the frames around it.
const BITRATE_BURST_SECS: f64 = 4.0;

/// Token bucket over relayed bytes. The cap a stream declared used to be
/// checked only as a number at start, so a modified client could then send at
/// any rate; past the allowance a chunk is dropped instead of relayed.
fn within_bitrate(
    allowance: &mut (f64, std::time::Instant),
    kbps: u32,
    len: usize,
    now: std::time::Instant,
) -> bool {
    let bytes_per_sec = f64::from(kbps) * 125.0;
    let (tokens, last) = allowance;
    let elapsed = now.saturating_duration_since(*last).as_secs_f64();
    *tokens = (*tokens + elapsed * bytes_per_sec).min(bytes_per_sec * BITRATE_BURST_SECS);
    *last = now;
    if *tokens < len as f64 {
        return false;
    }
    *tokens -= len as f64;
    true
}

pub(in crate::routes::ws) async fn handle_binary_chunk(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    data: bytes::Bytes,
) -> DispatchResult {
    if let Some((ch_id, st_id, seq, is_init)) = cs.pending_chunk.take() {
        // Viewers key chunks by stream id, so a chunk for a stream this sender
        // did not start would play under the real sharer's name.
        let key = (ch_id.clone(), cs.public_key.clone());
        if is_init {
            let mut shares = state.screen_shares.write().await;
            let Some(meta) = shares
                .get_mut(&key)
                .and_then(|active| active.streams.get_mut(&st_id))
            else {
                return DispatchResult::Continue;
            };
            meta.init_chunk = Some(data.clone());
        } else {
            let max_kbps = {
                let shares = state.screen_shares.read().await;
                match shares.get(&key).and_then(|a| a.streams.get(&st_id)) {
                    Some(meta) => meta.max_kbps,
                    None => return DispatchResult::Continue,
                }
            };
            if let Some(kbps) = max_kbps {
                let now = std::time::Instant::now();
                let entry = cs
                    .chunk_allowance
                    .entry(st_id.clone())
                    .or_insert((f64::from(kbps) * 125.0 * BITRATE_BURST_SECS, now));
                if !within_bitrate(entry, kbps, data.len(), now) {
                    return DispatchResult::Continue;
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
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, stream_id, kind, mime, has_audio, width, height, fps, kbps) = match msg {
        WsClientMessage::ScreenShareStart {
            channel_id,
            stream_id,
            kind,
            mime,
            has_audio,
            width,
            height,
            fps,
            kbps,
        } => (
            channel_id, stream_id, kind, mime, has_audio, width, height, fps, kbps,
        ),
        _ => return DispatchResult::Continue,
    };

    let limits = crate::routes::hub::read_stream_limits(&state.db).await;
    if let Some(what) = limits.exceeded_by(width, height, fps, kbps) {
        return send_error(
            ws_tx,
            "screen_share_start",
            format!("This hub caps a stream's {what}; choose a lower setting."),
        )
        .await;
    }

    // Channel-scoped VOICE_JOIN: a screen share is something you do once
    // present in the call, so it follows admission to the call and not
    // admission to the text (permissions.md §3, Voice). This used to sit
    // inside an `if cs.is_bot` branch and so applied to nobody else — the
    // one check on this path was reachable only by the callers the hub had
    // labelled. There is no label now, and the rule was never about one.
    // On top of that, `voice.screen_share` (#277): talking and streaming are
    // separate grants, so a hub can let everyone in and only some share.
    match crate::permissions::channel_permissions(&state.db, &cs.public_key, &channel_id).await {
        Ok(perms)
            if perms.has(crate::permissions::VOICE_JOIN)
                && perms.has(crate::permissions::VOICE_SCREEN_SHARE) => {}
        _ => {
            return send_error(
                ws_tx,
                "screen_share_start",
                "You cannot share into this channel.".to_string(),
            )
            .await;
        }
    }

    {
        let mut shares = state.screen_shares.write().await;
        let active = shares
            .entry((channel_id.clone(), cs.public_key.clone()))
            .or_insert_with(|| ActiveShare {
                streams: std::collections::HashMap::new(),
                cross_channel_subscribers: std::collections::HashSet::new(),
            });
        active.streams.insert(
            stream_id.clone(),
            crate::state::ScreenStreamMeta {
                kind: kind.clone(),
                mime: mime.clone(),
                has_audio,
                sharer_pubkey: cs.public_key.clone(),
                via_http: false,
                session_id: cs.session_id.clone(),
                init_chunk: None,
                started_at: std::time::Instant::now(),
                max_kbps: match (kbps, limits.max_kbps) {
                    (Some(d), Some(m)) => Some(d.min(m)),
                    (d, m) => d.or(m),
                },
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
    cs: &mut ConnState,
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

    // Watching needs the access the source channel gives to the room itself:
    // reading it or joining its voice (#282). An unknown channel answers the
    // same as a forbidden one.
    let can_view: bool = cs.subscribed.contains(&source_channel_id)
        || crate::permissions::channel_permissions(&state.db, &cs.public_key, &source_channel_id)
            .await
            .map(|p| {
                p.has(crate::permissions::MESSAGES_READ) || p.has(crate::permissions::VOICE_JOIN)
            })
            .unwrap_or(false);

    if !can_view {
        return send_error(
            ws_tx,
            "stream_subscribe",
            "Channel not found or access denied.".to_string(),
        )
        .await;
    }

    let found: Option<(String, String, String, bool)> = {
        let mut shares = state.screen_shares.write().await;
        let entry = shares.iter_mut().find(|((ch, _), active)| {
            ch == &source_channel_id && active.streams.contains_key(&stream_id)
        });
        entry.and_then(|((_, sharer), active)| {
            if cs.streams_on_request {
                cs.opened_streams
                    .insert((source_channel_id.clone(), stream_id.clone()));
            } else {
                active
                    .cross_channel_subscribers
                    .insert(cs.public_key.clone());
            }
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
        return send_error(
            ws_tx,
            "stream_subscribe",
            "No active stream with that ID in the specified channel.".to_string(),
        )
        .await;
    }
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_stream_unsubscribe(
    cs: &mut ConnState,
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

    if cs.streams_on_request {
        cs.opened_streams.remove(&(source_channel_id, stream_id));
        return DispatchResult::Continue;
    }
    let mut shares = state.screen_shares.write().await;
    if let Some((_, active)) = shares.iter_mut().find(|((ch, _), active)| {
        ch == &source_channel_id && active.streams.contains_key(&stream_id)
    }) {
        active.cross_channel_subscribers.remove(&cs.public_key);
    }
    DispatchResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn the_relay_holds_a_stream_to_its_bitrate() {
        let start = Instant::now();
        // 8 kbps = 1000 bytes a second, 4000 of burst.
        let mut allowance = (4000.0, start);
        assert!(within_bitrate(&mut allowance, 8, 4000, start));
        assert!(!within_bitrate(&mut allowance, 8, 1, start), "burst spent");
        let later = start + Duration::from_secs(1);
        assert!(within_bitrate(&mut allowance, 8, 1000, later));
        assert!(!within_bitrate(&mut allowance, 8, 1, later));
        let much_later = start + Duration::from_secs(60);
        assert!(within_bitrate(&mut allowance, 8, 4000, much_later));
        assert!(
            !within_bitrate(&mut allowance, 8, 1, much_later),
            "refill stops at the burst"
        );
    }
}
