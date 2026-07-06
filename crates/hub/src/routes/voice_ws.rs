use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::routes::chat_models::{VoiceParticipantInfo, WsServerMessage};
use crate::routes::ws::{get_voice_participants, leave_voice};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct VoiceWsParams {
    pub token: String,
    pub channel_id: String,
}

pub async fn handle_voice_ws(
    ws: WebSocketUpgrade,
    Query(params): Query<VoiceWsParams>,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| voice_ws_task(socket, params, state))
}

async fn voice_ws_task(socket: WebSocket, params: VoiceWsParams, state: Arc<AppState>) {
    // Authenticate token — same validator the main WS endpoint uses.
    let pubkey = match crate::auth::handlers::validate_ws_token(&state.db, &params.token).await {
        Ok(pk) => pk,
        Err(_) => return,
    };

    // `channel_id` may be reassigned below by the spawn-on-join path
    // (temp-voice-channels.md §2) once we know the target is a spawner.
    let mut channel_id = params.channel_id.clone();

    // Verify the channel exists and capture its type, needed for the
    // spawn-on-join check below.
    let channel_type: Option<String> = sqlx::query_scalar(
        "SELECT channel_type FROM channels WHERE id = $1 AND is_category = false",
    )
    .bind(&channel_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(channel_type) = channel_type else {
        return;
    };

    let (display_name, is_bot): (Option<String>, bool) = {
        let row: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
                .bind(&pubkey)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        match row {
            Some((dn, b)) => (dn, b),
            None => (None, false),
        }
    };

    // Bot audio injection (soundboard.md §2): a bot session joins this same
    // WS voice relay as a first-class participant, gated on the
    // `can_speak_voice` capability plus channel-scoped `read_messages` like
    // any other voice joiner. Human callers are unaffected by this branch.
    if is_bot {
        let caps_json: Option<String> =
            sqlx::query_scalar("SELECT capabilities FROM bot_profiles WHERE pubkey = $1")
                .bind(&pubkey)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        let capabilities: Vec<String> = caps_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        if !capabilities.iter().any(|c| c == "can_speak_voice") {
            return;
        }

        match crate::permissions::channel_permissions(&state.db, &pubkey, &channel_id).await {
            Ok(perms) if perms.has(crate::permissions::READ_MESSAGES) => {}
            _ => return,
        }
    }

    // Spawn-on-join (join-to-create temp voice channels,
    // temp-voice-channels.md §2): mirrors the main hub WS path in
    // routes/ws/handlers/voice.rs::handle_voice_join. The web client's audio
    // transport is this separate /voice/ws relay, so it needs the same
    // detection independently.
    if channel_type == "spawner" {
        // The bot branch above already gated on channel-scoped
        // read_messages against the spawner when applicable; human callers
        // are gated here, same rule (§3.4/§3.5: no effective READ_MESSAGES
        // means the channel — and therefore its spawn action — isn't
        // visible to them at all).
        if !is_bot {
            match crate::permissions::channel_permissions(&state.db, &pubkey, &channel_id).await {
                Ok(perms) if perms.has(crate::permissions::READ_MESSAGES) => {}
                _ => return,
            }
        }

        match crate::routes::channels::spawn_temp_channel(
            &state.db,
            &channel_id,
            &pubkey,
            display_name.as_deref(),
        )
        .await
        {
            Ok(spawned) => {
                channel_id = spawned.id;
                let json: std::sync::Arc<str> = std::sync::Arc::from(
                    serde_json::to_string(&WsServerMessage::ChannelsUpdated)
                        .unwrap()
                        .as_str(),
                );
                let _ = state
                    .chat_tx
                    .send((crate::routes::chat_models::ChatEvent::ChannelsUpdated, json));
            }
            Err(_) => return,
        }
    } else {
        // Rejoining an existing temp room cancels any pending GC timer
        // (temp-voice-channels.md §3), mirroring the main hub WS path.
        // No-op for ordinary channels since the WHERE clause only ever
        // matches is_temporary rows.
        let _ = sqlx::query(
            "UPDATE channels SET empty_since = NULL WHERE id = $1 AND is_temporary = TRUE",
        )
        .bind(&channel_id)
        .execute(&state.db)
        .await;
    }

    // Reject if already in this voice channel (duplicate join).
    {
        let channels = state.voice_channels.read().await;
        if let Some(ch) = channels.get(&channel_id) {
            if ch.contains_key(&pubkey) {
                return;
            }
        }
    }

    // Mark this pubkey as relay-active so the UDP loop can forward packets
    // originating from UDP peers to this WS client.
    state
        .voice_relay_active
        .write()
        .await
        .insert(pubkey.clone());

    // Assign a sender_id for this participant in this channel.
    let sender_id: u16 = {
        let mut counter = state.voice_next_sender_id.write().await;
        let c = counter.entry(channel_id.clone()).or_insert(0);
        let id = *c;
        *c = c.wrapping_add(1);
        id
    };
    state
        .voice_sender_ids
        .write()
        .await
        .entry(channel_id.clone())
        .or_default()
        .insert(pubkey.clone(), sender_id);

    // Add to voice_channels with the sentinel address — WS clients never bind a real UDP address.
    let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
    state
        .voice_channels
        .write()
        .await
        .entry(channel_id.clone())
        .or_default()
        .insert(pubkey.clone(), sentinel);

    // Create the mpsc channel used to push outbound binary frames to this client.
    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    state
        .voice_ws_senders
        .write()
        .await
        .insert(pubkey.clone(), ws_tx);

    // Collect current participants and send the ready frame.
    let participants = get_voice_participants(&state, &channel_id).await;
    let ready_msg = serde_json::json!({
        "type": "voice_ws_ready",
        "sender_id": sender_id,
        "participants": participants,
        // Resolved channel id — for a spawner join this is the newly
        // spawned temp room, not the channel the client requested. The
        // web client's resolveVoiceChannelId() prefers this field when
        // present (apps/web/src/platform/voiceReady.ts).
        "channel_id": channel_id,
    });

    // Broadcast VoiceParticipantJoined so other WS chat clients update their UI.
    let join_broadcast = WsServerMessage::VoiceParticipantJoined {
        channel_id: channel_id.clone(),
        participant: VoiceParticipantInfo {
            public_key: pubkey.clone(),
            display_name,
            is_bot,
        },
    };
    let _ = state
        .voice_event_tx
        .send((channel_id.clone(), join_broadcast));

    // Split the socket into sender and receiver halves.
    let (mut sink, mut stream) = socket.split();

    // Send the ready JSON text frame first.
    if sink
        .send(Message::Text(ready_msg.to_string().into()))
        .await
        .is_err()
    {
        cleanup(&state, &pubkey, &channel_id).await;
        return;
    }

    // Snapshot the UDP socket handle for the receive-loop fan-out.
    let udp_socket = state.voice_udp_socket.read().await.clone();

    // Outbound task: receives frames from the mpsc channel and writes them to the WS sink.
    let send_task = tokio::spawn(async move {
        while let Some(bytes) = ws_rx.recv().await {
            if sink.send(Message::Binary(bytes.into())).await.is_err() {
                break;
            }
        }
    });

    // Receive loop: client → hub → fan-out.
    let state_recv = state.clone();
    let pubkey_recv = pubkey.clone();
    let channel_recv = channel_id.clone();

    while let Some(Ok(msg)) = stream.next().await {
        match msg {
            Message::Binary(data) => {
                // Minimum upload packet: [seq:u16][ts:u32][opus...] = 6-byte header.
                if data.len() < 6 {
                    continue;
                }
                // If this sender is whispering, route their frames only to the
                // resolved target pubkeys, tagged 0x01; otherwise normal 0x00
                // fan-out to the whole channel.
                let whisper_pks = {
                    let map = state_recv.whisper_target_pubkeys.read().await;
                    map.get(&pubkey_recv).filter(|s| !s.is_empty()).cloned()
                };
                let packet_type: u8 = if whisper_pks.is_some() { 0x01 } else { 0x00 };
                // Build a ReceivedVoicePacket: [sender_id:u16][type][original upload bytes].
                let mut outbound = Vec::with_capacity(3 + data.len());
                outbound.extend_from_slice(&sender_id.to_be_bytes());
                outbound.push(packet_type);
                outbound.extend_from_slice(&data);

                fan_out(
                    &state_recv,
                    udp_socket.as_deref(),
                    &channel_recv,
                    &pubkey_recv,
                    &outbound,
                    whisper_pks.as_ref(),
                )
                .await;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    send_task.abort();
    cleanup(&state, &pubkey, &channel_id).await;
}

/// Fan out an already-encoded outbound packet to every other participant in the channel.
///
/// WS clients receive it via their mpsc channel; UDP clients receive it via sendto.
async fn fan_out(
    state: &AppState,
    udp_socket: Option<&tokio::net::UdpSocket>,
    channel_id: &str,
    sender_pk: &str,
    outbound: &[u8],
    // When Some, deliver only to these pubkeys (whisper). When None, deliver
    // to the whole channel.
    only_to: Option<&std::collections::HashSet<String>>,
) {
    let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let addr_map = state.voice_addr_map.read().await;
    let channels = state.voice_channels.read().await;
    let ws_senders = state.voice_ws_senders.read().await;

    if let Some(participants) = channels.get(channel_id) {
        for (pk, addr) in participants {
            if pk == sender_pk {
                continue;
            }
            if let Some(targets) = only_to {
                if !targets.contains(pk) {
                    continue;
                }
            }
            if let Some(tx) = ws_senders.get(pk.as_str()) {
                let _ = tx.send(outbound.to_vec());
            } else if *addr != sentinel && addr_map.contains_key(addr) {
                if let Some(sock) = udp_socket {
                    let _ = sock.send_to(outbound, *addr).await;
                }
            }
        }
    }
}

/// Clean up state when this WS connection closes.
async fn cleanup(state: &Arc<AppState>, pubkey: &str, channel_id: &str) {
    // Drop the sender so the send_task drains and exits.
    state.voice_ws_senders.write().await.remove(pubkey);
    // Delegate the rest of the voice teardown to the standard leave_voice path.
    leave_voice(state, pubkey, channel_id).await;
}
