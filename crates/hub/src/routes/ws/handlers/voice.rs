use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;
use rand::RngCore;

use crate::routes::chat_models::{VoiceParticipantInfo, WsClientMessage, WsServerMessage};
use crate::state::{AppState, PendingVoiceBind};

use crate::routes::ws::conn_state::{ConnState, DispatchResult};
use crate::routes::ws::voice::{
    apply_pending_voice_move_assignment, get_voice_participants, get_voice_roster,
    re_resolve_whisper_sessions, resolve_role_addrs, resolve_whisper_targets,
};

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

pub(in crate::routes::ws) async fn handle_voice_join(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    // udp_port is kept for wire-format compatibility but is no longer used
    // to fabricate a loopback address.  The real source address is learned
    // via the VXRG UDP register packet after voice_join completes.
    let (mut channel_id, _udp_port) = match msg {
        WsClientMessage::VoiceJoin {
            channel_id,
            udp_port,
        } => (channel_id, udp_port),
        _ => return DispatchResult::Continue,
    };

    // Hub-wide voice mute check.
    let is_hub_muted = crate::routes::moderation::is_voice_muted(&state.db, &cs.public_key)
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
        return DispatchResult::Continue;
    }

    // Per-channel voice mute check.
    let is_ch_muted =
        crate::routes::moderation::is_channel_voice_muted(&state.db, &channel_id, &cs.public_key)
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
        return DispatchResult::Continue;
    }

    // Channel visibility gate (§3.4/§3.5): a channel the caller can't
    // effectively READ_MESSAGES isn't visible to them at all, so voice join
    // is rejected the same way message history and the channel list are --
    // UNLESS a voice-only presence grant (events.md §7.4) covers this exact
    // (pubkey, channel) pair, in which case the organizer's consented move
    // is the authorization and the join proceeds without READ_MESSAGES.
    // This is the single enforcement point that bypasses read-gating; the
    // grant is never consulted anywhere else.
    match crate::permissions::channel_permissions(&state.db, &cs.public_key, &channel_id).await {
        Ok(perms) if !perms.has(crate::permissions::READ_MESSAGES) => {
            let has_grant = state
                .staging_voice_grants
                .read()
                .await
                .get(&cs.public_key)
                .map(|grants| grants.contains(&channel_id))
                .unwrap_or(false);
            if !has_grant {
                let err = WsServerMessage::Error {
                    context: "voice_join".to_string(),
                    message: "You do not have access to this channel.".to_string(),
                };
                let _ = ws_tx
                    .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                    .await;
                return DispatchResult::Continue;
            }
        }
        Err(_) => {
            let err = WsServerMessage::Error {
                context: "voice_join".to_string(),
                message: "Unable to verify channel access.".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
        Ok(_) => {}
    }

    // events.md §7.5 (updated lifetime): a squad room linked to an event
    // whose `ends_at` has passed blocks *new* joins -- it never yanks anyone
    // already inside. Existing occupants keep talking; the room dies via
    // the ordinary temp-channel empty-GC once it drains, or is deleted
    // immediately if already empty by the reminder worker's sweep.
    let squad_room_event_ended: bool = sqlx::query_scalar::<_, bool>(
        "SELECT e.ends_at IS NOT NULL AND e.ends_at <= $2
         FROM channels c
         JOIN hub_events e ON e.id = c.event_id
         WHERE c.id = $1",
    )
    .bind(&channel_id)
    .bind(crate::auth::handlers::unix_timestamp())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);

    if squad_room_event_ended {
        let err = WsServerMessage::Error {
            context: "voice_join".to_string(),
            message: "This event has ended; its squad room no longer accepts new joins."
                .to_string(),
        };
        let _ = ws_tx
            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
            .await;
        return DispatchResult::Continue;
    }

    // Spawn-on-join (join-to-create temp voice channels,
    // temp-voice-channels.md §2): if the target is a spawner, create a
    // personal sibling room and join that instead. The read gate above
    // already ran against the spawner, and the sibling inherits the same
    // ancestor-chain cascade, so no further permission check is needed.
    let target_channel_type: Option<String> =
        sqlx::query_scalar("SELECT channel_type FROM channels WHERE id = $1")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    if target_channel_type.as_deref() == Some("spawner") {
        let joiner_display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
                .bind(&cs.public_key)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();

        match crate::routes::channels::spawn_temp_channel(
            &state.db,
            &channel_id,
            &cs.public_key,
            joiner_display_name.as_deref(),
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
            Err((_, message)) => {
                let err = WsServerMessage::Error {
                    context: "voice_join".to_string(),
                    message,
                };
                let _ = ws_tx
                    .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                    .await;
                return DispatchResult::Continue;
            }
        }
    } else {
        // Rejoining an existing temp room cancels any pending GC timer
        // (temp-voice-channels.md §3). No-op for ordinary channels since
        // the WHERE clause only ever matches is_temporary rows.
        let _ = sqlx::query(
            "UPDATE channels SET empty_since = NULL WHERE id = $1 AND is_temporary = TRUE",
        )
        .bind(&channel_id)
        .execute(&state.db)
        .await;
    }

    // Talk-power check.
    let min_talk_power: i64 =
        sqlx::query_scalar("SELECT COALESCE(min_talk_power, 0) FROM channels WHERE id = $1")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
    let min_talk_power = if min_talk_power == 0 {
        sqlx::query_scalar::<_, i64>(
            "SELECT min_talk_power FROM channel_settings WHERE channel_id = $1",
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
        let user_talk_power: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(r.talk_power), 0)
             FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_public_key = $1",
        )
        .bind(&cs.public_key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(0);

        let user_priority = crate::permissions::user_permissions(&state.db, &cs.public_key)
            .await
            .as_ref()
            .map(|p| p.max_priority)
            .unwrap_or(0);

        let effective_power = user_talk_power.max(user_priority);

        let hand_raised =
            crate::routes::moderation::has_raised_hand(&state.db, &channel_id, &cs.public_key)
                .await;

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
            return DispatchResult::Continue;
        }
    }

    // --- Token-gated source-address learning (Phase 1) ---
    //
    // We no longer fabricate a 127.0.0.1 address.  Instead:
    // 1. Mint a 32-byte random single-use register token.
    // 2. Store it in voice_pending_binds with a 30-second TTL.
    // 3. Return it in the voice_joined reply; the client will send a VXRG
    //    UDP packet carrying the token, at which point the relay loop
    //    binds the real source address into voice_addr_map.
    //
    // Purge stale pending binds opportunistically (on each new mint).
    let udp_register_token: String = {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    let now = std::time::Instant::now();
    let ttl = std::time::Duration::from_secs(30);

    {
        let mut binds = state.voice_pending_binds.write().await;
        // Purge expired entries before inserting.
        binds.retain(|_, v| v.expires_at > now);
        // Remove any prior pending bind for this pubkey (re-join race).
        binds.retain(|_, v| v.pubkey != cs.public_key);
        binds.insert(
            udp_register_token.clone(),
            PendingVoiceBind {
                channel_id: channel_id.clone(),
                pubkey: cs.public_key.clone(),
                expires_at: now + ttl,
            },
        );
    }

    // Register the pubkey in voice_channels (membership) using a sentinel
    // address.  The real SocketAddr is filled in by the VXRG handler; until
    // then the sentinel is never present in voice_addr_map, so no audio is
    // ever relayed to it (the fan-out filters by voice_addr_map membership).
    let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
    state
        .voice_channels
        .write()
        .await
        .entry(channel_id.clone())
        .or_default()
        .insert(cs.public_key.clone(), sentinel);
    // voice_addr_map is NOT updated here; it is updated by the VXRG handler.
    state
        .voice_relay_active
        .write()
        .await
        .insert(cs.public_key.clone());

    cs.voice_channel = Some(channel_id.clone());

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
        .insert(cs.public_key.clone(), sender_id);

    let participants = get_voice_participants(state, &channel_id).await;

    let reply = WsServerMessage::VoiceJoined {
        channel_id: channel_id.clone(),
        hub_udp_port: state.voice_udp_port,
        participants,
        udp_register_token,
    };
    let json = serde_json::to_string(&reply).unwrap();
    let _ = ws_tx.send(Message::Text(json.into())).await;

    let (display_name, is_bot): (Option<String>, bool) = {
        let row: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
                .bind(&cs.public_key)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        match row {
            Some((dn, b)) => (dn, b),
            None => (None, false),
        }
    };

    let _ = state.voice_event_tx.send((
        channel_id.clone(),
        WsServerMessage::VoiceParticipantJoined {
            channel_id: channel_id.clone(),
            participant: VoiceParticipantInfo {
                public_key: cs.public_key.clone(),
                display_name: display_name.clone(),
                is_bot,
            },
        },
    ));

    let roster = get_voice_roster(state, &channel_id).await;
    let _ = state.voice_event_tx.send((
        channel_id.clone(),
        WsServerMessage::VoiceRosterUpdate {
            channel_id: channel_id.clone(),
            participants: roster,
        },
    ));

    re_resolve_whisper_sessions(state).await;

    // V4 voice encryption: notify existing voice participants that a new
    // sender joined so they can forward their AES sender keys to it.
    {
        let existing_pubkeys: Vec<String> = {
            let vc = state.voice_channels.read().await;
            vc.get(&channel_id)
                .map(|m| {
                    m.keys()
                        .filter(|pk| *pk != &cs.public_key)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        let req = WsServerMessage::VoiceKeyRequest {
            channel_id: channel_id.clone(),
            new_sender_id: sender_id,
            new_pubkey: cs.public_key.clone(),
        };
        let senders = state.ws_key_senders.read().await;
        for pk in &existing_pubkeys {
            if let Some(tx) = senders.get(pk) {
                let _ = tx.send(req.clone());
            }
        }
    }

    // Send current voice zone state snapshot to the joining participant.
    let zones_snapshot: Vec<crate::routes::chat_models::VoiceZoneSnapshot> = {
        let zones = state.voice_zones.read().await;
        zones
            .iter()
            .filter(|((ch, _), _)| ch == &channel_id)
            .map(
                |((_, zone_id), z)| crate::routes::chat_models::VoiceZoneSnapshot {
                    zone_id: zone_id.clone(),
                    name: z.name.clone(),
                    coordinate_system: z.coordinate_system.clone(),
                    attenuation: crate::routes::chat_models::AttenuationConfigMsg {
                        model: z.attenuation.model.clone(),
                        max_radius: z.attenuation.max_radius,
                        ref_dist: z.attenuation.ref_dist,
                        rolloff: z.attenuation.rolloff,
                    },
                    positions: z.positions.clone(),
                },
            )
            .collect()
    };
    if !zones_snapshot.is_empty() {
        let msg = WsServerMessage::VoiceZoneState {
            channel_id: channel_id.clone(),
            zones: zones_snapshot,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let _ = ws_tx.send(Message::Text(json.into())).await;
    }

    // Send video participants snapshot.
    let video_pubkeys: Vec<String> = {
        let vc = state.video_channels.read().await;
        vc.get(&channel_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    };
    if !video_pubkeys.is_empty() {
        let msg = WsServerMessage::VideoParticipants {
            channel_id: channel_id.clone(),
            pubkeys: video_pubkeys,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let _ = ws_tx.send(Message::Text(json.into())).await;
    }

    // Publish member.joined audit event.
    {
        let state_c = state.clone();
        let pk = cs.public_key.clone();
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
            )
            .await;
        });
    }

    // events.md §7.3: apply any queued voice-move assignment now that the
    // join has fully succeeded.
    apply_pending_voice_move_assignment(state, &cs.public_key, &channel_id).await;

    tracing::info!(
        "Voice join: {} in channel",
        &cs.public_key[..16.min(cs.public_key.len())]
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_leave(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::VoiceLeave { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    crate::routes::ws::connection::leave_voice(state, &cs.public_key, &channel_id).await;
    cs.voice_channel = None;
    re_resolve_whisper_sessions(state).await;

    {
        let state_c = state.clone();
        let pk = cs.public_key.clone();
        let ch = channel_id.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "member.left",
                Some(&pk),
                None,
                Some(&ch),
                serde_json::json!({}),
            )
            .await;
        });
    }
    tracing::info!(
        "Voice leave: {}",
        &cs.public_key[..16.min(cs.public_key.len())]
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_voice_speaking(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, speaking) = match msg {
        WsClientMessage::VoiceSpeaking {
            channel_id,
            speaking,
        } => (channel_id, speaking),
        _ => return DispatchResult::Continue,
    };
    let _ = state.voice_event_tx.send((
        channel_id.clone(),
        WsServerMessage::VoiceParticipantSpeaking {
            channel_id,
            public_key: cs.public_key.clone(),
            speaking,
        },
    ));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_whisper_start(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let targets = match msg {
        WsClientMessage::VoiceWhisperStart { targets } => targets,
        _ => return DispatchResult::Continue,
    };

    let my_addr = {
        let vc = state.voice_channels.read().await;
        if let Some(ch) = &cs.voice_channel {
            vc.get(ch).and_then(|p| p.get(&cs.public_key)).copied()
        } else {
            None
        }
    };
    let my_addr = match my_addr {
        Some(a) => a,
        None => return DispatchResult::Continue,
    };

    let mut addrs = resolve_whisper_targets(state, &targets, my_addr).await;
    for def in &targets {
        if def.target_type == "role" {
            addrs.extend(resolve_role_addrs(state, &def.id, my_addr).await);
        }
    }

    state
        .whisper_targets
        .write()
        .await
        .insert(cs.public_key.clone(), addrs.clone());
    state
        .whisper_target_defs
        .write()
        .await
        .insert(cs.public_key.clone(), targets.clone());

    // Resolve targets to pubkeys directly (works for web clients, which have
    // no stable UDP addr). "user" → the pubkey; "channel" → everyone in that
    // voice channel. This set drives both the notification delivery and the
    // WS voice relay's whisper routing (`voice_ws.rs`).
    let target_pks: std::collections::HashSet<String> = {
        let mut set = std::collections::HashSet::new();
        let vc = state.voice_channels.read().await;
        for def in &targets {
            match def.target_type.as_str() {
                "user" => {
                    set.insert(def.id.clone());
                }
                "channel" => {
                    if let Some(p) = vc.get(&def.id) {
                        for pk in p.keys() {
                            set.insert(pk.clone());
                        }
                    }
                }
                _ => {} // "role" targets still route via the UDP addr set above.
            }
        }
        set.remove(&cs.public_key); // never whisper to self
        set
    };
    state
        .whisper_target_pubkeys
        .write()
        .await
        .insert(cs.public_key.clone(), target_pks.clone());

    let target_pubkeys: Vec<String> = target_pks.into_iter().collect();
    let reply = WsServerMessage::VoiceWhisperStarted {
        sender_pubkey: cs.public_key.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::WhisperSignal {
        channel_id: cs.voice_channel.clone().unwrap_or_default(),
        to_pubkeys: target_pubkeys,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_whisper_stop(
    cs: &ConnState,
    state: &Arc<AppState>,
) -> DispatchResult {
    let prev_addrs = state.whisper_targets.write().await.remove(&cs.public_key);
    state
        .whisper_target_defs
        .write()
        .await
        .remove(&cs.public_key);
    let prev_pks = state
        .whisper_target_pubkeys
        .write()
        .await
        .remove(&cs.public_key);

    if prev_addrs.is_some() || prev_pks.is_some() {
        // Notify the pubkey-based target set (covers web + UDP targets).
        let target_pubkeys: Vec<String> = prev_pks.unwrap_or_default().into_iter().collect();
        let reply = WsServerMessage::VoiceWhisperStopped {
            sender_pubkey: cs.public_key.clone(),
        };
        let ev = crate::routes::chat_models::ChatEvent::WhisperSignal {
            channel_id: cs.voice_channel.clone().unwrap_or_default(),
            to_pubkeys: target_pubkeys,
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));
    }
    DispatchResult::Continue
}

/// Sends a `voice_move`-context `Error` back to the mover on `ws_tx`.
async fn send_voice_move_error(ws_tx: &mut WsTx, message: impl Into<String>) -> DispatchResult {
    let err = WsServerMessage::Error {
        context: "voice_move".to_string(),
        message: message.into(),
    };
    let _ = ws_tx
        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
        .await;
    DispatchResult::Continue
}

/// Move primitive (events.md §7.1, §7.3, §7.4): the mover asks the hub to
/// move `target_pubkey` into `target_channel_id`. The hub never yanks the
/// target server-side — it pushes a `voice_move` control message and the
/// target's own client runs its normal leave-and-join.
///
/// Phase 2 additions over the Phase 1 primitive:
/// - Target **not in voice** + `event_id` present → the move is queued as an
///   `event_move_assignments` row instead of rejected (§7.3); with no
///   `event_id` the Phase 1 rejection still applies (no event context to
///   apply it against later).
/// - Target **lacks `READ_MESSAGES`** on the destination + `event_id`
///   present → a voice-only presence grant is created (§7.4) and the move
///   proceeds instead of being rejected; with no `event_id` the Phase 1
///   rejection still applies (a generic mod-tool move must not reveal a
///   hidden channel).
pub(in crate::routes::ws) async fn handle_voice_move(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (target_pubkey, target_channel_id, event_id) = match msg {
        WsClientMessage::VoiceMove {
            target_pubkey,
            target_channel_id,
            event_id,
        } => (target_pubkey, target_channel_id, event_id),
        _ => return DispatchResult::Continue,
    };

    // Authorize the mover: MOVE_MEMBERS resolved channel-scoped against the
    // destination channel.
    match crate::permissions::channel_permissions(&state.db, &cs.public_key, &target_channel_id)
        .await
    {
        Ok(perms) if perms.has(crate::permissions::MOVE_MEMBERS) => {}
        Ok(_) => {
            return send_voice_move_error(
                ws_tx,
                "You do not have permission to move members into this channel.",
            )
            .await;
        }
        Err(_) => {
            return send_voice_move_error(ws_tx, "Unable to verify move permission.").await;
        }
    }

    // Destination must be a real, non-category channel.
    let target_channel_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM channels WHERE id = $1 AND is_category = false")
            .bind(&target_channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let target_channel_name = match target_channel_name {
        Some(name) => name,
        None => {
            return send_voice_move_error(ws_tx, "Target channel does not exist.").await;
        }
    };

    // Resolve the target's current voice channel, if any.
    let source_channel_id = {
        let vc = state.voice_channels.read().await;
        vc.iter()
            .find(|(_, participants)| participants.contains_key(&target_pubkey))
            .map(|(channel_id, _)| channel_id.clone())
    };

    let source_channel_id = match source_channel_id {
        Some(ch) => ch,
        None => {
            // Target not in voice: with an event context, queue the
            // assignment (§7.3) for auto-application on their next voice
            // join instead of rejecting. No event context => Phase 1's
            // rejection still applies (there's no later trigger to apply
            // a bare, event-less move against).
            let Some(eid) = &event_id else {
                return send_voice_move_error(ws_tx, "Target is not currently in voice.").await;
            };

            let now = crate::auth::handlers::unix_timestamp();
            let res = sqlx::query(
                "INSERT INTO event_move_assignments
                     (event_id, user_pubkey, target_channel_id, assigned_by, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (event_id, user_pubkey) DO UPDATE
                 SET target_channel_id = EXCLUDED.target_channel_id,
                     assigned_by = EXCLUDED.assigned_by,
                     created_at = EXCLUDED.created_at",
            )
            .bind(eid)
            .bind(&target_pubkey)
            .bind(&target_channel_id)
            .bind(&cs.public_key)
            .bind(now)
            .execute(&state.db)
            .await;

            if let Err(e) = res {
                return send_voice_move_error(ws_tx, format!("Unable to queue assignment: {e}"))
                    .await;
            }

            // No ack to the mover on success (mirrors the live-push path
            // below, which also replies only on error) — the staging panel
            // confirms via GET /events/:id/assignments.
            tracing::info!(
                "Voice move queued: {} assigned by {} -> channel {} (event {})",
                &target_pubkey[..16.min(target_pubkey.len())],
                &cs.public_key[..16.min(cs.public_key.len())],
                &target_channel_id[..8.min(target_channel_id.len())],
                eid
            );
            return DispatchResult::Continue;
        }
    };

    // Does the target already hold effective READ_MESSAGES on the
    // destination?
    let target_can_read = match crate::permissions::channel_permissions(
        &state.db,
        &target_pubkey,
        &target_channel_id,
    )
    .await
    {
        Ok(perms) => perms.has(crate::permissions::READ_MESSAGES),
        Err(_) => {
            return send_voice_move_error(ws_tx, "Unable to verify target's channel access.").await;
        }
    };

    if !target_can_read {
        if event_id.is_none() {
            // No event context => Phase 1's rejection still applies: a
            // generic mod-tool move must not reveal a hidden channel.
            return send_voice_move_error(ws_tx, "Target cannot read the destination channel.")
                .await;
        }
        // §7.4: the organizer's consented, event-scoped move is the
        // authorization for voice-only presence. Insert the grant BEFORE
        // the push below so the target's imminent join passes the
        // voice-join read gate.
        state
            .staging_voice_grants
            .write()
            .await
            .entry(target_pubkey.clone())
            .or_default()
            .insert(target_channel_id.clone());
    }

    // §7.2 consent model: auto-accept when the target has claimed a slot or
    // RSVP'd "going" on the driving event. A slot claim is stored as
    // status='going' + slot_id, so a plain status check covers both cases.
    // No event_id => auto: false.
    let auto = match &event_id {
        Some(eid) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM event_rsvps
                 WHERE event_id = $1 AND user_pubkey = $2 AND status = 'going'
             )",
        )
        .bind(eid)
        .bind(&target_pubkey)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false),
        None => false,
    };

    let push = WsServerMessage::VoiceMove {
        target_channel_id: target_channel_id.clone(),
        target_channel_name,
        source_channel_id: Some(source_channel_id),
        event_id: event_id.clone(),
        auto,
    };
    let ev = crate::routes::chat_models::ChatEvent::VoiceMove {
        to_pubkey: target_pubkey.clone(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&push).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));

    tracing::info!(
        "Voice move: {} requested by {} -> channel {}",
        &target_pubkey[..16.min(target_pubkey.len())],
        &cs.public_key[..16.min(cs.public_key.len())],
        &target_channel_id[..8.min(target_channel_id.len())]
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_zone_create(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let (zone_id, name, coordinate_system, attenuation, auth_mode, session_id) = match msg {
        WsClientMessage::VoiceZoneCreate {
            zone_id,
            name,
            coordinate_system,
            attenuation,
            auth_mode,
            session_id,
        } => (
            zone_id,
            name,
            coordinate_system,
            attenuation,
            auth_mode,
            session_id,
        ),
        _ => return DispatchResult::Continue,
    };

    let can_create = {
        let perms = crate::permissions::user_permissions(&state.db, &cs.public_key).await;
        perms
            .map(|p| p.has("manage_voice") || p.has("admin"))
            .unwrap_or(false)
    };
    if !can_create {
        let err = WsServerMessage::Error {
            context: "voice_zone_create".to_string(),
            message: "Requires manage_voice permission.".to_string(),
        };
        let _ = ws_tx
            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
            .await;
        return DispatchResult::Continue;
    }

    let ch_id = match cs.voice_channel.clone() {
        Some(ch) => ch,
        None => {
            let err = WsServerMessage::Error {
                context: "voice_zone_create".to_string(),
                message: "Must be in voice to create a zone.".to_string(),
            };
            let _ = ws_tx
                .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
                .await;
            return DispatchResult::Continue;
        }
    };

    let zone = crate::state::VoiceZone {
        zone_id: zone_id.clone(),
        channel_id: ch_id.clone(),
        name: name.clone(),
        coordinate_system: coordinate_system.clone(),
        attenuation: crate::state::AttenuationConfig {
            model: attenuation.model.clone(),
            max_radius: attenuation.max_radius,
            ref_dist: attenuation.ref_dist,
            rolloff: attenuation.rolloff,
        },
        auth_mode: auth_mode.clone(),
        creator_pubkey: cs.public_key.clone(),
        session_id: session_id.clone(),
        positions: std::collections::HashMap::new(),
    };
    state
        .voice_zones
        .write()
        .await
        .insert((ch_id.clone(), zone_id.clone()), zone);

    let reply = WsServerMessage::VoiceZoneCreated {
        channel_id: ch_id.clone(),
        zone_id: zone_id.clone(),
        name: name.clone(),
        coordinate_system: coordinate_system.clone(),
        attenuation: attenuation.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::VoiceZone {
        channel_id: ch_id.clone(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    tracing::info!(
        "Voice zone created: {} in channel {}",
        &zone_id[..8.min(zone_id.len())],
        &ch_id[..8.min(ch_id.len())]
    );
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_zone_destroy(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let zone_id = match msg {
        WsClientMessage::VoiceZoneDestroy { zone_id } => zone_id,
        _ => return DispatchResult::Continue,
    };

    let ch_id = match cs.voice_channel.clone() {
        Some(ch) => ch,
        None => return DispatchResult::Continue,
    };

    let can_destroy = {
        let zones = state.voice_zones.read().await;
        zones
            .get(&(ch_id.clone(), zone_id.clone()))
            .map(|z| z.creator_pubkey == cs.public_key)
            .unwrap_or(false)
    };
    let can_destroy = can_destroy || {
        let perms = crate::permissions::user_permissions(&state.db, &cs.public_key).await;
        perms
            .map(|p| p.has("manage_voice") || p.has("admin"))
            .unwrap_or(false)
    };
    if !can_destroy {
        return DispatchResult::Continue;
    }

    state
        .voice_zones
        .write()
        .await
        .remove(&(ch_id.clone(), zone_id.clone()));

    let reply = WsServerMessage::VoiceZoneDestroyed {
        channel_id: ch_id.clone(),
        zone_id: zone_id.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::VoiceZone {
        channel_id: ch_id.clone(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_voice_position_update(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (zone_id, position) = match msg {
        WsClientMessage::VoicePositionUpdate { zone_id, position } => (zone_id, position),
        _ => return DispatchResult::Continue,
    };

    let ch_id = match cs.voice_channel.clone() {
        Some(ch) => ch,
        None => return DispatchResult::Continue,
    };

    if position.is_empty() || position.len() > 3 {
        return DispatchResult::Continue;
    }

    let allowed = {
        let zones = state.voice_zones.read().await;
        if let Some(z) = zones.get(&(ch_id.clone(), zone_id.clone())) {
            match z.auth_mode.as_str() {
                "creator_only" => z.creator_pubkey == cs.public_key,
                "session_roster" => false,
                _ => true,
            }
        } else {
            false
        }
    };
    if !allowed {
        return DispatchResult::Continue;
    }

    state
        .voice_zones
        .write()
        .await
        .entry((ch_id.clone(), zone_id.clone()))
        .and_modify(|z| {
            z.positions.insert(cs.public_key.clone(), position.clone());
        });

    let reply = WsServerMessage::VoicePositionUpdated {
        channel_id: ch_id.clone(),
        zone_id: zone_id.clone(),
        pubkey: cs.public_key.clone(),
        position: position.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::VoiceZone {
        channel_id: ch_id.clone(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_video_enable(
    cs: &ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::VideoEnable { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    let in_voice = state
        .voice_channels
        .read()
        .await
        .get(&channel_id)
        .map(|c| c.contains_key(&cs.public_key))
        .unwrap_or(false);
    if !in_voice {
        let err = WsServerMessage::Error {
            context: "video_enable".to_string(),
            message: "Must be in voice to enable video.".to_string(),
        };
        let _ = ws_tx
            .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
            .await;
        return DispatchResult::Continue;
    }

    state
        .video_channels
        .write()
        .await
        .entry(channel_id.clone())
        .or_default()
        .insert(cs.public_key.clone());

    let reply = WsServerMessage::VideoParticipantEnabled {
        channel_id: channel_id.clone(),
        pubkey: cs.public_key.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::Video { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) async fn handle_video_disable(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let channel_id = match msg {
        WsClientMessage::VideoDisable { channel_id } => channel_id,
        _ => return DispatchResult::Continue,
    };

    {
        let mut vc = state.video_channels.write().await;
        if let Some(set) = vc.get_mut(&channel_id) {
            set.remove(&cs.public_key);
            if set.is_empty() {
                vc.remove(&channel_id);
            }
        }
    }

    let reply = WsServerMessage::VideoParticipantDisabled {
        channel_id: channel_id.clone(),
        pubkey: cs.public_key.clone(),
    };
    let ev = crate::routes::chat_models::ChatEvent::Video { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_video_offer(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, sdp) = match msg {
        WsClientMessage::VideoOffer {
            channel_id,
            to_pubkey,
            sdp,
        } => (channel_id, to_pubkey, sdp),
        _ => return DispatchResult::Continue,
    };
    let reply = WsServerMessage::VideoOfferIn {
        channel_id: channel_id.clone(),
        from_pubkey: cs.public_key.clone(),
        to_pubkey: to_pubkey.clone(),
        sdp,
    };
    let ev = crate::routes::chat_models::ChatEvent::Video { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_video_answer(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, sdp) = match msg {
        WsClientMessage::VideoAnswer {
            channel_id,
            to_pubkey,
            sdp,
        } => (channel_id, to_pubkey, sdp),
        _ => return DispatchResult::Continue,
    };
    let reply = WsServerMessage::VideoAnswerIn {
        channel_id: channel_id.clone(),
        from_pubkey: cs.public_key.clone(),
        to_pubkey: to_pubkey.clone(),
        sdp,
    };
    let ev = crate::routes::chat_models::ChatEvent::Video { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

pub(in crate::routes::ws) fn handle_video_ice(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, to_pubkey, candidate) = match msg {
        WsClientMessage::VideoIce {
            channel_id,
            to_pubkey,
            candidate,
        } => (channel_id, to_pubkey, candidate),
        _ => return DispatchResult::Continue,
    };
    let reply = WsServerMessage::VideoIceIn {
        channel_id: channel_id.clone(),
        from_pubkey: cs.public_key.clone(),
        to_pubkey: to_pubkey.clone(),
        candidate,
    };
    let ev = crate::routes::chat_models::ChatEvent::Video { channel_id };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
    DispatchResult::Continue
}

/// V4 voice encryption: forward an AES sender-key bundle to each named
/// recipient.  The hub never inspects the ciphertext — it only routes the
/// bundle from sender to the recipient's WS connection via `ws_key_senders`.
pub(in crate::routes::ws) async fn handle_voice_key_offer(
    cs: &ConnState,
    state: &Arc<AppState>,
    msg: WsClientMessage,
) -> DispatchResult {
    let (channel_id, bundles) = match msg {
        WsClientMessage::VoiceKeyOffer {
            channel_id,
            bundles,
        } => (channel_id, bundles),
        _ => return DispatchResult::Continue,
    };

    // Resolve the numeric sender_id for this client in the channel.
    let from_sender_id = state
        .voice_sender_ids
        .read()
        .await
        .get(&channel_id)
        .and_then(|m| m.get(&cs.public_key))
        .copied()
        .unwrap_or(0);

    let senders = state.ws_key_senders.read().await;
    for bundle in bundles {
        if let Some(tx) = senders.get(&bundle.recipient_pubkey) {
            let delivery = WsServerMessage::VoiceKeyReceived {
                channel_id: channel_id.clone(),
                from_sender_id,
                from_pubkey: cs.public_key.clone(),
                ciphertext_hex: bundle.ciphertext_hex,
                nonce_hex: bundle.nonce_hex,
            };
            let _ = tx.send(delivery);
        }
        // Unknown recipients are silently dropped — not an error.
    }
    DispatchResult::Continue
}
