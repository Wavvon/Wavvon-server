use std::collections::HashSet;

use crate::routes::chat_models::{VoiceParticipantInfo, VoiceRosterEntry};
use crate::state::AppState;

/// Builds the participant list for `channel_id` as seen by `viewer`:
/// invisible members are omitted (decisions.md 2026-07-12 — invisible users
/// are shown offline to everyone else; the voice list was the known gap),
/// except the viewer themselves, who always sees their own entry.
pub async fn get_voice_participants(
    state: &AppState,
    channel_id: &str,
    viewer: Option<&str>,
) -> Vec<VoiceParticipantInfo> {
    let keys: Vec<String> = {
        let channels = state.voice_channels.read().await;
        let Some(participants) = channels.get(channel_id) else {
            return Vec::new();
        };
        participants.keys().cloned().collect()
    };
    let invisible = crate::routes::users::invisible_subset(&state.db, &keys).await;

    let mut result = Vec::new();
    for pk in keys
        .iter()
        .filter(|pk| Some(pk.as_str()) == viewer || !invisible.contains(*pk))
    {
        let row: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
                .bind(pk)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();

        let (display_name, is_bot) = match row {
            Some((dn, b)) => (dn, b),
            None => (None, false),
        };

        result.push(VoiceParticipantInfo {
            public_key: pk.clone(),
            display_name,
            is_bot,
        });
    }
    result
}

/// Resolve "user" and "channel" target defs into SocketAddrs.
/// Role targets require a DB query and must be handled by the caller via `resolve_role_addrs`.
pub(super) async fn resolve_whisper_targets(
    state: &AppState,
    defs: &[crate::state::WhisperTargetDef],
    exclude_addr: std::net::SocketAddr,
) -> HashSet<std::net::SocketAddr> {
    let voice_channels = state.voice_channels.read().await;
    let mut addrs = HashSet::new();
    for def in defs {
        match def.target_type.as_str() {
            "user" => {
                // Search all channels for the target pubkey.
                for participants in voice_channels.values() {
                    if let Some(addr) = participants.get(&def.id) {
                        if *addr != exclude_addr {
                            addrs.insert(*addr);
                        }
                    }
                }
            }
            "channel" => {
                if let Some(participants) = voice_channels.get(&def.id) {
                    for addr in participants.values() {
                        if *addr != exclude_addr {
                            addrs.insert(*addr);
                        }
                    }
                }
            }
            _ => {} // "role" handled separately; unknown types silently ignored
        }
    }
    addrs
}

/// Resolve all users with `role_id` that are currently in voice into SocketAddrs.
pub(super) async fn resolve_role_addrs(
    state: &AppState,
    role_id: &str,
    exclude_addr: std::net::SocketAddr,
) -> HashSet<std::net::SocketAddr> {
    let role_users: Vec<String> =
        sqlx::query_scalar("SELECT user_public_key FROM user_roles WHERE role_id = $1")
            .bind(role_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let voice_channels = state.voice_channels.read().await;
    let mut addrs = HashSet::new();
    for pk in &role_users {
        for participants in voice_channels.values() {
            if let Some(addr) = participants.get(pk.as_str()) {
                if *addr != exclude_addr {
                    addrs.insert(*addr);
                }
            }
        }
    }
    addrs
}

/// Walk every active whisper session and rebuild its resolved SocketAddr set from stored defs.
/// Called after any VoiceJoin or VoiceLeave so the live target set stays correct.
pub(super) async fn re_resolve_whisper_sessions(state: &AppState) {
    // Snapshot the current defs outside the write lock.
    let defs_map: Vec<(String, Vec<crate::state::WhisperTargetDef>)> = {
        state
            .whisper_target_defs
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    for (sender_pk, defs) in defs_map {
        // Find the sender's current SocketAddr (they may have just left voice).
        let sender_addr = {
            let vc = state.voice_channels.read().await;
            vc.values().find_map(|p| p.get(&sender_pk)).copied()
        };
        let sender_addr = match sender_addr {
            Some(a) => a,
            None => {
                // Sender is no longer in voice; their session will be cleaned up by leave_voice.
                continue;
            }
        };
        let mut new_addrs = resolve_whisper_targets(state, &defs, sender_addr).await;
        for def in &defs {
            if def.target_type == "role" {
                new_addrs.extend(resolve_role_addrs(state, &def.id, sender_addr).await);
            }
        }
        state
            .whisper_targets
            .write()
            .await
            .insert(sender_pk, new_addrs);
    }
}

/// Applies a queued voice-move assignment (events.md §7.3) after a
/// successful voice join, if one exists for `pubkey` whose
/// `target_channel_id` differs from `joined_channel_id` and belongs to an
/// event that hasn't ended yet (`ends_at IS NULL OR ends_at > now`).
///
/// Called from both voice-join paths (`routes/ws/handlers/voice.rs` and
/// `routes/voice_ws.rs`) right after a join succeeds. Pushes a `voice_move`
/// exactly like a live move — creating a voice-only presence grant (§7.4)
/// first if the target lacks `READ_MESSAGES` on the assigned channel. The
/// assignment row is intentionally left in place (not consumed): a
/// drop-and-rejoin during the event re-applies it (doc ruling).
///
/// An assignment does not itself imply consent (§7.2) — an organizer may
/// assign a member who never claimed a slot or RSVP'd "going"; `auto` is
/// computed the same way a live move computes it, not assumed `true`.
pub async fn apply_pending_voice_move_assignment(
    state: &AppState,
    pubkey: &str,
    joined_channel_id: &str,
) {
    let now = crate::auth::handlers::unix_timestamp();

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT ema.event_id, ema.target_channel_id
         FROM event_move_assignments ema
         INNER JOIN hub_events he ON he.id = ema.event_id
         WHERE ema.user_pubkey = $1
           AND ema.target_channel_id != $2
           AND (he.ends_at IS NULL OR he.ends_at > $3)
         ORDER BY ema.created_at DESC
         LIMIT 1",
    )
    .bind(pubkey)
    .bind(joined_channel_id)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let Some((event_id, target_channel_id)) = row else {
        return;
    };

    let target_channel_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM channels WHERE id = $1 AND is_category = false")
            .bind(&target_channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    // The assigned channel may have been deleted since the assignment was
    // made; nothing to apply in that case (the row is cleaned up by the
    // hub_events ON DELETE CASCADE if the event itself is gone, or lingers
    // harmlessly otherwise until pruned at event end).
    let Some(target_channel_name) = target_channel_name else {
        return;
    };

    // §7.4: create a voice-only presence grant before the push if the
    // target lacks effective READ_MESSAGES on the assigned channel.
    if let Ok(perms) =
        crate::permissions::channel_permissions(&state.db, pubkey, &target_channel_id).await
    {
        if !perms.has(crate::permissions::READ_MESSAGES) {
            state
                .staging_voice_grants
                .write()
                .await
                .entry(pubkey.to_string())
                .or_default()
                .insert(target_channel_id.clone());
        }
    }

    // §7.2: an assignment does not itself imply consent -- compute `auto`
    // the same way a live move does (a "going" RSVP, or slot claim stored
    // the same way, on the driving event).
    let auto: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM event_rsvps
             WHERE event_id = $1 AND user_pubkey = $2 AND status = 'going'
         )",
    )
    .bind(&event_id)
    .bind(pubkey)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    let push = crate::routes::chat_models::WsServerMessage::VoiceMove {
        target_channel_id: target_channel_id.clone(),
        target_channel_name,
        source_channel_id: Some(joined_channel_id.to_string()),
        event_id: Some(event_id.clone()),
        auto,
    };
    let ev = crate::routes::chat_models::ChatEvent::VoiceMove {
        to_pubkey: pubkey.to_string(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&push).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));

    tracing::info!(
        "Voice move applied from queued assignment: {} -> channel {} (event {})",
        &pubkey[..16.min(pubkey.len())],
        &target_channel_id[..8.min(target_channel_id.len())],
        event_id
    );
}

/// Roster (sender_id ↔ pubkey map) for `VoiceRosterUpdate` broadcasts.
/// Invisible members are omitted unconditionally — the broadcast is one
/// payload for all recipients, so there is no per-viewer exemption here.
/// Audio stays functional: clients play frames from unmapped sender_ids at
/// default gain, so a hidden participant is still heard.
pub(super) async fn get_voice_roster(state: &AppState, channel_id: &str) -> Vec<VoiceRosterEntry> {
    let sender_ids = state.voice_sender_ids.read().await;
    let ch_map = match sender_ids.get(channel_id) {
        Some(m) => m.clone(),
        None => return vec![],
    };
    drop(sender_ids);

    let keys: Vec<String> = ch_map.keys().cloned().collect();
    let invisible = crate::routes::users::invisible_subset(&state.db, &keys).await;

    let mut result = Vec::new();
    for (pk, sid) in ch_map {
        if invisible.contains(&pk) {
            continue;
        }
        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
                .bind(&pk)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        result.push(VoiceRosterEntry {
            sender_id: sid,
            public_key: pk,
            display_name,
        });
    }
    result
}
