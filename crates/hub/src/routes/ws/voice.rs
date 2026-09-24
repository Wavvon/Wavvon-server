use std::collections::{HashMap, HashSet};

use crate::routes::chat_models::{
    ChatEvent, VoiceParticipantInfo, VoiceRosterEntry, WsServerMessage,
};
use crate::state::AppState;

/// Sends a targeted `voice_whisper_started`/`voice_whisper_stopped` to
/// exactly `pubkeys` (never a broadcast — whisper.md's "New WS envelopes").
/// `channel_id` is the whisperer's current voice channel, per the existing
/// `WhisperSignal` delivery convention (filtered by `to_pubkeys`, not by
/// channel subscription semantics, but still carried for the `channel_id()`
/// contract). No-op if `pubkeys` is empty so callers can pass a diff result
/// unconditionally.
pub(super) fn send_whisper_notification(
    state: &AppState,
    sender_pubkey: &str,
    channel_id: &str,
    started: bool,
    pubkeys: Vec<String>,
) {
    if pubkeys.is_empty() {
        return;
    }
    let reply = if started {
        WsServerMessage::VoiceWhisperStarted {
            sender_pubkey: sender_pubkey.to_string(),
        }
    } else {
        WsServerMessage::VoiceWhisperStopped {
            sender_pubkey: sender_pubkey.to_string(),
        }
    };
    let ev = ChatEvent::WhisperSignal {
        channel_id: channel_id.to_string(),
        to_pubkeys: pubkeys,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&reply).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
}

/// How one pubkey in a voice room is named to everyone else: display name,
/// bot flag, and — for an alliance-voice visitor — the hub that vouched for
/// them (alliances.md).
///
/// A visitor has no `users` row here by design, so the plain lookup returns
/// nothing and, before this, they appeared as a bare key. Their name is
/// hub-asserted rather than proven, which is why it never travels without the
/// hub that asserted it: a client renders "name · HubName", never a name that
/// could pass for a local member's.
pub async fn voice_identity(
    state: &AppState,
    pubkey: &str,
) -> (Option<String>, bool, Option<String>) {
    let member: Option<(Option<String>, bool)> =
        sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
            .bind(pubkey)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if let Some((display_name, is_bot)) = member {
        return (display_name, is_bot, None);
    }

    let visitor: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT v.display_name, m.hub_name
         FROM alliance_voice_visitors v
         LEFT JOIN alliance_members m ON m.hub_public_key = v.origin_hub_pubkey
         WHERE v.subject_pubkey = $1",
    )
    .bind(pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    match visitor {
        Some((display_name, hub_name)) => (display_name, false, hub_name),
        None => (None, false, None),
    }
}

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
    let sender_ids: HashMap<String, u16> = state
        .voice_sender_ids
        .read()
        .await
        .get(channel_id)
        .cloned()
        .unwrap_or_default();

    let mut result = Vec::new();
    for pk in keys
        .iter()
        .filter(|pk| Some(pk.as_str()) == viewer || !invisible.contains(*pk))
    {
        let (display_name, is_bot, visiting_from) = voice_identity(state, pk).await;

        result.push(VoiceParticipantInfo {
            public_key: pk.clone(),
            display_name,
            is_bot,
            sender_id: sender_ids.get(pk).copied(),
            visiting_from,
        });
    }
    result
}

/// Resolve all users with `role_id` that are currently present in any voice
/// channel (roster membership — regardless of whether their WT session has
/// bound yet) into their pubkeys.
async fn resolve_role_pubkeys(state: &AppState, role_id: &str) -> HashSet<String> {
    let role_users: Vec<String> =
        sqlx::query_scalar("SELECT user_public_key FROM user_roles WHERE role_id = $1")
            .bind(role_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let voice_channels = state.voice_channels.read().await;
    role_users
        .into_iter()
        .filter(|pk| voice_channels.values().any(|p| p.contains_key(pk)))
        .collect()
}

/// Resolve "user"/"channel"/"role" whisper target defs into the pubkey set
/// used for pubkey-keyed delivery (the WT relay's whisper routing in
/// `voice_wt.rs`, keyed by pubkey since every session is). Shared by the
/// initial resolution in `handle_voice_whisper_start` and the
/// membership-change rebuild in `re_resolve_whisper_sessions` below, so both
/// stay in sync.
pub(super) async fn resolve_whisper_target_pubkeys(
    state: &AppState,
    defs: &[crate::state::WhisperTargetDef],
    exclude_pubkey: &str,
) -> HashSet<String> {
    let optouts = state.whisper_optouts.read().await;
    let mut pks = HashSet::new();
    {
        let vc = state.voice_channels.read().await;
        for def in defs {
            match def.target_type.as_str() {
                "user" => {
                    if !optouts.contains(&def.id) {
                        pks.insert(def.id.clone());
                    }
                }
                "channel" => {
                    if let Some(p) = vc.get(&def.id) {
                        for pk in p.keys() {
                            if !optouts.contains(pk) {
                                pks.insert(pk.clone());
                            }
                        }
                    }
                }
                _ => {} // "role" resolved separately below (needs its own DB query).
            }
        }
    }
    for def in defs {
        if def.target_type == "role" {
            for pk in resolve_role_pubkeys(state, &def.id).await {
                if !optouts.contains(&pk) {
                    pks.insert(pk);
                }
            }
        }
    }
    pks.remove(exclude_pubkey);
    pks
}

/// Walk every active whisper session and rebuild its resolved pubkey target
/// set from stored defs. Called after any VoiceJoin or VoiceLeave (and
/// whisper opt-out toggling) so the live target set stays correct. Diffs
/// against the previous value and pushes targeted `voice_whisper_started` /
/// `voice_whisper_stopped` notifications to exactly the added/removed
/// recipients (whisper.md "New WS envelopes" — never a broadcast, and never a
/// duplicate notification to someone whose membership didn't change).
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
        // Find the sender's current channel (they may have just left voice).
        let channel_id = {
            let vc = state.voice_channels.read().await;
            vc.iter()
                .find_map(|(cid, p)| p.contains_key(&sender_pk).then(|| cid.clone()))
        };
        let Some(channel_id) = channel_id else {
            // Sender is no longer in voice; their session (and the
            // stop-notification to prior recipients) is handled by
            // `leave_voice`'s own whisper teardown.
            continue;
        };

        let new_pks = resolve_whisper_target_pubkeys(state, &defs, &sender_pk).await;
        let old_pks = state
            .whisper_target_pubkeys
            .write()
            .await
            .insert(sender_pk.clone(), new_pks.clone())
            .unwrap_or_default();

        let added: Vec<String> = new_pks.difference(&old_pks).cloned().collect();
        let removed: Vec<String> = old_pks.difference(&new_pks).cloned().collect();
        send_whisper_notification(state, &sender_pk, &channel_id, true, added);
        send_whisper_notification(state, &sender_pk, &channel_id, false, removed);
    }
}

/// Applies a queued voice-move assignment (events.md §7.3) after a
/// successful voice join, if one exists for `pubkey` whose
/// `target_channel_id` differs from `joined_channel_id` and belongs to an
/// event that hasn't ended yet (`ends_at IS NULL OR ends_at > now`).
///
/// Called from the voice-join path (`routes/ws/handlers/voice.rs`) right
/// after a join succeeds. Pushes a `voice_move`
/// exactly like a live move — creating a voice-only presence grant (§7.4)
/// first if the target lacks `MESSAGES_READ` on the assigned channel. The
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

    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT ema.event_id, ema.target_channel_id, ema.assigned_by
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

    let Some((event_id, target_channel_id, assigned_by)) = row else {
        return;
    };

    push_event_move(
        state,
        pubkey,
        &event_id,
        &target_channel_id,
        joined_channel_id,
        &assigned_by,
    )
    .await;
}

/// Push one queued assignment as a `voice_move`, from whichever trigger
/// reached it: the target's voice join, or the event's start
/// (`reminder_worker`). Shared so both triggers apply the same rules.
///
/// `assigned_by`'s authority is re-checked here, not only when the assignment
/// was written: an organizer demoted between the two must not still be moving
/// people, and a queued move can outlive the role that authorised it by hours.
pub async fn push_event_move(
    state: &AppState,
    pubkey: &str,
    event_id: &str,
    target_channel_id: &str,
    source_channel_id: &str,
    assigned_by: &str,
) {
    let target_channel_id = target_channel_id.to_string();
    let event_id = event_id.to_string();

    match crate::permissions::channel_permissions(&state.db, assigned_by, &target_channel_id).await
    {
        Ok(perms) if perms.has(crate::permissions::VOICE_MOVE_MEMBERS) => {}
        _ => {
            tracing::info!(
                "Queued voice move skipped: {} no longer holds move_members on channel {} (event {})",
                &assigned_by[..16.min(assigned_by.len())],
                &target_channel_id[..8.min(target_channel_id.len())],
                event_id
            );
            return;
        }
    }

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
    // target lacks effective MESSAGES_READ on the assigned channel.
    if let Ok(perms) =
        crate::permissions::channel_permissions(&state.db, pubkey, &target_channel_id).await
    {
        if !perms.has(crate::permissions::MESSAGES_READ) {
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
        source_channel_id: Some(source_channel_id.to_string()),
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
pub async fn get_voice_roster(state: &AppState, channel_id: &str) -> Vec<VoiceRosterEntry> {
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
