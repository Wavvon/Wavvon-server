//! The voice relay, apart from any transport (voice-transport-v3.md).
//!
//! The relay binds a single-use `voice_token` to `(channel_id, pubkey)`,
//! prepends `[sender_id: u16 BE][packet_type: u8]` to each sealed packet and
//! fans it out, honouring whisper targets, talk power and the WS session's
//! lifetime. It never parses or decrypts the payload (E2E, same privacy model
//! as DMs). A transport only has to accept a session by token, hand inbound
//! packets to [`relay`], and implement [`VoiceLink`] so the relay can send.

use std::sync::Arc;

use crate::state::{AppState, PendingVoiceBind};

/// What the relay needs from a transport session. Sends are best-effort and
/// never block: voice packets are unreliable by design, a late one is useless.
pub trait VoiceLink: Send + Sync {
    fn send(&self, packet: &[u8]);
    fn close(&self, reason: &str);
}

/// A voice room: each member's live transport session, or `None` while the
/// member is on the roster without one.
pub type VoiceRoom = std::collections::HashMap<String, Option<Arc<dyn VoiceLink>>>;

/// Consumes a pending bind. `None` for an unknown, used or expired token.
pub async fn take_bind(state: &AppState, token: &str) -> Option<PendingVoiceBind> {
    let now = std::time::Instant::now();
    let mut binds = state.voice_pending_binds.write().await;
    binds.retain(|_, v| v.expires_at > now);
    binds.remove(token)
}

/// Gives a bound member's session to the relay. `false` when the member
/// left the room between the bind and now (a moderator move, another socket's
/// leave): the session must not re-create a roster slot and listen in.
pub async fn attach(state: &AppState, bind: &PendingVoiceBind, link: Arc<dyn VoiceLink>) -> bool {
    let mut channels = state.voice_channels.write().await;
    match channels
        .get_mut(&bind.channel_id)
        .and_then(|room| room.get_mut(&bind.pubkey))
    {
        Some(slot) => {
            *slot = Some(link);
            true
        }
        None => false,
    }
}

/// The transport session ended: drop the audio-carrying handle but keep the
/// roster entry. WS `leave_voice` (disconnect or explicit VoiceLeave) is the
/// sole authority for removing it.
pub async fn detach(state: &AppState, bind: &PendingVoiceBind) {
    if let Some(chan) = state.voice_channels.write().await.get_mut(&bind.channel_id) {
        if let Some(slot) = chan.get_mut(&bind.pubkey) {
            *slot = None;
        }
    }
}

/// Header-only fan-out: prepends `[sender_id][packet_type]` and forwards to
/// every other bound session in the channel (or, for a whispering sender,
/// exclusively to the resolved whisper target set). Never inspects
/// `payload` beyond copying it verbatim.
pub async fn relay(state: &AppState, channel_id: &str, sender_pk: &str, payload: &[u8]) {
    // Enforcement point tying the transport session's lifetime to the WS
    // session's: `leave_voice` clears this set on disconnect, so a packet
    // racing ahead of session teardown is dropped here.
    if !state.voice_relay_active.read().await.contains(sender_pk) {
        return;
    }

    // Below the channel's `min_talk_power` with no talk grant: present and
    // listening, but not transmitting (permissions.md, "Talk power is not
    // this"). Decided once on join and parked in memory, because this runs per
    // packet and cannot ask the database anything.
    if state.voice_talk_blocked.read().await.contains(sender_pk) {
        return;
    }

    // Outbound loss, measured here because only here can it be measured: the
    // sender cannot know which of its own packets never arrived. `ctr` is in
    // the cleartext header, so this reads a counter and still never touches the
    // sealed payload. A packet too short to carry one is forwarded untracked
    // rather than dropped — the relay's job is forwarding, not validating.
    if let Some(ctr) = crate::voice_loss::read_ctr(payload) {
        let mut losses = state.voice_outbound_loss.write().await;
        let next = crate::voice_loss::track(losses.get(sender_pk).copied(), ctr);
        losses.insert(sender_pk.to_string(), next);
    }

    let sender_id: u16 = state
        .voice_sender_ids
        .read()
        .await
        .get(channel_id)
        .and_then(|m| m.get(sender_pk))
        .copied()
        .unwrap_or(0);

    let whisper_targets = state
        .whisper_target_pubkeys
        .read()
        .await
        .get(sender_pk)
        .cloned();
    let packet_type: u8 = if whisper_targets.is_some() {
        0x01
    } else {
        0x00
    };

    let mut outbound = Vec::with_capacity(3 + payload.len());
    outbound.extend_from_slice(&sender_id.to_be_bytes());
    outbound.push(packet_type);
    outbound.extend_from_slice(payload);

    let channels = state.voice_channels.read().await;
    let Some(participants) = channels.get(channel_id) else {
        return;
    };

    if let Some(targets) = whisper_targets {
        for pk in &targets {
            if let Some(Some(link)) = participants.get(pk.as_str()) {
                link.send(&outbound);
            }
        }
    } else {
        for (pk, session) in participants {
            if pk == sender_pk {
                continue;
            }
            if let Some(link) = session {
                link.send(&outbound);
            }
        }
    }
}
