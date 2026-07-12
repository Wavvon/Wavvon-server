use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub is_category: bool,
    #[serde(default)]
    pub description: Option<String>,
    /// "text" (default), "forum", "banner", or "spawner". Ignored for categories.
    #[serde(default)]
    pub channel_type: Option<String>,
    #[serde(default)]
    pub banner_url: Option<String>,
    #[serde(default)]
    pub banner_file_id: Option<String>,
    /// Only valid for `channel_type = "spawner"`. Name template for rooms it
    /// spawns; `{user}` is substituted with the joiner's display name.
    /// Defaults to `"{user}'s room"` when absent (see temp-voice-channels.md §2).
    #[serde(default)]
    pub spawner_name_template: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChannelResponse {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub parent_id: Option<String>,
    pub is_category: bool,
    pub display_order: i64,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub custom_icon_svg: Option<String>,
    pub created_at: i64,
    /// "text", "forum", "banner", or "spawner". Always "text" for categories.
    pub channel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_file_id: Option<String>,
    /// TRUE for a join-to-create personal room spawned from a spawner
    /// channel (temp-voice-channels.md).
    #[serde(default)]
    pub is_temporary: bool,
    /// Set only on temp channels: the joiner who owns (and may rename) it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<String>,
    /// Set only on spawner channels: the name template used for rooms it spawns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawner_name_template: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct UpdateChannelRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Tri-state: absent = don't touch, `Some(Some(id))` = set parent,
    /// `Some(None)` = move to top level.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub parent_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub icon: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub color: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub custom_icon_svg: Option<Option<String>>,
    /// Minimum role talk_power needed to transmit audio in this channel.
    /// 0 = no restriction. When set, requires ADMIN permission.
    #[serde(default)]
    pub min_talk_power: Option<i64>,
    /// Tri-state retention policy: absent = no change, `Some(Some(n))` = keep
    /// messages/posts for n days, `Some(None)` = clear (retain forever).
    /// Requires ADMIN permission.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub retention_days: Option<Option<i64>>,
    #[serde(default)]
    pub banner_url: Option<String>,
    #[serde(default)]
    pub banner_file_id: Option<String>,
}

/// Lets us distinguish "field missing" from "field explicitly null" in JSON.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// One inline attachment carried with a message. We embed bytes directly
/// (base64) rather than introducing a separate storage subsystem; the per-
/// message size cap below keeps this from getting out of hand.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    /// Base64-encoded file bytes (no data: URI prefix).
    pub data_b64: String,
}

/// Hard cap per message, summed across all attachments. 3 MB of base64
/// is roughly 2.25 MB of binary -- enough for screenshots, small images,
/// short clips, but bounded so the DB and WS frames don't get crushed.
pub const MAX_ATTACHMENTS_BYTES: usize = 3 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Optional parent message id to thread under.
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// Minimal preview of a parent message. We embed it in replies so the
/// client can render "replying to X" without a second fetch. If the
/// parent is gone, this is None and the reply renders alone.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReplyContext {
    pub message_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content_preview: String,
}

/// Aggregated reaction count for one emoji on one message. `me` flags
/// whether the requesting user is one of the reactors so the client can
/// render the toggle state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReactionSummary {
    pub emoji: String,
    pub count: i64,
    pub me: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageResponse {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: String,
    pub created_at: i64,
    #[serde(default)]
    pub edited_at: Option<i64>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub reactions: Vec<ReactionSummary>,
    #[serde(default)]
    pub reply_to: Option<ReplyContext>,
    /// When set, only the named user should see this message.
    /// NULL / None = normal broadcast. Used for ephemeral bot replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_to_pubkey: Option<String>,
    /// Number of direct replies to this message (denormalized counter).
    /// 0 for replies themselves; only root messages accumulate a non-zero count.
    #[serde(default)]
    pub reply_count: i64,
}

#[derive(Deserialize)]
pub struct ReactionRequest {
    pub emoji: String,
}

#[derive(Serialize, Deserialize)]
pub struct EditMessageRequest {
    pub content: String,
}

#[derive(Clone, Debug)]
pub enum ChatEvent {
    New {
        channel_id: String,
        message: MessageResponse,
    },
    Edited {
        channel_id: String,
        message: MessageResponse,
    },
    Deleted {
        channel_id: String,
        message_id: String,
    },
    /// Reactions changed on a message. We send the full per-message
    /// summary list rather than diffs so the client can replace the
    /// counts atomically without bookkeeping. `me` is intentionally
    /// false here -- it's per-viewer, the client recomputes it.
    ReactionsUpdated {
        channel_id: String,
        message_id: String,
        reactions: Vec<ReactionSummary>,
    },
    /// Ephemeral typing indicator. We piggyback on the chat broadcast
    /// channel since the WS dispatcher already has subscription filtering;
    /// the dispatcher skips echoing this back to the sender.
    Typing {
        channel_id: String,
        public_key: String,
        display_name: Option<String>,
        typing: bool,
    },
    ScreenShareStarted {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    ScreenShareStopped {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
    },
    /// v2 signaling envelope (offer/answer/ICE/viewer-joined/viewer-left).
    /// `to_pubkey` is the sole intended recipient; the WS dispatcher
    /// skips every connection that isn't that pubkey.
    ScreenShareSignal {
        channel_id: String,
        to_pubkey: String,
    },
    /// Notify a specific cross-channel subscriber that their subscribed stream ended.
    /// `to_pubkey` is the subscriber; this is delivered only to their connection.
    StreamSubscriptionEnded {
        to_pubkey: String,
        source_channel_id: String,
        stream_id: String,
    },
    /// A forum post/reply event (post_created, post_updated, post_deleted,
    /// reply_created, reply_updated, reply_deleted). The payload is the
    /// fully-serialised JSON value carried in the WS envelope.
    Forum { channel_id: String },
    /// Voice zone lifecycle and position-update events (voice_zone_created,
    /// voice_zone_destroyed, voice_position_updated). Routing is by channel_id.
    VoiceZone { channel_id: String },
    /// Video enable/disable broadcasts and targeted offer/answer/ICE signals.
    /// Broadcasts go to all voice-channel subscribers; offer/answer/ice are
    /// targeted and filtered in the WS dispatch loop by to_pubkey.
    Video { channel_id: String },
    /// Native poll vote-tally broadcast after every upsert.
    Poll { channel_id: String },
    /// Message pinned in a channel.
    MessagePinned { channel_id: String },
    /// Message unpinned from a channel.
    MessageUnpinned { channel_id: String },
    /// Whisper start/stop notification — delivered only to the resolved recipient set.
    /// `channel_id` is the whisperer's current voice channel (used only to satisfy the
    /// channel_id() contract; filtering is done via `to_pubkeys` in the WS dispatch loop).
    WhisperSignal {
        channel_id: String,
        to_pubkeys: Vec<String>,
    },
    /// Bot mini-app announce/dismiss event. Routed to channel subscribers.
    BotApp { channel_id: String },
    /// Soundboard clip-played attribution event (soundboard.md §1). Routed
    /// to channel subscribers -- the same audience as the voice roster the
    /// chip renders into.
    Soundboard { channel_id: String },
    /// Hub-wide notification that the channel list changed (created/updated/deleted/reordered).
    /// Returns "" from channel_id() so the subscription filter never matches; the WS
    /// dispatch loop handles it as a special broadcast-to-all case.
    ChannelsUpdated,
    /// A user's first WS session connected; delivered hub-wide.
    MemberOnline { public_key: String },
    /// A user's last WS session disconnected; delivered hub-wide.
    MemberOffline { public_key: String },
    /// A user changed their profile (display name / avatar); delivered
    /// hub-wide so other clients refresh the member list and message authors
    /// without a reconnect.
    MemberUpdated { public_key: String },
    /// A user changed their presence status (away/DND/custom text);
    /// delivered hub-wide like MemberOnline/MemberOffline. Never emitted for
    /// a transition into "invisible" — that broadcasts as MemberOffline
    /// instead (see `handle_set_status`).
    MemberStatus { public_key: String },
    /// An outgoing webhook auto-disabled itself after too many consecutive
    /// delivery failures. Hub-wide (admin UI filters/display client-side —
    /// there is no admin-only WS channel today).
    WebhookDisabled {
        webhook_id: String,
        reason: String,
        last_error: Option<String>,
    },
}

impl ChatEvent {
    pub fn channel_id(&self) -> &str {
        match self {
            ChatEvent::New { channel_id, .. }
            | ChatEvent::Edited { channel_id, .. }
            | ChatEvent::Deleted { channel_id, .. }
            | ChatEvent::ReactionsUpdated { channel_id, .. }
            | ChatEvent::Typing { channel_id, .. }
            | ChatEvent::ScreenShareStarted { channel_id, .. }
            | ChatEvent::ScreenShareStopped { channel_id, .. }
            | ChatEvent::ScreenShareSignal { channel_id, .. }
            | ChatEvent::Forum { channel_id }
            | ChatEvent::VoiceZone { channel_id }
            | ChatEvent::Video { channel_id }
            | ChatEvent::Poll { channel_id }
            | ChatEvent::MessagePinned { channel_id }
            | ChatEvent::MessageUnpinned { channel_id }
            | ChatEvent::WhisperSignal { channel_id, .. }
            | ChatEvent::BotApp { channel_id }
            | ChatEvent::Soundboard { channel_id } => channel_id,
            // StreamSubscriptionEnded is targeted by pubkey, not by channel subscription.
            // Return an empty string so the WS dispatcher's channel filter never matches it
            // (delivery is handled via the dedicated to_pubkey check below).
            ChatEvent::StreamSubscriptionEnded {
                source_channel_id, ..
            } => source_channel_id,
            // ChannelsUpdated, MemberOnline, MemberOffline, WebhookDisabled are
            // hub-wide; "" is never in any subscription set — handled as
            // special broadcast-to-all cases.
            ChatEvent::ChannelsUpdated
            | ChatEvent::MemberOnline { .. }
            | ChatEvent::MemberOffline { .. }
            | ChatEvent::MemberUpdated { .. }
            | ChatEvent::MemberStatus { .. }
            | ChatEvent::WebhookDisabled { .. } => "",
        }
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub before: Option<String>,
    pub limit: Option<i64>,
    /// Optional search query: if present, filter messages by content LIKE
    /// %q% (case-insensitive on SQLite). Pagination via before still works.
    pub q: Option<String>,
    /// Optional thread root message id. When present, return only replies
    /// (messages where reply_to = thread_root) ordered by created_at ASC.
    pub thread_root: Option<String>,
}

#[derive(Deserialize)]
pub struct WsParams {
    pub token: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum WsClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { channel_id: String },
    #[serde(rename = "unsubscribe")]
    Unsubscribe { channel_id: String },
    #[serde(rename = "voice_join")]
    VoiceJoin { channel_id: String, udp_port: u16 },
    #[serde(rename = "voice_watch")]
    VoiceWatch { channel_id: String },
    #[serde(rename = "voice_unwatch")]
    VoiceUnwatch,
    #[serde(rename = "voice_leave")]
    VoiceLeave { channel_id: String },
    #[serde(rename = "voice_speaking")]
    VoiceSpeaking { channel_id: String, speaking: bool },
    #[serde(rename = "typing")]
    Typing { channel_id: String, typing: bool },
    /// Set the sender's presence status. `status` is "online", "away",
    /// "dnd", or "invisible" ("online" clears); `custom` is an optional
    /// short status text. "invisible" keeps the connection fully live
    /// (DMs/messages/voice unaffected) but is reported as offline to other
    /// members everywhere presence is surfaced (roster, broadcasts).
    #[serde(rename = "set_status")]
    SetStatus {
        status: String,
        #[serde(default)]
        custom: Option<String>,
    },
    #[serde(rename = "dm_typing")]
    DmTyping {
        conversation_id: String,
        typing: bool,
    },
    #[serde(rename = "screen_share_start")]
    ScreenShareStart {
        channel_id: String,
        stream_id: String,
        kind: String,
        mime: String,
        has_audio: bool,
        /// v2: "chunks" (default, v1 relay) or "webrtc". Absent = "chunks" for
        /// old clients. Additive — old hubs and clients ignore this field.
        #[serde(default)]
        transport: Option<String>,
        /// v2: track metadata for webcam + screen multiplexing. Additive.
        #[serde(default)]
        tracks: Option<Vec<TrackMeta>>,
    },
    #[serde(rename = "screen_share_chunk")]
    ScreenShareChunk {
        channel_id: String,
        stream_id: String,
        seq: u32,
        is_init: bool,
    },
    #[serde(rename = "screen_share_stop")]
    ScreenShareStop {
        channel_id: String,
        stream_id: String,
    },
    // ---- Screen share v2: WebRTC signaling envelopes (client → hub) ----
    /// Sharer sends an SDP offer to a specific viewer.
    #[serde(rename = "screen_share_offer")]
    ScreenShareOffer {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        /// Opaque SDP text — hub does not parse this.
        sdp: String,
    },
    /// Viewer sends an SDP answer to the sharer.
    #[serde(rename = "screen_share_answer")]
    ScreenShareAnswer {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        sdp: String,
    },
    /// Either peer trickles an ICE candidate to the other.
    #[serde(rename = "screen_share_ice")]
    ScreenShareIce {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        /// JSON string: `{ candidate, sdpMid, sdpMLineIndex }` — opaque to hub.
        candidate: String,
    },
    /// Viewer signals to the sharer that it wants a peer connection.
    #[serde(rename = "screen_share_viewer_join")]
    ScreenShareViewerJoin {
        channel_id: String,
        stream_id: String,
    },
    /// Viewer tears down its peer connection.
    #[serde(rename = "screen_share_viewer_leave")]
    ScreenShareViewerLeave {
        channel_id: String,
        stream_id: String,
    },
    /// Request a snapshot of all active streams on the hub visible to this user.
    /// Hub replies with `HubStreams`.
    #[serde(rename = "stream_list")]
    StreamList,
    /// Subscribe to an active stream from a channel the user isn't in voice on.
    /// Authorization: user must have view access to `source_channel_id`.
    /// Hub replays the init chunk and forwards subsequent chunks to this subscriber.
    #[serde(rename = "stream_subscribe")]
    StreamSubscribe {
        source_channel_id: String,
        stream_id: String,
    },
    /// Unsubscribe from a previously subscribed cross-channel stream.
    #[serde(rename = "stream_unsubscribe")]
    StreamUnsubscribe {
        source_channel_id: String,
        stream_id: String,
    },

    // ---- Video signaling: client → hub ----
    #[serde(rename = "video_enable")]
    VideoEnable { channel_id: String },

    #[serde(rename = "video_disable")]
    VideoDisable { channel_id: String },

    #[serde(rename = "video_offer")]
    VideoOffer {
        channel_id: String,
        to_pubkey: String,
        sdp: String,
    },

    #[serde(rename = "video_answer")]
    VideoAnswer {
        channel_id: String,
        to_pubkey: String,
        sdp: String,
    },

    #[serde(rename = "video_ice")]
    VideoIce {
        channel_id: String,
        to_pubkey: String,
        candidate: String,
    },

    /// Sender opens a whisper session to the listed targets.
    #[serde(rename = "voice_whisper_start")]
    VoiceWhisperStart {
        targets: Vec<crate::state::WhisperTargetDef>,
    },
    /// Sender closes their active whisper session.
    #[serde(rename = "voice_whisper_stop")]
    VoiceWhisperStop,

    /// Bot sends this after connecting to request replay of missed events.
    #[serde(rename = "resume")]
    Resume { since_seq: i64 },
    /// User or bot interaction with a message component (button, select).
    #[serde(rename = "component_interaction")]
    ComponentInteraction {
        message_id: String,
        custom_id: String,
        #[serde(default)]
        values: Vec<String>,
    },

    // ---- Proximity voice: client → hub ----
    #[serde(rename = "voice_zone_create")]
    VoiceZoneCreate {
        zone_id: String,
        name: String,
        #[serde(default = "default_coord_system")]
        coordinate_system: String,
        attenuation: AttenuationConfigMsg,
        #[serde(default = "default_auth_mode")]
        auth_mode: String,
        #[serde(default)]
        session_id: Option<String>,
    },

    #[serde(rename = "voice_zone_destroy")]
    VoiceZoneDestroy { zone_id: String },

    #[serde(rename = "voice_position_update")]
    VoicePositionUpdate { zone_id: String, position: Vec<f64> },

    // ---- V4 voice encryption: client → hub ----
    /// Client distributes a sender key bundle to one or more participants.
    /// The AES sender key is encrypted with X25519 ECDH using each
    /// recipient's public key; the hub forwards bundles without inspecting
    /// the ciphertext.
    #[serde(rename = "voice_key_offer")]
    VoiceKeyOffer {
        channel_id: String,
        /// One bundle per recipient.
        bundles: Vec<VoiceKeyBundle>,
    },

    // ---- Bot mini-apps: client → hub ----
    /// Bot announces a mini-app session in a channel. Hub fans to all
    /// channel subscribers as BotAppLaunch. Only valid from bot connections.
    #[serde(rename = "bot_app_announce")]
    BotAppAnnounce {
        title: String,
        description: String,
        channel_id: String,
    },

    /// User requests to join an announced mini-app session.
    #[serde(rename = "bot_app_join")]
    BotAppJoin { bot_id: String, channel_id: String },

    /// Bot closes the mini-app session. Hub fans to all channel subscribers.
    /// Only valid from bot connections.
    #[serde(rename = "bot_app_dismiss")]
    BotAppDismiss { channel_id: String },
}

#[derive(Serialize, Clone)]
#[serde(tag = "type")]
pub enum WsServerMessage {
    #[serde(rename = "message")]
    ChatMessage {
        channel_id: String,
        message: MessageResponse,
    },
    #[serde(rename = "message_edited")]
    MessageEdited {
        channel_id: String,
        message: MessageResponse,
    },
    #[serde(rename = "message_deleted")]
    MessageDeleted {
        channel_id: String,
        message_id: String,
    },
    #[serde(rename = "reactions_updated")]
    ReactionsUpdated {
        channel_id: String,
        message_id: String,
        reactions: Vec<ReactionSummary>,
    },
    #[serde(rename = "typing")]
    Typing {
        channel_id: String,
        public_key: String,
        display_name: Option<String>,
        typing: bool,
    },
    #[serde(rename = "voice_joined")]
    VoiceJoined {
        channel_id: String,
        hub_udp_port: u16,
        participants: Vec<VoiceParticipantInfo>,
        /// Single-use token the client sends in a UDP VXRG register packet so
        /// the hub can learn the client's real public source address.  Delivered
        /// confidentially over the authenticated TLS WebSocket; 30-second TTL.
        udp_register_token: String,
    },
    #[serde(rename = "voice_participant_joined")]
    VoiceParticipantJoined {
        channel_id: String,
        participant: VoiceParticipantInfo,
    },
    #[serde(rename = "voice_participant_left")]
    VoiceParticipantLeft {
        channel_id: String,
        public_key: String,
    },
    #[serde(rename = "voice_participant_speaking")]
    VoiceParticipantSpeaking {
        channel_id: String,
        public_key: String,
        speaking: bool,
    },
    #[serde(rename = "voice_roster_update")]
    VoiceRosterUpdate {
        channel_id: String,
        participants: Vec<VoiceRosterEntry>,
    },
    /// Generic error message, shown to the user as a toast. `context` is a
    /// short machine-readable hint (e.g. "voice_join") so the client can
    /// route the message contextually if it wants.
    #[serde(rename = "error")]
    Error { context: String, message: String },
    #[serde(rename = "dm")]
    DirectMessage {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        content: String,
        timestamp: i64,
    },
    #[serde(rename = "dm_typing")]
    DmTyping {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        typing: bool,
    },
    #[serde(rename = "dm_member_changed")]
    DmMemberChanged {
        conversation_id: String,
        added: Vec<String>,
        removed: Vec<String>,
    },
    #[serde(rename = "screen_share_started")]
    ScreenShareStarted {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    #[serde(rename = "screen_share_chunk")]
    ScreenShareChunkOut {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        seq: u32,
        is_init: bool,
    },
    #[serde(rename = "screen_share_stopped")]
    ScreenShareStopped {
        channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
    },

    // ---- Screen share v2: hub→client forwarded signaling envelopes ----
    /// SDP offer forwarded to the target viewer (from_pubkey = sharer).
    #[serde(rename = "screen_share_offer_in")]
    ScreenShareOfferIn {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        sdp: String,
        from_pubkey: String,
    },
    /// SDP answer forwarded to the sharer (from_pubkey = viewer).
    #[serde(rename = "screen_share_answer_in")]
    ScreenShareAnswerIn {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        sdp: String,
        from_pubkey: String,
    },
    /// ICE candidate forwarded to the target peer.
    #[serde(rename = "screen_share_ice_in")]
    ScreenShareIceIn {
        channel_id: String,
        to_pubkey: String,
        stream_id: String,
        candidate: String,
        from_pubkey: String,
    },
    /// Hub notifies the sharer that a viewer wants to negotiate.
    #[serde(rename = "screen_share_viewer_joined")]
    ScreenShareViewerJoined {
        channel_id: String,
        stream_id: String,
        from_pubkey: String,
    },
    /// Hub notifies the sharer that a viewer left.
    #[serde(rename = "screen_share_viewer_left")]
    ScreenShareViewerLeft {
        channel_id: String,
        stream_id: String,
        from_pubkey: String,
    },

    // ---- Video signaling: hub → client ----
    /// Broadcast to voice channel: a participant enabled their webcam.
    #[serde(rename = "video_participant_enabled")]
    VideoParticipantEnabled { channel_id: String, pubkey: String },

    /// Broadcast to voice channel: a participant disabled their webcam.
    #[serde(rename = "video_participant_disabled")]
    VideoParticipantDisabled { channel_id: String, pubkey: String },

    /// Snapshot of all currently video-enabled pubkeys in a channel.
    /// Sent to a joining voice participant.
    #[serde(rename = "video_participants")]
    VideoParticipants {
        channel_id: String,
        pubkeys: Vec<String>,
    },

    /// SDP offer forwarded to the target peer (from_pubkey = offerer).
    #[serde(rename = "video_offer_in")]
    VideoOfferIn {
        channel_id: String,
        from_pubkey: String,
        to_pubkey: String,
        sdp: String,
    },

    /// SDP answer forwarded to the target peer (from_pubkey = answerer).
    #[serde(rename = "video_answer_in")]
    VideoAnswerIn {
        channel_id: String,
        from_pubkey: String,
        to_pubkey: String,
        sdp: String,
    },

    /// ICE candidate forwarded to the target peer.
    #[serde(rename = "video_ice_in")]
    VideoIceIn {
        channel_id: String,
        from_pubkey: String,
        to_pubkey: String,
        candidate: String,
    },

    /// Acknowledgement sent to a subscriber after StreamSubscribe succeeds.
    /// The hub will now forward chunks for this stream to the subscriber.
    /// If the stream has an init chunk cached, it is sent immediately after this message.
    #[serde(rename = "stream_subscribed")]
    StreamSubscribed {
        source_channel_id: String,
        stream_id: String,
        sharer_pubkey: String,
        kind: String,
        mime: String,
        has_audio: bool,
    },
    /// Sent when a subscribed stream stops (sharer stopped or disconnected).
    #[serde(rename = "stream_subscription_ended")]
    StreamSubscriptionEnded {
        source_channel_id: String,
        stream_id: String,
    },
    /// Snapshot of all currently active streams across all channels visible to
    /// this user. Sent in response to a `stream_list` client message.
    #[serde(rename = "hub_streams")]
    HubStreams { streams: Vec<HubStreamInfo> },
    /// Forum post/reply event. The `event` field carries the typed payload
    /// (type, channel_id, post_id, and optionally reply_id).
    #[serde(rename = "forum_event")]
    ForumEvent {
        channel_id: String,
        event: serde_json::Value,
    },

    // ---- Proximity voice: hub → client ----
    /// Broadcast to the channel when a voice zone is created.
    #[serde(rename = "voice_zone_created")]
    VoiceZoneCreated {
        channel_id: String,
        zone_id: String,
        name: String,
        coordinate_system: String,
        attenuation: AttenuationConfigMsg,
    },

    /// Broadcast to the channel when a voice zone is destroyed.
    #[serde(rename = "voice_zone_destroyed")]
    VoiceZoneDestroyed { channel_id: String, zone_id: String },

    /// Broadcast to the channel on every accepted position update.
    #[serde(rename = "voice_position_updated")]
    VoicePositionUpdated {
        channel_id: String,
        zone_id: String,
        pubkey: String,
        position: Vec<f64>,
    },

    /// Sent to a client on voice join — snapshot of all active zones in the channel.
    #[serde(rename = "voice_zone_state")]
    VoiceZoneState {
        channel_id: String,
        zones: Vec<VoiceZoneSnapshot>,
    },

    /// A message was pinned in a channel.
    #[serde(rename = "message_pinned")]
    MessagePinned {
        channel_id: String,
        message_id: String,
    },

    /// A message was unpinned from a channel.
    #[serde(rename = "message_unpinned")]
    MessageUnpinned {
        channel_id: String,
        message_id: String,
    },

    /// Live vote-tally update broadcast after every vote upsert.
    #[serde(rename = "poll_vote_updated")]
    PollVoteUpdated {
        channel_id: String,
        poll_id: String,
        totals: std::collections::HashMap<String, i64>,
    },

    /// Delivered only to the resolved whisper target set when a sender opens a whisper session.
    #[serde(rename = "voice_whisper_started")]
    VoiceWhisperStarted { sender_pubkey: String },

    /// Delivered only to the resolved whisper target set when a sender stops whispering.
    #[serde(rename = "voice_whisper_stopped")]
    VoiceWhisperStopped { sender_pubkey: String },

    /// Hub-wide signal that the channel list changed; clients should re-fetch /channels.
    #[serde(rename = "channels_updated")]
    ChannelsUpdated,

    /// Soundboard clip-played attribution (soundboard.md §1). Purely
    /// informational -- the server does not verify the clip was actually
    /// mixed into the sender's stream; clients render a transient
    /// "🔊 X played *name*" chip in the voice roster.
    #[serde(rename = "soundboard_played")]
    SoundboardPlayed {
        channel_id: String,
        clip_id: String,
        clip_name: String,
        public_key: String,
    },

    /// Sent when the hub dropped messages destined for this connection because
    /// it was consuming the broadcast channel too slowly. The client should
    /// re-fetch recent messages for any subscribed channels it cares about.
    #[serde(rename = "lagged")]
    Lagged {
        /// Number of messages dropped since the last delivery to this client.
        count: u64,
    },
    /// A user just came online (their first WS session connected).
    #[serde(rename = "member_online")]
    MemberOnline { public_key: String },
    /// A user just went offline (their last WS session disconnected).
    #[serde(rename = "member_offline")]
    MemberOffline { public_key: String },
    /// A user changed their display name and/or avatar. Carries the fresh
    /// values so clients update in place without re-fetching /users.
    #[serde(rename = "member_updated")]
    MemberUpdated {
        public_key: String,
        display_name: Option<String>,
        avatar: Option<String>,
    },
    /// A user changed their presence status. `status` is None for plain
    /// online (away/dnd otherwise); `custom` is optional short status text.
    #[serde(rename = "member_status")]
    MemberStatus {
        public_key: String,
        status: Option<String>,
        custom: Option<String>,
    },

    // ---- V4 voice encryption: hub → client ----
    /// Targeted delivery: another participant's encrypted sender-key bundle.
    /// The AES key ciphertext was encrypted by the sender using X25519 ECDH
    /// with this client's public key; the hub forwards it verbatim.
    #[serde(rename = "voice_key_received")]
    VoiceKeyReceived {
        channel_id: String,
        from_sender_id: u16,
        from_pubkey: String,
        /// AES key ciphertext (hex), encrypted with X25519 ECDH.
        ciphertext_hex: String,
        nonce_hex: String,
    },

    /// Broadcast to existing voice participants: a new sender joined and needs
    /// each participant to send their current AES key to that new participant.
    #[serde(rename = "voice_key_request")]
    VoiceKeyRequest {
        channel_id: String,
        new_sender_id: u16,
        new_pubkey: String,
    },

    // ---- Bot mini-apps: hub → client ----
    /// Hub fans a bot's announce to all subscribers of that channel.
    #[serde(rename = "bot_app_launch")]
    BotAppLaunch {
        bot_id: String,
        title: String,
        description: String,
        channel_id: String,
    },

    /// Hub sends this only to the joining client after minting a scoped token.
    #[serde(rename = "bot_app_open")]
    BotAppOpen {
        bot_id: String,
        channel_id: String,
        mini_app_url: String,
        session_token: String,
        /// True when the bot declared `requires_camera` AND the hub operator
        /// has set `bots_allow_camera = true`. Clients gate the webview camera
        /// permission on this flag.
        requires_camera: bool,
    },

    /// Hub fans a bot's dismiss to all subscribers — clients close open webviews.
    #[serde(rename = "bot_app_close")]
    BotAppClose { bot_id: String, channel_id: String },

    /// An outgoing webhook was auto-disabled after too many consecutive
    /// delivery failures. Hub-wide; the admin settings UI is the intended
    /// consumer, other clients ignore unknown fields.
    #[serde(rename = "webhook_disabled")]
    WebhookDisabled {
        webhook_id: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_error: Option<String>,
    },
}

/// Track metadata carried in `ScreenShareStart.tracks` (v2, additive).
/// Old clients that don't know this field ignore it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrackMeta {
    /// RTP `m=` mid value (a string matching `RTCRtpTransceiver.mid`).
    pub mid: String,
    /// "screen" or "webcam".
    pub kind: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VoiceParticipantInfo {
    pub public_key: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_bot: bool,
}

#[derive(Serialize, Clone)]
pub struct VoiceRosterEntry {
    pub sender_id: u16,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Proximity voice types
// ---------------------------------------------------------------------------

fn default_coord_system() -> String {
    "2d".to_string()
}
fn default_auth_mode() -> String {
    "any_channel_member".to_string()
}
fn default_attenuation_model() -> String {
    "linear".to_string()
}
fn default_max_radius() -> f64 {
    200.0
}
fn default_ref_dist() -> f64 {
    20.0
}
fn default_rolloff() -> f64 {
    1.0
}

/// Attenuation configuration carried in zone-create and zone-state messages.
#[derive(Deserialize, Serialize, Clone)]
pub struct AttenuationConfigMsg {
    #[serde(default = "default_attenuation_model")]
    pub model: String,
    #[serde(default = "default_max_radius")]
    pub max_radius: f64,
    #[serde(default = "default_ref_dist")]
    pub ref_dist: f64,
    #[serde(default = "default_rolloff")]
    pub rolloff: f64,
}

/// One zone entry in a `voice_zone_state` snapshot.
#[derive(Serialize, Clone)]
pub struct VoiceZoneSnapshot {
    pub zone_id: String,
    pub name: String,
    pub coordinate_system: String,
    pub attenuation: AttenuationConfigMsg,
    /// pubkey → position
    pub positions: std::collections::HashMap<String, Vec<f64>>,
}

/// One encrypted sender-key bundle destined for a single recipient.
/// Carried inside `VoiceKeyOffer`; forwarded verbatim as `VoiceKeyReceived`.
#[derive(Serialize, Deserialize, Clone)]
pub struct VoiceKeyBundle {
    pub recipient_pubkey: String,
    /// AES key ciphertext (hex), encrypted with X25519 ECDH.
    pub ciphertext_hex: String,
    pub nonce_hex: String,
}

/// One active stream entry returned by `HubStreams`.
#[derive(Serialize, Clone)]
pub struct HubStreamInfo {
    pub channel_id: String,
    pub stream_id: String,
    pub sharer_pubkey: String,
    pub kind: String,
    pub mime: String,
    pub has_audio: bool,
}
