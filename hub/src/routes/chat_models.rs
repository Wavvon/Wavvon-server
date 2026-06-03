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
    /// "text" (default) or "forum". Ignored for categories.
    #[serde(default)]
    pub channel_type: Option<String>,
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
    /// "text" or "forum". Always "text" for categories.
    pub channel_type: String,
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
    New { channel_id: String, message: MessageResponse },
    Edited { channel_id: String, message: MessageResponse },
    Deleted { channel_id: String, message_id: String },
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
    /// Any game-session event (created / joined / left / state-updated / ended).
    /// We carry a single variant here because the WS dispatcher only needs to
    /// match by channel_id for subscription filtering; the full typed envelope
    /// is pre-serialised into the Arc<str> that travels alongside.
    Game { channel_id: String },
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
            | ChatEvent::Game { channel_id } => channel_id,
            // StreamSubscriptionEnded is targeted by pubkey, not by channel subscription.
            // Return an empty string so the WS dispatcher's channel filter never matches it
            // (delivery is handled via the dedicated to_pubkey check below).
            ChatEvent::StreamSubscriptionEnded { source_channel_id, .. } => source_channel_id,
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
    #[serde(rename = "voice_leave")]
    VoiceLeave { channel_id: String },
    #[serde(rename = "voice_speaking")]
    VoiceSpeaking { channel_id: String, speaking: bool },
    #[serde(rename = "typing")]
    Typing { channel_id: String, typing: bool },
    #[serde(rename = "dm_typing")]
    DmTyping { conversation_id: String, typing: bool },
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

    // ---- Gaming Tier 2: client → hub ----

    #[serde(rename = "game_send")]
    GameSend {
        session_id: String,
        payload: serde_json::Value,
        #[serde(default)]
        to: Option<String>,
    },

    #[serde(rename = "game_set_status")]
    GameSetStatus { session_id: String, status: String },

    #[serde(rename = "game_snapshot")]
    GameSnapshot {
        session_id: String,
        /// Base64 or hex-encoded snapshot blob; stored opaque in DB.
        blob: String,
    },

    #[serde(rename = "game_end")]
    GameEnd {
        session_id: String,
        #[serde(default)]
        result: Option<serde_json::Value>,
    },
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
    /// Generic error message, shown to the user as a toast. `context` is a
    /// short machine-readable hint (e.g. "voice_join") so the client can
    /// route the message contextually if it wants.
    #[serde(rename = "error")]
    Error {
        context: String,
        message: String,
    },
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
    HubStreams {
        streams: Vec<HubStreamInfo>,
    },
    /// Forum post/reply event. The `event` field carries the typed payload
    /// (type, channel_id, post_id, and optionally reply_id).
    #[serde(rename = "forum_event")]
    ForumEvent {
        channel_id: String,
        event: serde_json::Value,
    },

    // ---- Gaming Tier 2: game session envelopes ----

    /// A new game session was created in a channel.
    #[serde(rename = "game_session_created")]
    GameSessionCreated {
        session_id: String,
        channel_id: String,
        game_id: String,
        host_pubkey: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_players: Option<i64>,
    },

    /// A player joined an existing game session.
    #[serde(rename = "game_session_joined")]
    GameSessionJoined {
        session_id: String,
        player_pubkey: String,
    },

    /// A player left a game session (voluntary leave or disconnect).
    #[serde(rename = "game_session_left")]
    GameSessionLeft {
        session_id: String,
        player_pubkey: String,
    },

    /// The host posted a state patch (opaque JSON). Relayed to all roster
    /// members so clients can apply it to their local view.
    #[serde(rename = "game_state_updated")]
    GameStateUpdated {
        session_id: String,
        patch: serde_json::Value,
    },

    /// The session ended (normal completion, abandonment, or forced deletion).
    #[serde(rename = "game_session_ended")]
    GameSessionEnded {
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<serde_json::Value>,
    },

    // ---- Spec Tier 2 hub→client additions ----

    /// A player joined the session roster (spec variant with display_name).
    #[serde(rename = "game_player_joined")]
    GamePlayerJoined {
        session_id: String,
        pubkey: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },

    /// A player left the session roster.
    #[serde(rename = "game_player_left")]
    GamePlayerLeft {
        session_id: String,
        pubkey: String,
    },

    /// The host role was transferred to a new player (after host disconnect).
    #[serde(rename = "game_host_changed")]
    GameHostChanged {
        session_id: String,
        new_host_pubkey: String,
    },

    /// A game move / event relayed from one player to the roster.
    /// The payload is opaque; the hub never interprets it.
    #[serde(rename = "game_event")]
    GameEvent {
        session_id: String,
        from_pubkey: String,
        payload: serde_json::Value,
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
