use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// All per-connection mutable locals that handler functions need to read or
/// mutate. Owned by the `handle_socket` loop and passed by `&mut` reference
/// into each dispatch function.
pub(super) struct ConnState {
    /// The identity (public key) for this connection.
    pub public_key: String,
    /// Whether this identity has an app registration (`app_profiles`), which
    /// is what the event stream, the resume replay and the mini-app relay key
    /// off. A property with a row behind it, not a kind of account.
    pub is_app: bool,
    /// Whether this connection is a mini-app-scoped session (mini-apps.md
    /// "Scoped session token") — bound to one channel, no voice access
    /// (voice-transport-v2.md: same block the deleted `/voice/ws` enforced).
    pub is_mini_app: bool,
    /// Set only for an `alliance_voice` visitor (alliances.md): the single
    /// shared channel their grant admitted them to. `Some` *is* the marker for
    /// "this connection is a visitor" — there is no separate bool, so the two
    /// can never disagree about whether to confine.
    pub alliance_voice_channel: Option<String>,
    /// Unique id for this WS session (UUID v4). Stored here so handler
    /// functions (e.g. screen share start) can tag resources they create
    /// without an extra parameter, enabling session-scoped cleanup on
    /// disconnect.
    pub session_id: String,
    /// Voice channel the client is currently in, if any.
    pub voice_channel: Option<String>,
    /// Pending screen-share chunk header waiting for the binary frame.
    /// Fields: (channel_id, stream_id, seq, is_init).
    pub pending_chunk: Option<(String, String, u32, bool)>,
    /// Channels whose events this connection currently receives.
    pub subscribed: HashSet<String>,
    /// Streams for which `screen_share_started` has already been sent to this
    /// client.  Keyed by (channel_id, stream_id).  Ensures the chunk relay arm
    /// never delivers a chunk before the client knows the stream exists.
    pub notified_streams: HashSet<(String, String)>,
    /// Rate-limit map for component interactions.
    /// Key: (user_pubkey, custom_id).  Value: last interaction instant.
    pub component_rate_limit: HashMap<(String, String), Instant>,
    /// DM conversation IDs this connection is a member of (loaded once at connect).
    pub my_conversations: HashSet<String>,
    /// Live events buffered while a replay is in progress.
    pub replay_buffer: Vec<String>,
    /// True while a `Resume` replay is executing.
    pub is_replaying: bool,
}

impl ConnState {
    pub fn new(
        public_key: String,
        is_app: bool,
        is_mini_app: bool,
        alliance_voice_channel: Option<String>,
        session_id: String,
        subscribed: HashSet<String>,
        my_conversations: HashSet<String>,
    ) -> Self {
        Self {
            public_key,
            is_app,
            is_mini_app,
            alliance_voice_channel,
            session_id,
            voice_channel: None,
            pending_chunk: None,
            subscribed,
            notified_streams: HashSet::new(),
            component_rate_limit: HashMap::new(),
            my_conversations,
            replay_buffer: Vec::new(),
            is_replaying: false,
        }
    }
}

/// Return value from every `handle_*` dispatch function.
/// `Break` means the connection should be torn down.
#[must_use]
pub(super) enum DispatchResult {
    Continue,
    Break,
}
