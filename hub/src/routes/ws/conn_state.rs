use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// All per-connection mutable locals that handler functions need to read or
/// mutate. Owned by the `handle_socket` loop and passed by `&mut` reference
/// into each dispatch function.
pub(super) struct ConnState {
    /// The identity (public key) for this connection.
    pub public_key: String,
    /// Whether this connection belongs to a bot.
    pub is_bot: bool,
    /// Voice channel the client is currently in, if any.
    pub voice_channel: Option<String>,
    /// Pending screen-share chunk header waiting for the binary frame.
    /// Fields: (channel_id, stream_id, seq, is_init).
    pub pending_chunk: Option<(String, String, u32, bool)>,
    /// Channels whose events this connection currently receives.
    pub subscribed: HashSet<String>,
    /// Rate-limit map for component interactions.
    /// Key: (user_pubkey, custom_id).  Value: last interaction instant.
    pub component_rate_limit: HashMap<(String, String), Instant>,
    /// DM conversation IDs this connection is a member of (loaded once at connect).
    pub my_conversations: HashSet<String>,
    /// Live events buffered while a bot replay is in progress.
    pub replay_buffer: Vec<String>,
    /// True while a bot `Resume` replay is executing.
    pub is_replaying: bool,
}

impl ConnState {
    pub fn new(
        public_key: String,
        is_bot: bool,
        subscribed: HashSet<String>,
        my_conversations: HashSet<String>,
    ) -> Self {
        Self {
            public_key,
            is_bot,
            voice_channel: None,
            pending_chunk: None,
            subscribed,
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
