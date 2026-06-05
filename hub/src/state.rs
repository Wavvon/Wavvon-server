use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, mpsc, RwLock};
use voxply_identity::Identity;

use crate::federation::client::FederationClient;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DmEvent {
    Message {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        content: String,
        timestamp: i64,
    },
    Typing {
        conversation_id: String,
        sender: String,
        sender_name: Option<String>,
        typing: bool,
    },
}

impl DmEvent {
    pub fn conversation_id(&self) -> &str {
        match self {
            DmEvent::Message { conversation_id, .. }
            | DmEvent::Typing { conversation_id, .. } => conversation_id,
        }
    }
    pub fn sender(&self) -> &str {
        match self {
            DmEvent::Message { sender, .. } | DmEvent::Typing { sender, .. } => sender,
        }
    }
}

/// Metadata for a single active screen-share stream.
#[derive(Clone)]
pub struct ScreenStreamMeta {
    pub kind: String,
    pub mime: String,
    pub has_audio: bool,
    pub sharer_pubkey: String,
    /// Cached WebM init segment for late joiners. Set on the first chunk
    /// where `is_init == true`.
    pub init_chunk: Option<Bytes>,
    /// Wall time when this stream was registered. Used to distinguish
    /// "share started before I subscribed" (push needed) from
    /// "share started after I subscribed" (broadcast delivers it).
    pub started_at: Instant,
}

/// All active streams for one (channel, sharer) pair.
///
/// The key is `(channel_id, sharer_pubkey)`. Multiple sharers per channel are
/// allowed — the cap was removed to support the multi-stream overlay feature.
pub struct ActiveShare {
    /// stream_id → metadata
    pub streams: HashMap<String, ScreenStreamMeta>,
    /// Set of viewer pubkeys currently negotiating or watching this share
    /// via WebRTC (v2). Used for join/leave routing and WS-disconnect cleanup.
    pub viewers: HashSet<String>,
    /// Pubkeys that subscribed to this share from a *different* channel via
    /// StreamSubscribe — they receive chunks without being in the source channel.
    pub cross_channel_subscribers: HashSet<String>,
}

/// A screen-share chunk broadcast to all WS connections.
#[derive(Clone)]
pub struct ScreenChunkEvent {
    pub channel_id: String,
    pub stream_id: String,
    pub sharer_pubkey: String,
    pub seq: u32,
    pub is_init: bool,
    pub data: Bytes,
}

/// Attenuation parameters for a voice zone.
#[derive(Clone, Debug)]
pub struct AttenuationConfig {
    pub model: String,        // "linear" | "inverse_square" | "step" | "exponential"
    pub max_radius: f64,
    pub ref_dist: f64,
    pub rolloff: f64,
}

/// In-memory state for one live voice zone.
///
/// Zones are channel-scoped and ephemeral (cleared on hub restart).
/// A future refinement can persist flagged zones to a DB table.
#[derive(Clone, Debug)]
pub struct VoiceZone {
    pub zone_id: String,
    pub channel_id: String,
    pub name: String,
    /// "2d" | "3d"
    pub coordinate_system: String,
    pub attenuation: AttenuationConfig,
    /// "creator_only" | "any_channel_member" | "session_roster"
    pub auth_mode: String,
    pub creator_pubkey: String,
    pub session_id: Option<String>,
    /// pubkey → position (2 or 3 floats)
    pub positions: HashMap<String, Vec<f64>>,
}

/// A single player in a live game session.
#[derive(Clone, Debug)]
pub struct GamePlayer {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub joined_at: i64,
    pub connected: bool,
}

/// In-memory state for one live game session.
///
/// The hub is a pure relay for Tier 2: it tracks the roster and the last
/// snapshot (if the game opted into durability), but never interprets the
/// game's own state payload.
#[derive(Clone, Debug)]
pub struct GameSessionState {
    pub id: String,
    pub channel_id: String,
    pub game_id: String,
    pub host_pubkey: String,
    /// Roster pubkeys for fast membership lookup.
    pub players: HashSet<String>,
    /// Full player metadata (display names, join order, connected flag).
    pub player_details: Vec<GamePlayer>,
    /// Session status: "lobby" | "in_progress" | "ended" | "abandoned"
    pub status: String,
    /// Maximum allowed players (from hub_games.max_players). None = unlimited.
    pub max_players: Option<i64>,
    /// Unix-seconds when the session was created.
    pub created_at: i64,
    /// Unix-seconds of the last event (used by the reaper for TTL).
    pub last_event_at: i64,
    /// Latest author-supplied durability snapshot. Opaque bytes.
    pub snapshot: Option<bytes::Bytes>,
    /// Opaque JSON state kept for patch_state backwards-compat.
    pub in_memory_state: serde_json::Value,
}

/// One element of a whisper target specification.
/// Carries the original descriptor so the hub can re-resolve on voice join/leave.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct WhisperTargetDef {
    #[serde(rename = "type")]
    pub target_type: String, // "user" | "channel" | "role"
    pub id: String,
}

pub struct AppState {
    pub hub_name: String,
    pub hub_identity: Identity,
    pub db: SqlitePool,
    pub pending_challenges: RwLock<HashMap<String, PendingChallenge>>,
    pub chat_tx: broadcast::Sender<(ChatEvent, Arc<str>)>,
    pub federation_client: FederationClient,
    pub peer_tokens: RwLock<HashMap<String, String>>,
    /// Plain HTTP client for outbound requests that don't go through the
    /// federation protocol (e.g. sending push invites to foreign hubs).
    pub http_client: reqwest::Client,
    // Voice: channel_id → {public_key → udp_addr}
    pub voice_channels: RwLock<HashMap<String, HashMap<String, SocketAddr>>>,
    /// Reverse index: SocketAddr → (channel_id, public_key).
    /// Kept in sync with voice_channels by VoiceJoin/VoiceLeave handlers in ws.rs.
    pub voice_addr_map: RwLock<HashMap<SocketAddr, (String, String)>>,
    /// sender_id assignment: channel_id → { pubkey → sender_id }
    pub voice_sender_ids: RwLock<HashMap<String, HashMap<String, u16>>>,
    /// Next available sender_id counter per channel
    pub voice_next_sender_id: RwLock<HashMap<String, u16>>,
    pub voice_udp_port: u16,
    pub voice_event_tx: broadcast::Sender<(String, WsServerMessage)>,
    // DM relay: broadcast DMs to all WS clients (they filter by conversation membership)
    pub dm_tx: broadcast::Sender<DmEvent>,
    // Online users: public_key set (updated by WS connect/disconnect)
    pub online_users: RwLock<std::collections::HashSet<String>>,
    /// Active screen-share sessions: (channel_id, sharer_pubkey) → ActiveShare.
    /// Multiple concurrent sharers per channel are allowed (multi-stream overlay).
    /// In-memory only — cleared on process restart.
    pub screen_shares: RwLock<HashMap<(String, String), ActiveShare>>,
    /// Broadcast channel carrying binary chunk events to all WS connections.
    pub screen_share_tx: broadcast::Sender<ScreenChunkEvent>,
    /// Active bot WS sessions: bot_pubkey → mpsc sender for pre-serialised
    /// JSON text frames. Bots use a separate channel from the regular WS
    /// broadcast so we can push targeted hub_event messages without looping
    /// through every connected client.
    pub bot_sessions: RwLock<HashMap<String, mpsc::Sender<String>>>,

    /// Active voice zones: (channel_id, zone_id) → VoiceZone.
    /// Ephemeral — cleared on hub restart.
    pub voice_zones: RwLock<HashMap<(String, String), VoiceZone>>,

    // ---- Gaming Tier 2 ----
    /// In-memory index of live game sessions: session_id → GameSessionState.
    /// Cleared on restart; the DB `game_sessions` table holds durable
    /// snapshots for games that opt into persistence.
    pub active_game_sessions: Arc<Mutex<HashMap<String, GameSessionState>>>,

    /// channel_id → pubkeys currently with video enabled
    pub video_channels: RwLock<HashMap<String, HashSet<String>>>,

    // ---- Farm integration (Phase 1, dual-issue step 1) ----

    /// Wall time when this hub process started. Used by /metrics.
    pub started_at: std::time::Instant,

    /// URL of the farm process this hub is paired with, if any.
    /// Populated from the `VOXPLY_FARM_URL` environment variable on startup.
    /// Surfaced in `GET /info` so clients know where to route auth.
    pub farm_url: Option<String>,
    /// Cached farm Ed25519 public key (hex). Populated from `GET {farm_url}/farm/info`
    /// on startup; refreshed (at most once per 60s) when a token fails verification —
    /// handles farm key rotation without requiring a restart.
    pub cached_farm_pubkey: Arc<RwLock<Option<String>>>,
    /// Unix timestamp of the last farm pubkey re-fetch attempt.
    /// Used to rate-limit re-fetch to at most once per 60s.
    pub last_farm_pubkey_fetch: Arc<RwLock<i64>>,

    /// Active whisper sessions: sender_pubkey → set of target SocketAddrs.
    /// When a sender has an entry here the UDP relay routes their frames
    /// exclusively to this set with packet_type = 0x01.
    pub whisper_targets: RwLock<HashMap<String, HashSet<SocketAddr>>>,
    /// Original target descriptors for re-resolution on any VoiceJoin/Leave.
    pub whisper_target_defs: RwLock<HashMap<String, Vec<WhisperTargetDef>>>,

    /// Per-IP fixed-window rate limiter for auth endpoints.
    /// key = IP string, value = (attempt_count, window_start).
    pub auth_rate_limit: Mutex<HashMap<String, (u32, std::time::Instant)>>,
}

pub struct PendingChallenge {
    pub challenge_bytes: Vec<u8>,
    pub expires_at: Instant,
}
