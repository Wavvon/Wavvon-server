use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::StatusCode;
use bytes::Bytes;
use sqlx::PgPool;
use store::StoreError;
use tokio::sync::{broadcast, mpsc, RwLock};
use wavvon_identity::Identity;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

use crate::federation::client::FederationClient;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};

/// Map a `StoreError` to an HTTP status + plain-text body.
///
/// Replaces the ad-hoc `.map_err(|_| (StatusCode::..., "...".into()))` and
/// `"UNIQUE"` string-sniffing that was scattered across route handlers.
/// Route handlers call `store_error_to_http(e)` or `.map_err(store_error_to_http)`.
pub fn store_error_to_http(e: StoreError) -> (StatusCode, String) {
    match e {
        StoreError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
        StoreError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        StoreError::PermissionDenied => (StatusCode::FORBIDDEN, "permission denied".into()),
        StoreError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
    }
}

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
    MemberChanged {
        conversation_id: String,
        actor: String,
        added: Vec<String>,
        removed: Vec<String>,
    },
}

impl DmEvent {
    pub fn conversation_id(&self) -> &str {
        match self {
            DmEvent::Message {
                conversation_id, ..
            }
            | DmEvent::Typing {
                conversation_id, ..
            }
            | DmEvent::MemberChanged {
                conversation_id, ..
            } => conversation_id,
        }
    }
    pub fn sender(&self) -> &str {
        match self {
            DmEvent::Message { sender, .. } | DmEvent::Typing { sender, .. } => sender,
            DmEvent::MemberChanged { actor, .. } => actor,
        }
    }
    /// Whether this event should be suppressed for its own sender (anti-echo).
    /// MemberChanged is delivered to everyone including the actor.
    pub fn suppress_echo(&self) -> bool {
        matches!(self, DmEvent::Message { .. } | DmEvent::Typing { .. })
    }
}

/// Metadata for a single active screen-share stream.
#[derive(Clone)]
pub struct ScreenStreamMeta {
    pub kind: String,
    pub mime: String,
    pub has_audio: bool,
    pub sharer_pubkey: String,
    /// Whether the sharer is a bot (`can_inject_video` gate,
    /// bot-capability-layer.md §3/§6 Phase 2). Used to scope the per-hub
    /// concurrent bot-video-stream budget to bot streams only -- human
    /// screen shares never count against it.
    pub is_bot: bool,
    /// Unique WS session id of the connection that started this stream.
    /// Used to discriminate cleanup: on disconnect only streams from the
    /// disconnecting session are removed, leaving streams from other
    /// concurrent sessions intact.
    pub session_id: String,
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
    pub model: String, // "linear" | "inverse_square" | "step" | "exponential"
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

/// One element of a whisper target specification.
/// Carries the original descriptor so the hub can re-resolve on voice join/leave.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct WhisperTargetDef {
    #[serde(rename = "type")]
    pub target_type: String, // "user" | "channel" | "role"
    pub id: String,
}

/// A pending WebTransport session-bind for a voice participant.
///
/// Minted at `VoiceJoin` and consumed, single-use, when the client opens a
/// WT session against `voice_wt_url` presenting the matching token
/// (voice-transport-v2.md). Expires after `expires_at`.
pub struct PendingVoiceBind {
    pub channel_id: String,
    pub pubkey: String,
    pub expires_at: Instant,
}

/// Circuit breaker state for the auto-moderation webhook (ME2).
///
/// Opened after 3 consecutive 5xx responses within 60 seconds.
/// While open, the webhook call is skipped entirely (fail-open).
/// Resets to closed on any successful (non-5xx) response.
#[derive(Default)]
pub struct WebhookCircuit {
    /// Number of consecutive 5xx failures in the current window.
    pub consecutive_failures: u32,
    /// Unix timestamp after which the circuit re-closes. `None` = closed.
    pub open_until: Option<i64>,
    /// Wall-clock time of the first failure in the current streak.
    /// Used to enforce the 60-second window requirement.
    pub streak_started_at: Option<i64>,
}

pub struct RateLimiters {
    /// Per-user fixed-window rate limiter for message posting (30 messages/60 s).
    pub messages: Mutex<HashMap<String, (u32, Instant)>>,
    /// Per-user fixed-window rate limiter for link preview fetches (10 requests/60 s).
    /// Each preview may trigger an outbound HTTP fetch, so we throttle per user.
    pub preview: Mutex<HashMap<String, (u32, Instant)>>,
    /// Per-hub-pubkey rate limiter for /federation/badge-offer (20 offers/3600 s).
    /// Keyed by the sender's hub public key hex.
    pub badge_offer: Mutex<HashMap<String, (u32, Instant)>>,
    /// Per-origin-hub rate limiter for federated forum writes
    /// (`/federation/forum/...`, forum.md §9 "Threat-model deltas": "Add a
    /// per-origin-hub rate limiter on federated forum writes"). Keyed by the
    /// calling hub's public key hex. 30 writes/60 s -- mirrors `badge_offer`'s
    /// shape (fixed window, same eviction policy) at a cadence sized for
    /// chat-like content rather than the much rarer badge handshake.
    pub forum_federated_write: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self {
            messages: Mutex::new(HashMap::new()),
            preview: Mutex::new(HashMap::new()),
            badge_offer: Mutex::new(HashMap::new()),
            forum_federated_write: Mutex::new(HashMap::new()),
        }
    }
}

/// In-flight WebAuthn registration: session_id → (user_pubkey, state).
pub struct RegChallenge {
    pub user_pubkey: String,
    pub state: PasskeyRegistration,
}

/// In-flight WebAuthn authentication: session_id → (user_pubkey, state, passkeys).
/// Passkeys are stored so the sign_count can be updated after a successful assertion.
pub struct AuthChallenge {
    pub user_pubkey: String,
    pub state: PasskeyAuthentication,
    pub passkeys: Vec<webauthn_rs::prelude::Passkey>,
}

/// `(issuer_pubkey, master_pubkey)` → `(fetched_at, portfolio)`.
pub type CertPortfolioCache =
    HashMap<(String, String), (i64, Vec<crate::routes::certs::Certification>)>;

pub struct AppState {
    pub hub_name: String,
    pub hub_identity: Identity,
    pub db: PgPool,
    /// Read-replica pool, if configured. Route handlers that do only reads
    /// may use this via `state.db_read.as_ref().unwrap_or(&state.db)`.
    pub db_read: Option<PgPool>,
    /// Abstracted store handle — use this for new code; existing handlers
    /// may still use `state.db` directly while the per-handler migration
    /// proceeds incrementally.
    pub store: Arc<dyn store::HubStore>,
    /// Outstanding auth challenges, keyed by the challenge hex (NOT the
    /// pubkey) so concurrent auth flows for the same key don't stomp each
    /// other's challenge — e.g. two simultaneous federated DM deliveries to
    /// the same peer hub.
    pub pending_challenges: RwLock<HashMap<String, PendingChallenge>>,
    /// `(issuer_pubkey, master_pubkey)` → `(fetched_at, portfolio)` for certs
    /// this hub pulled from a trusted issuer during admission
    /// (hub-certifications.md §11). Short-lived on purpose: a sibling that
    /// revokes is honoured within one TTL, and within a farm the fetch it
    /// saves is a loopback call anyway.
    pub cert_portfolio_cache: RwLock<CertPortfolioCache>,
    pub chat_tx: broadcast::Sender<(ChatEvent, Arc<str>)>,
    pub federation_client: FederationClient,
    pub peer_tokens: RwLock<HashMap<String, String>>,
    /// Plain HTTP client for outbound requests that don't go through the
    /// federation protocol (e.g. sending push invites to foreign hubs).
    pub http_client: reqwest::Client,
    // Voice (voice-transport-v2.md): channel_id → {public_key → WT session}.
    // `None` means the pubkey has joined voice over WS but hasn't (yet, or
    // no longer) bound a live WebTransport datagram session — mirrors the
    // old sentinel-address membership marker, minus the sentinel.
    pub voice_channels: RwLock<HashMap<String, HashMap<String, Option<wtransport::Connection>>>>,
    /// sender_id assignment: channel_id → { pubkey → sender_id }
    pub voice_sender_ids: RwLock<HashMap<String, HashMap<String, u16>>>,
    /// Next available sender_id counter per channel
    pub voice_next_sender_id: RwLock<HashMap<String, u16>>,
    pub voice_udp_port: u16,
    /// Absolute `https://host:port/voice` URL for this hub's WebTransport
    /// voice endpoint, or `None` when no public host is known (no
    /// `WAVVON_PUBLIC_URL` and not in LAN mode). Derived once at startup
    /// from (in priority order) `WAVVON_PUBLIC_URL`'s host, then the
    /// LAN-mode advertise address, both paired with `voice_udp_port`.
    /// Surfaced on `/info` and in `voice_joined` — see voice-transport-v2.md.
    pub voice_wt_url: Option<String>,
    /// The address clients should store for this hub, published on `/info`.
    ///
    /// Starts as the locally-derived public URL and is replaced by whatever
    /// the farm reports in its heartbeat response — that is how a hub learns
    /// it has been given a new name, without a restart. `RwLock` because the
    /// heartbeat task writes it while request handlers read it.
    pub canonical_url: Arc<RwLock<Option<String>>>,
    /// Hex SHA-256 digest of the WT endpoint's current self-signed
    /// certificate. `None` when a CA-issued cert (`WAVVON_TLS_CERT`/`_KEY`)
    /// is in use, or before the cert has been generated. Rotates in place
    /// (see `voice_wt::spawn_cert_rotation`) — always read fresh, never cached
    /// by callers.
    pub voice_cert_hash: RwLock<Option<String>>,
    pub voice_event_tx: broadcast::Sender<(String, WsServerMessage)>,
    // DM relay: broadcast DMs to all WS clients (they filter by conversation membership)
    pub dm_tx: broadcast::Sender<DmEvent>,
    // Online users: public_key → session refcount (updated by WS connect/disconnect).
    // A key is present iff at least one WS session for that pubkey is alive.
    // Refcounted so multi-device / reconnect-overlap is handled correctly: the
    // second connect increments, the first disconnect decrements but does NOT
    // remove the key until the count reaches zero.
    pub online_users: RwLock<HashMap<String, usize>>,
    /// Active screen-share sessions: (channel_id, sharer_pubkey) → ActiveShare.
    /// Multiple concurrent sharers per channel are allowed (multi-stream overlay).
    /// In-memory only — cleared on process restart.
    pub screen_shares: RwLock<HashMap<(String, String), ActiveShare>>,
    /// Broadcast channel carrying binary chunk events to all WS connections.
    pub screen_share_tx: broadcast::Sender<ScreenChunkEvent>,
    /// Active bot WS sessions: bot_pubkey → { session_id → mpsc sender }.
    ///
    /// A bot pubkey can have multiple concurrent WS sessions (e.g. reconnect
    /// overlap, multi-process bot deployments).  Each session is identified by
    /// a unique UUID generated at connect time.  On disconnect only the entry
    /// for that session's UUID is removed — not all entries for the pubkey —
    /// so the surviving session(s) continue to receive push messages.
    ///
    /// Token-expiry sweep removes all sessions for a pubkey at once (a token
    /// revocation is pubkey-wide).
    pub bot_sessions: RwLock<HashMap<String, HashMap<String, mpsc::Sender<String>>>>,

    /// Active voice zones: (channel_id, zone_id) → VoiceZone.
    /// Ephemeral — cleared on hub restart.
    pub voice_zones: RwLock<HashMap<(String, String), VoiceZone>>,

    /// channel_id → pubkeys currently with video enabled
    pub video_channels: RwLock<HashMap<String, HashSet<String>>>,

    // ---- Farm integration (Phase 1, dual-issue step 1) ----
    /// Wall time when this hub process started. Used by /metrics.
    pub started_at: std::time::Instant,

    /// URL of the farm process this hub is paired with, if any.
    /// Populated from the `WAVVON_FARM_URL` environment variable on startup.
    /// Surfaced in `GET /info` so clients know where to route auth.
    pub farm_url: Option<String>,
    /// Cached farm Ed25519 public key (hex). Populated from `GET {farm_url}/farm/info`
    /// on startup; refreshed (at most once per 60s) when a token fails verification —
    /// handles farm key rotation without requiring a restart.
    pub cached_farm_pubkey: Arc<RwLock<Option<String>>>,
    /// Unix timestamp of the last farm pubkey re-fetch attempt.
    /// Used to rate-limit re-fetch to at most once per 60s.
    pub last_farm_pubkey_fetch: Arc<RwLock<i64>>,

    /// Original target descriptors for re-resolution on any VoiceJoin/Leave.
    pub whisper_target_defs: RwLock<HashMap<String, Vec<WhisperTargetDef>>>,
    /// Whisper targets: sender_pubkey → set of target pubkeys. Since every
    /// voice participant (desktop and web alike) is a WT session keyed by
    /// pubkey (voice-transport-v2.md), this one pubkey-keyed set is enough —
    /// there is no separate SocketAddr-based target set to keep in sync.
    /// The WT receive loop (`voice_wt.rs`) routes a whispering sender's
    /// datagrams exclusively to this set with packet_type = 0x01.
    pub whisper_target_pubkeys: RwLock<HashMap<String, HashSet<String>>>,

    /// pubkey → unix timestamp of last voice activity (join or a
    /// `voice_speaking` message). Drives the AFK sweep in `afk_worker`:
    /// a participant whose stamp is older than the hub's `afk_timeout_secs`
    /// gets a `voice_move` push into the configured AFK channel.
    ///
    /// Ephemeral, in-memory only. Stamped on `VoiceJoin` and on every
    /// `VoiceSpeaking` message; removed by `leave_voice`.
    pub voice_last_active: RwLock<HashMap<String, i64>>,

    /// Pubkeys that have opted out of RECEIVING whispers (whisper.md).
    /// Ephemeral, in-memory only -- resets on hub restart. Consulted at the
    /// top of every whisper-target resolution function (`resolve_whisper_targets`,
    /// `resolve_role_addrs`, `resolve_whisper_target_pubkeys` in
    /// `routes/ws/voice.rs`) so an opted-out pubkey is filtered out of every
    /// target set. Opting out only affects receiving -- an opted-out user can
    /// still start a whisper of their own.
    pub whisper_optouts: RwLock<HashSet<String>>,

    /// Pubkeys that currently own a live voice relay slot.
    ///
    /// Inserted on `VoiceJoin`; removed on `leave_voice` (called on WS
    /// disconnect and on explicit `VoiceLeave`).  The WT receive loop checks
    /// this set before forwarding a datagram so that a session whose WS
    /// connection closed cannot keep relaying traffic.
    ///
    /// O(1) read under a shared lock — intentionally kept as a plain
    /// `RwLock<HashSet>` to avoid adding a new crate dependency.
    pub voice_relay_active: RwLock<HashSet<String>>,

    /// Per-sender outbound packet loss, seen from the relay: pubkey ->
    /// counter-span tracker (voice_loss.rs). Reported back to that sender on
    /// its own `pong`, which is the only client that may see it -- outbound
    /// loss is a property of one participant's uplink and telling the channel
    /// about it would be gossip, not diagnostics.
    ///
    /// Reset on voice join, so a figure never describes a previous session.
    pub voice_outbound_loss: RwLock<HashMap<String, crate::voice_loss::SenderLoss>>,

    /// Voice-only presence grants (events.md §7.4): pubkey → set of
    /// channel_ids the pubkey may join voice on despite lacking effective
    /// `READ_MESSAGES` there.
    ///
    /// Ephemeral, in-memory only — never persisted, never survives a
    /// restart. Created just before the hub pushes a `voice_move` whose
    /// target lacks read access on the destination; consumed (checked, not
    /// removed) by the voice-join read gate; removed by `leave_voice` on
    /// leave/disconnect. Exactly one enforcement point (the voice-join gate)
    /// consults this map — message history, WS subscribe, channel list, and
    /// event read-gating all stay strict per the decisions.md entry.
    pub staging_voice_grants: RwLock<HashMap<String, HashSet<String>>>,

    /// Pending WebTransport session-binds waiting for the client to open its
    /// `voice_wt_url?token=<hex>` session (voice-transport-v2.md).
    ///
    /// Key is the hex register token (64 chars, 32 random bytes).
    /// Entries are inserted at `VoiceJoin` and consumed, single-use, on the
    /// first WT session request presenting a matching token.  Expired
    /// entries are purged opportunistically on each new mint and on each
    /// session-accept attempt.
    pub voice_pending_binds: RwLock<HashMap<String, PendingVoiceBind>>,

    /// Per-*session* WS senders for targeted delivery: voice key
    /// distribution (V4) and mini-app messages addressed to a user.
    /// Keyed `pubkey -> session_id -> sender`, registered on WS connect and
    /// deregistered on that session's own disconnect.
    ///
    /// Nested, and not one sender per pubkey, for the reason `bot_sessions`
    /// is nested: one pubkey has several sockets more often than not — a
    /// second tab, a paired device, or the overlap while a reconnect stands
    /// up its socket before the old one finishes tearing down. A flat map
    /// took the newest socket and then let the *older* socket's cleanup
    /// remove it, so the survivor was registered nowhere and every targeted
    /// message to that user was dropped with nothing reporting it. For voice
    /// that means no sender key arrives, so every datagram is discarded at
    /// the key lookup and the call is silent — see `send_to_user`.
    pub ws_key_senders: RwLock<
        HashMap<String, HashMap<String, tokio::sync::mpsc::UnboundedSender<WsServerMessage>>>,
    >,

    /// Grouped rate limiters (auth per-IP, messages per-user).
    pub rate_limiters: RateLimiters,

    /// In-memory link preview cache: url → (result, inserted_at).
    /// Entries expire after 30 minutes.
    pub preview_cache: std::sync::Mutex<
        std::collections::HashMap<
            String,
            (crate::routes::preview::LinkPreview, std::time::Instant),
        >,
    >,

    /// Full-text search backend. Either TantivySearch or NullSearch.
    pub search: Arc<dyn crate::search::MessageSearch>,

    /// Guards against concurrent admin reindex runs. Set to `true` while a
    /// reindex is in progress; callers that see `true` receive 202 with
    /// `{"status":"already_running"}` and do not start a second job.
    pub reindex_running: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// The operator-configured owner public key, if any (`WAVVON_OWNER_PUBKEY`).
    ///
    /// When set, startup seeding already inserted a `builtin-owner` row before
    /// the server accepted connections.  `assign_initial_roles` checks this to
    /// decide whether the first-registrant auto-grant should run: if it is
    /// `Some`, the auto-grant is skipped entirely.
    pub owner_pubkey: Option<String>,

    /// Mirror of `Settings::bots_allow_camera`.
    /// When true, bot mini-apps that declare `requires_camera` receive camera
    /// access in the client webview/iframe sandbox.
    pub bots_allow_camera: bool,

    /// Mirror of `Settings::bots_allow_video` (bot-capability-layer.md §1/§4/§6
    /// Phase 2). Operator kill-switch for `can_inject_video`: a grant alone is
    /// never sufficient, this flag must also be on. Defaults to false.
    pub bots_allow_video: bool,
    /// Mirror of `Settings::bot_video_stream_budget` (bot-capability-layer.md
    /// §4 "media budget"). Max number of concurrent bot-initiated video
    /// streams across the whole hub; frames aren't buffered/queued past this,
    /// `screen_share_start` is simply rejected once the cap is hit.
    ///
    /// ponytail: coarse hub-wide counter, not per-channel/per-bot. Docs leave
    /// the exact shape open ("the precise number is a hub config knob") --
    /// upgrade to a finer-grained (per-channel or per-bot) budget if a single
    /// hub-wide cap proves too coarse in practice.
    pub bot_video_stream_budget: usize,

    /// WebAuthn relying-party instance. Shared across all requests.
    pub webauthn: Arc<Webauthn>,
    /// In-flight registration challenges: session_id → RegChallenge.
    pub webauthn_reg_challenges: RwLock<HashMap<String, RegChallenge>>,
    /// In-flight authentication challenges: session_id → AuthChallenge.
    pub webauthn_auth_challenges: RwLock<HashMap<String, AuthChallenge>>,
    /// Device token TTL in seconds (from settings).
    pub device_token_ttl_secs: i64,

    /// ME2: Circuit breaker for the auto-moderation webhook.
    ///
    /// Shared across all request handlers so consecutive failures from any
    /// concurrent request accumulate in a single counter.
    pub webhook_circuit: Arc<tokio::sync::Mutex<WebhookCircuit>>,

    /// Mirror of `Settings::lan_mode` (`WAVVON_LAN_MODE`). See `crate::lan`
    /// for the private-address guard and self-signed cert helpers this gates.
    pub lan_mode: bool,
    /// Trust tier in effect when `lan_mode` is on: `Some("self")` for
    /// self-signed + fingerprint pinning, `Some("none")` for gated
    /// plaintext. `None` when `lan_mode` is off.
    pub lan_tls_mode: Option<String>,
    /// SHA-256 fingerprint (hex) of the LAN self-signed cert, present only
    /// when `lan_mode` is on and `lan_tls_mode == Some("self")`. Surfaced on
    /// `/info` and in the mDNS `fp` TXT record so clients can pin it TOFU-style.
    pub lan_fingerprint: Option<String>,
}

impl AppState {
    /// Deliver a targeted WS message to **every** session a pubkey has open,
    /// and report how many took it.
    ///
    /// All of them rather than a chosen one: the hub cannot tell which of a
    /// user's sockets is the one in voice, and the messages routed this way
    /// are ignored by a client that has no session for them (the web client
    /// no-ops when `voiceSessionRef` is null). Sending to one guessed socket
    /// is how a user with two tabs open hears nothing.
    pub async fn send_to_user(&self, pubkey: &str, msg: WsServerMessage) -> usize {
        let senders = self.ws_key_senders.read().await;
        let Some(sessions) = senders.get(pubkey) else {
            return 0;
        };
        sessions
            .values()
            .filter(|tx| tx.send(msg.clone()).is_ok())
            .count()
    }
}

pub struct PendingChallenge {
    /// The pubkey the challenge was issued to; verify must present the same.
    pub public_key: String,
    pub challenge_bytes: Vec<u8>,
    pub expires_at: Instant,
}
