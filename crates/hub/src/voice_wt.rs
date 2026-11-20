//! WebTransport adapter for the voice relay (voice-transport-v2.md; the
//! relay itself is transport-agnostic, see `voice_relay`).
//!
//! A single QUIC/WebTransport endpoint, bound on `WAVVON_VOICE_UDP_PORT`,
//! replaces the old raw-UDP relay and the `/voice/ws` web relay. Clients
//! join voice over the normal hub WS (`voice_join`/`voice_joined`) and then
//! open a WT session against the URL/token `voice_joined` carries. The hub
//! is a header-only forwarder: it prepends `[sender_id: u16 BE][packet_type:
//! u8]` to each datagram and fans it out — it never parses or decrypts the
//! sealed Opus payload (E2E, same privacy model as DMs).

use std::sync::Arc;

use wtransport::endpoint::{endpoint_side, IncomingSession};
use wtransport::{Endpoint, Identity as WtIdentity, ServerConfig};

use crate::auth::handlers::unix_timestamp;
use crate::state::AppState;
use crate::voice_relay::{self, VoiceLink};

/// A WebTransport session as the relay sees it.
struct WtLink(wtransport::Connection);

impl VoiceLink for WtLink {
    fn send(&self, packet: &[u8]) {
        let _ = self.0.send_datagram(packet);
    }

    fn close(&self, reason: &str) {
        self.0
            .close(wtransport::VarInt::from_u32(0), reason.as_bytes());
    }
}

/// Self-signed cert validity window (voice-transport-v2.md) — the maximum
/// WebTransport's `serverCertificateHashes` trust tier allows.
const VALIDITY_DAYS: i64 = 14;
/// Regenerate once fewer than this many days remain.
const ROTATE_WHEN_REMAINING_DAYS: i64 = 4;
/// How often the maintenance task re-checks cert age.
const ROTATE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Persisted cert/key/meta paths, keyed by the voice port so that multiple
/// hub processes sharing a working directory (farm-spawned hubs, parallel
/// test binaries) never race on one file triple — concurrent writers used
/// to leave a mismatched cert/key pair on disk, which wtransport panics on
/// at load. The meta sidecar records the cert's generation time (unix
/// seconds): `serverCertificateHashes` trust is hash-based so the cert
/// carries hostname-agnostic SANs, and this is cheaper than an X.509 parse
/// to re-derive expiry — matches `lan.rs`'s persist-alongside convention.
fn cert_paths(port: u16) -> (String, String, String) {
    (
        format!("voice_wt_cert_{port}.pem"),
        format!("voice_wt_cert_{port}.key"),
        format!("voice_wt_cert_{port}.created_at"),
    )
}

fn self_signed_sans() -> [&'static str; 3] {
    ["localhost", "127.0.0.1", "::1"]
}

fn cert_hash_hex(identity: &WtIdentity) -> String {
    hex::encode(identity.certificate_chain().as_slice()[0].hash().as_ref())
}

struct SelfSignedVoiceCert {
    identity: WtIdentity,
    hash_hex: String,
    created_at: i64,
}

impl SelfSignedVoiceCert {
    fn needs_rotation(&self) -> bool {
        (unix_timestamp() - self.created_at) / 86400 >= VALIDITY_DAYS - ROTATE_WHEN_REMAINING_DAYS
    }
}

async fn generate_and_persist(port: u16) -> anyhow::Result<SelfSignedVoiceCert> {
    let identity = WtIdentity::self_signed_builder()
        .subject_alt_names(self_signed_sans())
        .from_now_utc()
        .validity_days(VALIDITY_DAYS as u32)
        .build()
        .map_err(|e| anyhow::anyhow!("invalid voice WT self-signed cert SANs: {e:?}"))?;
    let created_at = unix_timestamp();

    // Port 0 = ephemeral bind (tests): the process can't be restarted onto
    // the "same" port, so persistence buys nothing — keep it in memory.
    if port != 0 {
        let (cert_path, key_path, meta_path) = cert_paths(port);
        identity
            .certificate_chain()
            .store_pemfile(&cert_path)
            .await?;
        wavvon_identity::write_secret(&key_path, identity.private_key().to_secret_pem())?;
        // Meta written last: its presence is the commit marker the loader
        // requires, so a torn write of the pair is never loaded.
        tokio::fs::write(&meta_path, created_at.to_string()).await?;
    }

    let hash_hex = cert_hash_hex(&identity);
    Ok(SelfSignedVoiceCert {
        identity,
        hash_hex,
        created_at,
    })
}

/// Loads the persisted self-signed cert if it exists and isn't due for
/// rotation yet; otherwise generates (and persists) a fresh one. Mirrors
/// `lan::load_or_create_self_signed`'s reuse-across-restarts behavior, plus
/// the rotation `lan.rs`'s never-expiring LAN cert doesn't need.
async fn load_or_create_self_signed(port: u16) -> anyhow::Result<SelfSignedVoiceCert> {
    let loaded: Option<SelfSignedVoiceCert> = async {
        if port == 0 {
            return None;
        }
        let (cert_path, key_path, meta_path) = cert_paths(port);
        let created_at: i64 = tokio::fs::read_to_string(&meta_path)
            .await
            .ok()?
            .trim()
            .parse()
            .ok()?;
        wavvon_identity::restrict_secret(&key_path);
        let identity = WtIdentity::load_pemfiles(&cert_path, &key_path)
            .await
            .ok()?;
        Some(SelfSignedVoiceCert {
            hash_hex: cert_hash_hex(&identity),
            identity,
            created_at,
        })
    }
    .await;

    match loaded {
        Some(cert) if !cert.needs_rotation() => Ok(cert),
        _ => generate_and_persist(port).await,
    }
}

fn build_server_config(identity: WtIdentity, port: u16) -> ServerConfig {
    ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity)
        .build()
}

/// Sets up and starts the WebTransport voice relay: binds the endpoint on
/// `port` (`0` picks an ephemeral port — useful for tests), records the
/// active cert's hash on `state.voice_cert_hash` (`None` when a CA cert is
/// in use), and spawns the accept loop plus — self-signed mode only — the
/// daily rotation task. Returns the port actually bound.
///
/// `tls_cert`/`tls_key` are the *raw* `WAVVON_TLS_CERT`/`WAVVON_TLS_KEY`
/// settings, not LAN mode's effective override: a LAN-mode self-signed cert
/// has no rotation story and no `serverCertificateHashes`-compatible
/// validity window, so voice always manages its own identity independently.
pub async fn start(
    state: Arc<AppState>,
    port: u16,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> anyhow::Result<u16> {
    let (identity, hash) = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => (WtIdentity::load_pemfiles(cert, key).await?, None),
        _ => {
            let cert = load_or_create_self_signed(port).await?;
            (cert.identity, Some(cert.hash_hex))
        }
    };
    let self_signed = hash.is_some();
    *state.voice_cert_hash.write().await = hash;

    let config = build_server_config(identity, port);
    let endpoint = Arc::new(Endpoint::server(config)?);
    let bound_port = endpoint.local_addr()?.port();

    spawn_relay(endpoint.clone(), state.clone());
    if self_signed {
        spawn_cert_rotation(endpoint, state, bound_port);
    }

    Ok(bound_port)
}

/// Accept loop: one task per incoming session, so a slow/malicious client
/// blocked on its own handshake can't stall other sessions.
fn spawn_relay(endpoint: Arc<Endpoint<endpoint_side::Server>>, state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            let incoming = endpoint.accept().await;
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_session(incoming, state).await {
                    tracing::debug!("voice WT session ended: {e}");
                }
            });
        }
    });
}

/// Daily maintenance task: regenerates the self-signed cert once it's
/// within `ROTATE_WHEN_REMAINING_DAYS` of expiry and hot-swaps it into the
/// running endpoint via `reload_config` (no rebind, existing sessions are
/// undisturbed). Only spawned when the hub isn't running a CA-issued cert.
fn spawn_cert_rotation(
    endpoint: Arc<Endpoint<endpoint_side::Server>>,
    state: Arc<AppState>,
    port: u16,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(ROTATE_CHECK_INTERVAL).await;
            match load_or_create_self_signed(port).await {
                Ok(cert) => {
                    let current = state.voice_cert_hash.read().await.clone();
                    if current.as_deref() == Some(cert.hash_hex.as_str()) {
                        continue; // not due — same cert as before
                    }
                    let config = build_server_config(cert.identity, port);
                    if let Err(e) = endpoint.reload_config(config, false) {
                        tracing::warn!("voice WT cert rotation: reload_config failed: {e}");
                        continue;
                    }
                    tracing::info!(
                        "voice WT cert rotated (hash {}…)",
                        &cert.hash_hex[..16.min(cert.hash_hex.len())]
                    );
                    *state.voice_cert_hash.write().await = Some(cert.hash_hex);
                }
                Err(e) => tracing::warn!("voice WT cert rotation check failed: {e}"),
            }
        }
    });
}

/// Parses `?token=<hex>` out of a WT session's request path/query. No other
/// query params are defined; anything else in the query string is ignored.
fn extract_token(path: &str) -> Option<&str> {
    let (_, query) = path.split_once('?')?;
    query.split('&').find_map(|kv| kv.strip_prefix("token="))
}

/// The first characters of a key, enough to recognise a member in the log.
fn short(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(12)]
}

// Sessions are logged once each at INFO (opened, refused, closed), never per
// datagram: "the QUIC session never reached the hub" and "it reached the hub
// and was refused" must not look the same to an operator. The token is never
// logged.
async fn handle_session(incoming: IncomingSession, state: Arc<AppState>) -> anyhow::Result<()> {
    let session_request = incoming.await?;
    let peer = session_request.remote_address();

    let Some(token) = extract_token(session_request.path()) else {
        tracing::info!(%peer, "voice WT session refused: no token");
        session_request.not_found().await;
        return Ok(());
    };

    let bind = voice_relay::take_bind(&state, token).await;
    let Some(bind) = bind else {
        tracing::info!(%peer, "voice WT session refused: unknown, used or expired token");
        session_request.forbidden().await;
        return Ok(());
    };

    let connection = session_request.accept().await?;
    let opened = std::time::Instant::now();
    tracing::info!(
        %peer,
        member = short(&bind.pubkey),
        channel = %bind.channel_id,
        "voice WT session opened"
    );

    voice_relay::attach(&state, &bind, Arc::new(WtLink(connection.clone()))).await;

    let ended = loop {
        tokio::select! {
            datagram = connection.receive_datagram() => {
                match datagram {
                    Ok(datagram) => {
                        voice_relay::relay(&state, &bind.channel_id, &bind.pubkey, &datagram.payload()).await;
                    }
                    Err(e) => break e.to_string(),
                }
            }
            reason = connection.closed() => break reason.to_string(),
        }
    };
    tracing::info!(
        member = short(&bind.pubkey),
        channel = %bind.channel_id,
        secs = opened.elapsed().as_secs(),
        reason = %ended,
        "voice WT session closed"
    );

    voice_relay::detach(&state, &bind).await;

    Ok(())
}
