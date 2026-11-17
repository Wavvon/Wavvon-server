//! Web Push (RFC 8030, RFC 8291 encryption, RFC 8292 VAPID) for a closed web
//! client: a mention, a reply or a DM reaches a member with no socket open.
//!
//! The payload travels through the browser vendor's push service, so it names
//! only the hub, the channel or conversation and the kind of event, never a
//! message's text. The subscription endpoint comes from the browser, so every
//! request to it goes through the same SSRF rule as an outgoing webhook, and
//! the connection is pinned to the addresses that rule checked.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Pushes one identity may receive per window, across all its devices.
const PUSH_LIMIT: u32 = 30;
const PUSH_WINDOW: Duration = Duration::from_secs(60);
/// How long a push service keeps an undelivered message.
const PUSH_TTL_SECS: u32 = 24 * 60 * 60;

/// A member's notify modes for this hub, as the client last sent them.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NotifyPrefs {
    #[serde(default)]
    pub hub: Option<NotifyMode>,
    #[serde(default)]
    pub channels: HashMap<String, NotifyMode>,
    /// A timed mute: the epoch-ms deadline after which the hub's mode no
    /// longer applies. The client sends a deadline rather than re-sending
    /// its modes when the mute ends, because a closed tab cannot.
    #[serde(default)]
    pub hub_until: Option<i64>,
    #[serde(default)]
    pub channels_until: HashMap<String, i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyMode {
    All,
    Mentions,
    Silent,
}

impl NotifyPrefs {
    /// Mentions, replies and DMs push under `all` and `mentions` alike; only
    /// `silent` stops them, channel over hub, as the client decides.
    /// A mode whose deadline has passed counts as unset, so an expired
    /// channel mute falls back to the hub's mode.
    fn silences(&self, channel_id: Option<&str>, now_ms: i64) -> bool {
        let live = |mode: Option<&NotifyMode>, until: Option<i64>| {
            mode.filter(|_| until.is_none_or(|u| u > now_ms)).copied()
        };
        let channel = channel_id
            .and_then(|c| live(self.channels.get(c), self.channels_until.get(c).copied()));
        channel.or(live(self.hub.as_ref(), self.hub_until)) == Some(NotifyMode::Silent)
    }
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// The hub's VAPID key, generated on first use and kept in the database, so a
/// backup carries it and a restore leaves every subscription valid.
pub async fn vapid_key(db: &sqlx::PgPool) -> Result<p256::SecretKey, sqlx::Error> {
    let fresh = p256::SecretKey::random(&mut rand::rngs::OsRng);
    sqlx::query("INSERT INTO push_vapid (private_key) VALUES ($1) ON CONFLICT (id) DO NOTHING")
        .bind(URL_SAFE_NO_PAD.encode(fresh.to_bytes()))
        .execute(db)
        .await?;
    let stored: String = sqlx::query_scalar("SELECT private_key FROM push_vapid")
        .fetch_one(db)
        .await?;
    b64url_decode(&stored)
        .and_then(|b| p256::SecretKey::from_slice(&b).ok())
        .ok_or_else(|| sqlx::Error::Decode("push_vapid.private_key does not parse".into()))
}

/// The application server key a browser subscribes with.
pub fn vapid_public(key: &p256::SecretKey) -> String {
    URL_SAFE_NO_PAD.encode(key.public_key().to_encoded_point(false).as_bytes())
}

/// RFC 8292 token for one push service origin.
fn vapid_jwt(key: &p256::SecretKey, aud: &str, sub: &str) -> String {
    let exp = crate::auth::handlers::unix_timestamp() + 12 * 60 * 60;
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "aud": aud, "exp": exp, "sub": sub }).to_string());
    let input = format!("{header}.{claims}");
    let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from(key).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// What a push says, and all it says.
#[derive(Debug, Clone, Serialize)]
pub struct PushPayload {
    pub hub: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
}

/// After a channel message is stored: push to members it mentions (`@name`
/// or their public key) and to the author of the message it replies to.
pub fn notify_channel_message(
    state: Arc<AppState>,
    channel_id: String,
    sender: String,
    content: String,
    reply_to_sender: Option<String>,
) {
    tokio::spawn(async move {
        let (names, keys) = mention_tokens(&content);
        let mentioned: Vec<String> = if names.is_empty() && keys.is_empty() {
            Vec::new()
        } else {
            sqlx::query_scalar(
                "SELECT public_key FROM users
                 WHERE LOWER(display_name) = ANY($1) OR public_key = ANY($2)",
            )
            .bind(&names)
            .bind(&keys)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
        };
        let mut targets: Vec<(String, &'static str)> =
            mentioned.into_iter().map(|pk| (pk, "mention")).collect();
        if let Some(r) = reply_to_sender {
            if !targets.iter().any(|(pk, _)| *pk == r) {
                targets.push((r, "reply"));
            }
        }
        for (pk, kind) in targets {
            if pk == sender {
                continue;
            }
            let readable = crate::permissions::channel_permissions(&state.db, &pk, &channel_id)
                .await
                .map(|p| p.has(crate::permissions::MESSAGES_READ))
                .unwrap_or(false);
            if !readable {
                continue;
            }
            let payload = PushPayload {
                hub: state.hub_identity.public_key_hex(),
                kind,
                channel_id: Some(channel_id.clone()),
                conversation_id: None,
            };
            push_to(&state, &pk, Some(&channel_id), &payload).await;
        }
    });
}

/// After a DM is stored here: push to its other members who subscribed here.
pub fn notify_dm(
    state: Arc<AppState>,
    conversation_id: String,
    sender: String,
    members: Vec<String>,
) {
    tokio::spawn(async move {
        for pk in members {
            if pk == sender {
                continue;
            }
            let payload = PushPayload {
                hub: state.hub_identity.public_key_hex(),
                kind: "dm",
                channel_id: None,
                conversation_id: Some(conversation_id.clone()),
            };
            push_to(&state, &pk, None, &payload).await;
        }
    });
}

/// `@name` tokens (lowercased, the client's `mentionsName` rule) and public
/// keys written out in full.
fn mention_tokens(content: &str) -> (Vec<String>, Vec<String>) {
    let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    let mut names = HashSet::new();
    for part in content.split('@').skip(1) {
        let name: String = part.chars().take_while(|c| word(*c)).collect();
        if !name.is_empty() {
            names.insert(name.to_lowercase());
        }
    }
    let keys: HashSet<String> = content
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|t| t.len() == 64)
        .map(str::to_lowercase)
        .collect();
    (names.into_iter().collect(), keys.into_iter().collect())
}

/// Is this identity over its push budget? Counts the attempt.
fn over_budget(state: &AppState, pubkey: &str) -> bool {
    let mut map = state
        .rate_limiters
        .push
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if map.len() >= 2_000 {
        map.retain(|_, (_, ts)| now.duration_since(*ts) <= PUSH_WINDOW);
    }
    let entry = map.entry(pubkey.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > PUSH_WINDOW {
        *entry = (0, now);
    }
    entry.0 += 1;
    entry.0 > PUSH_LIMIT
}

async fn push_to(state: &AppState, pubkey: &str, channel_id: Option<&str>, payload: &PushPayload) {
    // A member with a socket open already hears it there.
    if state
        .ws_key_senders
        .read()
        .await
        .get(pubkey)
        .is_some_and(|s| !s.is_empty())
    {
        return;
    }
    let dnd: Option<String> =
        sqlx::query_scalar("SELECT presence_status FROM users WHERE public_key = $1")
            .bind(pubkey)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .flatten();
    if dnd.as_deref() == Some("dnd") {
        return;
    }
    let subs: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT endpoint, p256dh, auth, notify FROM push_subscriptions WHERE user_pubkey = $1",
    )
    .bind(pubkey)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let subs: Vec<_> = subs
        .into_iter()
        .filter(|(_, _, _, notify)| {
            !serde_json::from_str::<NotifyPrefs>(notify)
                .unwrap_or_default()
                .silences(channel_id, now_ms)
        })
        .collect();
    if subs.is_empty() || over_budget(state, pubkey) {
        return;
    }
    let key = match vapid_key(&state.db).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("web push: no VAPID key: {e}");
            return;
        }
    };
    let body = serde_json::to_vec(payload).unwrap_or_default();
    for (endpoint, p256dh, auth, _) in subs {
        match send(state, &key, &endpoint, &p256dh, &auth, &body).await {
            Ok(404 | 410) => {
                let _ = sqlx::query(
                    "DELETE FROM push_subscriptions WHERE endpoint = $1 AND user_pubkey = $2",
                )
                .bind(&endpoint)
                .bind(pubkey)
                .execute(&state.db)
                .await;
            }
            Ok(s) if !(200..300).contains(&s) => {
                tracing::debug!("web push: push service answered {s}");
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("web push: {e}"),
        }
    }
}

/// Encrypt and POST one push. Answers the push service's status code.
async fn send(
    state: &AppState,
    key: &p256::SecretKey,
    endpoint: &str,
    p256dh: &str,
    auth: &str,
    body: &[u8],
) -> Result<u16, String> {
    let ua_public = b64url_decode(p256dh)
        .and_then(|b| p256::PublicKey::from_sec1_bytes(&b).ok())
        .ok_or("bad p256dh")?;
    let auth = b64url_decode(auth)
        .filter(|a| a.len() == 16)
        .ok_or("bad auth")?;
    let encrypted = web_push_native::encrypt(
        body.to_vec(),
        &ua_public,
        web_push_native::Auth::from_slice(&auth),
    )
    .map_err(|e| e.to_string())?;

    let url = reqwest::Url::parse(endpoint).map_err(|e| e.to_string())?;
    let allow_private = state.allow_private_webhooks;
    if !allow_private && url.scheme() != "https" {
        return Err("endpoint is not https".into());
    }
    let host = url.host_str().ok_or("endpoint has no host")?.to_string();
    if !allow_private && host.eq_ignore_ascii_case("localhost") {
        return Err("ssrf_blocked".into());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addr_ok = |a: SocketAddr| allow_private || !crate::routes::preview::is_private_ip(a.ip());
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addrs = crate::routes::preview::resolve_and_check(bare, port, &addr_ok)
        .await
        .map_err(str::to_string)?;

    let aud = url.origin().ascii_serialization();
    let sub = state
        .canonical_url
        .read()
        .await
        .clone()
        .filter(|u| u.starts_with("https://"))
        .unwrap_or_else(|| "https://github.com/Wavvon".to_string());
    let jwt = vapid_jwt(key, &aud, &sub);

    // Pinned to the checked addresses, no proxy, no redirects: the same
    // policy as a link-preview fetch.
    let client = reqwest::Client::builder()
        .resolve_to_addrs(&host, &addrs)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(url)
        .header("TTL", PUSH_TTL_SECS)
        .header("Urgency", "high")
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header(
            "Authorization",
            format!("vapid t={jwt}, k={}", vapid_public(key)),
        )
        .body(encrypted)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_tokens_follow_the_client_rule() {
        let pk = "ab".repeat(32);
        let (mut names, keys) = mention_tokens(&format!("hi @Alice and @bob.s, see {pk}!"));
        names.sort();
        assert_eq!(names, vec!["alice", "bob.s"]);
        assert_eq!(keys, vec![pk]);
        assert_eq!(mention_tokens("mail me at x@ y"), (vec![], vec![]));
    }

    #[test]
    fn silent_channel_overrides_hub_and_hub_applies_to_dms() {
        let mut p = NotifyPrefs::default();
        assert!(!p.silences(Some("c"), 0));
        p.hub = Some(NotifyMode::Silent);
        assert!(p.silences(Some("c"), 0) && p.silences(None, 0));
        p.channels.insert("c".into(), NotifyMode::Mentions);
        assert!(!p.silences(Some("c"), 0));
    }

    #[test]
    fn a_timed_mute_stops_silencing_at_its_deadline() {
        let mut p = NotifyPrefs {
            hub: Some(NotifyMode::Silent),
            hub_until: Some(1_000),
            ..Default::default()
        };
        assert!(p.silences(None, 999));
        assert!(!p.silences(None, 1_000));
        p.hub_until = None;
        p.channels.insert("c".into(), NotifyMode::Mentions);
        p.channels_until.insert("c".into(), 500);
        // An expired channel mode falls back to the (silent) hub mode.
        assert!(!p.silences(Some("c"), 400));
        assert!(p.silences(Some("c"), 600));
    }

    #[test]
    fn vapid_jwt_verifies_with_the_advertised_key() {
        use p256::ecdsa::signature::Verifier;
        let key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let jwt = vapid_jwt(&key, "https://push.example", "https://hub.example");
        let (input, sig) = jwt.rsplit_once('.').unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&b64url_decode(sig).unwrap()).unwrap();
        let public =
            p256::PublicKey::from_sec1_bytes(&b64url_decode(&vapid_public(&key)).unwrap()).unwrap();
        p256::ecdsa::VerifyingKey::from(&public)
            .verify(input.as_bytes(), &sig)
            .unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(input.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(claims["aud"], "https://push.example");
    }
}
