//! Voice in alliance channels (alliances.md "Voice in alliance channels").
//!
//! The owning hub's relay **is** the room. A member of hub B who joins voice
//! in a channel hub A shares with their alliance gets a short-lived,
//! voice-scoped session on **hub A** and dials hub A's WebTransport relay as an
//! ordinary pubkey. One room, one hub, one `sender_id` space, one E2E key
//! fan-out — and nothing in `voice_wt.rs`, `voice_channels`,
//! `voice_sender_ids` or the datagram format changes.
//!
//! Hub B's only job is the one thing hub A cannot do for itself: sign an
//! assertion that this pubkey is its member and that channel is shared with
//! the alliance. Everything security-relevant is then re-checked by hub A
//! against its *own* view — it never trusts B's.
//!
//! The grant is `{payload, signature}` over the payload's JSON, the same
//! primitive as hub badges (`routes/badges.rs`) and deliberately **not** a new
//! `identity` crate envelope: only the two hubs and the client ever read it, no
//! client has to reproduce it byte-for-byte, so it owes nothing to
//! `wire-format.md` and needs no three-way mirror.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::state::AppState;

/// How long a minted grant is good for. A ticket to open one session, not a
/// membership: long enough to walk challenge → verify → WS → `voice_join`,
/// short enough that a leaked grant is worthless before anyone can use it.
pub const GRANT_TTL_SECS: i64 = 300;

/// How long an admitted visitor's row lives. Bounded independently of the
/// grant, because the grant is spent at admission and this is what limits how
/// long the visit itself can last.
pub const VISIT_TTL_SECS: i64 = 60 * 60 * 4;

/// The signed assertion, minted by the origin hub and presented to the owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllianceVoiceGrantPayload {
    pub alliance_id: String,
    /// The hub this grant is addressed to. Checked by the owner, so a grant
    /// minted for hub A cannot be replayed at hub C.
    pub owner_hub_pubkey: String,
    pub channel_id: String,
    /// The visitor's canonical (master) pubkey. The owner requires the
    /// challenge-response to have authenticated *this* identity, so the grant
    /// vouches for membership, never for identity.
    pub subject_pubkey: String,
    pub origin_hub_pubkey: String,
    pub origin_hub_url: String,
    /// Roster display only, and hub-vouched rather than proven. Must never
    /// feed anything that assumes a verified name.
    pub display_name: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllianceVoiceGrant {
    pub payload: AllianceVoiceGrantPayload,
    /// Hex Ed25519 signature over `serde_json::to_string(&payload)`.
    pub signature: String,
}

#[derive(Deserialize)]
pub struct MintGrantRequest {
    pub channel_id: String,
}

#[derive(Serialize)]
pub struct MintGrantResponse {
    pub grant: AllianceVoiceGrant,
    /// Where the client should authenticate to redeem it. The client does not
    /// have to resolve the owning hub itself — this route already had to.
    pub owner_hub_url: String,
    pub owner_hub_pubkey: String,
    pub channel_name: String,
}

/// Why a grant was refused. Names rather than prose so the client can branch.
fn forbid(code: &str) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, code.to_string())
}

/// This hub's own public URL, as the operator configured it. The visitor needs
/// it to know where the grant came from, and the owner stores it so a roster can
/// say which hub a visitor is from.
async fn load_hub_url(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// `POST /alliances/:id/voice-grant` — mint a grant for one of *another*
/// member's shared voice channels.
///
/// Gated on the only local permission that means anything about a remote
/// channel: is the caller a member here in good standing. Everything about the
/// channel is resolved by asking the peer that owns it, using the same
/// walk-the-members federation path `get_alliance_channel_messages` already
/// uses for reads.
pub async fn mint_voice_grant(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Json(req): Json<MintGrantRequest>,
) -> Result<Json<MintGrantResponse>, (StatusCode, String)> {
    super::models::require_alliance_visibility(&state, &user.public_key, &alliance_id).await?;

    let our_pubkey = state.hub_identity.public_key_hex();

    // Good standing here, checked explicitly rather than left to the auth
    // middleware: the middleware knows about bans and approval, and this also
    // has to refuse a *muted* member. Vouching for someone you have silenced
    // would export a moderation decision as its own loophole.
    let now = crate::auth::handlers::unix_timestamp();

    let approval: Option<String> =
        sqlx::query_scalar("SELECT approval_status FROM users WHERE public_key = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    match approval.as_deref() {
        None => return Err(forbid("not_a_member")),
        Some("approved") => {}
        Some(status) => {
            tracing::debug!(status = %status, "voice-grant refused: not approved");
            return Err(forbid("not_in_good_standing"));
        }
    }

    // The shared helper, not a second copy of the mute predicate.
    if crate::routes::moderation::is_muted(&state.db, &user.public_key).await? {
        return Err(forbid("muted"));
    }

    // This hub must actually be in the alliance.
    let is_member: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2",
    )
    .bind(&alliance_id)
    .bind(&our_pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    if is_member.is_none() {
        return Err((StatusCode::NOT_FOUND, "alliance_not_found".to_string()));
    }

    // A channel we own needs no grant at all — plain `voice_join` on this hub
    // is the whole flow. Answering with a grant would mint a visitor session
    // for a member, which is strictly worse for them: no roles, no history.
    let ours = super::channels::effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    if ours.iter().any(|c| c.id == req.channel_id) {
        return Err((StatusCode::CONFLICT, "channel_is_local".to_string()));
    }

    // Ask each peer whether it owns this channel, exactly as the alliance
    // message read does. `local_only` on the peer means "your own effective
    // set", so `include_descendants` and the depth-32 guard are already
    // applied by the owner — this hub does not re-implement either.
    let members = sqlx::query_as::<_, super::models::MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at
         FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&our_pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;

    for member in members {
        let token = match super::channels::peer_token(&state, &member).await {
            Some(t) => t,
            None => continue,
        };
        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        let Some(entry) = shared.iter().find(|s| s.channel_id == req.channel_id) else {
            continue;
        };

        // A category has no room, and neither does a banner or a spawner. The
        // hub has no separate voice channel_type — every leaf `text` channel
        // hosts a voice call alongside its text pane — so this is the whole
        // test for "is there a room here".
        if entry.is_category || entry.channel_type != "text" {
            return Err((StatusCode::BAD_REQUEST, "not_a_voice_space".to_string()));
        }

        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
                .bind(&user.public_key)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?
                .flatten();

        let our_url = load_hub_url(&state).await;
        let payload = AllianceVoiceGrantPayload {
            alliance_id: alliance_id.clone(),
            owner_hub_pubkey: member.hub_public_key.clone(),
            channel_id: req.channel_id.clone(),
            // The canonical identity, not the device subkey: the owner
            // re-authenticates the *master* through its own challenge, and a
            // grant naming a subkey would not match on a paired device.
            subject_pubkey: user
                .master_pubkey
                .clone()
                .unwrap_or_else(|| user.public_key.clone()),
            origin_hub_pubkey: our_pubkey.clone(),
            origin_hub_url: our_url,
            display_name,
            issued_at: now,
            expires_at: now + GRANT_TTL_SECS,
        };
        let payload_json = serde_json::to_string(&payload).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialise error: {e}"),
            )
        })?;
        let signature = hex::encode(state.hub_identity.sign(payload_json.as_bytes()).to_bytes());

        tracing::info!(
            alliance = %alliance_id,
            channel = %req.channel_id,
            owner = %member.hub_public_key,
            "Minted alliance voice grant"
        );

        return Ok(Json(MintGrantResponse {
            grant: AllianceVoiceGrant { payload, signature },
            owner_hub_url: member.hub_url,
            owner_hub_pubkey: member.hub_public_key,
            channel_name: entry.channel_name.clone(),
        }));
    }

    Err((
        StatusCode::NOT_FOUND,
        "alliance_channel_not_found".to_string(),
    ))
}

/// What the owning hub concluded about a presented grant.
pub struct AdmittedVisitor {
    pub origin_hub_pubkey: String,
    pub origin_hub_url: String,
    pub display_name: Option<String>,
    pub channel_id: String,
}

/// Owner-side verification, called from `/auth/verify`.
///
/// `authenticated_pubkey` is the canonical identity the challenge-response just
/// proved. The grant asserts membership of the origin hub and nothing else —
/// if it named an identity the caller had not just signed for, it would be a
/// bearer token for someone else's voice.
///
/// Every channel fact is re-resolved against **this** hub's own shared set.
/// Trusting the origin's copy would let an allied hub name any channel it
/// liked, which is the difference between an admission path and a hole.
pub async fn verify_grant(
    state: &AppState,
    grant: &AllianceVoiceGrant,
    authenticated_pubkey: &str,
) -> Result<AdmittedVisitor, (StatusCode, String)> {
    let p = &grant.payload;
    let now = crate::auth::handlers::unix_timestamp();

    if p.subject_pubkey != authenticated_pubkey {
        return Err(forbid("grant_subject_mismatch"));
    }
    if p.owner_hub_pubkey != state.hub_identity.public_key_hex() {
        return Err(forbid("grant_not_for_this_hub"));
    }
    if now > p.expires_at {
        return Err(forbid("grant_expired"));
    }
    // A future-dated grant is a clock the origin controls, so cap the window
    // rather than trusting `issued_at`.
    if p.expires_at - p.issued_at > GRANT_TTL_SECS {
        return Err(forbid("grant_ttl_too_long"));
    }

    let payload_json = serde_json::to_string(p)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "serialise".to_string()))?;
    let sig_bytes =
        hex::decode(&grant.signature).map_err(|_| forbid("grant_signature_malformed"))?;
    wavvon_identity::verify_signature(&p.origin_hub_pubkey, payload_json.as_bytes(), &sig_bytes)
        .map_err(|_| forbid("grant_signature_invalid"))?;

    // The origin must be a hub we are actually allied with, in this alliance.
    let allied: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2",
    )
    .bind(&p.alliance_id)
    .bind(&p.origin_hub_pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    if allied.is_none() {
        return Err(forbid("origin_not_allied"));
    }

    // Our own effective shared set, not the origin's claim about it.
    let ours = super::channels::effective_shared_channels(&state.db, &p.alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    let Some(entry) = ours.iter().find(|c| c.id == p.channel_id) else {
        return Err(forbid("channel_not_shared"));
    };
    if entry.is_category || entry.channel_type != "text" {
        return Err(forbid("not_a_voice_space"));
    }

    // Per-share policy. Read from the *direct* share row, so a descendant
    // inherits the default exactly the way `forum_remote_write` does.
    let policy: Option<String> = sqlx::query_scalar(
        "SELECT voice_remote_join FROM alliance_shared_channels
         WHERE alliance_id = $1 AND channel_id = $2",
    )
    .bind(&p.alliance_id)
    .bind(&p.channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    if policy.as_deref() == Some("none") {
        return Err(forbid("voice_remote_join_disabled"));
    }

    // Locally banned wins over any ally's opinion, and is re-checked on every
    // redemption rather than only at mint time — the origin hub cannot know we
    // banned someone, and a grant is not a way around it.
    //
    // The row only exists for someone who was once a member here, which is
    // exactly the case that matters: banning a local user must not leave them a
    // side door in as a visitor from an allied hub.
    let banned: Option<i32> = sqlx::query_scalar("SELECT 1 FROM bans WHERE target_public_key = $1")
        .bind(&p.subject_pubkey)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    if banned.is_some() {
        return Err(forbid("banned"));
    }

    // The shared federated-ban policy, not a reimplementation of it. Its own
    // doc comment says every enforcement point must call it, because the
    // overrides were once missed at the message layer by exactly the inline
    // copy this avoids.
    if crate::routes::moderation::is_denied_by_federated_policy(&state.db, &p.subject_pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?
    {
        return Err(forbid("federated_ban"));
    }

    Ok(AdmittedVisitor {
        origin_hub_pubkey: p.origin_hub_pubkey.clone(),
        origin_hub_url: p.origin_hub_url.clone(),
        display_name: p.display_name.clone(),
        channel_id: p.channel_id.clone(),
    })
}

/// Record the admission. Replaces any previous row for this pubkey, so a
/// visitor moving between two shared channels holds exactly one visit.
pub async fn record_visit(
    state: &AppState,
    subject_pubkey: &str,
    v: &AdmittedVisitor,
) -> Result<String, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();
    let token = hex::encode({
        let mut bytes = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        bytes
    });
    sqlx::query(
        "INSERT INTO alliance_voice_visitors
           (subject_pubkey, token, origin_hub_pubkey, origin_hub_url, display_name,
            channel_id, admitted_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (subject_pubkey) DO UPDATE SET
            token             = EXCLUDED.token,
            origin_hub_pubkey = EXCLUDED.origin_hub_pubkey,
            origin_hub_url    = EXCLUDED.origin_hub_url,
            display_name      = EXCLUDED.display_name,
            channel_id        = EXCLUDED.channel_id,
            admitted_at       = EXCLUDED.admitted_at,
            expires_at        = EXCLUDED.expires_at",
    )
    .bind(subject_pubkey)
    .bind(&token)
    .bind(&v.origin_hub_pubkey)
    .bind(&v.origin_hub_url)
    .bind(&v.display_name)
    .bind(&v.channel_id)
    .bind(now)
    .bind(now + VISIT_TTL_SECS)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB: {e}")))?;
    Ok(token)
}

/// Resolve a bearer token to a live visit. `None` for anything that is not a
/// current visitor token, so the caller falls through to its normal paths.
///
/// Returns `(subject_pubkey, channel_id)`.
pub async fn resolve_visitor_token(db: &sqlx::PgPool, token: &str) -> Option<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT subject_pubkey, channel_id FROM alliance_voice_visitors
         WHERE token = $1 AND expires_at > $2",
    )
    .bind(token)
    .bind(crate::auth::handlers::unix_timestamp())
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

/// The channel a visitor is admitted to, if their visit is still live.
///
/// `None` for anyone who is not a current visitor, which is also the answer for
/// an ordinary member — callers use it to mean "confine this pubkey", never to
/// mean "this pubkey may join".
pub async fn admitted_channel(state: &AppState, subject_pubkey: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT channel_id FROM alliance_voice_visitors
         WHERE subject_pubkey = $1 AND expires_at > $2",
    )
    .bind(subject_pubkey)
    .bind(crate::auth::handlers::unix_timestamp())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
}
