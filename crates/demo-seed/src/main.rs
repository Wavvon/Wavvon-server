//! demo-seed: populates a running Wavvon hub with realistic demo content.
//!
//! Run against a **fresh** hub (empty DB). On a non-fresh hub the tool
//! detects existing channels and exits with a clear error rather than
//! duplicating content.
//!
//! Configuration:
//!   HUB_URL          base URL of the hub  (default: http://localhost:3000)
//!   CREDS_OUT        path for the JSON credentials file
//!                    (default: demo-credentials.json in the current directory)
//!   INVITE_CODE      owner-granting invite code to redeem for the admin
//!                    identity (also settable via `--invite <code>`).
//!                    Fresh hubs boot with `invite_only=true` (task #31) and
//!                    mint a single-use owner invite, printed by the hub at
//!                    startup / `wavvon-hub --doctor` — there is no API to
//!                    fetch it, so it must be pasted in here. Not needed
//!                    against a hub that already has `invite_only=false`.
//!
//! Usage:
//!   cargo run -p demo-seed
//!   HUB_URL=http://myhub.example:3000 cargo run -p demo-seed
//!   cargo run -p demo-seed -- --invite a1b2c3d4e5f6
//!   INVITE_CODE=a1b2c3d4e5f6 cargo run -p demo-seed

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Wire types (mirrors the hub's auth models — kept local so this crate has
// no compile dependency on wavvon_hub itself)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    token: String,
    scope: String,
}

#[derive(Deserialize)]
struct ChannelResponse {
    id: String,
    #[allow(dead_code)]
    name: String,
}

#[derive(Deserialize)]
struct MessageResponse {
    id: String,
}

// ---------------------------------------------------------------------------
// Credentials output (written to CREDS_OUT)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PersistedIdentity {
    display_name: String,
    public_key: String,
    /// Ed25519 secret key, hex-encoded (32 bytes = 64 hex chars).
    /// Load with Identity::from_secret_hex if you add that helper, or
    /// reconstruct via ed25519_dalek::SigningKey::from_bytes.
    secret_key_hex: String,
    session_token: String,
    recovery_phrase: String,
}

#[derive(Serialize)]
struct CredsOutput {
    hub_url: String,
    admin: PersistedIdentity,
    members: Vec<PersistedIdentity>,
}

// ---------------------------------------------------------------------------
// 429-resilient send helper
//
// reqwest::RequestBuilder is consumed by .send(), so we rely on try_clone()
// to get a fresh builder for each retry attempt. try_clone() returns None
// only when the body is a streaming type; all our requests use .json() bodies
// (stored in memory) so it always succeeds.
//
// Retry schedule on 429:
//   - Honour Retry-After header (integer seconds) when the hub sends one.
//   - Otherwise use exponential backoff: 2s, 4s, 8s, 16s, 30s (capped).
//   - Give up after MAX_RETRIES attempts.
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 8;

/// Send `builder`, retrying transparently on HTTP 429.
///
/// Panics (returns Err) after MAX_RETRIES attempts or if the builder cannot
/// be cloned (should never happen for our json-body requests).
async fn send(builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    // We need to clone the builder before each attempt because .send()
    // consumes it.  Keep the original alive as the template.
    let mut backoff_secs: u64 = 2;

    for attempt in 0..=MAX_RETRIES {
        let clone = builder
            .try_clone()
            .context("RequestBuilder::try_clone() returned None — streaming body not supported")?;

        let resp = clone.send().await.context("HTTP send failed")?;

        if resp.status().as_u16() != 429 {
            return Ok(resp);
        }

        if attempt == MAX_RETRIES {
            bail!(
                "Still receiving 429 after {} retries — giving up",
                MAX_RETRIES
            );
        }

        // Respect Retry-After if the hub sends one (integer seconds).
        let wait = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(backoff_secs);

        println!(
            "  [rate-limit] 429 received (attempt {}/{}), waiting {}s ...",
            attempt + 1,
            MAX_RETRIES,
            wait
        );

        sleep(Duration::from_secs(wait)).await;

        // Double backoff for next iteration, capped at 30s.
        backoff_secs = (backoff_secs * 2).min(30);
    }

    unreachable!()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// POST /auth/challenge + POST /auth/verify → session token.
///
/// `invite_code` is forwarded on the verify call when present. It is only
/// consulted by the hub when the hub is invite-only *and* this is a
/// brand-new identity with no roles yet — passing one against a hub that
/// doesn't require it is harmless (the hub ignores the field in that case).
async fn authenticate(
    client: &Client,
    hub: &str,
    identity: &Identity,
    invite_code: Option<&str>,
) -> Result<String> {
    let pub_key = identity.public_key_hex();

    // Step 1: request challenge
    let resp: ChallengeResponse = send(
        client
            .post(format!("{hub}/auth/challenge"))
            .json(&json!({ "public_key": pub_key })),
    )
    .await
    .context("POST /auth/challenge failed")?
    .error_for_status()
    .context("challenge returned error status")?
    .json()
    .await
    .context("challenge response parse failed")?;

    // Step 2: sign the raw challenge bytes
    let challenge_bytes = hex::decode(&resp.challenge).context("challenge is not valid hex")?;
    let signature = identity.sign(&challenge_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    // Step 3: verify
    let mut body = json!({
        "public_key": pub_key,
        "challenge": resp.challenge,
        "signature": sig_hex,
    });
    if let Some(code) = invite_code {
        body["invite_code"] = json!(code);
    }

    let verify_resp = send(client.post(format!("{hub}/auth/verify")).json(&body))
        .await
        .context("POST /auth/verify failed")?;

    if verify_resp.status().as_u16() == 403 {
        let detail = verify_resp.text().await.unwrap_or_default();
        bail!(
            "POST /auth/verify returned 403 for key {}: {detail}. \
             This hub is likely invite_only (fresh hubs default to invite_only=true — \
             task #31). Pass the owner invite code printed in the hub's startup logs \
             (or `wavvon-hub --doctor` output) via --invite <code> or INVITE_CODE=<code>.",
            &pub_key[..16]
        );
    }

    let verify: VerifyResponse = verify_resp
        .error_for_status()
        .context("verify returned error status")?
        .json()
        .await
        .context("verify response parse failed")?;

    // If the hub returned a lobby scope the identity's PoW level is below
    // min_security_level. On a fresh hub with defaults this should not happen;
    // we surface it clearly so the operator knows.
    if verify.scope == "lobby" {
        bail!(
            "Hub returned scope=lobby for key {}. \
             The hub requires PoW authentication. \
             Lower min_security_level to 0 before running the seeder, or \
             add PoW computation to the seeder (see HUB_URL/admin/settings/pow).",
            &pub_key[..16]
        );
    }

    Ok(verify.token)
}

/// POST /invites — mints a fresh invite the admin uses to onboard the
/// remaining demo members. Needed because the owner invite redeemed by the
/// admin (`INVITE_CODE`) is single-use (task #34's admin-grant guard) and
/// can't be reused for the rest of the roster.
async fn create_invite(client: &Client, hub: &str, token: &str, max_uses: i64) -> Result<String> {
    #[derive(Deserialize)]
    struct CreateInviteResponse {
        code: String,
    }

    let resp: CreateInviteResponse = send(
        client
            .post(format!("{hub}/invites"))
            .bearer_auth(token)
            .json(&json!({ "max_uses": max_uses })),
    )
    .await
    .context("POST /invites failed")?
    .error_for_status()
    .context("create_invite returned error status")?
    .json()
    .await
    .context("invite response parse failed")?;
    Ok(resp.code)
}

/// PATCH /me  to set the display name.
async fn set_display_name(client: &Client, hub: &str, token: &str, name: &str) -> Result<()> {
    send(
        client
            .patch(format!("{hub}/me"))
            .bearer_auth(token)
            .json(&json!({ "display_name": name })),
    )
    .await
    .context("PATCH /me failed")?
    .error_for_status()
    .context("set_display_name returned error status")?;
    Ok(())
}

/// POST /channels  (text channel or category).
async fn create_channel(
    client: &Client,
    hub: &str,
    token: &str,
    name: &str,
    parent_id: Option<&str>,
    is_category: bool,
) -> Result<ChannelResponse> {
    let mut body = json!({ "name": name });
    if is_category {
        body["is_category"] = json!(true);
    }
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }

    let ch: ChannelResponse = send(
        client
            .post(format!("{hub}/channels"))
            .bearer_auth(token)
            .json(&body),
    )
    .await
    .context(format!("POST /channels ({name}) failed"))?
    .error_for_status()
    .context(format!("create_channel({name}) error status"))?
    .json()
    .await
    .context("channel response parse failed")?;
    Ok(ch)
}

/// POST /channels/:id/messages  — returns the message id.
async fn send_message(
    client: &Client,
    hub: &str,
    token: &str,
    channel_id: &str,
    content: &str,
    reply_to: Option<&str>,
) -> Result<String> {
    let mut body = json!({ "content": content });
    if let Some(parent) = reply_to {
        body["reply_to"] = json!(parent);
    }
    let msg: MessageResponse = send(
        client
            .post(format!("{hub}/channels/{channel_id}/messages"))
            .bearer_auth(token)
            .json(&body),
    )
    .await
    .context("POST /channels/:id/messages failed")?
    .error_for_status()
    .context("send_message error status")?
    .json()
    .await
    .context("message response parse failed")?;
    Ok(msg.id)
}

/// POST /channels/:channel_id/messages/:msg_id/reactions
async fn add_reaction(
    client: &Client,
    hub: &str,
    token: &str,
    channel_id: &str,
    message_id: &str,
    emoji: &str,
) -> Result<()> {
    let resp = send(
        client
            .post(format!(
                "{hub}/channels/{channel_id}/messages/{message_id}/reactions"
            ))
            .bearer_auth(token)
            .json(&json!({ "emoji": emoji })),
    )
    .await
    .context("POST .../reactions failed")?;

    let status = resp.status();
    // 204 = success, 409 = already reacted (idempotent enough)
    if !status.is_success() && status.as_u16() != 409 {
        bail!("add_reaction returned {status}");
    }
    Ok(())
}

/// POST /channels/:channel_id/pins/:message_id
/// Requires manage_messages; only admin (owner) calls this.
async fn pin_message(
    client: &Client,
    hub: &str,
    token: &str,
    channel_id: &str,
    message_id: &str,
) -> Result<()> {
    let resp = send(
        client
            .post(format!("{hub}/channels/{channel_id}/pins/{message_id}"))
            .bearer_auth(token),
    )
    .await
    .context("POST .../pins/:msg_id failed")?;

    let status = resp.status();
    if !status.is_success() {
        bail!("pin_message returned {status}");
    }
    Ok(())
}

/// POST /channels/:channel_id/polls
async fn create_poll(
    client: &Client,
    hub: &str,
    token: &str,
    channel_id: &str,
    question: &str,
    options: &[(&str, &str)],
) -> Result<String> {
    let opts: Vec<Value> = options
        .iter()
        .map(|(id, text)| json!({ "id": id, "text": text }))
        .collect();

    let resp: Value = send(
        client
            .post(format!("{hub}/channels/{channel_id}/polls"))
            .bearer_auth(token)
            .json(&json!({ "question": question, "options": opts })),
    )
    .await
    .context("POST .../polls failed")?
    .error_for_status()
    .context("create_poll error status")?
    .json()
    .await
    .context("poll response parse failed")?;

    resp["id"]
        .as_str()
        .map(|s| s.to_string())
        .context("poll response missing id")
}

/// PATCH /hub  — set name and description. Requires admin permission.
async fn configure_hub(
    client: &Client,
    hub: &str,
    token: &str,
    name: &str,
    description: &str,
) -> Result<()> {
    send(
        client
            .patch(format!("{hub}/hub"))
            .bearer_auth(token)
            .json(&json!({ "name": name, "description": description })),
    )
    .await
    .context("PATCH /hub failed")?
    .error_for_status()
    .context("configure_hub error status")?;
    Ok(())
}

/// GET /channels — check whether the hub already has channels.
async fn existing_channel_count(client: &Client, hub: &str, token: &str) -> Result<usize> {
    let channels: Value = send(client.get(format!("{hub}/channels")).bearer_auth(token))
        .await
        .context("GET /channels failed")?
        .error_for_status()
        .context("list_channels error status")?
        .json()
        .await
        .context("channels response parse failed")?;

    channels
        .as_array()
        .map(|a| a.len())
        .context("channels response is not an array")
}

fn persisted(identity: &Identity, display_name: &str, token: &str) -> PersistedIdentity {
    PersistedIdentity {
        display_name: display_name.to_string(),
        public_key: identity.public_key_hex(),
        // Recovery phrase (24 BIP39 words) is the durable backup; secret_key_hex
        // is the raw key for tooling that wants to reconstruct the Identity
        // directly; session token is ephemeral and only useful for the
        // current hub run.
        secret_key_hex: identity.secret_key_hex(),
        session_token: token.to_string(),
        recovery_phrase: identity.recovery_phrase(),
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// Pace between identity registrations to avoid exhausting the auth token
/// bucket (burst=10, refill=1/s).  Each registration needs 2 auth calls
/// (challenge + verify).  Waiting 2s between registrations gives the bucket
/// 2 tokens back before the next pair of calls, keeping us comfortably inside
/// the sustained rate even if other traffic shares the IP.
const REGISTRATION_PACE: Duration = Duration::from_secs(2);

/// Reads `--invite <code>` from argv, falling back to the `INVITE_CODE`
/// env var. Returns `None` when neither is set — fine for a hub that isn't
/// invite_only, an error otherwise (surfaced from `authenticate`'s 403 path).
fn owner_invite_code() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    owner_invite_code_from(&args, std::env::var("INVITE_CODE").ok())
}

/// Pure logic behind [`owner_invite_code`], parameterised on argv and the
/// env var value so it's testable without touching real process state.
/// `--invite` takes priority over `INVITE_CODE` when both are present.
fn owner_invite_code_from(args: &[String], invite_code_env: Option<String>) -> Option<String> {
    args.iter()
        .position(|a| a == "--invite")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or(invite_code_env)
        .filter(|s| !s.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    let hub_url = std::env::var("HUB_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let creds_out =
        std::env::var("CREDS_OUT").unwrap_or_else(|_| "demo-credentials.json".to_string());
    let invite_code = owner_invite_code();

    println!("demo-seed: target hub = {hub_url}");
    match &invite_code {
        Some(_) => {
            println!("demo-seed: owner invite code provided, will redeem it for the admin identity")
        }
        None => println!(
            "demo-seed: no owner invite code provided (--invite / INVITE_CODE) — \
             assuming the hub is not invite_only"
        ),
    }

    // TLS verification is only skipped for a loopback target (the intended
    // use of this tool is seeding a local demo hub). A HUB_URL pointed at a
    // real host still gets full certificate verification -- this client
    // authenticates as the hub owner, so silently trusting any certificate
    // for a non-local hub would let a network MITM capture that token.
    let hub_is_loopback = reqwest::Url::parse(&hub_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .map(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"))
        .unwrap_or(false);
    let mut client_builder = Client::builder();
    if hub_is_loopback {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .context("failed to build HTTP client")?;

    // ------------------------------------------------------------------
    // Step 1: Health check
    // ------------------------------------------------------------------
    let health = client
        .get(format!("{hub_url}/health"))
        .send()
        .await
        .context("Could not reach hub — is it running?")?;
    if !health.status().is_success() {
        bail!("Hub health check returned {}", health.status());
    }
    println!("Hub is reachable.");

    // ------------------------------------------------------------------
    // Step 2: Create the admin (first user — becomes builtin-owner).
    //
    // The hub's assign_initial_roles() makes the very first authenticated
    // user the owner by assigning 'builtin-owner'. That role carries the
    // 'admin' permission which unlocks PATCH /hub, channel management,
    // pin/manage_messages, lobby settings, etc.
    // ------------------------------------------------------------------
    let admin = Identity::generate();
    println!("Authenticating admin identity ...");
    let admin_token = authenticate(&client, &hub_url, &admin, invite_code.as_deref())
        .await
        .context("Admin authentication failed. If the hub already has users it is not fresh.")?;
    set_display_name(&client, &hub_url, &admin_token, "Nova")
        .await
        .context("Failed to set admin display name")?;
    println!("Admin authenticated and named 'Nova'.");

    // ------------------------------------------------------------------
    // Step 3: Idempotency guard — fail fast if hub is not fresh
    // ------------------------------------------------------------------
    let channel_count = existing_channel_count(&client, &hub_url, &admin_token).await?;
    if channel_count > 0 {
        bail!(
            "Hub already has {channel_count} channel(s). \
             demo-seed requires a fresh hub (empty DB). \
             Wipe the DB and restart the hub before re-running."
        );
    }

    // ------------------------------------------------------------------
    // Step 4: Configure hub branding
    // ------------------------------------------------------------------
    configure_hub(
        &client,
        &hub_url,
        &admin_token,
        "Wavvon HQ",
        "The official Wavvon community hub",
    )
    .await
    .context("Failed to configure hub branding")?;
    println!("Hub branding set to 'Wavvon HQ'.");

    // ------------------------------------------------------------------
    // Step 5: Create member identities
    //
    // Paced at REGISTRATION_PACE apart so that the auth token bucket
    // (burst=10, refill=1/s) refills between the challenge+verify pair
    // for each member.  The send() helper will also back off automatically
    // on any 429 that slips through.
    //
    // The owner invite the admin redeemed above (if any) is single-use
    // (task #34's admin-grant guard forces max_uses=1 on any invite that
    // grants an admin-holding role) so it cannot be reused for the rest of
    // the roster. The now-admin identity mints its own invite for them —
    // harmless to pass on a non-invite_only hub, where it's simply ignored.
    // ------------------------------------------------------------------
    let member_names = [
        "patches",
        "ferris_the_crab",
        "MidnightOwl",
        "kira.dev",
        "Stonebeard",
        "pixelpause",
        "Vex",
    ];

    let members_invite_code =
        create_invite(&client, &hub_url, &admin_token, member_names.len() as i64)
            .await
            .context("Failed to mint an invite for the demo members")?;
    println!(
        "Minted a {}-use invite for the demo members.",
        member_names.len()
    );

    let mut member_tokens: Vec<(Identity, String)> = Vec::new();
    for name in &member_names {
        // Pace before each registration (including the first) to let the
        // bucket recover from the admin's two auth calls above.
        sleep(REGISTRATION_PACE).await;

        let id = Identity::generate();
        let token = authenticate(&client, &hub_url, &id, Some(&members_invite_code))
            .await
            .context(format!("Auth failed for member {name}"))?;
        set_display_name(&client, &hub_url, &token, name)
            .await
            .context(format!("Set display name failed for {name}"))?;
        println!("Member '{name}' registered.");
        member_tokens.push((id, token));
    }

    // Convenience: index into member_tokens by name position
    let tok = |i: usize| member_tokens[i].1.as_str();

    // ------------------------------------------------------------------
    // Step 6: Create channel structure
    //
    //  Community (category)
    //    #welcome
    //    #general
    //  Gaming (category)
    //    #game-night
    //  Dev (category)
    //    #dev-talk
    //  Voice (category)
    //    Lounge          <- text+voice unified channel named "Lounge"
    // ------------------------------------------------------------------
    println!("Creating channels ...");

    let community_cat =
        create_channel(&client, &hub_url, &admin_token, "Community", None, true).await?;
    let welcome_ch = create_channel(
        &client,
        &hub_url,
        &admin_token,
        "welcome",
        Some(&community_cat.id),
        false,
    )
    .await?;
    let general_ch = create_channel(
        &client,
        &hub_url,
        &admin_token,
        "general",
        Some(&community_cat.id),
        false,
    )
    .await?;

    let gaming_cat = create_channel(&client, &hub_url, &admin_token, "Gaming", None, true).await?;
    let game_night_ch = create_channel(
        &client,
        &hub_url,
        &admin_token,
        "game-night",
        Some(&gaming_cat.id),
        false,
    )
    .await?;

    let dev_cat = create_channel(&client, &hub_url, &admin_token, "Dev", None, true).await?;
    let dev_talk_ch = create_channel(
        &client,
        &hub_url,
        &admin_token,
        "dev-talk",
        Some(&dev_cat.id),
        false,
    )
    .await?;

    let voice_cat = create_channel(&client, &hub_url, &admin_token, "Voice", None, true).await?;
    let _lounge_ch = create_channel(
        &client,
        &hub_url,
        &admin_token,
        "Lounge",
        Some(&voice_cat.id),
        false,
    )
    .await?;

    println!("Channels created: welcome, general, game-night, dev-talk, Lounge");

    // ------------------------------------------------------------------
    // Step 7: Post welcome message and pin it
    // ------------------------------------------------------------------
    let welcome_msg_id = send_message(
        &client,
        &hub_url,
        &admin_token,
        &welcome_ch.id,
        "**Welcome to Wavvon HQ!** \
         This is the official community hub. \
         Introduce yourself in #general, plan game nights in #game-night, \
         and geek out about Rust in #dev-talk. \
         Glad you're here.",
        None,
    )
    .await?;

    pin_message(
        &client,
        &hub_url,
        &admin_token,
        &welcome_ch.id,
        &welcome_msg_id,
    )
    .await
    .context("Pinning welcome message failed — owner should have manage_messages")?;
    println!("Welcome message posted and pinned.");

    // ------------------------------------------------------------------
    // Step 8: #general conversation (casual community chatter)
    // ------------------------------------------------------------------
    println!("Seeding #general ...");

    let g1 = send_message(
        &client,
        &hub_url,
        tok(0),
        &general_ch.id,
        "Hey everyone! Just got the desktop client running — first impressions are really solid.",
        None,
    )
    .await?;
    add_reaction(&client, &hub_url, tok(1), &general_ch.id, &g1, "🎉").await?;
    add_reaction(&client, &hub_url, tok(2), &general_ch.id, &g1, "👍").await?;

    let _g2 = send_message(
        &client,
        &hub_url,
        tok(1),
        &general_ch.id,
        "Same here. The voice quality in Lounge is noticeably better than what I was using before.",
        None,
    )
    .await?;

    let g3 = send_message(
        &client,
        &hub_url,
        tok(2),
        &general_ch.id,
        "I self-hosted this on a $6 VPS and it's been running for three days without a restart. \
         The memory footprint is tiny — under 20 MB idle. Impressive for a Rust binary.",
        None,
    )
    .await?;
    add_reaction(&client, &hub_url, tok(3), &general_ch.id, &g3, "🦀").await?;

    let _g4 = send_message(&client, &hub_url, tok(3), &general_ch.id,
        "Tip for self-hosters: add `RUST_LOG=warn` in your systemd unit — the default trace output \
         fills up the journal fast on a busy hub.", None).await?;

    let g5 = send_message(
        &client,
        &hub_url,
        &admin_token,
        &general_ch.id,
        "Good call. I'll add that to the README self-hosting guide.",
        None,
    )
    .await?;

    let _g6 = send_message(
        &client,
        &hub_url,
        tok(4),
        &general_ch.id,
        "Is the iOS client on the roadmap?",
        None,
    )
    .await?;

    let _g7 = send_message(
        &client,
        &hub_url,
        &admin_token,
        &general_ch.id,
        "Android first, then iOS — both are in flight. Web client is already usable if you need \
         something cross-platform today.",
        Some(&g5),
    )
    .await?;

    let _g8 = send_message(
        &client,
        &hub_url,
        tok(5),
        &general_ch.id,
        "The web client works really well on mobile browser too, just FYI.",
        None,
    )
    .await?;

    let g9 = send_message(&client, &hub_url, tok(6), &general_ch.id,
        "Quick question — does federation with other hubs work out of the box or does it need config?", None).await?;
    add_reaction(&client, &hub_url, tok(0), &general_ch.id, &g9, "🤔").await?;

    let _g10 = send_message(
        &client,
        &hub_url,
        &admin_token,
        &general_ch.id,
        "It needs the `[federation]` section in `hub.toml` — point it at a farm URL and \
         federation turns on automatically. Docs are at the wiki.",
        Some(&g9),
    )
    .await?;

    // ------------------------------------------------------------------
    // Step 9: #game-night conversation (planning session)
    // ------------------------------------------------------------------
    println!("Seeding #game-night ...");

    let _n1 = send_message(&client, &hub_url, tok(1), &game_night_ch.id,
        "Who's down for a game night this Friday? I'm thinking we do a few rounds of Codenames then switch to something co-op.", None).await?;

    let n2 = send_message(
        &client,
        &hub_url,
        tok(4),
        &game_night_ch.id,
        "Friday works! I'm up for Codenames. Any interest in **Overcooked 2** for the co-op part?",
        None,
    )
    .await?;
    add_reaction(&client, &hub_url, tok(0), &game_night_ch.id, &n2, "👨‍🍳").await?;
    add_reaction(&client, &hub_url, tok(5), &game_night_ch.id, &n2, "👨‍🍳").await?;

    let _n3 = send_message(
        &client,
        &hub_url,
        tok(2),
        &game_night_ch.id,
        "I'm in but can only make it after 9 PM EST — does that work for everyone?",
        None,
    )
    .await?;

    let _n4 = send_message(
        &client,
        &hub_url,
        tok(6),
        &game_night_ch.id,
        "9 PM EST is fine for me. Stonebeard you're on the other side of the world though?",
        None,
    )
    .await?;

    let _n5 = send_message(
        &client,
        &hub_url,
        tok(3),
        &game_night_ch.id,
        "Ha, yeah, 3 AM my time but I'm a night owl anyway. Count me in.",
        None,
    )
    .await?;

    let _n6 = send_message(&client, &hub_url, tok(5), &game_night_ch.id,
        "Nice. I'll set up a Jackbox room too as a backup in case Overcooked causes too much chaos 😄", None).await?;

    // Poll in #game-night
    let _poll_id = create_poll(
        &client,
        &hub_url,
        tok(1),
        &game_night_ch.id,
        "What time Friday works best for game night?",
        &[
            ("8pm_est", "8 PM EST"),
            ("9pm_est", "9 PM EST"),
            ("10pm_est", "10 PM EST"),
        ],
    )
    .await
    .context("create_poll failed")?;
    println!("Poll created in #game-night.");

    let _n7 = send_message(
        &client,
        &hub_url,
        tok(0),
        &game_night_ch.id,
        "Voted! 9 PM works best for me too.",
        None,
    )
    .await?;

    // ------------------------------------------------------------------
    // Step 10: #dev-talk conversation (Rust / self-hosting tech)
    // ------------------------------------------------------------------
    println!("Seeding #dev-talk ...");

    let _d1 = send_message(&client, &hub_url, tok(3), &dev_talk_ch.id,
        "Fighting the borrow checker again. Spent an hour on a lifetime issue that turned out to be \
         a missing `Arc<Mutex<T>>` wrapper. Classic.", None).await?;

    let d2 = send_message(&client, &hub_url, tok(2), &dev_talk_ch.id,
        "I feel that. What was the actual error message? Sometimes the compiler hint is more helpful \
         than it looks at first glance.", None).await?;
    add_reaction(&client, &hub_url, tok(3), &dev_talk_ch.id, &d2, "💯").await?;

    let d3 = send_message(
        &client,
        &hub_url,
        tok(3),
        &dev_talk_ch.id,
        "Something like:\n```\nerror[E0502]: cannot borrow `data` as mutable because \
         it is also borrowed as immutable\n```\nTurns out I was holding a read guard \
         across an await point. Once I dropped it before the `.await` everything clicked.",
        Some(&d2),
    )
    .await?;
    add_reaction(&client, &hub_url, tok(0), &dev_talk_ch.id, &d3, "🦀").await?;

    let _d4 = send_message(
        &client,
        &hub_url,
        tok(4),
        &dev_talk_ch.id,
        "Async Rust and borrow scopes across await points is genuinely one of the trickier parts. \
         The `tokio::select!` docs have a great section on it if you haven't seen it.",
        None,
    )
    .await?;

    let d5 = send_message(
        &client,
        &hub_url,
        tok(5),
        &dev_talk_ch.id,
        "Unrelated: anyone using `sqlx` offline mode in CI? I'm trying to avoid needing a live DB \
         for the compile step.",
        None,
    )
    .await?;

    let _d6 = send_message(
        &client,
        &hub_url,
        tok(2),
        &dev_talk_ch.id,
        "Yes — run `cargo sqlx prepare` locally and commit the `.sqlx/` directory. \
         Then set `SQLX_OFFLINE=true` in CI. Works great.",
        Some(&d5),
    )
    .await?;
    add_reaction(&client, &hub_url, tok(5), &dev_talk_ch.id, &d5, "🙌").await?;

    let _d7 = send_message(
        &client,
        &hub_url,
        &admin_token,
        &dev_talk_ch.id,
        "Worth noting: Wavvon hub itself uses `sqlx` with `AnyPool` so it can swap between \
         SQLite (dev/self-host) and Postgres (production) without changing query code.",
        None,
    )
    .await?;

    let d8 = send_message(
        &client,
        &hub_url,
        tok(6),
        &dev_talk_ch.id,
        "That's a nice pattern. Is there a guide somewhere on the Postgres migration path?",
        None,
    )
    .await?;
    add_reaction(&client, &hub_url, tok(4), &dev_talk_ch.id, &d8, "👀").await?;

    let _d9 = send_message(
        &client,
        &hub_url,
        &admin_token,
        &dev_talk_ch.id,
        "Not yet — it's on the roadmap. For now the short answer is: point \
         `DATABASE_URL` at a Postgres DSN and run `sqlx migrate run`. \
         The migrations are written to work on both backends.",
        Some(&d8),
    )
    .await?;

    let _d10 = send_message(&client, &hub_url, tok(1), &dev_talk_ch.id,
        "Self-hosting tip: run the hub behind [Caddy](https://caddyserver.com/) for automatic \
         HTTPS. The config is literally two lines:\n```\nwavvon.example.com\nreverse_proxy localhost:3000\n```", None).await?;

    // ------------------------------------------------------------------
    // Step 11: Persist credentials
    // ------------------------------------------------------------------
    let mut member_creds: Vec<PersistedIdentity> = Vec::new();
    for (i, name) in member_names.iter().enumerate() {
        let (ref id, ref token) = member_tokens[i];
        member_creds.push(persisted(id, name, token));
    }

    let creds = CredsOutput {
        hub_url: hub_url.clone(),
        admin: persisted(&admin, "Nova", &admin_token),
        members: member_creds,
    };

    let creds_json = serde_json::to_string_pretty(&creds).context("Failed to serialise creds")?;
    std::fs::write(&creds_out, &creds_json)
        .with_context(|| format!("Failed to write credentials to {creds_out}"))?;

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    println!();
    println!("=============================================================");
    println!("demo-seed complete!");
    println!("=============================================================");
    println!("Hub       : {hub_url}");
    println!("Branding  : 'Wavvon HQ' / 'The official Wavvon community hub'");
    println!("Channels  : welcome (pinned), general, game-night (poll), dev-talk, Lounge");
    println!("Identities: Nova (admin/owner) + 7 members");
    println!("Messages  : ~30 realistic messages spread across channels");
    println!("Creds out : {creds_out}");
    println!();
    println!("Admin bootstrap note:");
    println!("  The FIRST identity to call POST /auth/verify on a fresh hub is assigned");
    println!(
        "  'builtin-owner' automatically (see hub/src/auth/handlers.rs:assign_initial_roles)."
    );
    println!("  Nova is that first identity — she has the 'admin' permission.");
    println!();
    println!("Lobby note:");
    println!("  Default min_security_level=0, lobby_enabled=true: all identities get");
    println!("  scope='member' immediately. No PoW required on a default-config hub.");
    println!("=============================================================");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_invite_source_returns_none() {
        assert_eq!(owner_invite_code_from(&args(&["demo-seed"]), None), None);
    }

    #[test]
    fn env_var_used_when_no_cli_flag() {
        assert_eq!(
            owner_invite_code_from(&args(&["demo-seed"]), Some("abc123".to_string())),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn cli_flag_used_when_present() {
        assert_eq!(
            owner_invite_code_from(&args(&["demo-seed", "--invite", "deadbeef"]), None),
            Some("deadbeef".to_string())
        );
    }

    #[test]
    fn cli_flag_takes_priority_over_env_var() {
        assert_eq!(
            owner_invite_code_from(
                &args(&["demo-seed", "--invite", "from-cli"]),
                Some("from-env".to_string())
            ),
            Some("from-cli".to_string())
        );
    }

    #[test]
    fn dangling_invite_flag_with_no_value_falls_back_to_env() {
        assert_eq!(
            owner_invite_code_from(
                &args(&["demo-seed", "--invite"]),
                Some("from-env".to_string())
            ),
            Some("from-env".to_string())
        );
    }

    #[test]
    fn empty_values_are_treated_as_absent() {
        assert_eq!(
            owner_invite_code_from(&args(&["demo-seed", "--invite", ""]), None),
            None
        );
        assert_eq!(
            owner_invite_code_from(&args(&["demo-seed"]), Some(String::new())),
            None
        );
    }
}
