//! Thin reqwest executor around the Wavvon hub's public HTTP routes.
//! Modeled directly on `demo-seed` (`crates/demo-seed/src/main.rs`): the
//! same Ed25519 challenge-response auth, wire types mirrored locally so
//! this crate carries no compile dependency on `wavvon_hub`, and the same
//! 429-resilient send helper (here shared via `retry::send`).

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use wavvon_identity::Identity;

use crate::plan::HubChannelKind;
use crate::retry::send;

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
struct IdResponse {
    id: String,
}

/// POST /auth/challenge + POST /auth/verify -> session token.
pub async fn authenticate(client: &Client, hub: &str, identity: &Identity) -> Result<String> {
    let pub_key = identity.public_key_hex();

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

    let challenge_bytes = hex::decode(&resp.challenge).context("challenge is not valid hex")?;
    let signature = identity.sign(&challenge_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    let verify: VerifyResponse = send(client.post(format!("{hub}/auth/verify")).json(&json!({
        "public_key": pub_key,
        "challenge": resp.challenge,
        "signature": sig_hex,
    })))
    .await
    .context("POST /auth/verify failed")?
    .error_for_status()
    .context("verify returned error status")?
    .json()
    .await
    .context("verify response parse failed")?;

    if verify.scope == "lobby" {
        bail!(
            "Hub returned scope=lobby for key {}. The hub requires PoW authentication; \
             lower min_security_level to 0 before running discord-import, or add PoW \
             computation here (see HUB_URL/admin/settings/pow).",
            &pub_key[..16]
        );
    }

    Ok(verify.token)
}

/// GET /channels -- used for the fresh-hub precondition (§2: `apply`
/// refuses if channels already exist, matching demo-seed's posture).
pub async fn existing_channel_count(client: &Client, hub: &str, token: &str) -> Result<usize> {
    let channels: serde_json::Value =
        send(client.get(format!("{hub}/channels")).bearer_auth(token))
            .await
            .context("GET /channels failed")?
            .error_for_status()
            .context("GET /channels returned error status")?
            .json()
            .await
            .context("channels response parse failed")?;

    channels
        .as_array()
        .map(|a| a.len())
        .context("channels response is not an array")
}

/// Fields for `POST /roles`, bundled into one struct so the call site
/// doesn't have to juggle a long positional argument list.
pub struct NewRole<'a> {
    pub name: &'a str,
    pub priority: i64,
    pub display_separately: bool,
    pub color: Option<&'a str>,
    pub permissions: &'a [String],
}

/// POST /roles.
pub async fn create_role(
    client: &Client,
    hub: &str,
    token: &str,
    role: &NewRole<'_>,
) -> Result<String> {
    let resp: IdResponse = send(client.post(format!("{hub}/roles")).bearer_auth(token).json(
        &json!({
            "name": role.name,
            "priority": role.priority,
            "display_separately": role.display_separately,
            "color": role.color,
            "permissions": role.permissions,
        }),
    ))
    .await
    .context(format!("POST /roles ({}) failed", role.name))?
    .error_for_status()
    .context(format!("create_role({}) error status", role.name))?
    .json()
    .await
    .context("role response parse failed")?;

    Ok(resp.id)
}

/// POST /channels.
pub async fn create_channel(
    client: &Client,
    hub: &str,
    token: &str,
    name: &str,
    parent_id: Option<&str>,
    kind: HubChannelKind,
) -> Result<String> {
    let mut body = json!({ "name": name });
    match kind {
        HubChannelKind::Category => {
            body["is_category"] = json!(true);
        }
        HubChannelKind::Text => {
            body["channel_type"] = json!("text");
        }
        HubChannelKind::Forum => {
            body["channel_type"] = json!("forum");
        }
    }
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }

    let resp: IdResponse = send(
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

    Ok(resp.id)
}

/// PUT /channels/:id/permissions/:role_id.
pub async fn put_channel_permissions(
    client: &Client,
    hub: &str,
    token: &str,
    channel_id: &str,
    role_id: &str,
    allow: &[String],
    deny: &[String],
) -> Result<()> {
    send(
        client
            .put(format!("{hub}/channels/{channel_id}/permissions/{role_id}"))
            .bearer_auth(token)
            .json(&json!({ "allow": allow, "deny": deny })),
    )
    .await
    .context("PUT /channels/:id/permissions/:role_id failed")?
    .error_for_status()
    .context("put_channel_permissions error status")?;
    Ok(())
}
