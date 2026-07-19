use anyhow::{Context, Result};

use crate::auth::models::{ChallengeResponse, VerifyResponse};
use crate::routes::alliance_models::{AllianceDetailResponse, SharedChannelResponse};
use crate::routes::chat_models::{ChannelResponse, MessageResponse};
use crate::routes::dm_models::FederatedDmRequest;
use crate::routes::health::InfoResponse;
use crate::routes::post_models::{PostDetail, PostListResponse, ReplyView};
use wavvon_identity::Identity;

pub struct FederationClient {
    http: reqwest::Client,
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_info(&self, base_url: &str) -> Result<InfoResponse> {
        self.http
            .get(format!("{base_url}/info"))
            .send()
            .await
            .context("Failed to connect to peer")?
            .json()
            .await
            .context("Invalid info response")
    }

    pub async fn authenticate(&self, base_url: &str, identity: &Identity) -> Result<String> {
        let pub_key = identity.public_key_hex();

        let challenge: ChallengeResponse = self
            .http
            .post(format!("{base_url}/auth/challenge"))
            .json(&serde_json::json!({ "public_key": pub_key }))
            .send()
            .await
            .context("Failed to request challenge from peer")?
            .json()
            .await
            .context("Invalid challenge response")?;

        let challenge_bytes =
            hex::decode(&challenge.challenge).context("Invalid challenge hex from peer")?;
        let signature = identity.sign(&challenge_bytes);

        let verify: VerifyResponse = self
            .http
            .post(format!("{base_url}/auth/verify"))
            .json(&serde_json::json!({
                "public_key": pub_key,
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
                "is_hub": true,
            }))
            .send()
            .await
            .context("Failed to verify with peer")?
            .json()
            .await
            .context("Invalid verify response")?;

        Ok(verify.token)
    }

    pub async fn get_channels(&self, base_url: &str, token: &str) -> Result<Vec<ChannelResponse>> {
        self.http
            .get(format!("{base_url}/channels"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch channels from peer")?
            .json()
            .await
            .context("Invalid channels response")
    }

    pub async fn send_message(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        content: &str,
    ) -> Result<MessageResponse> {
        self.http
            .post(format!("{base_url}/channels/{channel_id}/messages"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "content": content }))
            .send()
            .await
            .context("Failed to send message to peer")?
            .json()
            .await
            .context("Invalid message response")
    }

    pub async fn get_messages(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
    ) -> Result<Vec<MessageResponse>> {
        self.http
            .get(format!("{base_url}/channels/{channel_id}/messages"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch messages from peer")?
            .json()
            .await
            .context("Invalid messages response")
    }

    /// Read-through fetch of a forum channel's post list from the peer that
    /// owns it. Siblings of `get_messages`/`send_message` -- same
    /// bearer-auth'd hop, just against the local (non-alliance-prefixed)
    /// forum route, since the peer serves its own channel locally.
    pub async fn get_forum_posts(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        cursor: Option<&str>,
        limit: Option<i64>,
    ) -> Result<PostListResponse> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor", c.to_string()));
        }
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        self.http
            .get(format!("{base_url}/channels/{channel_id}/posts"))
            .bearer_auth(token)
            .query(&query)
            .send()
            .await
            .context("Failed to fetch forum posts from peer")?
            .json()
            .await
            .context("Invalid forum posts response")
    }

    /// Read-through fetch of a single forum post (with its reply page) from
    /// the peer that owns it.
    pub async fn get_forum_post(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        post_id: &str,
        after: Option<&str>,
        limit: Option<i64>,
    ) -> Result<PostDetail> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(a) = after {
            query.push(("after", a.to_string()));
        }
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        self.http
            .get(format!("{base_url}/channels/{channel_id}/posts/{post_id}"))
            .bearer_auth(token)
            .query(&query)
            .send()
            .await
            .context("Failed to fetch forum post from peer")?
            .json()
            .await
            .context("Invalid forum post response")
    }

    /// Proxied create-post over the alliance forum write path (forum.md §9
    /// "Proxied writes"). Hits the owning hub's dedicated
    /// `/federation/forum/...` endpoint (NOT the plain
    /// `/channels/:cid/posts` route the read-through siblings above use for
    /// reads) -- the owning hub gates this write by its `forum_remote_write`
    /// policy rather than the caller's own (non-existent, on that hub)
    /// channel permissions.
    pub async fn create_forum_post(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        author_pubkey: &str,
        title: &str,
        body: &str,
    ) -> Result<PostDetail> {
        let resp = self
            .http
            .post(format!(
                "{base_url}/federation/forum/channels/{channel_id}/posts"
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "author_pubkey": author_pubkey,
                "title": title,
                "body": body,
            }))
            .send()
            .await
            .context("Failed to create forum post on peer")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Peer returned HTTP {status}: {body}");
        }
        resp.json()
            .await
            .context("Invalid forum post create response")
    }

    /// Proxied create-reply, sibling of [`Self::create_forum_post`].
    #[allow(clippy::too_many_arguments)]
    pub async fn create_forum_reply(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        post_id: &str,
        author_pubkey: &str,
        body: &str,
        reply_to_id: Option<&str>,
    ) -> Result<ReplyView> {
        let resp = self
            .http
            .post(format!(
                "{base_url}/federation/forum/channels/{channel_id}/posts/{post_id}/replies"
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "author_pubkey": author_pubkey,
                "body": body,
                "reply_to_id": reply_to_id,
            }))
            .send()
            .await
            .context("Failed to create forum reply on peer")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Peer returned HTTP {status}: {body}");
        }
        resp.json()
            .await
            .context("Invalid forum reply create response")
    }

    /// Proxied post reaction, sibling of [`Self::create_forum_post`].
    pub async fn add_forum_post_reaction(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        post_id: &str,
        author_pubkey: &str,
        emoji: &str,
    ) -> Result<reqwest::Response> {
        self.http
            .post(format!(
                "{base_url}/federation/forum/channels/{channel_id}/posts/{post_id}/reactions"
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "author_pubkey": author_pubkey,
                "emoji": emoji,
            }))
            .send()
            .await
            .context("Failed to add forum reaction on peer")
    }

    pub async fn post_alliance_join(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
        invite_token: &str,
        own_hub_url: &str,
    ) -> Result<reqwest::Response> {
        self.http
            .post(format!("{base_url}/alliances/{alliance_id}/join"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "invite_token": invite_token,
                "hub_url": own_hub_url,
            }))
            .send()
            .await
            .context("Failed to call alliance join endpoint")
    }

    pub async fn get_alliance_detail(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
    ) -> Result<AllianceDetailResponse> {
        self.http
            .get(format!("{base_url}/alliances/{alliance_id}"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch alliance detail")?
            .json()
            .await
            .context("Invalid alliance detail response")
    }

    pub async fn get_alliance_shared_channels(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
    ) -> Result<Vec<SharedChannelResponse>> {
        // `local_only=true` tells the peer to answer with just its own
        // shared channels, not a merge of every member it knows about.
        // Membership lists are already replicated to every hub at join
        // time, so this hub's own top-level loop will query every other
        // member directly -- without this flag two (or more) mutually
        // aware hubs would each try to resolve the other's merged view,
        // calling back and forth without ever terminating.
        self.http
            .get(format!(
                "{base_url}/alliances/{alliance_id}/channels?local_only=true"
            ))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch alliance channels from peer")?
            .json()
            .await
            .context("Invalid alliance channels response")
    }

    pub async fn post_federated_dm(
        &self,
        base_url: &str,
        token: &str,
        envelope: &FederatedDmRequest,
    ) -> Result<reqwest::Response> {
        self.http
            .post(format!("{base_url}/federation/dm"))
            .bearer_auth(token)
            .json(envelope)
            .send()
            .await
            .context("Failed to deliver DM to peer")
    }

    /// POST a badge offer to a remote hub's unauthenticated
    /// `/federation/badge-offer` endpoint.
    #[allow(clippy::too_many_arguments)]
    pub async fn post_badge_offer(
        &self,
        base_url: &str,
        from_hub_pubkey: &str,
        from_hub_url: &str,
        label: &str,
        note: Option<&str>,
        payload: &str,
        signature: &str,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!("{base_url}/federation/badge-offer"))
            .json(&serde_json::json!({
                "from_hub_pubkey": from_hub_pubkey,
                "from_hub_url": from_hub_url,
                "label": label,
                "note": note,
                "payload": payload,
                "signature": signature,
            }))
            .send()
            .await
            .context("Failed to reach recipient hub")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Recipient returned HTTP {status}: {body}");
        }

        Ok(())
    }
}
