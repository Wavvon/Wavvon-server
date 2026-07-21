use serde::{Deserialize, Serialize};

// ── DB row types (sqlx::FromRow) ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct PostRow {
    pub id: String,
    pub channel_id: String,
    pub author_pubkey: String,
    pub title: String,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub is_pinned: bool,
    pub is_locked: bool,
    pub reply_count: i64,
    pub last_activity_at: i64,
    pub deleted_at: Option<i64>,
    pub attachments: String,
    /// Origin hub public key hex when authored via the alliance forum
    /// write-proxy (forum.md §9); `None` for locally-authored posts.
    pub author_hub: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct ReplyRow {
    pub id: String,
    pub post_id: String,
    pub author_pubkey: String,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub reply_to_id: Option<String>,
    pub deleted_at: Option<i64>,
    pub attachments: String,
    /// Origin hub public key hex when authored via the alliance forum
    /// write-proxy (forum.md §9); `None` for locally-authored replies.
    pub author_hub: Option<String>,
}

// ── Wire types (Serialize / Deserialize) ────────────────────────────────────

/// Aggregated emoji reaction count with viewer-own flag.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReactionCount {
    pub emoji: String,
    pub count: i64,
    /// Whether the requesting user has reacted with this emoji.
    pub me: bool,
}

/// File attachment metadata stored as JSON in the DB.
#[derive(Serialize, Deserialize, Clone, Debug, sqlx::FromRow)]
pub struct Attachment {
    pub url: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
}

// ── Post tags (forum.md §10) ────────────────────────────────────────────────

/// A tag definition on a forum channel (admin-curated, forum.md §10.1).
#[derive(Serialize, Deserialize, Clone, Debug, sqlx::FromRow)]
pub struct ForumTag {
    pub id: String,
    pub channel_id: String,
    pub label: String,
    pub color: Option<String>,
    pub position: i64,
    pub created_at: i64,
}

/// Create a tag definition (`POST /channels/:cid/tags`).
#[derive(Deserialize)]
pub struct CreateTagRequest {
    pub label: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub position: Option<i64>,
}

/// Edit a tag definition (`PATCH /tags/:tid`). `label`/`position` follow the
/// usual "absent = unchanged" rule; `color` is tri-state
/// (`Option<Option<String>>`) because it is the one nullable field here and
/// the omitted-vs-null trap (CLAUDE.md) has bitten this exact shape before
/// (role color/icon) -- `None` = unchanged, `Some(None)` = clear to no color.
#[derive(Deserialize, Default)]
pub struct EditTagRequest {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some_nested")]
    pub color: Option<Option<String>>,
    #[serde(default)]
    pub position: Option<i64>,
}

fn deserialize_some_nested<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

/// A tag as it appears attached to a post (forum.md §10.2). Populated per
/// post from the `post_tags` join, never stored inline.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TagRef {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// Summary of a post as it appears in the list view.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostSummary {
    pub id: String,
    pub channel_id: String,
    pub author_pubkey: Option<String>,
    pub title: Option<String>,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<i64>,
    pub is_pinned: bool,
    pub is_locked: bool,
    pub reply_count: i64,
    pub last_activity_at: i64,
    pub is_deleted: bool,
    /// Number of replies posted after the viewer's last read cursor for this
    /// post. `None` when the request was made without authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_reply_count: Option<i64>,
    pub reactions: Vec<ReactionCount>,
    pub attachments: Vec<Attachment>,
    /// Origin hub public key hex when this post came in through the alliance
    /// forum write-proxy (forum.md §9 "Proxied writes"); `None` for
    /// locally-authored posts. Hub-asserted, not cryptographically proven --
    /// clients must render it as mediated ("via HubName"), never as a
    /// verified badge. Omitted from the wire when absent so un-upgraded
    /// peers still parse the shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_hub: Option<String>,
    /// Tags assigned to this post (forum.md §10.2). `#[serde(default)]` so
    /// un-upgraded peers parse.
    #[serde(default)]
    pub tags: Vec<TagRef>,
}

/// Full post including body and first page of replies.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostDetail {
    #[serde(flatten)]
    pub summary: PostSummary,
    pub body: Option<String>,
    pub replies: Vec<ReplyView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_cursor: Option<String>,
}

/// A single reply in a post's reply thread.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReplyView {
    pub id: String,
    pub post_id: String,
    pub author_pubkey: Option<String>,
    pub body: Option<String>,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<String>,
    pub is_deleted: bool,
    pub reactions: Vec<ReactionCount>,
    pub attachments: Vec<Attachment>,
    /// Origin hub public key hex when this reply came in through the
    /// alliance forum write-proxy; see `PostSummary::author_hub`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_hub: Option<String>,
}

/// Paged list of posts.
#[derive(Serialize, Deserialize)]
pub struct PostListResponse {
    pub posts: Vec<PostSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Create a new post.
#[derive(Deserialize)]
pub struct CreatePostRequest {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub attachments: Option<Vec<Attachment>>,
    /// Tag ids to assign at creation (forum.md §10.2). Every id must belong
    /// to this channel's tag set; capped at 5; enforced against
    /// `forum_require_tag` on the channel.
    #[serde(default)]
    pub tag_ids: Option<Vec<String>>,
}

/// Edit an existing post's title and/or body.
#[derive(Deserialize, Default)]
pub struct EditPostRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    /// Replace the post's tag assignments. Omitted = unchanged (never
    /// clears); `Some(vec![])` clears all tags (forum.md §10.2).
    #[serde(default)]
    pub tag_ids: Option<Vec<String>>,
}

/// Create a reply in a post's thread.
#[derive(Deserialize)]
pub struct CreateReplyRequest {
    pub body: String,
    #[serde(default)]
    pub reply_to_id: Option<String>,
    #[serde(default)]
    pub attachments: Option<Vec<Attachment>>,
}

/// Edit a reply body.
#[derive(Deserialize)]
pub struct EditReplyRequest {
    pub body: String,
}

/// FTS search results for a forum channel.
#[derive(Serialize, Deserialize)]
pub struct PostSearchResponse {
    pub results: Vec<PostSearchHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A single FTS hit (may be from a post body/title or a reply body).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PostSearchHit {
    pub post_id: String,
    pub title_snippet: String,
    pub body_snippet: String,
    pub is_reply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_id: Option<String>,
}

/// Cursor parameters for post list pagination.
#[derive(Deserialize, Default)]
pub struct PostListParams {
    /// Opaque cursor: "last_activity_at:id" of the last seen post.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    /// Filter to posts carrying this tag id (forum.md §10.2). Single-tag
    /// filter only in v1.
    #[serde(default)]
    pub tag: Option<String>,
}

/// Parameters for reply list pagination.
#[derive(Deserialize, Default)]
pub struct ReplyListParams {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Search query parameter.
#[derive(Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
}

// ── Federation: proxied writes (forum.md §9 phase 2) ────────────────────────
//
// Hit by an allied hub's `/federation/forum/...` call, not by an end user
// directly. `author_pubkey` is the asserted (not cryptographically proven)
// identity of the remote member who performed the action -- accepted within
// alliance trust, same model as the existing federated-DM sender field.
// `author_hub` is NOT part of the request body: the owning hub derives it
// from the authenticated caller (`PeerHub::public_key`), so a peer cannot
// assert a different hub's identity as the origin.

/// Proxied post creation, carrying the asserted author.
#[derive(Deserialize)]
pub struct FederatedCreatePostRequest {
    pub author_pubkey: String,
    pub title: String,
    pub body: String,
}

/// Proxied reply creation, carrying the asserted author.
#[derive(Deserialize)]
pub struct FederatedCreateReplyRequest {
    pub author_pubkey: String,
    pub body: String,
    #[serde(default)]
    pub reply_to_id: Option<String>,
}

/// Proxied reaction, carrying the asserted author.
#[derive(Deserialize)]
pub struct FederatedReactionRequest {
    pub author_pubkey: String,
    pub emoji: String,
}

// ── Federation: origin-hub retraction (forum.md §9 phase 3) ────────────────
//
// A `DELETE /federation/forum/...` call, gated by `PeerHub` like the phase-2
// write endpoints above. `author_pubkey` is the asserted local user doing
// the retracting; the owning hub only honors the delete when BOTH the
// target row's `author_hub` matches the calling peer AND its
// `author_pubkey` matches this assertion -- a hub can retract only its own
// users' content, never anyone else's.

/// Proxied retraction (post or reply delete), carrying the asserted author.
#[derive(Deserialize)]
pub struct FederatedRetractRequest {
    pub author_pubkey: String,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_attachments(json: &str) -> Vec<Attachment> {
    if json.is_empty() || json == "[]" {
        return Vec::new();
    }
    serde_json::from_str(json).unwrap_or_default()
}

/// Convert a PostRow to a PostSummary. `viewer_can_moderate` controls whether
/// the author field is preserved for tombstoned rows. Reactions and attachments
/// are always passed in by the caller (fetched separately).
pub fn post_to_summary(
    row: &PostRow,
    viewer_can_moderate: bool,
    reactions: Vec<ReactionCount>,
    tags: Vec<TagRef>,
) -> PostSummary {
    let is_deleted = row.deleted_at.is_some();
    PostSummary {
        id: row.id.clone(),
        channel_id: row.channel_id.clone(),
        author_pubkey: if is_deleted && !viewer_can_moderate {
            None
        } else {
            Some(row.author_pubkey.clone())
        },
        title: if is_deleted {
            None
        } else {
            Some(row.title.clone())
        },
        created_at: row.created_at,
        edited_at: row.edited_at,
        is_pinned: row.is_pinned,
        is_locked: row.is_locked,
        reply_count: row.reply_count,
        last_activity_at: row.last_activity_at,
        is_deleted,
        unread_reply_count: None,
        reactions,
        attachments: parse_attachments(&row.attachments),
        author_hub: if is_deleted && !viewer_can_moderate {
            None
        } else {
            row.author_hub.clone()
        },
        tags,
    }
}

/// Convert a ReplyRow to a ReplyView.
pub fn reply_to_view(
    row: &ReplyRow,
    viewer_can_moderate: bool,
    reactions: Vec<ReactionCount>,
) -> ReplyView {
    let is_deleted = row.deleted_at.is_some();
    ReplyView {
        id: row.id.clone(),
        post_id: row.post_id.clone(),
        author_pubkey: if is_deleted && !viewer_can_moderate {
            None
        } else {
            Some(row.author_pubkey.clone())
        },
        body: if is_deleted {
            None
        } else {
            Some(row.body.clone())
        },
        created_at: row.created_at,
        edited_at: row.edited_at,
        reply_to_id: row.reply_to_id.clone(),
        is_deleted,
        reactions,
        attachments: parse_attachments(&row.attachments),
        author_hub: if is_deleted && !viewer_can_moderate {
            None
        } else {
            row.author_hub.clone()
        },
    }
}
