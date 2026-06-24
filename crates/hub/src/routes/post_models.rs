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
    pub is_pinned: i64,
    pub is_locked: i64,
    pub reply_count: i64,
    pub last_activity_at: i64,
    pub deleted_at: Option<i64>,
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
}

// ── Wire types (Serialize / Deserialize) ────────────────────────────────────

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
}

/// Edit an existing post's title and/or body.
#[derive(Deserialize, Default)]
pub struct EditPostRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// Create a reply in a post's thread.
#[derive(Deserialize)]
pub struct CreateReplyRequest {
    pub body: String,
    #[serde(default)]
    pub reply_to_id: Option<String>,
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

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Convert a PostRow to a PostSummary. `viewer_can_moderate` controls whether
/// the author field is preserved for tombstoned rows.
pub fn post_to_summary(row: &PostRow, viewer_can_moderate: bool) -> PostSummary {
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
        is_pinned: row.is_pinned != 0,
        is_locked: row.is_locked != 0,
        reply_count: row.reply_count,
        last_activity_at: row.last_activity_at,
        is_deleted,
        unread_reply_count: None,
    }
}

/// Convert a ReplyRow to a ReplyView.
pub fn reply_to_view(row: &ReplyRow, viewer_can_moderate: bool) -> ReplyView {
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
    }
}
