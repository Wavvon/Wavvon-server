// DB row types shared across alliance submodules.

#[derive(sqlx::FromRow)]
pub(super) struct AllianceRow {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct MemberRow {
    pub hub_public_key: String,
    pub hub_name: String,
    pub hub_url: String,
    pub joined_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct SharedChannelRow {
    pub channel_id: String,
    pub channel_name: String,
}

#[derive(sqlx::FromRow)]
pub(super) struct LocalMessageRow {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: String,
    pub attachments: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub(super) struct PendingInviteRow {
    pub id: String,
    pub alliance_id: String,
    pub alliance_name: String,
    pub from_hub_url: String,
    pub from_hub_name: String,
    pub from_hub_public_key: String,
    pub invite_token: String,
    pub created_at: i64,
    pub message: Option<String>,
}
