// DB row types shared across alliance submodules, and the visibility rule
// every alliance route applies to its caller.

use axum::http::StatusCode;

use crate::state::AppState;

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

/// One channel in an alliance's *effective* shared set -- i.e. after
/// expanding `include_descendants` shares into their subtrees. See
/// `effective_shared_channels` in `channels.rs`.
#[derive(sqlx::FromRow, Clone)]
pub(super) struct EffectiveChannelRow {
    pub id: String,
    pub name: String,
    pub channel_type: String,
    pub is_category: bool,
    pub parent_id: Option<String>,
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
    pub embeds: Option<String>,
    pub game: Option<String>,
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

/// Refuse a **peer hub** asking about an alliance it is not in.
///
/// A hub can be in many alliances and they do not merge: it shares different
/// channels into each, and a partner in one has no standing in another. The
/// question only arises for a federating peer — a local caller is a member of
/// *this* hub, which is in the alliance by definition.
///
/// It has to be asked, because a peer token is not a relationship: any hub may
/// authenticate here with `is_hub=true` and lands in `peers` with no invite
/// (deliberately — a peer is not a person joining a community). Without this,
/// `GET /alliances` handed a stranger the id and name of every alliance this
/// hub is in, and the routes below then served their shared channels and their
/// messages.
pub(super) async fn require_alliance_visibility(
    state: &AppState,
    caller: &str,
    alliance_id: &str,
) -> Result<(), (StatusCode, String)> {
    let is_peer: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE public_key = $1)")
            .bind(caller)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if !is_peer {
        return Ok(());
    }

    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2)",
    )
    .bind(alliance_id)
    .bind(caller)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if member {
        Ok(())
    } else {
        // Not found rather than forbidden: whether an alliance exists here is
        // itself the thing being withheld.
        Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()))
    }
}

/// Whether `caller` is a peer hub, for the routes that filter a list instead
/// of refusing outright.
pub(super) async fn caller_is_peer(
    state: &AppState,
    caller: &str,
) -> Result<bool, (StatusCode, String)> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE public_key = $1)")
        .bind(caller)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}
