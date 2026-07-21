use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::alliance_models::*;
use crate::routes::post_models::{
    CreatePostRequest, CreateReplyRequest, PostDetail, PostListParams, PostListResponse,
    ReplyListParams, ReplyView,
};
use crate::routes::posts::ReactionRequest;
use crate::state::AppState;

use super::models::{EffectiveChannelRow, LocalMessageRow, MemberRow};

/// Resolves the effective shared-channel set for an alliance: explicit
/// `alliance_shared_channels` rows, plus (for rows with
/// `include_descendants = true`) every channel reachable by following
/// `parent_id` down from the shared root. Depth-guarded at 32 to protect
/// against pathological parent chains. This is computed at read time (no
/// descendant rows are materialized), so it gives live semantics: a child
/// created after the share still shows up, and unsharing the root drops
/// the whole subtree.
///
/// The returned rows form well-rooted trees: `parent_id` is set to `None`
/// whenever the real parent is not itself part of the effective set.
/// Order is depth-first-ish (depth, then display_order) so categories tend
/// to precede their children.
async fn effective_shared_channels(
    db: &sqlx::PgPool,
    alliance_id: &str,
) -> Result<Vec<EffectiveChannelRow>, sqlx::Error> {
    let mut rows = sqlx::query_as::<_, EffectiveChannelRow>(
        "WITH RECURSIVE shared_tree AS (
            SELECT c.id, c.name, c.channel_type, c.is_category, c.parent_id, c.display_order,
                   0 AS depth, asc_.include_descendants AS include_descendants
            FROM alliance_shared_channels asc_
            JOIN channels c ON c.id = asc_.channel_id
            WHERE asc_.alliance_id = $1
            UNION ALL
            SELECT c.id, c.name, c.channel_type, c.is_category, c.parent_id, c.display_order,
                   t.depth + 1, t.include_descendants
            FROM channels c
            JOIN shared_tree t ON c.parent_id = t.id
            WHERE t.include_descendants AND t.depth < 32
        )
        SELECT id, name, channel_type, is_category, parent_id
        FROM (
            SELECT DISTINCT ON (id) id, name, channel_type, is_category, parent_id, display_order, depth
            FROM shared_tree
            ORDER BY id, depth
        ) ranked
        ORDER BY depth, display_order",
    )
    .bind(alliance_id)
    .fetch_all(db)
    .await?;

    let ids: std::collections::HashSet<String> = rows.iter().map(|r| r.id.clone()).collect();
    for row in rows.iter_mut() {
        if let Some(pid) = &row.parent_id {
            if !ids.contains(pid) {
                row.parent_id = None;
            }
        }
    }

    Ok(rows)
}

pub async fn share_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Json(req): Json<ShareChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Verify alliance exists
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM alliances WHERE id = $1")
        .bind(&alliance_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    // Verify channel exists. Any space type is shareable -- no channel_type
    // restriction here; sharing a category is what enables `include_descendants`.
    let ch_exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&req.channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    if let Some(policy) = &req.forum_remote_write {
        if !matches!(
            policy.as_str(),
            "none" | "replies_only" | "posts_and_replies"
        ) {
            return Err((
                StatusCode::BAD_REQUEST,
                "forum_remote_write must be 'none', 'replies_only', or 'posts_and_replies'"
                    .to_string(),
            ));
        }
    }

    let now = crate::auth::handlers::unix_timestamp();

    // `forum_remote_write` is COALESCEd on both branches: an insert with no
    // policy supplied falls back to the column's own default
    // ('replies_only'), and a re-share (e.g. to flip include_descendants)
    // that omits the field leaves the existing policy untouched rather than
    // clobbering it back to the default.
    sqlx::query(
        "INSERT INTO alliance_shared_channels (alliance_id, channel_id, shared_at, include_descendants, forum_remote_write)
         VALUES ($1, $2, $3, $4, COALESCE($5, 'replies_only'))
         ON CONFLICT (alliance_id, channel_id)
         DO UPDATE SET include_descendants = EXCLUDED.include_descendants,
                       forum_remote_write = COALESCE($5, alliance_shared_channels.forum_remote_write)",
    )
    .bind(&alliance_id)
    .bind(&req.channel_id)
    .bind(now)
    .bind(req.include_descendants)
    .bind(&req.forum_remote_write)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn unshare_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query("DELETE FROM alliance_shared_channels WHERE alliance_id = $1 AND channel_id = $2")
        .bind(&alliance_id)
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Query params accepted by `GET /alliances/:id/channels`.
#[derive(Deserialize, Default)]
pub struct ListSharedChannelsQuery {
    /// Set by `FederationClient::get_alliance_shared_channels` when this
    /// request is itself a federation hop resolving another hub's members.
    /// Without this, an alliance with mutually-aware members would have
    /// each hub's remote-merge step call the other's, which calls back into
    /// the first, and so on -- an unbounded A<->B<->... cycle. Real
    /// (browser) clients never set this, so they still get the full merged
    /// view across every member hub.
    #[serde(default)]
    pub local_only: bool,
}

pub async fn list_shared_channels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(alliance_id): Path<String>,
    Query(q): Query<ListSharedChannelsQuery>,
) -> Result<Json<Vec<SharedChannelResponse>>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    // 1) Locally shared channels -- the effective set (explicit shares plus
    // live-expanded descendants of any include_descendants=true share).
    let rows = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // forum_remote_write only lives on the *direct* share row (see
    // `forum_write_policy` in routes/posts.rs); descendant-inherited entries
    // fall back to the same default the migration applies.
    let policy_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT channel_id, forum_remote_write FROM alliance_shared_channels WHERE alliance_id = $1",
    )
    .bind(&alliance_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let policy_map: std::collections::HashMap<String, String> = policy_rows.into_iter().collect();

    let local_hub_name = crate::routes::hub::current_hub_name(&state).await;
    let mut out: Vec<SharedChannelResponse> = rows
        .into_iter()
        .map(|r| SharedChannelResponse {
            forum_remote_write: policy_map
                .get(&r.id)
                .cloned()
                .unwrap_or_else(|| "replies_only".to_string()),
            channel_id: r.id,
            channel_name: r.name,
            hub_public_key: hub_key.clone(),
            hub_name: local_hub_name.clone(),
            channel_type: r.channel_type,
            parent_id: r.parent_id,
            is_category: r.is_category,
        })
        .collect();

    if q.local_only {
        return Ok(Json(out));
    }

    // 2) Remote members' shared channels via federation. Skip ourselves; if a
    //    peer is unreachable or auth fails, drop them silently — the user gets
    //    a partial view rather than a hard error.
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&hub_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(e) => {
                    tracing::warn!(
                        "Skipping alliance peer {}: auth failed: {e}",
                        &member.hub_public_key[..16.min(member.hub_public_key.len())]
                    );
                    continue;
                }
            },
        };

        match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(remote) => {
                // The peer fills in its own hub_public_key/hub_name; trust that.
                out.extend(remote);
            }
            Err(e) => {
                tracing::warn!(
                    "Skipping alliance peer {}: fetch failed: {e}",
                    &member.hub_public_key[..16.min(member.hub_public_key.len())]
                );
            }
        }
    }

    Ok(Json(out))
}

/// Send a message to an alliance channel. If the channel is locally owned
/// we just delegate to the normal send path; otherwise we federate to the
/// peer that owns it. The peer sees the message as coming from THIS hub
/// (federation auth uses the hub identity, not the user's). That's a
/// known tradeoff -- proper user-as-sender across hubs would require
/// peer hubs to recognize foreign user identities, which is its own
/// feature. For now, content goes through, sender attribution doesn't.
pub async fn post_alliance_channel_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
    Json(req): Json<crate::routes::chat_models::SendMessageRequest>,
) -> Result<
    (
        StatusCode,
        Json<crate::routes::chat_models::MessageResponse>,
    ),
    (StatusCode, String),
> {
    let perms = crate::permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(crate::permissions::SEND_MESSAGES)?;

    let hub_key = state.hub_identity.public_key_hex();

    // Locally-owned alliance channel (explicit share, or a descendant of an
    // include_descendants share)? Reuse the regular send path.
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if let Some(local) = effective.iter().find(|c| c.id == channel_id) {
        if local.is_category || (local.channel_type != "text" && local.channel_type != "forum") {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "channel type '{}' does not accept alliance messages",
                    if local.is_category {
                        "category"
                    } else {
                        local.channel_type.as_str()
                    }
                ),
            ));
        }
        return crate::routes::messages::send_message(
            State(state),
            user,
            Path(channel_id),
            Json(req),
        )
        .await;
    }

    // Otherwise, find the peer that owns this channel and proxy.
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&hub_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        // Found the owner. Prefix the user's name so attribution survives the
        // hub-as-sender hop. e.g. "[alice via wavvon.example] hello".
        let user_label: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
                .bind(&user.public_key)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        let local_hub_name = crate::routes::hub::current_hub_name(&state).await;
        let prefix = match user_label {
            Some(name) => format!("[{name} via {}] ", local_hub_name),
            None => format!("[{} via {}] ", &user.public_key[..16], local_hub_name),
        };
        let prefixed = format!("{prefix}{}", req.content);

        return state
            .federation_client
            .send_message(&member.hub_url, &token, &channel_id, &prefixed)
            .await
            .map(|m| (StatusCode::CREATED, Json(m)))
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to deliver message to peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// List posts in an alliance-shared forum channel: read-through proxy to
/// the owning hub, same pattern as `get_alliance_channel_messages`. A
/// locally-owned channel delegates straight to the local forum handler
/// (which enforces the `channel_type == 'forum'` gate itself); a
/// peer-owned channel is resolved by walking alliance members and proxied
/// over federation. See forum.md section 9 -- read-only first slice, no
/// replication, owning hub stays authoritative.
pub async fn get_alliance_forum_posts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
    Query(params): Query<PostListParams>,
) -> Result<Json<PostListResponse>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::list_posts(
            State(state),
            user,
            Path(channel_id),
            Query(params),
        )
        .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&hub_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .get_forum_posts(
                &member.hub_url,
                &token,
                &channel_id,
                params.cursor.as_deref(),
                params.limit,
                params.tag.as_deref(),
            )
            .await
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to fetch forum posts from peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// Get one post (with its reply page) from an alliance-shared forum
/// channel. Same owner-resolution + proxy shape as
/// [`get_alliance_forum_posts`].
pub async fn get_alliance_forum_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id, post_id)): Path<(String, String, String)>,
    Query(params): Query<ReplyListParams>,
) -> Result<Json<PostDetail>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::get_post(
            State(state),
            user,
            Path((channel_id, post_id)),
            Query(params),
        )
        .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&hub_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .get_forum_post(
                &member.hub_url,
                &token,
                &channel_id,
                &post_id,
                params.after.as_deref(),
                params.limit,
            )
            .await
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to fetch forum post from peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// Create a post in an alliance-shared forum channel. Locally-owned
/// channels delegate straight to the local handler (the real calling user's
/// own `create_posts` permission applies, as usual). A peer-owned channel is
/// proxied to the owning hub's dedicated federation write endpoint, carrying
/// the calling user's own pubkey as the asserted author -- see forum.md §9
/// "Proxied writes" and `FederationClient::create_forum_post`.
pub async fn post_alliance_forum_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
    Json(req): Json<CreatePostRequest>,
) -> Result<(StatusCode, Json<PostDetail>), (StatusCode, String)> {
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::create_post(State(state), user, Path(channel_id), Json(req))
            .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .create_forum_post(
                &member.hub_url,
                &token,
                &channel_id,
                &user.public_key,
                &req.title,
                &req.body,
            )
            .await
            .map(|d| (StatusCode::CREATED, Json(d)))
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to create forum post on peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// Create a reply in an alliance-shared forum channel's post. Same
/// local-vs-proxy split as [`post_alliance_forum_post`].
pub async fn post_alliance_forum_reply(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id, post_id)): Path<(String, String, String)>,
    Json(req): Json<CreateReplyRequest>,
) -> Result<(StatusCode, Json<ReplyView>), (StatusCode, String)> {
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::create_reply(
            State(state),
            user,
            Path((channel_id, post_id)),
            Json(req),
        )
        .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .create_forum_reply(
                &member.hub_url,
                &token,
                &channel_id,
                &post_id,
                &user.public_key,
                &req.body,
                req.reply_to_id.as_deref(),
            )
            .await
            .map(|v| (StatusCode::CREATED, Json(v)))
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to create forum reply on peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// React to a post in an alliance-shared forum channel. Same local-vs-proxy
/// split as [`post_alliance_forum_post`]. Reply reactions are not yet
/// federated (ponytail: add a matching proxy if allied reply-reaction
/// federation is needed -- post reactions cover the primary use case).
pub async fn react_alliance_forum(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id, post_id)): Path<(String, String, String)>,
    Json(req): Json<ReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::add_post_reaction(
            State(state),
            user,
            Path((channel_id, post_id)),
            Json(req),
        )
        .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        let resp = state
            .federation_client
            .add_forum_post_reaction(
                &member.hub_url,
                &token,
                &channel_id,
                &post_id,
                &user.public_key,
                &req.emoji,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to add forum reaction on peer: {e}"),
                )
            })?;

        return if resp.status().is_success() {
            Ok(StatusCode::CREATED)
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err((
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                body,
            ))
        };
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// Retract (soft-delete) a post in an alliance-shared forum channel. Same
/// local-vs-proxy split as [`post_alliance_forum_post`]: a locally-owned
/// channel delegates straight to the local delete handler, which already
/// enforces "author or `manage_posts`". A peer-owned channel is proxied to
/// the owning hub's dedicated federation retraction endpoint (forum.md §9
/// "Origin-hub retraction"), carrying the calling user's own pubkey as the
/// asserted author -- the owning hub is the one that verifies the target
/// row actually belongs to this hub's user; retraction of someone else's
/// content is rejected there (403), never silently no-op'd here.
pub async fn delete_alliance_forum_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id, post_id)): Path<(String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::delete_post(State(state), user, Path((channel_id, post_id)))
            .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .delete_forum_post(
                &member.hub_url,
                &token,
                &channel_id,
                &post_id,
                &user.public_key,
            )
            .await
            .map(|_| StatusCode::NO_CONTENT)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to delete forum post on peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

/// Retract (soft-delete) a reply in an alliance-shared forum channel's post.
/// Same local-vs-proxy split as [`delete_alliance_forum_post`].
pub async fn delete_alliance_forum_reply(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id, post_id, reply_id)): Path<(String, String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if effective.iter().any(|c| c.id == channel_id) {
        return crate::routes::posts::delete_reply(
            State(state),
            user,
            Path((channel_id, post_id, reply_id)),
        )
        .await;
    }

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        return state
            .federation_client
            .delete_forum_reply(
                &member.hub_url,
                &token,
                &channel_id,
                &post_id,
                &reply_id,
                &user.public_key,
            )
            .await
            .map(|_| StatusCode::NO_CONTENT)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to delete forum reply on peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}

pub async fn get_alliance_channel_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
) -> Result<Json<Vec<crate::routes::chat_models::MessageResponse>>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    // Locally-owned alliance channel (explicit share, or a descendant of an
    // include_descendants share)? Just read directly.
    let effective = effective_shared_channels(&state.db, &alliance_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let local_entry = effective.iter().find(|c| c.id == channel_id);

    if let Some(local) = local_entry {
        // Non-message spaces (categories, banners, spawners) don't have a
        // message history to read -- an empty list is simpler for clients
        // than special-casing every alliance-channel view.
        if local.is_category || (local.channel_type != "text" && local.channel_type != "forum") {
            return Ok(Json(Vec::new()));
        }

        let rows = sqlx::query_as::<_, LocalMessageRow>(
            "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name,
                    m.content, m.attachments, m.created_at, m.edited_at, m.embeds, m.game
             FROM messages m LEFT JOIN users u ON m.sender = u.public_key
             WHERE m.channel_id = $1
             ORDER BY m.created_at DESC, m.id DESC LIMIT 50",
        )
        .bind(&channel_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        let mut out: Vec<crate::routes::chat_models::MessageResponse> =
            Vec::with_capacity(rows.len());
        for r in rows {
            let reactions =
                crate::routes::messages::load_reactions(&state.db, &r.id, &user.public_key).await?;
            out.push(crate::routes::chat_models::MessageResponse {
                id: r.id,
                channel_id: r.channel_id,
                sender: r.sender,
                sender_name: r.sender_name,
                content: r.content,
                created_at: r.created_at,
                edited_at: r.edited_at,
                attachments: r
                    .attachments
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default(),
                reactions,
                // Reply context not federated yet -- shows fine on the owning
                // hub, just no preview here.
                reply_to: None,
                visible_to_pubkey: None,
                reply_count: 0,
                embeds: r
                    .embeds
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| serde_json::from_str(s).ok()),
                game: r
                    .game
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| serde_json::from_str(s).ok()),
            });
        }
        return Ok(Json(out));
    }

    // Otherwise the channel must belong to a peer member of this alliance.
    // Walk members and ask each one if they own this channel.
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1 AND hub_public_key != $2",
    )
    .bind(&alliance_id)
    .bind(&hub_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for member in members {
        let token = {
            let map = state.peer_tokens.read().await;
            map.get(&member.hub_public_key).cloned()
        };
        let token = match token {
            Some(t) => t,
            None => match state
                .federation_client
                .authenticate(&member.hub_url, &state.hub_identity)
                .await
            {
                Ok(t) => {
                    state
                        .peer_tokens
                        .write()
                        .await
                        .insert(member.hub_public_key.clone(), t.clone());
                    t
                }
                Err(_) => continue,
            },
        };

        // Check if this peer owns the channel by listing their shared channels.
        let shared = match state
            .federation_client
            .get_alliance_shared_channels(&member.hub_url, &token, &alliance_id)
            .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !shared.iter().any(|s| s.channel_id == channel_id) {
            continue;
        }

        // The peer owns it -- federate the message read.
        return state
            .federation_client
            .get_messages(&member.hub_url, &token, &channel_id)
            .await
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failed to fetch messages from peer: {e}"),
                )
            });
    }

    Err((
        StatusCode::NOT_FOUND,
        "Alliance channel not found on any member hub".to_string(),
    ))
}
