use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::alliance_models::*;
use crate::state::AppState;

use super::models::{LocalMessageRow, MemberRow, SharedChannelRow};

pub async fn share_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Json(req): Json<ShareChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Verify alliance exists
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM alliances WHERE id = ?")
        .bind(&alliance_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    // Verify channel exists
    let ch_exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
        .bind(&req.channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO alliance_shared_channels (alliance_id, channel_id, shared_at) VALUES (?, ?, ?)
         ON CONFLICT (alliance_id, channel_id) DO NOTHING",
    )
    .bind(&alliance_id)
    .bind(&req.channel_id)
    .bind(now)
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

    sqlx::query("DELETE FROM alliance_shared_channels WHERE alliance_id = ? AND channel_id = ?")
        .bind(&alliance_id)
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_shared_channels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<Json<Vec<SharedChannelResponse>>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    // 1) Locally shared channels
    let rows = sqlx::query_as::<_, SharedChannelRow>(
        "SELECT asc_.channel_id, c.name as channel_name
         FROM alliance_shared_channels asc_
         INNER JOIN channels c ON asc_.channel_id = c.id
         WHERE asc_.alliance_id = ?",
    )
    .bind(&alliance_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let local_hub_name = crate::routes::hub::current_hub_name(&state).await;
    let mut out: Vec<SharedChannelResponse> = rows
        .into_iter()
        .map(|r| SharedChannelResponse {
            channel_id: r.channel_id,
            channel_name: r.channel_name,
            hub_public_key: hub_key.clone(),
            hub_name: local_hub_name.clone(),
        })
        .collect();

    // 2) Remote members' shared channels via federation. Skip ourselves; if a
    //    peer is unreachable or auth fails, drop them silently — the user gets
    //    a partial view rather than a hard error.
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = ? AND hub_public_key != ?",
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

    // Locally-owned alliance channel: reuse the regular send path.
    let is_local: Option<String> = sqlx::query_scalar(
        "SELECT channel_id FROM alliance_shared_channels WHERE alliance_id = ? AND channel_id = ?",
    )
    .bind(&alliance_id)
    .bind(&channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_local.is_some() {
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
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = ? AND hub_public_key != ?",
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
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = ?")
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

pub async fn get_alliance_channel_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((alliance_id, channel_id)): Path<(String, String)>,
) -> Result<Json<Vec<crate::routes::chat_models::MessageResponse>>, (StatusCode, String)> {
    let hub_key = state.hub_identity.public_key_hex();

    // Locally-owned alliance channel? Just read directly.
    let is_local: Option<String> = sqlx::query_scalar(
        "SELECT channel_id FROM alliance_shared_channels WHERE alliance_id = ? AND channel_id = ?",
    )
    .bind(&alliance_id)
    .bind(&channel_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_local.is_some() {
        let rows = sqlx::query_as::<_, LocalMessageRow>(
            "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name,
                    m.content, m.attachments, m.created_at, m.edited_at
             FROM messages m LEFT JOIN users u ON m.sender = u.public_key
             WHERE m.channel_id = ?
             ORDER BY m.created_at DESC, m.rowid DESC LIMIT 50",
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
            });
        }
        return Ok(Json(out));
    }

    // Otherwise the channel must belong to a peer member of this alliance.
    // Walk members and ask each one if they own this channel.
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = ? AND hub_public_key != ?",
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
