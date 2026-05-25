use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::alliance_models::*;
use crate::state::AppState;

pub async fn create_alliance(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateAllianceRequest>,
) -> Result<(StatusCode, Json<AllianceResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query("INSERT INTO alliances (id, name, created_by, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(&req.name)
        .bind(&user.public_key)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add this hub as the first member. Use the live name from hub_settings
    // (an admin may have renamed since startup) rather than state.hub_name.
    let hub_name = crate::routes::hub::current_hub_name(&state).await;
    sqlx::query(
        "INSERT INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&state.hub_identity.public_key_hex())
    .bind(&hub_name)
    .bind("self")
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Created alliance '{}'", req.name);

    Ok((
        StatusCode::CREATED,
        Json(AllianceResponse {
            id,
            name: req.name,
            created_by: user.public_key,
            created_at: now,
        }),
    ))
}

pub async fn list_alliances(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<AllianceResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, AllianceRow>(
        "SELECT DISTINCT a.id, a.name, a.created_by, a.created_at
         FROM alliances a
         INNER JOIN alliance_members am ON a.id = am.alliance_id
         WHERE am.hub_public_key = ?
         ORDER BY a.created_at",
    )
    .bind(&state.hub_identity.public_key_hex())
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AllianceResponse {
                id: r.id,
                name: r.name,
                created_by: r.created_by,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn get_alliance(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<Json<AllianceDetailResponse>, (StatusCode, String)> {
    let alliance = sqlx::query_as::<_, AllianceRow>(
        "SELECT id, name, created_by, created_at FROM alliances WHERE id = ?",
    )
    .bind(&alliance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Alliance not found".to_string()))?;

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = ?",
    )
    .bind(&alliance_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(AllianceDetailResponse {
        id: alliance.id,
        name: alliance.name,
        created_by: alliance.created_by,
        created_at: alliance.created_at,
        members: members
            .into_iter()
            .map(|m| AllianceMemberInfo {
                hub_public_key: m.hub_public_key,
                hub_name: m.hub_name,
                hub_url: m.hub_url,
                joined_at: m.joined_at,
            })
            .collect(),
    }))
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
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM alliances WHERE id = ?")
            .bind(&alliance_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    // Verify channel exists
    let ch_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR IGNORE INTO alliance_shared_channels (alliance_id, channel_id, shared_at) VALUES (?, ?, ?)",
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
) -> Result<(StatusCode, Json<crate::routes::chat_models::MessageResponse>), (StatusCode, String)> {
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
        // hub-as-sender hop. e.g. "[alice via voxply.example] hello".
        let user_label: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
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
                crate::routes::messages::load_reactions(&state.db, &r.id, &user.public_key)
                    .await?;
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

pub async fn leave_alliance(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let hub_key = state.hub_identity.public_key_hex();

    // Remove shared channels
    sqlx::query(
        "DELETE FROM alliance_shared_channels WHERE alliance_id = ? AND channel_id IN (SELECT id FROM channels)",
    )
    .bind(&alliance_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Remove membership
    sqlx::query("DELETE FROM alliance_members WHERE alliance_id = ? AND hub_public_key = ?")
        .bind(&alliance_id)
        .bind(&hub_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // If no members left, delete the alliance
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alliance_members WHERE alliance_id = ?")
            .bind(&alliance_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if member_count == 0 {
        sqlx::query("DELETE FROM alliances WHERE id = ?")
            .bind(&alliance_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// Invite: generate a signed token that another hub can use to join
pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<Json<AllianceInviteResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let alliance = sqlx::query_as::<_, AllianceRow>(
        "SELECT id, name, created_by, created_at FROM alliances WHERE id = ?",
    )
    .bind(&alliance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Alliance not found".to_string()))?;

    // Sign the alliance_id with the hub's identity as the invite token
    let signature = state.hub_identity.sign(alliance_id.as_bytes());
    let token = hex::encode(signature.to_bytes());

    Ok(Json(AllianceInviteResponse {
        token,
        alliance_id: alliance.id,
        alliance_name: alliance.name,
        hub_url: format!("self"), // The receiving hub knows our URL from the API call
    }))
}

// Joining-side: this hub's admin pastes an invite. We call the inviter to
// register, fetch the alliance details, and mirror them into our own DB.
// Without this our `list_alliances` would never show alliances we joined.
pub async fn join_alliance_local(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<JoinAllianceLocalRequest>,
) -> Result<Json<AllianceDetailResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let inviter_url = req.inviter_hub_url.trim_end_matches('/').to_string();
    let detail = do_join_alliance(&state, &inviter_url, &req.alliance_id, &req.invite_token, &req.own_hub_url).await?;
    Ok(Json(detail))
}

// ---------------------------------------------------------------------------
// Push-invite feature
// ---------------------------------------------------------------------------

/// Extract a common join sequence shared by `join_alliance_local` and
/// `accept_pending_invite` to avoid duplication.
async fn do_join_alliance(
    state: &Arc<AppState>,
    inviter_url: &str,
    alliance_id: &str,
    invite_token: &str,
    own_hub_url: &str,
) -> Result<AllianceDetailResponse, (StatusCode, String)> {
    let token = state
        .federation_client
        .authenticate(inviter_url, &state.hub_identity)
        .await
        .map_err(|e| {
            tracing::warn!("Alliance join: could not authenticate with inviter {inviter_url}: {e}");
            (
                StatusCode::BAD_GATEWAY,
                "Could not reach the inviting hub. It may be offline or its URL has changed."
                    .to_string(),
            )
        })?;

    let join_resp = state
        .federation_client
        .post_alliance_join(inviter_url, &token, alliance_id, invite_token, own_hub_url)
        .await
        .map_err(|e| {
            tracing::warn!("Alliance join: join request to {inviter_url} failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                "Could not reach the inviting hub. It may be offline or its URL has changed."
                    .to_string(),
            )
        })?;
    if !join_resp.status().is_success() {
        let status = join_resp.status();
        let body = join_resp.text().await.unwrap_or_default();
        tracing::warn!("Alliance join: inviter {inviter_url} rejected join (HTTP {status}): {body}");
        let msg = if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
            "The invite has expired or has already been used.".to_string()
        } else if status == StatusCode::CONFLICT {
            "This hub is already a member of the alliance.".to_string()
        } else {
            "The inviting hub declined the join request. The invite may be invalid or expired."
                .to_string()
        };
        return Err((StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY), msg));
    }

    let detail = state
        .federation_client
        .get_alliance_detail(inviter_url, &token, alliance_id)
        .await
        .map_err(|e| {
            tracing::warn!("Alliance join: could not fetch detail from {inviter_url}: {e}");
            (
                StatusCode::BAD_GATEWAY,
                "Joined the alliance but could not load its details. Try refreshing the page."
                    .to_string(),
            )
        })?;

    // Mirror locally
    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT OR IGNORE INTO alliances (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&detail.id)
    .bind(&detail.name)
    .bind(&detail.created_by)
    .bind(detail.created_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for m in &detail.members {
        sqlx::query(
            "INSERT OR IGNORE INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&detail.id)
        .bind(&m.hub_public_key)
        .bind(&m.hub_name)
        .bind(if m.hub_public_key == state.hub_identity.public_key_hex() {
            "self".to_string()
        } else {
            m.hub_url.clone()
        })
        .bind(m.joined_at)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Cache the inviter's session token for future federation calls.
    let inviter_pubkey: Option<String> = sqlx::query_scalar(
        "SELECT hub_public_key FROM alliance_members WHERE alliance_id = ? AND hub_url = ?",
    )
    .bind(&detail.id)
    .bind(inviter_url)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if let Some(pk) = inviter_pubkey {
        state.peer_tokens.write().await.insert(pk.clone(), token.clone());

        let exists: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM peers WHERE public_key = ?")
                .bind(&pk)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        if exists.is_none() {
            for m in &detail.members {
                if m.hub_url != "self" && m.hub_url == inviter_url {
                    let _ = sqlx::query(
                        "INSERT OR IGNORE INTO peers (public_key, name, url, added_at) VALUES (?, ?, ?, ?)",
                    )
                    .bind(&m.hub_public_key)
                    .bind(&m.hub_name)
                    .bind(&m.hub_url)
                    .bind(now)
                    .execute(&state.db)
                    .await;
                }
            }
        }
    }

    tracing::info!("Joined alliance '{}' via {}", detail.name, inviter_url);
    Ok(detail)
}

/// `POST /alliances/{alliance_id}/push-invite`
/// Hub A admin pushes a direct invite to Hub B over HTTP.
pub async fn push_invite_handler(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
    Json(req): Json<crate::routes::alliance_models::PushInviteRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Verify alliance exists
    let alliance = sqlx::query_as::<_, AllianceRow>(
        "SELECT id, name, created_by, created_at FROM alliances WHERE id = ?",
    )
    .bind(&alliance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Alliance not found".to_string()))?;

    // Hub name from settings
    let hub_name: String = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'name'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .unwrap_or_else(|| "Unknown".to_string());

    // Generate invite token: sign alliance_id bytes, hex-encode
    let signature = state.hub_identity.sign(alliance_id.as_bytes());
    let invite_token = hex::encode(signature.to_bytes());

    let payload = crate::routes::alliance_models::FederationAllianceInvitePayload {
        id: Uuid::new_v4().to_string(),
        alliance_id: alliance.id,
        alliance_name: alliance.name,
        from_hub_url: req.own_hub_url.clone(),
        from_hub_name: hub_name,
        from_hub_public_key: state.hub_identity.public_key_hex(),
        invite_token,
        message: req.message.clone(),
    };

    let target_url = req.target_hub_url.trim_end_matches('/').to_string();
    let resp = state
        .http_client
        .post(format!("{target_url}/federation/alliance-invite"))
        .json(&payload)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to reach target hub: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("Target hub rejected invite: {body}"),
        ));
    }

    Ok(StatusCode::OK)
}

/// `POST /federation/alliance-invite`
/// Hub B receives a pushed invite from Hub A (no auth required).
pub async fn receive_federation_alliance_invite(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<crate::routes::alliance_models::FederationAllianceInvitePayload>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR IGNORE INTO pending_alliance_invites
         (id, alliance_id, alliance_name, from_hub_url, from_hub_name, from_hub_public_key, invite_token, created_at, message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&payload.id)
    .bind(&payload.alliance_id)
    .bind(&payload.alliance_name)
    .bind(&payload.from_hub_url)
    .bind(&payload.from_hub_name)
    .bind(&payload.from_hub_public_key)
    .bind(&payload.invite_token)
    .bind(now)
    .bind(payload.message.as_deref())
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Received alliance invite from '{}' for alliance '{}'",
        payload.from_hub_name,
        payload.alliance_name
    );

    Ok(StatusCode::OK)
}

/// `GET /alliances/pending-invites`
/// List all pending push invites received by this hub (ADMIN only).
pub async fn list_pending_invites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<crate::routes::alliance_models::PendingAllianceInviteRow>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, PendingInviteRow>(
        "SELECT id, alliance_id, alliance_name, from_hub_url, from_hub_name, from_hub_public_key, invite_token, created_at, message
         FROM pending_alliance_invites
         ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| crate::routes::alliance_models::PendingAllianceInviteRow {
                id: r.id,
                alliance_id: r.alliance_id,
                alliance_name: r.alliance_name,
                from_hub_url: r.from_hub_url,
                from_hub_name: r.from_hub_name,
                from_hub_public_key: r.from_hub_public_key,
                invite_token: r.invite_token,
                created_at: r.created_at,
                message: r.message,
            })
            .collect(),
    ))
}

/// `POST /alliances/pending-invites/{invite_id}/accept`
/// Accept a pending push invite, join the alliance, and remove the invite row.
/// The request body must contain `own_hub_url` — the publicly reachable URL of
/// this hub — so the inviting hub can call back to verify identity.
pub async fn accept_pending_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(invite_id): Path<String>,
    Json(req): Json<crate::routes::alliance_models::AcceptPendingInviteRequest>,
) -> Result<Json<AllianceDetailResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let invite = sqlx::query_as::<_, PendingInviteRow>(
        "SELECT id, alliance_id, alliance_name, from_hub_url, from_hub_name, from_hub_public_key, invite_token, created_at, message
         FROM pending_alliance_invites WHERE id = ?",
    )
    .bind(&invite_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Pending invite not found".to_string()))?;

    let inviter_url = invite.from_hub_url.trim_end_matches('/').to_string();

    let detail = do_join_alliance(
        &state,
        &inviter_url,
        &invite.alliance_id,
        &invite.invite_token,
        &req.own_hub_url,
    )
    .await?;

    // Remove the pending invite now that we've successfully joined.
    sqlx::query("DELETE FROM pending_alliance_invites WHERE id = ?")
        .bind(&invite_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(detail))
}

/// `DELETE /alliances/pending-invites/{invite_id}`
/// Decline (remove) a pending push invite.
pub async fn decline_pending_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query("DELETE FROM pending_alliance_invites WHERE id = ?")
        .bind(&invite_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// Join: a remote hub calls this with an invite token to join the alliance
pub async fn join_alliance(
    State(state): State<Arc<AppState>>,
    Path(alliance_id): Path<String>,
    Json(req): Json<JoinAllianceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify the invite token (signature of alliance_id by this hub)
    let sig_bytes = hex::decode(&req.invite_token)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid invite token hex".to_string()))?;

    voxply_identity::verify_signature(
        &state.hub_identity.public_key_hex(),
        alliance_id.as_bytes(),
        &sig_bytes,
    )
    .map_err(|_| (StatusCode::FORBIDDEN, "Invalid invite token".to_string()))?;

    // Discover the joining hub's info
    let hub_info = state
        .federation_client
        .get_info(&req.hub_url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Cannot reach hub: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT OR IGNORE INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&alliance_id)
    .bind(&hub_info.public_key)
    .bind(&hub_info.name)
    .bind(&req.hub_url)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Also peer with them if not already peered
    let peer_exists: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM peers WHERE public_key = ?")
            .bind(&hub_info.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if peer_exists.is_none() {
        sqlx::query("INSERT INTO peers (public_key, name, url, added_at) VALUES (?, ?, ?, ?)")
            .bind(&hub_info.public_key)
            .bind(&hub_info.name)
            .bind(&req.hub_url)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        // Authenticate to peer
        if let Ok(token) = state
            .federation_client
            .authenticate(&req.hub_url, &state.hub_identity)
            .await
        {
            state
                .peer_tokens
                .write()
                .await
                .insert(hub_info.public_key.clone(), token);
        }
    }

    tracing::info!("Hub '{}' joined alliance {}", hub_info.name, &alliance_id[..8]);

    Ok(StatusCode::OK)
}

#[derive(sqlx::FromRow)]
struct AllianceRow {
    id: String,
    name: String,
    created_by: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    hub_public_key: String,
    hub_name: String,
    hub_url: String,
    joined_at: i64,
}

#[derive(sqlx::FromRow)]
struct SharedChannelRow {
    channel_id: String,
    channel_name: String,
}

#[derive(sqlx::FromRow)]
struct LocalMessageRow {
    id: String,
    channel_id: String,
    sender: String,
    sender_name: Option<String>,
    content: String,
    attachments: Option<String>,
    created_at: i64,
    edited_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PendingInviteRow {
    id: String,
    alliance_id: String,
    alliance_name: String,
    from_hub_url: String,
    from_hub_name: String,
    from_hub_public_key: String,
    invite_token: String,
    created_at: i64,
    message: Option<String>,
}
