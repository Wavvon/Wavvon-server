use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::routes::chat_models::{Attachment, MAX_ATTACHMENTS_BYTES};
use crate::routes::dm_models::*;
use crate::state::{AppState, DmEvent};

pub async fn create_conversation(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateConversationRequest>,
) -> Result<(StatusCode, Json<ConversationResponse>), (StatusCode, String)> {
    if req.members.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Need at least one other member".to_string()));
    }

    let conv_type = if req.members.len() == 1 { "dm" } else { "group" };

    // For DMs (1-on-1), check if a conversation already exists between these two users
    if conv_type == "dm" {
        let existing = find_existing_dm(&state, &user.public_key, &req.members[0]).await?;
        if let Some(conv) = existing {
            return Ok((StatusCode::OK, Json(conv)));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query("INSERT INTO conversations (id, conv_type, created_at) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(conv_type)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add the creator (always local)
    sqlx::query("INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url) VALUES (?, ?, ?, NULL)")
        .bind(&id)
        .bind(&user.public_key)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add other members with their (optional) delivery hub URL.
    // Remote members may not yet exist in our users table — insert a stub so
    // the FK holds. We only track public_key for these; they never sign in here.
    for member_key in &req.members {
        let hub_url = req.member_hubs.get(member_key).cloned();
        ensure_user_stub(&state.db, member_key, now).await?;
        sqlx::query("INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(member_key)
            .bind(now)
            .bind(&hub_url)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let mut all_members = req.members.clone();
    all_members.push(user.public_key);

    Ok((
        StatusCode::CREATED,
        Json(ConversationResponse {
            id,
            conv_type: conv_type.to_string(),
            members: all_members,
            created_at: now,
            last_activity_at: now,
        }),
    ))
}

pub async fn list_conversations(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<ConversationResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, ConvRow>(
        "SELECT c.id, c.conv_type, c.created_at
         FROM conversations c
         INNER JOIN conversation_members cm ON c.id = cm.conversation_id
         WHERE cm.public_key = ?
         ORDER BY c.created_at DESC",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        let members: Vec<String> = sqlx::query_scalar(
            "SELECT public_key FROM conversation_members WHERE conversation_id = ?",
        )
        .bind(&row.id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        // Last activity = most recent dm_message in this conversation, or
        // the conversation creation time if there are no messages yet.
        let last_msg: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(created_at) FROM dm_messages WHERE conversation_id = ?",
        )
        .bind(&row.id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        result.push(ConversationResponse {
            id: row.id,
            conv_type: row.conv_type,
            members,
            created_at: row.created_at,
            last_activity_at: last_msg.unwrap_or(row.created_at),
        });
    }

    Ok(Json(result))
}

pub async fn send_dm(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Json(req): Json<SendDmRequest>,
) -> Result<(StatusCode, Json<DmMessageResponse>), (StatusCode, String)> {
    let members = load_members(&state, &conversation_id).await?;
    if !members.iter().any(|m| m.public_key == user.public_key) {
        return Err((StatusCode::FORBIDDEN, "Not a member of this conversation".to_string()));
    }

    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = ?")
        .bind(&conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    // Validate: exactly one of content or encrypted_envelope must be provided.
    // Encrypted messages are only allowed in 1:1 DMs (not group).
    let is_encrypted = match (&req.content, &req.encrypted_envelope) {
        (None, None) => {
            return Err((StatusCode::BAD_REQUEST, "Either content or encrypted_envelope is required".to_string()));
        }
        (Some(_), Some(_)) => {
            return Err((StatusCode::BAD_REQUEST, "Provide content or encrypted_envelope, not both".to_string()));
        }
        (None, Some(_)) => {
            if conv_type != "dm" {
                return Err((StatusCode::BAD_REQUEST, "E2E encryption is only supported for 1:1 DMs".to_string()));
            }
            true
        }
        (Some(_), None) => false,
    };

    // Same per-message attachment cap as channel messages.
    let attach_total: usize = req.attachments.iter().map(|a| a.data_b64.len()).sum();
    if attach_total > MAX_ATTACHMENTS_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Attachments exceed {}MB cap",
                MAX_ATTACHMENTS_BYTES / 1024 / 1024
            ),
        ));
    }

    if is_encrypted {
        let env = req.encrypted_envelope.as_ref().unwrap();
        // Verify the Ed25519 signature over the envelope fields.
        let msg = envelope_signing_bytes(env);
        let sig_bytes = hex::decode(&env.signature_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature hex: {e}")))?;
        voxply_identity::verify_signature(&user.public_key, &msg, &sig_bytes)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid envelope signature: {e}")))?;
    }

    let attachments_json = if req.attachments.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&req.attachments)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?,
        )
    };

    let message_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    if is_encrypted {
        let env = req.encrypted_envelope.as_ref().unwrap();
        let ciphertext_json = serde_json::to_string(env)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode envelope: {e}")))?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json)
             VALUES (?, ?, ?, NULL, ?, NULL, ?, 1, ?)",
        )
        .bind(&message_id)
        .bind(&conversation_id)
        .bind(&user.public_key)
        .bind(&attachments_json)
        .bind(now)
        .bind(&ciphertext_json)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    } else {
        let content = req.content.as_deref().unwrap_or("");
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json)
             VALUES (?, ?, ?, ?, ?, NULL, ?, 0, NULL)",
        )
        .bind(&message_id)
        .bind(&conversation_id)
        .bind(&user.public_key)
        .bind(content)
        .bind(&attachments_json)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Broadcast to local WS subscribers (other members on this same hub).
    let sender_name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM users WHERE public_key = ?",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .flatten();

    // For encrypted messages, broadcast a placeholder so WS subscribers get
    // notified and know to re-fetch the full envelope via the HTTP API.
    let ws_content = if is_encrypted {
        "[encrypted]".to_string()
    } else {
        req.content.clone().unwrap_or_default()
    };

    let _ = state.dm_tx.send(DmEvent::Message {
        conversation_id: conversation_id.clone(),
        sender: user.public_key.clone(),
        sender_name: sender_name.clone(),
        content: ws_content,
        timestamp: now,
    });

    // Federate to each remote member's delivery hub.
    // Phase 5: if the member has a HomeHubList designation stored here, deliver
    // to every URL in that list (one outbox row per URL). Otherwise fall back to
    // the single hub_url recorded in conversation_members.
    let member_keys: Vec<String> = members.iter().map(|m| m.public_key.clone()).collect();
    for m in &members {
        if m.public_key == user.public_key {
            continue;
        }

        // Resolve delivery URLs via the home-hub designation when available.
        let delivery_urls: Vec<String> = {
            // Step 1: look up master_pubkey for this member.
            let master_pubkey: Option<String> = sqlx::query_scalar(
                "SELECT master_pubkey FROM users WHERE public_key = ?",
            )
            .bind(&m.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

            // Step 2: if a master is known, try the designation table.
            let designation_urls: Option<Vec<String>> = if let Some(ref mpk) = master_pubkey {
                let hubs_json: Option<String> = sqlx::query_scalar(
                    "SELECT hubs_json FROM home_hub_designations WHERE master_pubkey = ?",
                )
                .bind(mpk)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                hubs_json.and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
            } else {
                None
            };

            // Step 3: use the designation list, or fall back to the stored hub_url.
            match designation_urls {
                Some(urls) if !urls.is_empty() => urls,
                _ => match &m.hub_url {
                    Some(url) => vec![url.clone()],
                    None => continue,
                },
            }
        };

        let envelope = FederatedDmRequest {
            message_id: message_id.clone(),
            conversation_id: conversation_id.clone(),
            conv_type: conv_type.clone(),
            sender: user.public_key.clone(),
            members: member_keys.clone(),
            content: req.content.clone(),
            attachments: req.attachments.clone(),
            signature: None,
            created_at: now,
            encrypted_envelope: req.encrypted_envelope.clone(),
        };

        for hub_url in &delivery_urls {
            sqlx::query(
                "INSERT OR IGNORE INTO dm_outbox
                 (message_id, recipient_hub_url, attempts, next_attempt_at)
                 VALUES (?, ?, 0, ?)",
            )
            .bind(&message_id)
            .bind(hub_url)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            match deliver_federated_dm(&state, hub_url, &envelope).await {
                Ok(()) => {
                    let _ = sqlx::query(
                        "DELETE FROM dm_outbox WHERE message_id = ? AND recipient_hub_url = ?",
                    )
                    .bind(&message_id)
                    .bind(hub_url)
                    .execute(&state.db)
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        "DM {} to {} failed immediately, leaving in outbox for retry: {e}",
                        &message_id[..8],
                        hub_url
                    );
                    let _ = sqlx::query(
                        "UPDATE dm_outbox SET attempts = 1, next_attempt_at = ?, last_error = ?
                         WHERE message_id = ? AND recipient_hub_url = ?",
                    )
                    .bind(now + 10)
                    .bind(&e)
                    .bind(&message_id)
                    .bind(hub_url)
                    .execute(&state.db)
                    .await;
                }
            }
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(DmMessageResponse {
            id: message_id,
            conversation_id,
            sender: user.public_key,
            sender_name,
            content: req.content,
            created_at: now,
            attachments: req.attachments,
            delivery_failed: false,
            is_encrypted,
            encrypted_envelope: req.encrypted_envelope,
        }),
    ))
}

pub async fn list_dm_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<Vec<DmMessageResponse>>, (StatusCode, String)> {
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ? AND public_key = ?",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_member == 0 {
        return Err((StatusCode::FORBIDDEN, "Not a member of this conversation".to_string()));
    }

    let rows = sqlx::query_as::<_, DmMessageRow>(
        "SELECT m.id, m.conversation_id, m.sender, u.display_name as sender_name,
                m.content, m.attachments, m.created_at,
                COALESCE(m.is_encrypted, 0) AS is_encrypted,
                m.ciphertext_json,
                EXISTS (
                    SELECT 1 FROM dm_outbox o
                    WHERE o.message_id = m.id AND o.bounced_at IS NOT NULL
                ) AS delivery_failed
         FROM dm_messages m
         LEFT JOIN users u ON u.public_key = m.sender
         WHERE m.conversation_id = ?
         ORDER BY m.created_at ASC",
    )
    .bind(&conversation_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut responses = Vec::with_capacity(rows.len());
    for r in rows {
        let is_enc = r.is_encrypted != 0;
        let encrypted_envelope = if is_enc {
            r.ciphertext_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<EncryptedDmEnvelope>(s).ok())
        } else {
            None
        };
        responses.push(DmMessageResponse {
            id: r.id,
            conversation_id: r.conversation_id,
            sender: r.sender,
            sender_name: r.sender_name,
            content: r.content,
            created_at: r.created_at,
            attachments: parse_dm_attachments(r.attachments),
            delivery_failed: r.delivery_failed != 0,
            is_encrypted: is_enc,
            encrypted_envelope,
        });
    }

    Ok(Json(responses))
}

fn parse_dm_attachments(json: Option<String>) -> Vec<Attachment> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Signing bytes for the encrypted DM envelope. Both sender and hub use this.
fn envelope_signing_bytes(env: &EncryptedDmEnvelope) -> Vec<u8> {
    let mut out = b"voxply/dm-ciphertext/v1\0".to_vec();
    for s in [&env.conv_id, &env.ciphertext_hex, &env.nonce_hex, &env.dh_pubkey_hex] {
        let b = s.as_bytes();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Hub-to-hub DM delivery endpoint. The caller is an authenticated peer hub.
pub async fn receive_federated_dm(
    State(state): State<Arc<AppState>>,
    _peer: AuthUser,
    Json(req): Json<FederatedDmRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // Idempotent: if we've already stored this message, succeed without double-broadcast.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM dm_messages WHERE id = ?")
        .bind(&req.message_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_some() {
        return Ok(StatusCode::OK);
    }

    // Auto-create the conversation on this hub if this is the first time we've seen it.
    let conv_exists: Option<String> = sqlx::query_scalar("SELECT id FROM conversations WHERE id = ?")
        .bind(&req.conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if conv_exists.is_none() {
        sqlx::query("INSERT INTO conversations (id, conv_type, created_at) VALUES (?, ?, ?)")
            .bind(&req.conversation_id)
            .bind(&req.conv_type)
            .bind(req.created_at)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        for member in &req.members {
            ensure_user_stub(&state.db, member, req.created_at).await?;
            sqlx::query(
                "INSERT OR IGNORE INTO conversation_members
                 (conversation_id, public_key, joined_at, hub_url) VALUES (?, ?, ?, NULL)",
            )
            .bind(&req.conversation_id)
            .bind(member)
            .bind(req.created_at)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }
    }

    ensure_user_stub(&state.db, &req.sender, req.created_at).await?;

    let attachments_json = if req.attachments.is_empty() {
        None
    } else {
        serde_json::to_string(&req.attachments).ok()
    };

    let is_encrypted = req.encrypted_envelope.is_some();

    if is_encrypted {
        let env = req.encrypted_envelope.as_ref().unwrap();
        // Verify the signature before storing.
        let msg = envelope_signing_bytes(env);
        let sig_bytes = hex::decode(&env.signature_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature hex: {e}")))?;
        voxply_identity::verify_signature(&req.sender, &msg, &sig_bytes)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid envelope signature: {e}")))?;

        let ciphertext_json = serde_json::to_string(env)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json)
             VALUES (?, ?, ?, NULL, ?, ?, ?, 1, ?)",
        )
        .bind(&req.message_id)
        .bind(&req.conversation_id)
        .bind(&req.sender)
        .bind(&attachments_json)
        .bind(&req.signature)
        .bind(req.created_at)
        .bind(&ciphertext_json)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    } else {
        let content = req.content.as_deref().unwrap_or("");
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)",
        )
        .bind(&req.message_id)
        .bind(&req.conversation_id)
        .bind(&req.sender)
        .bind(content)
        .bind(&attachments_json)
        .bind(&req.signature)
        .bind(req.created_at)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Broadcast to any local members connected via WS.
    let sender_name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM users WHERE public_key = ?",
    )
    .bind(&req.sender)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let ws_content = if is_encrypted {
        "[encrypted]".to_string()
    } else {
        req.content.clone().unwrap_or_default()
    };

    let _ = state.dm_tx.send(DmEvent::Message {
        conversation_id: req.conversation_id,
        sender: req.sender,
        sender_name,
        content: ws_content,
        timestamp: req.created_at.max(now),
    });

    Ok(StatusCode::OK)
}

// --- Helpers ---

/// Ensure a user row exists for `public_key` so FKs into the users table hold.
/// For remote users we only know their key; the stub is created with no display name.
async fn ensure_user_stub(
    db: &sqlx::SqlitePool,
    public_key: &str,
    now: i64,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT OR IGNORE INTO users (public_key, display_name, first_seen_at, last_seen_at)
         VALUES (?, NULL, ?, ?)",
    )
    .bind(public_key)
    .bind(now)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

/// Public wrapper around `deliver_federated_dm` for the retry worker.
pub async fn deliver_federated_dm_public(
    state: &AppState,
    hub_url: &str,
    envelope: &FederatedDmRequest,
) -> Result<(), String> {
    deliver_federated_dm(state, hub_url, envelope).await
}

async fn deliver_federated_dm(
    state: &AppState,
    hub_url: &str,
    envelope: &FederatedDmRequest,
) -> Result<(), String> {
    // Ensure we have a session token for this remote hub — authenticate once if not cached.
    let token = {
        let peer_key: Option<String> =
            sqlx::query_scalar("SELECT public_key FROM peers WHERE url = ?")
                .bind(hub_url)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| format!("peer lookup: {e}"))?;

        let cached = if let Some(ref key) = peer_key {
            state.peer_tokens.read().await.get(key).cloned()
        } else {
            None
        };

        if let Some(t) = cached {
            t
        } else {
            let fresh = state
                .federation_client
                .authenticate(hub_url, &state.hub_identity)
                .await
                .map_err(|e| format!("authenticate: {e}"))?;

            let info = state
                .federation_client
                .get_info(hub_url)
                .await
                .map_err(|e| format!("get_info: {e}"))?;
            let now = crate::auth::handlers::unix_timestamp();
            let _ = sqlx::query(
                "INSERT INTO peers (public_key, name, url, added_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT(public_key) DO UPDATE SET name = ?, url = ?",
            )
            .bind(&info.public_key)
            .bind(&info.name)
            .bind(hub_url)
            .bind(now)
            .bind(&info.name)
            .bind(hub_url)
            .execute(&state.db)
            .await;
            state
                .peer_tokens
                .write()
                .await
                .insert(info.public_key, fresh.clone());
            fresh
        }
    };

    let resp = state
        .federation_client
        .post_federated_dm(hub_url, &token, envelope)
        .await
        .map_err(|e| format!("deliver: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("remote hub returned {}", resp.status()));
    }
    Ok(())
}

struct ConvMember {
    public_key: String,
    hub_url: Option<String>,
}

async fn load_members(
    state: &AppState,
    conversation_id: &str,
) -> Result<Vec<ConvMember>, (StatusCode, String)> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT public_key, hub_url FROM conversation_members WHERE conversation_id = ?",
    )
    .bind(conversation_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(pk, url)| ConvMember {
            public_key: pk,
            hub_url: url,
        })
        .collect())
}

async fn find_existing_dm(
    state: &AppState,
    user_a: &str,
    user_b: &str,
) -> Result<Option<ConversationResponse>, (StatusCode, String)> {
    let convs: Vec<String> = sqlx::query_scalar(
        "SELECT cm1.conversation_id FROM conversation_members cm1
         INNER JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
         INNER JOIN conversations c ON c.id = cm1.conversation_id
         WHERE cm1.public_key = ? AND cm2.public_key = ? AND c.conv_type = 'dm'",
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for conv_id in convs {
        let member_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ?",
        )
        .bind(&conv_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if member_count == 2 {
            let conv = sqlx::query_as::<_, ConvRow>(
                "SELECT id, conv_type, created_at FROM conversations WHERE id = ?",
            )
            .bind(&conv_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            return Ok(Some(ConversationResponse {
                id: conv.id,
                conv_type: conv.conv_type,
                members: vec![user_a.to_string(), user_b.to_string()],
                created_at: conv.created_at,
                last_activity_at: conv.created_at,
            }));
        }
    }

    Ok(None)
}

#[derive(sqlx::FromRow)]
struct ConvRow {
    id: String,
    conv_type: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DmMessageRow {
    id: String,
    conversation_id: String,
    sender: String,
    sender_name: Option<String>,
    content: Option<String>,
    attachments: Option<String>,
    created_at: i64,
    is_encrypted: i64,
    ciphertext_json: Option<String>,
    /// 0 or 1 from SQLite EXISTS — there's no native bool, so we cast at
    /// the boundary in list_dm_messages.
    delivery_failed: i64,
}
