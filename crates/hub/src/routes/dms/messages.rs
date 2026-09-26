use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::{AuthUser, PeerHub};
use crate::routes::dm_models::*;
use crate::state::{AppState, DmEvent};

use super::keys::{
    bind_cert_master, group_envelope_signing_bytes, verify_envelope_sender, verify_tiered_signature,
};
use super::models::{ensure_user_stub, load_members, parse_dm_attachments, DmMessageRow};

pub async fn send_dm(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Json(req): Json<SendDmRequest>,
) -> Result<(StatusCode, Json<DmMessageResponse>), (StatusCode, String)> {
    let members = load_members(&state, &conversation_id).await?;
    if !members.iter().any(|m| m.public_key == user.public_key) {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    // Federated-ban check: a federally banned user must not be able to send DMs
    // even when they hold an active session token obtained before the ban.
    if crate::routes::moderation::is_federated_banned(&state.db, &user.public_key).await? {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    // 30 messages per 60 seconds per user
    {
        let mut map = state
            .rate_limiters
            .messages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let entry = map.entry(user.public_key.clone()).or_insert((0, now));
        if now.duration_since(entry.1) > std::time::Duration::from_secs(60) {
            *entry = (0, now);
        }
        if entry.0 >= 30 {
            return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()));
        }
        entry.0 += 1;
    }

    // Block check: if any recipient has blocked the sender, return a success-shaped
    // response (200 OK with a placeholder) so the sender cannot detect the block.
    for m in &members {
        if m.public_key == user.public_key {
            continue;
        }
        if crate::routes::identity::is_dm_blocked(&state.db, &m.public_key, &user.public_key).await
        {
            // Return success-shaped 200; nothing is stored or broadcast.
            let now = crate::auth::handlers::unix_timestamp();
            return Ok((
                StatusCode::CREATED,
                Json(DmMessageResponse {
                    id: uuid::Uuid::new_v4().to_string(),
                    conversation_id,
                    sender: user.public_key,
                    sender_name: None,
                    content: req.content,
                    created_at: now,
                    attachments: req.attachments,
                    delivery_failed: false,
                    is_encrypted: false,
                    encrypted_envelope: None,
                    group_encrypted_envelope: None,
                }),
            ));
        }
    }

    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = $1")
        .bind(&conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    // Validate: exactly one of content, encrypted_envelope, or group_encrypted_envelope
    // must be provided.
    let present = [
        req.content.is_some(),
        req.encrypted_envelope.is_some(),
        req.group_encrypted_envelope.is_some(),
    ]
    .iter()
    .filter(|&&v| v)
    .count();
    if present == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "One of content, encrypted_envelope, or group_encrypted_envelope is required"
                .to_string(),
        ));
    }
    if present > 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Provide exactly one of content, encrypted_envelope, or group_encrypted_envelope"
                .to_string(),
        ));
    }

    let is_encrypted = req.encrypted_envelope.is_some();
    let is_group_encrypted = req.group_encrypted_envelope.is_some();

    if is_encrypted && conv_type != "dm" {
        return Err((
            StatusCode::BAD_REQUEST,
            "E2E encryption is only supported for 1:1 DMs".to_string(),
        ));
    }
    if is_group_encrypted && conv_type != "group" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Group E2E encryption is only supported for group conversations".to_string(),
        ));
    }

    // Same per-message attachment cap as channel messages.
    // Operator-configurable since 2026-08-21 (hub_settings
    // `max_attachment_bytes`); the old constant is now only the default.
    let cap = crate::routes::hub::read_attachment_cap(&state.db).await;
    let attach_total: u64 = req
        .attachments
        .iter()
        .map(|a| a.data_b64.len() as u64)
        .sum();
    if attach_total > cap {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("Attachments exceed {}MB cap", cap / 1024 / 1024),
        ));
    }

    if is_encrypted {
        let env = req.encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "encrypted_envelope missing".to_string(),
        ))?;

        // Tiered signature verification (docs/docs/decisions.md
        // "Paired-device DMs attribute to canonical via cert-chained
        // envelopes"): no signer_cert verifies the signature against the
        // authenticated canonical identity directly (today's behavior,
        // unchanged); a signer_cert verifies against the cert's subkey and
        // returns the cert's master for the binding check below.
        let cert_master = verify_envelope_sender(env, &user.public_key)?;
        bind_cert_master(cert_master, &user)?;
        // The envelope always claims the canonical pubkey as sender —
        // whether signed directly (no cert) or via a paired device's
        // subkey (cert present) — never the authenticated session's own
        // auth pubkey when that differs (a paired device's session is
        // already resolved to canonical by `resolve_canonical_identity`,
        // so `user.public_key` below IS canonical).
        if env.sender_pubkey != user.public_key {
            return Err((
                StatusCode::BAD_REQUEST,
                "encrypted_envelope.sender_pubkey must match the authenticated identity"
                    .to_string(),
            ));
        }
    }

    if is_group_encrypted {
        let env = req.group_encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "group_encrypted_envelope missing".to_string(),
        ))?;
        let msg = group_envelope_signing_bytes(
            &env.conv_id,
            env.sender_key_version,
            env.iteration,
            &env.ciphertext_hex,
            &env.nonce_hex,
        );
        // Tiered, for the same reason the 1:1 envelope above is: a paired
        // device holds its subkey and a cert, never the canonical signing key.
        let cert_master = verify_tiered_signature(
            &msg,
            &env.signature_hex,
            env.signer_cert.as_ref(),
            &user.public_key,
            "group envelope",
        )?;
        bind_cert_master(cert_master, &user)?;

        if env.sender_pubkey != user.public_key {
            return Err((
                StatusCode::BAD_REQUEST,
                "group_encrypted_envelope.sender_pubkey must match the authenticated identity"
                    .to_string(),
            ));
        }
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
        let env = req.encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "encrypted_envelope missing".to_string(),
        ))?;
        let ciphertext_json = serde_json::to_string(env).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Encode envelope: {e}"),
            )
        })?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, NULL, $4, NULL, $5, TRUE, $6, FALSE)",
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
    } else if is_group_encrypted {
        let env = req.group_encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "group_encrypted_envelope missing".to_string(),
        ))?;
        let ciphertext_json = serde_json::to_string(env).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Encode group envelope: {e}"),
            )
        })?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, NULL, $4, NULL, $5, FALSE, $6, TRUE)",
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

        // If the client supplied a plaintext signature, verify it now (before
        // storage) so we don't persist a message with a bad signature that would
        // be rejected by receiving hubs during federation.
        let plaintext_sig_hex: Option<String> = if let Some(ref sig_hex) = req.plaintext_signature {
            let signing_bytes = wavvon_identity::federated_plaintext_dm_signing_bytes(
                &conversation_id,
                &conv_type,
                content,
            );
            let sig_bytes = hex::decode(sig_hex).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Bad plaintext_signature hex: {e}"),
                )
            })?;
            wavvon_identity::verify_signature(&user.public_key, &signing_bytes, &sig_bytes)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid plaintext_signature: {e}"),
                    )
                })?;
            Some(sig_hex.clone())
        } else {
            None
        };

        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NULL, FALSE)",
        )
        .bind(&message_id)
        .bind(&conversation_id)
        .bind(&user.public_key)
        .bind(content)
        .bind(&attachments_json)
        .bind(&plaintext_sig_hex)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Broadcast to local WS subscribers (other members on this same hub).
    let sender_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    // For encrypted messages, broadcast a placeholder so WS subscribers get
    // notified and know to re-fetch the full envelope via the HTTP API.
    let ws_content = if is_encrypted || is_group_encrypted {
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
            // Step 1: look up master_pubkey for this member. Same resolver the
            // mirror path uses — reading only `users.master_pubkey` here meant
            // a member whose cert was registered without a re-auth got mirrored
            // to but never fanned out to.
            let master_pubkey: Option<String> = master_of(&state, &m.public_key).await;

            // Step 2: if a master is known, try the designation table.
            let designation_urls: Option<Vec<String>> = if let Some(ref mpk) = master_pubkey {
                let hubs_json: Option<String> = sqlx::query_scalar(
                    "SELECT hubs_json FROM home_hub_designations WHERE master_pubkey = $1",
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
            // Forward the sender's plaintext signature so receiving hubs can
            // verify it against the `sender` pubkey.  Encrypted-envelope DMs
            // carry their own per-envelope signature and don't need this field.
            signature: req.plaintext_signature.clone(),
            created_at: now,
            encrypted_envelope: req.encrypted_envelope.clone(),
            group_encrypted_envelope: req.group_encrypted_envelope.clone(),
            sender_hub_url: None,
            // Forward the cert-chained attribution proof (if any) so a
            // federated hub can verify a paired-device sender without a
            // session — see dm_models.rs::FederatedDmRequest::signer_cert.
            signer_cert: req
                .encrypted_envelope
                .as_ref()
                .and_then(|e| e.signer_cert.clone()),
            // The sender's own delivery, whoever it reaches.
            mirror: false,
        };

        for hub_url in &delivery_urls {
            // Persist the outbox entry before spawning so the message is not
            // lost if the process restarts between the spawn and the delivery.
            sqlx::query(
                "INSERT INTO dm_outbox
                 (message_id, recipient_hub_url, attempts, next_attempt_at)
                 VALUES ($1, $2, 0, $3) ON CONFLICT (message_id, recipient_hub_url) DO NOTHING",
            )
            .bind(&message_id)
            .bind(hub_url)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            // Deliver in background so slow or unreachable peers do not stall
            // the response to the sender. The outbox entry above is the
            // durability guarantee; the retry worker will pick it up on failure.
            let bg_state = state.clone();
            let bg_url = hub_url.clone();
            let bg_env = envelope.clone();
            let bg_msg_id = message_id.clone();
            tokio::spawn(async move {
                match deliver_federated_dm(&bg_state, &bg_url, &bg_env).await {
                    Ok(()) => {
                        let _ = sqlx::query(
                            "DELETE FROM dm_outbox WHERE message_id = $1 AND recipient_hub_url = $2",
                        )
                        .bind(&bg_msg_id)
                        .bind(&bg_url)
                        .execute(&bg_state.db)
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "DM {} to {} failed immediately, leaving in outbox for retry: {e}",
                            &bg_msg_id[..8],
                            bg_url
                        );
                        let _ = sqlx::query(
                            "UPDATE dm_outbox SET attempts = 1, next_attempt_at = $1, last_error = $2
                             WHERE message_id = $3 AND recipient_hub_url = $4",
                        )
                        .bind(now + 10)
                        .bind(&e)
                        .bind(&bg_msg_id)
                        .bind(&bg_url)
                        .execute(&bg_state.db)
                        .await;
                    }
                }
            });
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
            group_encrypted_envelope: req.group_encrypted_envelope,
        }),
    ))
}

pub async fn list_dm_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Query(params): Query<crate::routes::chat_models::PaginationParams>,
) -> Result<Json<Vec<DmMessageResponse>>, (StatusCode, String)> {
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = $1 AND public_key = $2",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if is_member == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    // Same `before` + `limit` keyset the channel message list uses. Both
    // clients have been sending these two params all along; until 2026-08-08
    // this handler took no query params at all and returned the entire
    // conversation history on every open.
    let limit = params.limit.unwrap_or(50).clamp(1, 100);

    // Newest `limit` rows (optionally older than the cursor), then flipped
    // back to ascending — the clients render oldest-first and prepend when
    // paging backwards.
    let mut rows = sqlx::query_as::<_, DmMessageRow>(
        "SELECT m.id, m.conversation_id, m.sender, u.display_name as sender_name,
                m.content, m.attachments, m.created_at,
                COALESCE(m.is_encrypted, FALSE) AS is_encrypted,
                m.ciphertext_json,
                COALESCE(m.is_group_encrypted, FALSE) AS is_group_encrypted,
                EXISTS (
                    SELECT 1 FROM dm_outbox o
                    WHERE o.message_id = m.id AND o.bounced_at IS NOT NULL
                ) AS delivery_failed
         FROM dm_messages m
         LEFT JOIN users u ON u.public_key = m.sender
         WHERE m.conversation_id = $1
           AND ($2::text IS NULL OR (m.created_at, m.id) <
                ((SELECT created_at FROM dm_messages WHERE id = $2), $2))
         ORDER BY m.created_at DESC, m.id DESC
         LIMIT $3",
    )
    .bind(&conversation_id)
    .bind(params.before.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    rows.reverse();

    let mut responses = Vec::with_capacity(rows.len());
    for r in rows {
        let is_enc = r.is_encrypted;
        let is_group_enc = r.is_group_encrypted;
        let encrypted_envelope = if is_enc {
            r.ciphertext_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<EncryptedDmEnvelope>(s).ok())
        } else {
            None
        };
        let group_encrypted_envelope = if is_group_enc {
            r.ciphertext_json
                .as_deref()
                .and_then(|s| serde_json::from_str::<GroupEncryptedEnvelope>(s).ok())
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
            delivery_failed: r.delivery_failed,
            is_encrypted: is_enc,
            encrypted_envelope,
            group_encrypted_envelope,
        });
    }

    Ok(Json(responses))
}

/// Hub-to-hub DM delivery endpoint.
///
/// Two-layer verification:
/// 1. `PeerHub` extractor (defense-in-depth): requires the bearer token to
///    belong to a key in the `peers` table.  This filters out most unauthorized
///    callers but is NOT the security boundary for sender-identity claims,
///    because `peers` rows can be inserted via the self-asserted `is_hub=true`
///    path in `/auth/verify`.
/// 2. Sender signature (the real boundary): for plaintext DMs, `req.signature`
///    must be a valid Ed25519 signature by `req.sender` over the canonical
///    signing bytes for the message.  An attacker who sets `sender=victim` but
///    does not hold victim's private key cannot produce a valid signature and
///    will be rejected with 401.  Encrypted-envelope DMs are authenticated by
///    their own per-envelope signatures (already verified here).
pub async fn receive_federated_dm(
    State(state): State<Arc<AppState>>,
    _peer: PeerHub,
    Json(req): Json<FederatedDmRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // Idempotent: if we've already stored this message, succeed without double-broadcast.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM dm_messages WHERE id = $1")
        .bind(&req.message_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_some() {
        return Ok(StatusCode::OK);
    }

    // Block check for federated inbound DM: if any local recipient has blocked the sender,
    // return 200 (success-shaped) so the sending hub cannot detect the block.
    for member_key in &req.members {
        if member_key == &req.sender {
            continue;
        }
        if crate::routes::identity::is_dm_blocked(&state.db, member_key, &req.sender).await {
            return Ok(StatusCode::OK);
        }
    }

    // Auto-create the conversation on this hub if this is the first time we've seen it.
    let conv_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM conversations WHERE id = $1")
            .bind(&req.conversation_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if conv_exists.is_none() {
        // Federated delivery is at-least-once (the sender retries on failure),
        // so creation must be idempotent — a concurrent or repeated delivery
        // of the same conversation is a no-op, not an error.
        sqlx::query(
            "INSERT INTO conversations (id, conv_type, created_at) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&req.conversation_id)
        .bind(&req.conv_type)
        .bind(req.created_at)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        for member in &req.members {
            ensure_user_stub(&state.db, member, req.created_at).await?;
            sqlx::query(
                "INSERT INTO conversation_members
                 (conversation_id, public_key, joined_at, hub_url) VALUES ($1, $2, $3, NULL)
                 ON CONFLICT (conversation_id, public_key) DO NOTHING",
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
    let is_group_encrypted = req.group_encrypted_envelope.is_some();

    if is_encrypted {
        let env = req.encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "encrypted_envelope missing".to_string(),
        ))?;

        // Tiered verification, mirroring send_dm (docs/docs/decisions.md
        // "Paired-device DMs attribute to canonical via cert-chained
        // envelopes"). No signer_cert verifies against `req.sender`
        // directly — today's behavior, unchanged.
        let cert_master = verify_envelope_sender(env, &req.sender)?;
        // Prefer the per-envelope cert; fall back to the top-level
        // forwarded cert for a peer that only set that one.
        let master_opt =
            cert_master.or_else(|| req.signer_cert.as_ref().map(|c| c.master_pubkey.clone()));
        if let Some(master) = master_opt {
            let bound =
                resolve_master_binding(&state, &req.sender, &master, req.sender_hub_url.as_deref())
                    .await?;
            if !bound {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "signer_cert master is not bound to sender".to_string(),
                ));
            }
        }

        let ciphertext_json = serde_json::to_string(env)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, NULL, $4, $5, $6, TRUE, $7, FALSE)
             ON CONFLICT (id) DO NOTHING",
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
    } else if is_group_encrypted {
        let env = req.group_encrypted_envelope.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            "group_encrypted_envelope missing".to_string(),
        ))?;
        let msg = group_envelope_signing_bytes(
            &env.conv_id,
            env.sender_key_version,
            env.iteration,
            &env.ciphertext_hex,
            &env.nonce_hex,
        );
        let sig_bytes = hex::decode(&env.signature_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Bad group envelope signature hex: {e}"),
            )
        })?;
        wavvon_identity::verify_signature(&req.sender, &msg, &sig_bytes).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid group envelope signature: {e}"),
            )
        })?;

        let ciphertext_json = serde_json::to_string(env)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?;
        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, NULL, $4, $5, $6, FALSE, $7, TRUE)
             ON CONFLICT (id) DO NOTHING",
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

        // Require the sender to have signed the plaintext payload.
        // This is the cryptographic proof that the `sender` field is authentic:
        // an attacker setting sender=victim cannot produce victim's signature.
        // This check holds regardless of how the caller passed the PeerHub
        // extractor (including via the self-asserted is_hub=true path).
        let sig_hex = req.signature.as_deref().ok_or((
            StatusCode::BAD_REQUEST,
            "plaintext federated DM requires a sender signature".to_string(),
        ))?;
        let signing_bytes = wavvon_identity::federated_plaintext_dm_signing_bytes(
            &req.conversation_id,
            &req.conv_type,
            content,
        );
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Bad signature hex: {e}")))?;
        wavvon_identity::verify_signature(&req.sender, &signing_bytes, &sig_bytes).map_err(
            |e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("Sender signature verification failed: {e}"),
                )
            },
        )?;

        sqlx::query(
            "INSERT INTO dm_messages (id, conversation_id, sender, content, attachments, signature, created_at, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NULL, FALSE)
             ON CONFLICT (id) DO NOTHING",
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
    let sender_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
            .bind(&req.sender)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let ws_content = if is_encrypted || is_group_encrypted {
        "[encrypted]".to_string()
    } else {
        req.content.clone().unwrap_or_default()
    };

    let _ = state.dm_tx.send(DmEvent::Message {
        conversation_id: req.conversation_id.clone(),
        sender: req.sender.clone(),
        sender_name,
        content: ws_content,
        timestamp: req.created_at.max(now),
    });

    // Step 2 of home-hub.md "DM delivery": this hub accepted the message, and
    // the recipient's *other* home hubs have to end up with it too, or a
    // client reading a different slot sees nothing. A copy is never copied
    // again — see FederatedDmRequest::mirror.
    if !req.mirror {
        queue_home_hub_mirrors(&state, &req, now).await;
    }

    Ok(StatusCode::OK)
}

/// Queue an inbox copy of `req` to every other home hub of every local
/// recipient.
///
/// Queued rather than sent: the outbox already has backoff, bounce and restart
/// survival, and "as soon as they're reachable" is the specified behaviour —
/// a peer that is down when the message lands still has to converge.
///
/// Best-effort by design. Failing to mirror must not fail the delivery that
/// already succeeded: the message is stored and the local recipient has it.
/// The master identity a roster pubkey belongs to, or `None` when this hub
/// cannot tell.
///
/// A home hub list is signed by, and stored under, the **master** key — which
/// is derived from the identity seed and is not the pubkey the roster knows
/// anyone by. The hub learns the link from a device cert: at auth
/// (`resolve_canonical_identity` writes `users.master_pubkey`) or when one is
/// registered. An identity that has never presented a cert — a single device
/// whose owner never named it — has no link here, and so no home hub list this
/// hub can find. That is a limit of what the hub knows, not of the mirroring:
/// it is the same condition under which a *sender's* hub declines to fan out.
async fn master_of(state: &AppState, member: &str) -> Option<String> {
    let from_users: Option<String> =
        sqlx::query_scalar("SELECT master_pubkey FROM users WHERE public_key = $1")
            .bind(member)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if from_users.is_some() {
        return from_users;
    }
    // A cert registered without an auth that carried it still names the master.
    sqlx::query_scalar("SELECT master_pubkey FROM subkey_certs WHERE subkey_pubkey = $1")
        .bind(member)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

async fn queue_home_hub_mirrors(state: &AppState, req: &FederatedDmRequest, now: i64) {
    let own_url = state
        .canonical_url
        .read()
        .await
        .clone()
        .map(|u| u.trim_end_matches('/').to_string());

    let mut targets: Vec<String> = Vec::new();
    for member in &req.members {
        if member == &req.sender {
            continue;
        }
        let Some(master) = master_of(state, member).await else {
            continue;
        };

        let hubs_json: Option<String> = sqlx::query_scalar(
            "SELECT hubs_json FROM home_hub_designations WHERE master_pubkey = $1",
        )
        .bind(&master)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let Some(hubs) = hubs_json.and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
        else {
            continue;
        };

        for hub in hubs {
            let hub = hub.trim_end_matches('/').to_string();
            if hub.is_empty() || Some(&hub) == own_url.as_ref() || targets.contains(&hub) {
                continue;
            }
            targets.push(hub);
        }
    }

    for hub_url in targets {
        // ON CONFLICT DO NOTHING: the sender may already have delivered here
        // (it fans out to the whole list when it knows it), and a second
        // arrival is a no-op anyway.
        let queued = sqlx::query(
            "INSERT INTO dm_outbox
             (message_id, recipient_hub_url, attempts, next_attempt_at, mirror)
             VALUES ($1, $2, 0, $3, TRUE)
             ON CONFLICT (message_id, recipient_hub_url) DO NOTHING",
        )
        .bind(&req.message_id)
        .bind(&hub_url)
        .bind(now)
        .execute(&state.db)
        .await;
        if let Err(e) = queued {
            tracing::warn!("DM mirror to {hub_url} could not be queued: {e}");
        }
    }
}

/// Resolve whether `master` (a `signer_cert.master_pubkey` carried on an
/// incoming federated DM) is bound to `canonical` (`req.sender`) — i.e.
/// that the master genuinely certified `canonical` as one of its own
/// subkeys, not just the subkey that signed this particular envelope
/// (docs/docs/decisions.md "Paired-device DMs attribute to canonical via
/// cert-chained envelopes", binding tier (c)).
///
/// Tries the local `users` row first (covers senders this hub already
/// knows about — including the origin hub, where `resolve_canonical_identity`
/// populated it at auth time). Falls back to fetching the sender's device
/// registry from `sender_hub_url` and checking for a self-cert
/// (`subkey_pubkey == canonical`, signed by `master`), caching the result
/// on success so future messages from the same sender skip the network
/// round-trip.
async fn resolve_master_binding(
    state: &AppState,
    canonical: &str,
    master: &str,
    sender_hub_url: Option<&str>,
) -> Result<bool, (StatusCode, String)> {
    let local_master: Option<String> =
        sqlx::query_scalar("SELECT master_pubkey FROM users WHERE public_key = $1")
            .bind(canonical)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    if let Some(m) = local_master {
        return Ok(m == master);
    }

    let Some(hub_url) = sender_hub_url else {
        return Ok(false);
    };

    let Ok(resp) = state
        .http_client
        .get(format!("{hub_url}/identity/{master}/devices"))
        .send()
        .await
    else {
        return Ok(false);
    };

    let Ok(certs) = resp.json::<Vec<wavvon_identity::SubkeyCert>>().await else {
        return Ok(false);
    };

    let proven = certs
        .iter()
        .any(|c| c.subkey_pubkey == canonical && c.master_pubkey == master && c.verify().is_ok());

    if proven {
        // Best-effort cache; COALESCE preserves whatever a concurrent auth
        // may have already recorded rather than racing it.
        let _ = sqlx::query(
            "UPDATE users SET master_pubkey = COALESCE(master_pubkey, $1) WHERE public_key = $2",
        )
        .bind(master)
        .bind(canonical)
        .execute(&state.db)
        .await;
    }

    Ok(proven)
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
            sqlx::query_scalar("SELECT public_key FROM peers WHERE url = $1")
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
                "INSERT INTO peers (public_key, name, url, added_at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT(public_key) DO UPDATE SET name = $5, url = $6",
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
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("remote hub returned {status}: {body}"));
    }
    Ok(())
}
