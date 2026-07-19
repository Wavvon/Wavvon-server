use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use sqlx::PgPool;
use wavvon_identity::SubkeyCert;

use crate::auth::middleware::AuthUser;
use crate::auth::models::{
    ChallengeRequest, ChallengeResponse, RenewResponse, VerifyRequest, VerifyResponse,
};
use crate::state::{AppState, PendingChallenge};

/// Map an authenticating (subkey, optional cert) pair to a stable
/// canonical user identity. Returns (canonical_pubkey, master_pubkey).
///
/// - No cert: legacy single-key auth. Canonical = the auth pubkey.
///   No master is recorded.
/// - Cert + matching master already in users.master_pubkey: resolves
///   to that user's canonical pubkey. This is the "second paired
///   device finds existing user" case.
/// - Cert + the auth pubkey already exists as a legacy user
///   (master_pubkey IS NULL): treated as the legacy-user upgrade
///   path — canonical stays the legacy pubkey so existing roles and
///   memberships carry over, but the cert's master will be recorded.
/// - Cert + neither: brand-new paired device. Canonical = the
///   master pubkey.
pub async fn resolve_canonical_identity(
    db: &PgPool,
    auth_pubkey: &str,
    cert: Option<&SubkeyCert>,
) -> Result<(String, Option<String>), (StatusCode, String)> {
    let cert = match cert {
        None => return Ok((auth_pubkey.to_string(), None)),
        Some(c) => c,
    };

    cert.verify()
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid cert: {e}")))?;
    if cert.subkey_pubkey != auth_pubkey {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Cert subkey_pubkey doesn't match auth pubkey".to_string(),
        ));
    }
    let master = cert.master_pubkey.clone();

    // Existing multi-device user?
    if let Some(canonical) =
        sqlx::query_scalar::<_, String>("SELECT public_key FROM users WHERE master_pubkey = $1")
            .bind(&master)
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    {
        return Ok((canonical, Some(master)));
    }

    // Legacy user upgrading? (the auth subkey is the legacy pubkey)
    let legacy_exists: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE public_key = $1 AND master_pubkey IS NULL",
    )
    .bind(auth_pubkey)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if let Some(canonical) = legacy_exists {
        return Ok((canonical, Some(master)));
    }

    // Brand-new paired device.
    Ok((master.clone(), Some(master)))
}

pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>), (StatusCode, String)> {
    let mut challenge_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge_hex = hex::encode(&challenge_bytes);

    let pending = PendingChallenge {
        public_key: req.public_key,
        challenge_bytes,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    {
        let mut map = state.pending_challenges.write().await;
        // Lazy prune so abandoned challenges don't accumulate.
        let now = Instant::now();
        map.retain(|_, p| now <= p.expires_at);
        map.insert(challenge_hex.clone(), pending);
    }

    Ok((
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge: challenge_hex,
        }),
    ))
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let pending = state
        .pending_challenges
        .write()
        .await
        .remove(&req.challenge)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "No pending challenge for this key".to_string(),
        ))?;

    if pending.public_key != req.public_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Challenge was issued to a different key".to_string(),
        ));
    }

    if Instant::now() > pending.expires_at {
        return Err((StatusCode::UNAUTHORIZED, "Challenge expired".to_string()));
    }

    let challenge_bytes = hex::decode(&req.challenge)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid challenge hex".to_string()))?;

    if challenge_bytes != pending.challenge_bytes {
        return Err((StatusCode::UNAUTHORIZED, "Challenge mismatch".to_string()));
    }

    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;

    wavvon_identity::verify_signature(&req.public_key, &challenge_bytes, &signature_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

    // Multi-device: if a cert is presented, resolve to the canonical
    // user identity (master or, for legacy upgrades, the existing
    // legacy pubkey). Without a cert, the auth pubkey IS the canonical.
    let (canonical_pubkey, master_pubkey) =
        resolve_canonical_identity(&state.db, &req.public_key, req.subkey_cert.as_ref()).await?;

    // External bot gate: when is_bot=true the hub requires a pre-existing
    // users row with approval_status='bot_pending' or 'approved'. Bots cannot
    // self-register — the invite flow creates the row first.
    if req.is_bot == Some(true) {
        let status: Option<String> = sqlx::query_scalar::<_, String>(
            "SELECT approval_status FROM users WHERE public_key = $1 AND is_bot = TRUE",
        )
        .bind(&canonical_pubkey)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        match status.as_deref() {
            None => return Err((StatusCode::FORBIDDEN, "bot_not_invited".to_string())),
            Some("bot_pending") | Some("approved") => {} // proceed
            _ => return Err((StatusCode::FORBIDDEN, "bot_not_invited".to_string())),
        }

        // Ensure is_bot flag is set (idempotent).
        sqlx::query("UPDATE users SET is_bot = TRUE WHERE public_key = $1")
            .bind(&canonical_pubkey)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        // Upsert bot_profiles from bot_meta and register commands.
        if let Some(meta) = &req.bot_meta {
            let now = unix_timestamp();
            let game_json = meta
                .game
                .as_ref()
                .map(|g| serde_json::to_string(g).unwrap_or_default());
            sqlx::query(
                "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, mini_app_url, requires_camera, game, updated_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                 ON CONFLICT(pubkey) DO UPDATE SET
                   name=excluded.name, avatar_url=excluded.avatar_url,
                   description=excluded.description, webhook_url=excluded.webhook_url,
                   homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
                   mini_app_url=excluded.mini_app_url, requires_camera=excluded.requires_camera,
                   game=excluded.game,
                   updated_at=excluded.updated_at",
            )
            .bind(&canonical_pubkey)
            .bind(&meta.name)
            .bind(&meta.avatar_url)
            .bind(&meta.description)
            .bind(&meta.webhook_url)
            .bind(&meta.homepage_url)
            .bind(serde_json::to_string(&meta.capabilities.as_deref().unwrap_or(&[])).unwrap())
            .bind(&meta.mini_app_url)
            .bind(meta.requires_camera.unwrap_or(false))
            .bind(&game_json)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            if let Some(cmds) = &meta.commands {
                sqlx::query("DELETE FROM bot_commands WHERE pubkey = $1")
                    .bind(&canonical_pubkey)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                for cmd in cmds {
                    sqlx::query(
                        "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
                         VALUES($1,$2,$3,$4,$5,$6,$7)",
                    )
                    .bind(&canonical_pubkey)
                    .bind(&cmd.name)
                    .bind(&cmd.description)
                    .bind(&cmd.args)
                    .bind(cmd.scope.as_deref().unwrap_or("channel"))
                    .bind(cmd.privileged.unwrap_or(false))
                    .bind(cmd.cooldown_seconds.unwrap_or(3))
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                }
            }

            // Flip approval_status to approved (idempotent if already approved).
            sqlx::query("UPDATE users SET approval_status = 'approved' WHERE public_key = $1")
                .bind(&canonical_pubkey)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }
    }

    // Bans follow the canonical identity — a banned user can't
    // bypass by pairing a new device.
    if crate::routes::moderation::is_banned(&state.db, &canonical_pubkey).await? {
        return Err((StatusCode::FORBIDDEN, "User is banned".to_string()));
    }

    // Federated bans: shared policy (overrides, then per-source policy) —
    // see moderation::is_denied_by_federated_policy for the rules. A DB error
    // here fails closed (500) rather than silently admitting.
    {
        let check_pubkey = master_pubkey.as_deref().unwrap_or(&canonical_pubkey);
        let denied =
            crate::routes::moderation::is_denied_by_federated_policy(&state.db, check_pubkey)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        if denied {
            return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
        }
    }

    // First-ever user on a hub is implicitly approved (they'll become
    // Owner below). Excludes the 'system' sentinel that bootstrap inserts
    // as channels' created_by — otherwise a preset-seeded hub always has
    // one "user" and the real first joiner never becomes owner (found live
    // 2026-07-06).
    let existing_users: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key <> 'system'")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // The hub owner (already holds builtin-owner) and the implicit first
    // user are never lobby-confined or hard-rejected by min_security_level
    // on their own hub. Without this, a nonzero min_security_level preset
    // locks the owner out of their own first join (found live 2026-07-06 —
    // see bootstrap.rs presets::gaming and lobby-bot-survey.md Feature 1).
    let already_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_public_key = $1 AND role_id = 'builtin-owner')",
    )
    .bind(&canonical_pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    // A federating peer hub (is_hub=true) is a machine, not a human doing
    // PoW — it must never be lobby-confined, or /federation/* calls would
    // fail opaquely against a gated hub. Exempt it like owner/first-user.
    let owner_exempt = existing_users == 0 || already_owner || req.is_hub == Some(true);

    // Check security level requirement (lobby-bot-survey.md Feature 1).
    let min_level: u32 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_security_level'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let lobby_enabled: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'lobby_enabled'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|v| v == "1")
    .unwrap_or(true);

    // Claimed level presented directly at /auth/verify (as opposed to the
    // progressive /lobby/submit-pow path). Always verified when the gate is
    // active so a forged claim can't inflate `users.pow_level` below —
    // claimed_level == 0 (the default, no proof presented) always verifies
    // trivially (see `verify_security_level`), so an absent proof is a
    // harmless no-op here.
    let mut claimed_security_level: u32 = 0;

    if min_level > 0 && !owner_exempt {
        let nonce = req.security_nonce.unwrap_or(0);
        let claimed_level = req.security_level.unwrap_or(0);

        if !wavvon_identity::verify_security_level(&req.public_key, nonce, claimed_level) {
            return Err((
                StatusCode::FORBIDDEN,
                "Invalid security level proof".to_string(),
            ));
        }

        if claimed_level < min_level && !lobby_enabled {
            // No lobby to soft-land in: keep the pre-lobby hard-reject
            // behavior. When the lobby IS enabled, admission proceeds below
            // and the session is tagged scope="lobby" instead of being
            // rejected outright — this used to hard-403 every sub-level
            // join (including the owner's) before the lobby existed.
            return Err((
                StatusCode::FORBIDDEN,
                format!("Security level {claimed_level} is below minimum {min_level}"),
            ));
        }

        claimed_security_level = claimed_level;
    }

    // Check min_pow_level requirement (structured pow_proof field).
    let min_pow_level: u8 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_pow_level'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    if min_pow_level > 0 {
        match &req.pow_proof {
            None => {
                return Err((StatusCode::FORBIDDEN, "pow_required".to_string()));
            }
            Some(proof) => {
                if proof.level < min_pow_level {
                    return Err((StatusCode::FORBIDDEN, "pow_required".to_string()));
                }
                let nonce: u64 = proof.nonce.parse().map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "Invalid pow_proof nonce".to_string(),
                    )
                })?;
                if !wavvon_identity::verify_security_level(
                    &req.public_key,
                    nonce,
                    proof.level as u32,
                ) {
                    return Err((StatusCode::FORBIDDEN, "pow_required".to_string()));
                }
            }
        }
    }

    // Check cert_mode requirement (Task #21).
    let cert_mode = crate::routes::certs::load_cert_mode(&state).await;
    if cert_mode != "none" {
        let trusted_issuers = crate::routes::certs::load_trusted_issuers(&state).await;
        let cert_require = crate::routes::certs::load_cert_require(&state).await;

        // Resolve the master pubkey: with a subkey cert it's the master, otherwise the auth pubkey.
        let master_pk = req
            .subkey_cert
            .as_ref()
            .map(|c| c.master_pubkey.clone())
            .unwrap_or_else(|| req.public_key.clone());

        let certs = req.certifications.as_deref().unwrap_or(&[]);

        let satisfied = certs.iter().any(|cert| {
            // Run sync-safe verification; async only needed for /info lookup which we skip
            // in v1 (we trust the signature; issuer /info is advisory for display/trust list).
            let payload = &cert.payload;

            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            if payload.subject_pubkey != master_pk {
                return false;
            }
            if now_ts > payload.expires_at {
                return false;
            }
            if payload.standing != "good" {
                return false;
            }

            let sig_bytes = match hex::decode(&cert.signature) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let payload_json = match serde_json::to_string(payload) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if wavvon_identity::verify_signature(
                &payload.issuer_pubkey,
                payload_json.as_bytes(),
                &sig_bytes,
            )
            .is_err()
            {
                return false;
            }

            // cert_require property rules
            if let Some(min_pow) = cert_require.min_pow_level {
                match payload.pow_level {
                    Some(lvl) if lvl >= min_pow => {}
                    _ => return false,
                }
            }
            if let Some(min_days) = cert_require.min_member_since_days {
                let required_since = now_ts - (min_days as i64) * 86400;
                if payload.member_since > required_since {
                    return false;
                }
            }

            // trust check
            match cert_mode.as_str() {
                "any" => true,
                "trusted" => trusted_issuers
                    .iter()
                    .any(|ti| ti.pubkey == payload.issuer_pubkey),
                _ => false,
            }
        });

        if !satisfied {
            return Err((StatusCode::FORBIDDEN, "cert_required".to_string()));
        }
    }

    let now = unix_timestamp();

    // Does this hub gate new members behind admin approval?
    let require_approval: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'require_approval'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|v| v == "true")
    .unwrap_or(false);

    // `existing_users` was already computed above (before the
    // security-level gate) for the owner-exemption check; reused here.
    let initial_status = if require_approval && existing_users > 0 {
        "pending"
    } else {
        "approved"
    };

    // Upsert the canonical user row. COALESCE on master_pubkey means a
    // row that already has a master keeps it — no second device with
    // a different cert can hijack an existing identity.
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status, master_pubkey)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT(public_key) DO UPDATE SET
            last_seen_at = $6,
            master_pubkey = COALESCE(users.master_pubkey, excluded.master_pubkey)",
    )
    .bind(&canonical_pubkey)
    .bind(now)
    .bind(now)
    .bind(initial_status)
    .bind(&master_pubkey)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Compute session scope (lobby-bot-survey.md Feature 1): a session is
    // "lobby"-scoped when the lobby is enabled and the user's persisted PoW
    // level is below min_security_level. The owner/first-user exemption
    // computed above means those two identities always land at "member"
    // here regardless of level. Must run after the user upsert above (needs
    // the row to exist) and before the session is created below (the scope
    // is stored on the session).
    let stored_pow_level: u32 =
        sqlx::query_scalar::<_, i64>("SELECT pow_level FROM users WHERE public_key = $1")
            .bind(&canonical_pubkey)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(0) as u32;

    let effective_pow_level = stored_pow_level.max(claimed_security_level);

    // Persist any improvement so /lobby/status and future logins see it even
    // when the higher level came directly through /auth/verify's
    // security_level/security_nonce fields rather than the progressive
    // /lobby/submit-pow path.
    if effective_pow_level > stored_pow_level {
        sqlx::query("UPDATE users SET pow_level = $1 WHERE public_key = $2")
            .bind(effective_pow_level as i64)
            .bind(&canonical_pubkey)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let scope = if owner_exempt {
        "member".to_string()
    } else if lobby_enabled && effective_pow_level < min_level {
        "lobby".to_string()
    } else {
        "member".to_string()
    };

    let token = hex::encode({
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });

    // Bot sessions carry a 30-day expiry; human sessions don't expire.
    let bot_expires_at: Option<i64> = if req.is_bot == Some(true) {
        Some(now + 30 * 24 * 3600)
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at, scope) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&token)
    .bind(&canonical_pubkey)
    .bind(now)
    .bind(bot_expires_at)
    .bind(&scope)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Check invite requirement for new users
    let has_roles: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_public_key = $1")
            .bind(&canonical_pubkey)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Role granted by a role-granting invite (task #34), if the joining
    // user presented one. Assigned alongside builtin-everyone below.
    let mut invite_grant_role_id: Option<String> = None;
    let mut invite_created_by: Option<String> = None;

    if has_roles == 0 {
        // New user — check if hub requires an invite
        if crate::routes::invites::is_invite_only(&state.db).await? {
            match &req.invite_code {
                Some(code) => {
                    let (created_by, grant_role_id) =
                        crate::routes::invites::validate_and_use_invite(&state.db, code).await?;
                    invite_created_by = Some(created_by);
                    invite_grant_role_id = grant_role_id;
                }
                None => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "This hub requires an invite code".to_string(),
                    ));
                }
            }
        }
    }

    // Assign roles for new users
    let has_roles: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_public_key = $1")
            .bind(&canonical_pubkey)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if has_roles == 0 {
        assign_initial_roles(&state.db, &canonical_pubkey, now).await?;
        if existing_users == 0 {
            sqlx::query(
                "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
                 VALUES ($1, 'builtin-owner', $2)
                 ON CONFLICT (user_public_key, role_id) DO NOTHING",
            )
            .bind(&canonical_pubkey)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }
        // Role-granting invite (task #34) — or, absent an explicit grant, the
        // hub-level `default_invite_role_id` (invite role policies) — applied
        // through the shared helper also used by the `/join/:code` redemption
        // path (its ON CONFLICT DO NOTHING covers the rare, harmless case
        // where this is also the same role granted above — e.g. the
        // first-boot owner invite grants builtin-owner to the very first
        // user, who already received it via existing_users == 0). Only
        // consulted when an invite was actually redeemed this call
        // (`invite_created_by` is `Some`) — registrations that didn't use an
        // invite at all don't pick up the default.
        if let Some(created_by) = &invite_created_by {
            crate::routes::invites::apply_invite_role_grant(
                &state.db,
                created_by,
                invite_grant_role_id.as_deref(),
                &canonical_pubkey,
                now,
            )
            .await?;
        }
    }

    // Bot challenge gate: if challenge_mode != 'off', require a valid token.
    let challenge_mode: String = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'challenge_mode'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "off".to_string());

    if challenge_mode != "off" {
        match &req.challenge_token {
            None => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Challenge token required".to_string(),
                ));
            }
            Some(ct) => {
                let ct_row: Option<(i64, i64, Option<i64>, String)> = sqlx::query_as(
                    "SELECT issued_at, expires_at, consumed_at, pubkey FROM challenge_tokens WHERE token = $1",
                )
                .bind(ct)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                match ct_row {
                    None => {
                        return Err((StatusCode::FORBIDDEN, "Invalid challenge token".to_string()))
                    }
                    Some((_issued, expires, consumed, token_pubkey)) => {
                        if consumed.is_some() {
                            return Err((
                                StatusCode::FORBIDDEN,
                                "Challenge token already used".to_string(),
                            ));
                        }
                        if now > expires {
                            return Err((
                                StatusCode::FORBIDDEN,
                                "Challenge token expired".to_string(),
                            ));
                        }
                        if token_pubkey != req.public_key {
                            return Err((
                                StatusCode::FORBIDDEN,
                                "Challenge token pubkey mismatch".to_string(),
                            ));
                        }
                        // Mark consumed
                        sqlx::query(
                            "UPDATE challenge_tokens SET consumed_at = $1 WHERE token = $2",
                        )
                        .bind(now)
                        .bind(ct)
                        .execute(&state.db)
                        .await
                        .map_err(|e| {
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                        })?;
                    }
                }
            }
        }
    }

    // Hub federation path: when is_hub=true, register the caller in the
    // `peers` table so the `PeerHub` extractor can route hub sessions
    // separately from human/bot sessions.  We still complete the full
    // human-admission flow above (users row + roles) because the hub needs
    // `send_messages` permission to proxy alliance messages.
    //
    // NOTE: this self-registration is NOT a security boundary for DM
    // injection.  Any key can self-assert is_hub=true and land in `peers`.
    // The real anti-spoofing gate is the Ed25519 sender signature checked in
    // `receive_federated_dm`, which cannot be forged without the sender's key.
    if req.is_hub == Some(true) {
        let short_name = &canonical_pubkey[..16.min(canonical_pubkey.len())];
        let _ = sqlx::query(
            "INSERT INTO peers (public_key, name, url, added_at)
             VALUES ($1, $2, '', $3)
             ON CONFLICT(public_key) DO NOTHING",
        )
        .bind(&canonical_pubkey)
        .bind(short_name)
        .bind(now)
        .execute(&state.db)
        .await;
        tracing::info!(
            "Hub authenticated: pubkey={} registered as peer",
            &canonical_pubkey[..16],
        );
    } else {
        tracing::info!(
            "User authenticated: canonical={} (cert={}, scope={})",
            &canonical_pubkey[..16],
            master_pubkey.is_some(),
            scope,
        );
    }

    Ok(Json(VerifyResponse {
        token,
        scope,
        canonical_pubkey,
    }))
}

/// Result of a successful [`validate_ws_token`] call.
pub struct WsAuth {
    pub public_key: String,
    /// Session scope: `"member"`, `"mini_app"`, or (bot tokens / legacy rows)
    /// effectively `"member"`. Never `"lobby"` — that scope is rejected
    /// before this is constructed.
    pub scope: String,
    /// Set only when `scope == "mini_app"`: the single channel this
    /// mini-app session (bot-mini-apps.md "Scoped session token") is bound
    /// to. Callers use this to confine auto-subscription/roster loading to
    /// just this channel instead of every channel the underlying user can
    /// read.
    pub mini_app_channel_id: Option<String>,
}

/// Validate a hub session token for WebSocket connections.
///
/// Mirrors the checks in the HTTP `AuthUser` extractor so the two paths
/// cannot drift:
///   1. Session lookup + expiry (same query as the HTTP path)
///   2. Subkey revocation check
///   3. `approval_status` gate (bots are always "approved")
///   4. Local ban check (bans table)
///   5. Lobby scope gate: a lobby-scoped session (lobby-bot-survey.md
///      Feature 1) cannot open a WebSocket at all — channel messaging,
///      presence, and voice signaling all ride the WS connection, and none
///      of that is on the lobby allowlist. WS push for lobby promotion is
///      deferred (v1 polls `/lobby/status`), so there is nothing a lobby
///      session legitimately needs a WS for yet.
///
/// A `mini_app`-scoped session (bot-mini-apps.md) is allowed through — the
/// mini-app webview's whole purpose is to talk over `/ws` — but callers
/// must consult `WsAuth::mini_app_channel_id` to confine what it can see.
pub async fn validate_ws_token(
    db: &PgPool,
    token: &str,
) -> Result<WsAuth, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;

    // (public_key, approval_status, expires_at, scope, mini_app_channel_id)
    type WsSessionRow = (String, String, Option<i64>, String, Option<String>);

    // Try session table first.
    let row: Option<WsSessionRow> = sqlx::query_as(
        "SELECT s.public_key, u.approval_status, s.expires_at, s.scope, s.mini_app_channel_id
         FROM sessions s
         INNER JOIN users u ON s.public_key = u.public_key
         WHERE s.token = $1",
    )
    .bind(token)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (pk, approval_status, scope, mini_app_channel_id) =
        if let Some((pk, status, expires_at, scope, mini_app_channel_id)) = row {
            if let Some(exp) = expires_at {
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if exp < now_ts {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        r#"{"error":"token_expired"}"#.to_string(),
                    ));
                }
            }
            if scope == "lobby" {
                return Err((StatusCode::FORBIDDEN, "lobby_scope_confined".to_string()));
            }
            (pk, status, scope, mini_app_channel_id)
        } else {
            // Try bot tokens.
            let bot_key: Option<String> =
                sqlx::query_scalar("SELECT public_key FROM bot_tokens WHERE token = $1")
                    .bind(token)
                    .fetch_optional(db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            match bot_key {
                Some(k) => (k, "approved".to_string(), "member".to_string(), None),
                None => {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "Invalid or expired token".to_string(),
                    ))
                }
            }
        };

    // Subkey revocation check.
    let revoked_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM subkey_revocations WHERE subkey_pubkey = $1")
            .bind(&pk)
            .fetch_one(db)
            .await
            .unwrap_or(0);
    if revoked_count > 0 {
        return Err((StatusCode::UNAUTHORIZED, "Key has been revoked".to_string()));
    }

    // Approval gate.
    if approval_status == "pending" {
        return Err((
            StatusCode::FORBIDDEN,
            "Account is pending admin approval".to_string(),
        ));
    }

    // Local ban check.
    if crate::routes::moderation::is_banned(db, &pk).await? {
        return Err((StatusCode::FORBIDDEN, "User is banned".to_string()));
    }

    Ok(WsAuth {
        public_key: pk,
        scope,
        mini_app_channel_id,
    })
}

/// Assign builtin roles to a brand-new user who has none yet.
///
/// Grants `builtin-everyone` to a new user. The caller additionally grants
/// `builtin-owner` when this is the first user on the hub.
/// Returns an error only for genuine DB failures so callers can propagate it.
pub async fn assign_initial_roles(
    db: &PgPool,
    public_key: &str,
    now: i64,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
         VALUES ($1, 'builtin-everyone', $2)
         ON CONFLICT (user_public_key, role_id) DO NOTHING",
    )
    .bind(public_key)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(())
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn unix_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Converts a Unix timestamp (seconds) to a compact ISO-8601 string
/// (`YYYY-MM-DDTHH:MM:SSZ`). Used for badge payload timestamps.
pub fn iso_from_unix(secs: i64) -> String {
    let secs = secs as u64;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let jdn = days + 2_440_588;
    let l = jdn + 68_569;
    let n = (4 * l) / 146_097;
    let l = l - (146_097 * n).div_ceil(4);
    let year_i = (4_000 * (l + 1)) / 1_461_001;
    let l = l - (1_461 * year_i) / 4 + 31;
    let month_i = (80 * l) / 2_447;
    let day = l - (2_447 * month_i) / 80;
    let l = month_i / 11;
    let month = month_i + 2 - 12 * l;
    let year = 100 * (n - 49) + year_i + l;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Returns the current UTC time as a compact ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn unix_timestamp_iso() -> String {
    iso_from_unix(unix_timestamp())
}

/// POST /auth/renew — issue a fresh 30-day session token while the current one
/// is still live. Intended for bots renewing their long-lived tokens
/// proactively. The old token is NOT invalidated — the running WS session
/// continues on it until its original expiry.
///
/// Wire shape: same challenge-response body as `/auth/verify`. The bearer
/// token in the Authorization header authenticates the current session; the
/// challenge-response proves the caller still holds the private key.
pub async fn renew(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<RenewResponse>, (StatusCode, String)> {
    // The caller must have a valid existing session (AuthUser extractor handles that).
    // Validate the new challenge-response the same way verify() does.

    let pending = state
        .pending_challenges
        .write()
        .await
        .remove(&req.challenge)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "No pending challenge for this key".to_string(),
        ))?;

    if pending.public_key != req.public_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Challenge was issued to a different key".to_string(),
        ));
    }

    if Instant::now() > pending.expires_at {
        return Err((StatusCode::UNAUTHORIZED, "Challenge expired".to_string()));
    }

    let challenge_bytes = hex::decode(&req.challenge)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid challenge hex".to_string()))?;

    if challenge_bytes != pending.challenge_bytes {
        return Err((StatusCode::UNAUTHORIZED, "Challenge mismatch".to_string()));
    }

    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;

    // The renewing pubkey must match the authenticated user's public key.
    if req.public_key != user.public_key {
        return Err((
            StatusCode::FORBIDDEN,
            "Renew pubkey does not match authenticated identity".to_string(),
        ));
    }

    wavvon_identity::verify_signature(&req.public_key, &challenge_bytes, &signature_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

    let token = hex::encode({
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });
    let now = unix_timestamp();
    let expires_at = now + 30 * 24 * 3600;

    sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&token)
    .bind(&user.public_key)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(RenewResponse { token, expires_at }))
}
