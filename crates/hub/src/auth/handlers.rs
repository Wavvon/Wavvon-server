use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use sqlx::PgPool;
use wavvon_identity::SubkeyCert;

use crate::auth::models::{ChallengeRequest, ChallengeResponse, VerifyRequest, VerifyResponse};
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

    // Voice in alliance channels (alliances.md): a member of an allied hub
    // redeeming a grant to join one of our shared voice rooms.
    //
    // Handled here, before every gate below it, because a visitor is not a
    // member and none of those gates are about them: no invite, no PoW, no
    // cert admission, no approval queue, no roles, and above all **no `users`
    // row**. Falling through would either create one or refuse them.
    //
    // Skipped entirely if they already have a row here. A member holds a
    // strictly better session than a visitor one, and silently downgrading
    // someone to a voice-only scope because their client sent a grant would be
    // a confusing way to lose your own hub.
    if let Some(grant) = req.alliance_voice_grant.as_ref() {
        let already_member: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM users WHERE public_key = $1")
                .bind(&canonical_pubkey)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if already_member.is_none() {
            let visitor =
                crate::routes::alliances::verify_grant(&state, grant, &canonical_pubkey).await?;
            // The visit row *is* the session — `sessions.public_key` references
            // `users`, and a visitor has no user row, so there is nothing to
            // insert there. The token and its expiry live on the visit.
            let token =
                crate::routes::alliances::record_visit(&state, &canonical_pubkey, &visitor).await?;

            tracing::info!(
                subject = %canonical_pubkey,
                origin = %visitor.origin_hub_pubkey,
                channel = %visitor.channel_id,
                "Admitted alliance voice visitor"
            );

            return Ok(Json(VerifyResponse {
                token,
                scope: "alliance_voice".to_string(),
                canonical_pubkey,
            }));
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
    // see bootstrap.rs presets::gaming and lobby-survey.md Feature 1).
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

    // Check security level requirement (lobby-survey.md Feature 1).
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

        // One predicate, applied to pushed and pulled certs alike. It used to
        // be re-implemented inline here, beside the copy in certs.rs — two
        // admission rules that had to be kept in step by hand.
        let mut satisfied = false;
        for cert in req.certifications.as_deref().unwrap_or(&[]) {
            if crate::routes::certs::verify_certification(
                &state,
                cert,
                &master_pk,
                &cert_mode,
                &trusted_issuers,
                &cert_require,
            )
            .await
            {
                satisfied = true;
                break;
            }
        }

        // Nothing presented, or nothing presented that passes: fetch the
        // candidate's portfolio from the issuers we trust and try again
        // (hub-certifications.md §11). This is the path that makes the feature
        // work at all — no client sends the `certifications` array, so before
        // it a hub with `cert_mode != none` refused everyone with
        // `cert_required`. Costs at most a handful of short, cached, usually
        // loopback requests, and only on the miss.
        if !satisfied {
            for cert in
                crate::routes::certs::pull_portfolios(&state, &trusted_issuers, &master_pk).await
            {
                if crate::routes::certs::verify_certification(
                    &state,
                    &cert,
                    &master_pk,
                    &cert_mode,
                    &trusted_issuers,
                    &cert_require,
                )
                .await
                {
                    satisfied = true;
                    break;
                }
            }
        }

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

    // Record the device alongside the user row, now that every gate above has
    // passed. `users.master_pubkey` is the link a home-hub lookup follows, but
    // the Devices screen lists `subkey_certs`, so writing one without the other
    // left a device linked to its master and absent from its owner's own list.
    //
    // Here rather than in `resolve_canonical_identity`, which runs before the
    // ban, invite and PoW gates: a rejected sign-in must not leave a row
    // behind. Best-effort — a registry write must not fail a sign-in that has
    // otherwise succeeded.
    if let Some(cert) = req.subkey_cert.as_ref() {
        if let Err(e) = crate::routes::identity::upsert_subkey_cert(&state.db, cert).await {
            tracing::warn!("could not record device cert at auth: {e}");
        }
    }

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

    // Compute session scope (lobby-survey.md Feature 1): a session is
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

    sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at, scope) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&token)
    .bind(&canonical_pubkey)
    .bind(now)
    .bind(Option::<i64>::None)
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

    // One admission gate, and a program goes through it: a client running
    // unattended presents an invite code like anybody else. The second gate
    // that used to stand beside this one — a pubkey the admin had pre-seeded
    // with `is_bot = TRUE` — is gone with the flag, and with it the hole
    // where a stranger's pubkey could be flagged before its owner ever
    // arrived (decisions.md, "A bot is a client like any other").
    //
    // A federating peer hub (is_hub=true) stays exempt, and that exemption is
    // a different thing: it is not a person joining this community. It
    // authenticates to deliver federation traffic, receives no human roles, and
    // its token is tagged so `PeerHub` can tell it apart. An invite code is a
    // thing a community gives a person; there is nobody here to give one to.
    //
    // Without this, two hubs with default settings could never form an
    // alliance at all -- a fresh hub is invite_only, so hub B's federation
    // client got "This hub requires an invite code" from hub A and the join
    // failed with a 502 that blamed the network. Invisible to the integration
    // suite, which builds `AppState` directly and never writes the
    // `invite_only` setting, so `is_invite_only` answered false there. Found
    // by driving two real hub binaries (e2e-topology).
    if has_roles == 0 && req.is_hub != Some(true) {
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

    // Admission challenge gate: if challenge_mode != 'off', require a valid token.
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
    // separately from member sessions.  We still complete the full
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
    /// Session scope: `"member"`, `"mini_app"` or `"alliance_voice"`; a
    /// legacy row reads as `"member"`. Never `"lobby"` — that scope is
    /// rejected before this is constructed.
    pub scope: String,
    /// Set only when `scope == "mini_app"`: the single channel this
    /// mini-app session (mini-apps.md "Scoped session token") is bound
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
///   3. `approval_status` gate
///   4. Local ban check (bans table)
///   5. Lobby scope gate: a lobby-scoped session (lobby-survey.md
///      Feature 1) cannot open a WebSocket at all — channel messaging,
///      presence, and voice signaling all ride the WS connection, and none
///      of that is on the lobby allowlist. WS push for lobby promotion is
///      deferred (v1 polls `/lobby/status`), so there is nothing a lobby
///      session legitimately needs a WS for yet.
///
/// A `mini_app`-scoped session (mini-apps.md) is allowed through — the
/// mini-app webview's whole purpose is to talk over `/ws` — but callers
/// must consult `WsAuth::mini_app_channel_id` to confine what it can see.
pub async fn validate_ws_token(
    state: &crate::state::AppState,
    token: &str,
) -> Result<WsAuth, (axum::http::StatusCode, String)> {
    let db = &state.db;
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
            // A `bot_tokens` lookup used to sit here, ahead of the farm
            // branch. It is gone: nothing ever wrote that table, and a
            // program arrives on the session path above like every other
            // identity (decisions.md, "A bot is a client like any other").
            //
            // Farm-issued token, verified against the farm pubkey exactly
            // as the HTTP path does — one function, so the two cannot
            // drift. This branch was missing entirely: on a farm-managed
            // hub the client authenticates at the farm, so *every* socket
            // it opened was refused while its HTTP calls worked. No
            // messages, no presence, no voice signalling, and no error
            // anywhere except a socket that never connected.
            if let Some((visitor_pk, _channel)) =
                crate::routes::alliances::resolve_visitor_token(db, token).await
            {
                // An alliance-voice visitor (alliances.md). The socket is the
                // only thing they are really here for — `voice_join`, the E2E
                // key offer, the speaking flag — and `dispatch_client_msg`
                // confines it to exactly that set.
                (
                    visitor_pk,
                    "approved".to_string(),
                    "alliance_voice".to_string(),
                    None,
                )
            } else if token.contains('.') {
                let pk = crate::auth::middleware::resolve_farm_token(state, token).await?;
                let status: Option<String> =
                    sqlx::query_scalar("SELECT approval_status FROM users WHERE public_key = $1")
                        .bind(&pk)
                        .fetch_optional(db)
                        .await
                        .map_err(|e| {
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                        })?;
                (
                    pk,
                    status.unwrap_or_else(|| "approved".to_string()),
                    "member".to_string(),
                    None,
                )
            } else {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Invalid or expired token".to_string(),
                ));
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

    // Approval gate. A visitor never reaches this as "pending": they have no
    // `users` row, so nothing about them is awaiting approval.
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
