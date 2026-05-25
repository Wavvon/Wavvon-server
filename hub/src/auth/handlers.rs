use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use sqlx::SqlitePool;
use voxply_identity::SubkeyCert;

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
    db: &SqlitePool,
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
    if let Some(canonical) = sqlx::query_scalar::<_, String>(
        "SELECT public_key FROM users WHERE master_pubkey = ?",
    )
    .bind(&master)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    {
        return Ok((canonical, Some(master)));
    }

    // Legacy user upgrading? (the auth subkey is the legacy pubkey)
    let legacy_exists: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE public_key = ? AND master_pubkey IS NULL",
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
) -> (StatusCode, Json<ChallengeResponse>) {
    let mut challenge_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge_hex = hex::encode(&challenge_bytes);

    let pending = PendingChallenge {
        challenge_bytes,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    state
        .pending_challenges
        .write()
        .await
        .insert(req.public_key, pending);

    (
        StatusCode::OK,
        Json(ChallengeResponse {
            challenge: challenge_hex,
        }),
    )
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let pending = state
        .pending_challenges
        .write()
        .await
        .remove(&req.public_key)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "No pending challenge for this key".to_string(),
        ))?;

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

    voxply_identity::verify_signature(&req.public_key, &challenge_bytes, &signature_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

    // Multi-device: if a cert is presented, resolve to the canonical
    // user identity (master or, for legacy upgrades, the existing
    // legacy pubkey). Without a cert, the auth pubkey IS the canonical.
    let (canonical_pubkey, master_pubkey) =
        resolve_canonical_identity(&state.db, &req.public_key, req.subkey_cert.as_ref())
            .await?;

    // Bans follow the canonical identity — a banned user can't
    // bypass by pairing a new device.
    if crate::routes::moderation::is_banned(&state.db, &canonical_pubkey).await? {
        return Err((StatusCode::FORBIDDEN, "User is banned".to_string()));
    }

    // Check security level requirement
    let min_level: u32 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_security_level'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    if min_level > 0 {
        let nonce = req.security_nonce.unwrap_or(0);
        let claimed_level = req.security_level.unwrap_or(0);

        if claimed_level < min_level {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Security level {claimed_level} is below minimum {min_level}"),
            ));
        }

        if !voxply_identity::verify_security_level(&req.public_key, nonce, claimed_level) {
            return Err((
                StatusCode::FORBIDDEN,
                "Invalid security level proof".to_string(),
            ));
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

    // First-ever user on a hub is implicitly approved (they'll become Owner).
    let existing_users: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

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
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(public_key) DO UPDATE SET
            last_seen_at = ?,
            master_pubkey = COALESCE(users.master_pubkey, excluded.master_pubkey)",
    )
    .bind(&canonical_pubkey)
    .bind(&now)
    .bind(&now)
    .bind(initial_status)
    .bind(&master_pubkey)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let token = hex::encode({
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    });

    sqlx::query("INSERT INTO sessions (token, public_key, created_at) VALUES (?, ?, ?)")
        .bind(&token)
        .bind(&canonical_pubkey)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Check invite requirement for new users
    let has_roles: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_roles WHERE user_public_key = ?",
    )
    .bind(&canonical_pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if has_roles == 0 {
        // New user — check if hub requires an invite
        if crate::routes::invites::is_invite_only(&state.db).await? {
            match &req.invite_code {
                Some(code) => {
                    crate::routes::invites::validate_and_use_invite(&state.db, code).await?;
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
    let has_roles: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_roles WHERE user_public_key = ?",
    )
    .bind(&canonical_pubkey)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if has_roles == 0 {
        // Check if anyone already has the Owner role
        let owner_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = 'builtin-owner'",
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if owner_exists == 0 {
            sqlx::query(
                "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, 'builtin-owner', ?)",
            )
            .bind(&canonical_pubkey)
            .bind(&now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        }

        sqlx::query(
            "INSERT OR IGNORE INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, 'builtin-everyone', ?)",
        )
        .bind(&canonical_pubkey)
        .bind(&now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
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
                return Err((StatusCode::FORBIDDEN, "Challenge token required".to_string()));
            }
            Some(ct) => {
                let ct_row: Option<(i64, i64, Option<i64>, String)> = sqlx::query_as(
                    "SELECT issued_at, expires_at, consumed_at, pubkey FROM challenge_tokens WHERE token = ?",
                )
                .bind(ct)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

                match ct_row {
                    None => return Err((StatusCode::FORBIDDEN, "Invalid challenge token".to_string())),
                    Some((_issued, expires, consumed, token_pubkey)) => {
                        if consumed.is_some() {
                            return Err((StatusCode::FORBIDDEN, "Challenge token already used".to_string()));
                        }
                        if now > expires {
                            return Err((StatusCode::FORBIDDEN, "Challenge token expired".to_string()));
                        }
                        if token_pubkey != req.public_key {
                            return Err((StatusCode::FORBIDDEN, "Challenge token pubkey mismatch".to_string()));
                        }
                        // Mark consumed
                        sqlx::query(
                            "UPDATE challenge_tokens SET consumed_at = ? WHERE token = ?",
                        )
                        .bind(now)
                        .bind(ct)
                        .execute(&state.db)
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                    }
                }
            }
        }
    }

    // Compute session scope: "lobby" if lobby is enabled and user's pow_level < min_security_level
    let lobby_enabled: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'lobby_enabled'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|v| v == "1")
    .unwrap_or(true);

    let pow_level: u32 = sqlx::query_scalar::<_, i64>(
        "SELECT pow_level FROM users WHERE public_key = ?",
    )
    .bind(&canonical_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0) as u32;

    let scope = if lobby_enabled && pow_level < min_level {
        "lobby".to_string()
    } else {
        "member".to_string()
    };

    tracing::info!(
        "User authenticated: canonical={} (cert={}, scope={})",
        &canonical_pubkey[..16],
        master_pubkey.is_some(),
        scope,
    );

    Ok(Json(VerifyResponse { token, scope }))
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
