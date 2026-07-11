use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use base64::Engine;
use serde::Deserialize;

use crate::state::AppState;

pub struct AuthUser {
    pub public_key: String,
    /// Session scope:
    /// - `"member"` — full access, subject to normal role/permission checks.
    ///   Default for token paths that predate scoping (bot tokens, farm
    ///   tokens, webauthn/device-token logins).
    /// - `"lobby"` (lobby-bot-survey.md Feature 1) — confined to
    ///   `LOBBY_ALLOWED_PATHS` below, regardless of any roles held.
    /// - `"mini_app"` (bot-mini-apps.md "Scoped session token") — minted by
    ///   `bot_app_join`; confined to `MINI_APP_ALLOWED_PATHS` (empty — REST
    ///   is fully off-limits, `/ws` is the only surface this scope reaches).
    pub scope: String,
}

/// Extractor for federation endpoints that must only be called by a registered
/// peer hub.
///
/// Resolves the bearer token exactly like `AuthUser`, then performs an extra
/// check: the authenticated public key must exist in the `peers` table.
/// A request from a normal user session is rejected with 403 Forbidden.
///
/// **Defense-in-depth only.** The `peers` table can be populated via the
/// self-asserted `is_hub=true` path in `/auth/verify`, which means a
/// determined attacker can pass this check with an arbitrary keypair.
/// The actual anti-spoofing boundary for plaintext DMs is the Ed25519
/// signature check in `receive_federated_dm`: the `sender` field must be
/// backed by a valid signature that only the true sender can produce.
pub struct PeerHub {
    pub public_key: String,
}

impl FromRequestParts<Arc<AppState>> for PeerHub {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Reuse all the existing token-validation logic.
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        // The authenticated pubkey must be in the `peers` table.
        // Uses EXISTS so PostgreSQL always returns boolean — avoids int4/int8
        // type mismatch that SELECT 1 decoded as i64 would produce.
        let is_peer: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE public_key = $1)")
                .bind(&auth_user.public_key)
                .fetch_one(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if !is_peer {
            return Err((
                StatusCode::FORBIDDEN,
                "Caller is not a registered peer hub".to_string(),
            ));
        }

        Ok(PeerHub {
            public_key: auth_user.public_key,
        })
    }
}

/// Paths that pending (not-yet-approved) users are allowed to hit.
/// They can see their own status at /me and nothing else.
const PENDING_ALLOWED_PATHS: &[&str] = &["/me"];

/// Paths a `scope: "lobby"` session may reach (lobby-bot-survey.md Feature
/// 1). Everything else 403s — "anything not explicitly allowed for lobby
/// scope is denied" is the documented default-deny posture, enforced here
/// once for every route rather than per-handler. A lobby user can check
/// their own identity, poll/advance their lobby status, read the welcome
/// blurb, and take the onboarding survey (Feature 3, which explicitly runs
/// "in the lobby if Feature 1 is active"). No messaging, channels, or voice.
const LOBBY_ALLOWED_PATHS: &[&str] = &[
    "/me",
    "/lobby/status",
    "/lobby/submit-pow",
    "/lobby/welcome",
    "/survey/current",
    "/survey/submit",
];

/// REST paths a `scope: "mini_app"` session may reach (bot-mini-apps.md
/// "Scoped session token": "Cannot call admin or federation endpoints").
///
/// Deliberately empty: every documented mini-app interaction (launch card
/// click, in-game messages, the bot relay) rides `/ws`, which this scope is
/// explicitly allowed to reach (see `validate_ws_token`) and which confines
/// auto-subscription to the bound channel (see `connection::handle_socket`).
/// A mini-app session has no legitimate REST use today — including
/// `/me` mutations, which the token this scope replaces (a full user
/// session) used to allow. If a real mini-app REST need shows up later,
/// add it here explicitly rather than falling back to the member default.
const MINI_APP_ALLOWED_PATHS: &[&str] = &[];

/// Minimum seconds between farm pubkey re-fetch attempts (handles key rotation
/// without hammering the farm on every bad-token request).
const FARM_REFETCH_COOLDOWN: i64 = 60;

/// Farm token payload — only the fields we need for hub-side admission.
/// Unknown fields are ignored (`deny_unknown_fields` is NOT set intentionally).
#[derive(Deserialize)]
struct FarmTokenPayload {
    /// Expiry unix timestamp.
    pub exp: i64,
    /// Farm pubkey hex — must match the hub's cached farm pubkey.
    pub iss_pk: String,
    /// Canonical user pubkey hex.
    pub sub: String,
}

/// Base64url engine (no padding) matching the farm's token encoder.
fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

/// Try to verify a farm token string against `farm_pubkey_hex`.
/// Returns the canonical user pubkey (`sub`) on success.
fn try_verify_farm_token(
    farm_pubkey_hex: &str,
    token_str: &str,
) -> Result<String, (StatusCode, String)> {
    let dot = token_str
        .find('.')
        .ok_or((StatusCode::UNAUTHORIZED, "Malformed farm token".to_string()))?;
    let payload_b64 = &token_str[..dot];
    let sig_b64 = &token_str[dot + 1..];

    let engine = b64();
    let payload_bytes = engine.decode(payload_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid farm token encoding".to_string(),
        )
    })?;
    let sig_bytes = engine.decode(sig_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid farm token signature encoding".to_string(),
        )
    })?;

    // Verify Ed25519 signature via the identity crate helper.
    wavvon_identity::verify_signature(farm_pubkey_hex, &payload_bytes, &sig_bytes).map_err(
        |_| {
            (
                StatusCode::UNAUTHORIZED,
                "Invalid farm token signature".to_string(),
            )
        },
    )?;

    // Deserialise after signature check.
    let payload: FarmTokenPayload = serde_json::from_slice(&payload_bytes).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Malformed farm token payload".to_string(),
        )
    })?;

    // Check expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if now >= payload.exp {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Farm token has expired".to_string(),
        ));
    }

    // Check iss_pk matches what we have cached (defence-in-depth).
    if payload.iss_pk != farm_pubkey_hex {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Farm token iss_pk does not match cached farm pubkey".to_string(),
        ));
    }

    Ok(payload.sub)
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            ))?;

        let token = header.strip_prefix("Bearer ").ok_or((
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization format".to_string(),
        ))?;

        // Session scope (lobby-bot-survey.md Feature 1). Defaults to
        // "member" for every path except the legacy hub-token session
        // lookup below, which reads the actual value persisted on the
        // session row at `/auth/verify` time. Farm-token and bot-token
        // sessions are never lobby-confined.
        let mut scope = "member".to_string();

        // -----------------------------------------------------------------
        // Dispatch: farm token (contains '.') vs legacy opaque hub token.
        // -----------------------------------------------------------------
        let public_key = if token.contains('.') {
            // --- Farm token path ---
            let cached_pubkey = state.cached_farm_pubkey.read().await.clone();

            match &cached_pubkey {
                None => return Err((StatusCode::UNAUTHORIZED, "no_farm_configured".to_string())),
                Some(farm_pubkey) => {
                    match try_verify_farm_token(farm_pubkey, token) {
                        Ok(sub) => sub,
                        Err(first_err) => {
                            // Rate-limited re-fetch: try once per 60s to pick up key rotation.
                            let should_refetch = {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64;
                                let last = *state.last_farm_pubkey_fetch.read().await;
                                now - last > FARM_REFETCH_COOLDOWN
                            };

                            if should_refetch {
                                if let Some(ref farm_url) = state.farm_url {
                                    let refetch_result = state
                                        .http_client
                                        .get(format!("{farm_url}/farm/info"))
                                        .send()
                                        .await;

                                    // Update fetch timestamp regardless of outcome.
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                        as i64;
                                    *state.last_farm_pubkey_fetch.write().await = now;

                                    if let Ok(resp) = refetch_result {
                                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                                            if let Some(pk) =
                                                body.get("public_key").and_then(|v| v.as_str())
                                            {
                                                let new_pk = pk.to_string();
                                                *state.cached_farm_pubkey.write().await =
                                                    Some(new_pk.clone());

                                                // Retry with new pubkey.
                                                match try_verify_farm_token(&new_pk, token) {
                                                    Ok(sub) => sub,
                                                    Err(_) => return Err(first_err),
                                                }
                                            } else {
                                                return Err(first_err);
                                            }
                                        } else {
                                            return Err(first_err);
                                        }
                                    } else {
                                        return Err(first_err);
                                    }
                                } else {
                                    return Err(first_err);
                                }
                            } else {
                                return Err(first_err);
                            }
                        }
                    }
                }
            }
        } else {
            // --- Legacy opaque hub-token path (unchanged) ---
            // Try sessions first.
            let row: Option<(String, String, Option<i64>, String)> = sqlx::query_as(
                "SELECT s.public_key, u.approval_status, s.expires_at, s.scope
                 FROM sessions s
                 INNER JOIN users u ON s.public_key = u.public_key
                 WHERE s.token = $1",
            )
            .bind(token)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            let (pk, approval_status) = if let Some((pk, status, expires_at, sess_scope)) = row {
                // Enforce session expiry. NULL expires_at means the session
                // never expires (human sessions). Non-NULL must be in the
                // future.
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
                scope = sess_scope;
                (pk, status)
            } else {
                // Try bot tokens.
                let bot_key: Option<String> =
                    sqlx::query_scalar("SELECT public_key FROM bot_tokens WHERE token = $1")
                        .bind(token)
                        .fetch_optional(&state.db)
                        .await
                        .map_err(|e| {
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                        })?;

                match bot_key {
                    Some(k) => (k, "approved".to_string()),
                    None => {
                        return Err((
                            StatusCode::UNAUTHORIZED,
                            "Invalid or expired token".to_string(),
                        ))
                    }
                }
            };

            // Reject revoked keys.
            let revoked_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM subkey_revocations WHERE subkey_pubkey = $1",
            )
            .bind(&pk)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

            if revoked_count > 0 {
                return Err((StatusCode::UNAUTHORIZED, "Key has been revoked".to_string()));
            }

            if approval_status == "pending" {
                let path = parts.uri.path();
                if !PENDING_ALLOWED_PATHS.contains(&path) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Account is pending admin approval".to_string(),
                    ));
                }
            }

            pk
        };

        // -----------------------------------------------------------------
        // Per-hub admission checks common to both token paths.
        // -----------------------------------------------------------------
        // For farm-token users the users row may not exist yet (first visit).
        // We do a lazy upsert here so the rest of the hub code can safely
        // assume a users row exists.
        // The approval flow, role assignment, ban checks etc. are preserved.
        // -----------------------------------------------------------------

        // Only do the upsert on the farm-token path — legacy hub tokens go
        // through verify() which already handles this. We detect farm-token
        // path by the presence of '.' in the original bearer token.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if token.contains('.') {
            // Lazy upsert: insert if not present, update last_seen otherwise.
            sqlx::query(
                "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status)
                 VALUES ($1, $2, $3, 'approved')
                 ON CONFLICT(public_key) DO UPDATE SET last_seen_at = excluded.last_seen_at",
            )
            .bind(&public_key)
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            // One combined query collects most of what the admission checks
            // below need (role_count, ban, approval_status) in a single
            // round-trip. The federated-ban decision is NOT inlined here: it
            // has override + per-source-policy rules that live in
            // moderation::is_federated_banned — duplicating them as SQL once
            // let the overrides drift out of this path.
            let checks: FarmTokenChecks = sqlx::query_as(
                "SELECT
                     u.approval_status,
                     (SELECT COUNT(*) FROM user_roles      WHERE user_public_key  = $1) AS role_count,
                     (SELECT COUNT(*) FROM bans            WHERE target_public_key = $1) AS ban_count
                 FROM users u WHERE u.public_key = $1",
            )
            .bind(&public_key)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            if checks.role_count == 0 {
                crate::auth::handlers::assign_initial_roles(&state.db, &public_key, now).await?;
            }

            if checks.ban_count > 0 {
                return Err((StatusCode::FORBIDDEN, "User is banned".to_string()));
            }

            if crate::routes::moderation::is_federated_banned(&state.db, &public_key).await? {
                return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
            }

            if checks.approval_status == "pending" {
                let path = parts.uri.path();
                if !PENDING_ALLOWED_PATHS.contains(&path) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Account is pending admin approval".to_string(),
                    ));
                }
            }
        }

        // Lobby confinement (lobby-bot-survey.md Feature 1): a lobby-scoped
        // session may only reach the small allowlist above — every other
        // route 403s, regardless of any roles the underlying user holds.
        // Checked last so it composes with (rather than replaces) the
        // pending-approval, ban, and revocation gates above.
        if scope == "lobby" {
            let path = parts.uri.path();
            if !LOBBY_ALLOWED_PATHS.contains(&path) {
                return Err((StatusCode::FORBIDDEN, "lobby_scope_confined".to_string()));
            }
        }

        // Mini-app confinement (bot-mini-apps.md "Scoped session token"): a
        // `bot_app_join`-minted session is bound to one channel over `/ws`
        // and must not reach admin, federation, or any other REST route —
        // see `MINI_APP_ALLOWED_PATHS`'s doc comment for why that's empty.
        if scope == "mini_app" {
            let path = parts.uri.path();
            if !MINI_APP_ALLOWED_PATHS.contains(&path) {
                return Err((StatusCode::FORBIDDEN, "mini_app_scope_confined".to_string()));
            }
        }

        Ok(AuthUser { public_key, scope })
    }
}

#[derive(sqlx::FromRow)]
struct FarmTokenChecks {
    approval_status: String,
    role_count: i64,
    ban_count: i64,
}
