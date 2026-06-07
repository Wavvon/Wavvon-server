/// Farm auth routes: challenge / verify / renew.
///
/// The wire bodies are identical to the hub's existing auth routes — only the
/// host they're sent to changes. That's deliberate: the client migration is
/// "switch the base URL," nothing else.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::HeaderMap;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::state::FarmState;
use crate::token::{sign_token, verify_token, FarmTokenPayload};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub public_key: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub public_key: String,
    pub signature: String,
    /// Optional scope override. Clients may request `"lobby"` explicitly; the
    /// farm will honour `"member"` or `"lobby"` (anything else defaults to
    /// `"member"`).
    pub scope: Option<String>,
    /// TOTP code — required when the admin account has TOTP enabled.
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 30 days in seconds.
const SESSION_TTL: i64 = 30 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// POST /auth/challenge
// ---------------------------------------------------------------------------

pub async fn challenge(
    State(state): State<Arc<FarmState>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge_hex = hex::encode(&nonce);
    let expires_at = unix_now() + 60;

    // Upsert: one pending challenge per pubkey (replacing any stale one).
    sqlx::query(
        "INSERT INTO pending_challenges (public_key, challenge_hex, expires_at)
         VALUES (?, ?, ?)
         ON CONFLICT(public_key) DO UPDATE SET
             challenge_hex = excluded.challenge_hex,
             expires_at    = excluded.expires_at",
    )
    .bind(&req.public_key)
    .bind(&challenge_hex)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(ChallengeResponse {
        challenge: challenge_hex,
    }))
}

// ---------------------------------------------------------------------------
// POST /auth/verify
// ---------------------------------------------------------------------------

pub async fn verify(
    State(state): State<Arc<FarmState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let now = unix_now();

    // Pull and validate the pending challenge.
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT challenge_hex, expires_at FROM pending_challenges WHERE public_key = ?",
    )
    .bind(&req.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (challenge_hex, expires_at) = row
        .ok_or((StatusCode::UNAUTHORIZED, "No pending challenge for this key".to_string()))?;

    if now >= expires_at {
        // Delete expired challenge before returning.
        let _ = sqlx::query("DELETE FROM pending_challenges WHERE public_key = ?")
            .bind(&req.public_key)
            .execute(&state.db)
            .await;
        return Err((StatusCode::UNAUTHORIZED, "Challenge expired".to_string()));
    }

    // Verify the Ed25519 signature over the challenge bytes.
    let challenge_bytes =
        hex::decode(&challenge_hex).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Bad challenge hex in DB".to_string()))?;
    let sig_bytes =
        hex::decode(&req.signature).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;

    voxply_identity::verify_signature(&req.public_key, &challenge_bytes, &sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

    // TOTP check — only applies when the verified pubkey is the admin key.
    {
        let admin_row: Option<(Option<String>, i64)> =
            sqlx::query_as("SELECT totp_secret, totp_enabled FROM farms WHERE id = 1")
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        let admin_pubkey: Option<String> =
            sqlx::query_scalar("SELECT admin_pubkey FROM farms WHERE id = 1")
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                .flatten();

        if admin_pubkey.as_deref() == Some(req.public_key.as_str()) {
            if let Some((totp_secret, totp_enabled)) = admin_row {
                if totp_enabled != 0 {
                    let secret = totp_secret.ok_or_else(|| {
                        (StatusCode::INTERNAL_SERVER_ERROR, "totp_secret_missing".to_string())
                    })?;
                    let code = req.totp_code.as_deref().ok_or_else(|| {
                        (StatusCode::UNAUTHORIZED, "totp_required".to_string())
                    })?;
                    let valid = (|| -> Option<bool> {
                        let bytes = Secret::Encoded(secret.clone()).to_bytes().ok()?;
                        let totp = TOTP::new(
                            Algorithm::SHA1, 6, 1, 30, bytes,
                            None, "voxply-farm".to_string(),
                        ).ok()?;
                        totp.check_current(code).ok()
                    })()
                    .unwrap_or(false);
                    if !valid {
                        return Err((StatusCode::UNAUTHORIZED, "invalid_totp".to_string()));
                    }
                }
            }
        }
    }

    // Delete the used challenge.
    sqlx::query("DELETE FROM pending_challenges WHERE public_key = ?")
        .bind(&req.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Upsert the farm_users row. Canonical pubkey = auth pubkey (no cert resolution
    // in Phase 1 — that lives on the hub still; the farm just records who showed up).
    sqlx::query(
        "INSERT INTO farm_users (public_key, master_pubkey, first_seen_at, last_seen_at)
         VALUES (?, NULL, ?, ?)
         ON CONFLICT(public_key) DO UPDATE SET last_seen_at = excluded.last_seen_at",
    )
    .bind(&req.public_key)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Mint a fresh session record.
    let jti = {
        let mut bytes = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let exp = now + SESSION_TTL;
    let scope = normalise_scope(req.scope.as_deref());

    sqlx::query(
        "INSERT INTO farm_sessions (jti, public_key, issued_at, expires_at, scope)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&jti)
    .bind(&req.public_key)
    .bind(now)
    .bind(exp)
    .bind(&scope)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let payload = FarmTokenPayload {
        v: 1,
        iss: state.farm_url.clone(),
        iss_pk: state.public_key_hex(),
        sub: req.public_key.clone(),
        master: None,
        jti,
        iat: now,
        exp,
        scope,
    };

    let token = sign_token(&state.keypair, &payload);
    Ok(Json(TokenResponse { token }))
}

// ---------------------------------------------------------------------------
// POST /auth/renew
// ---------------------------------------------------------------------------

pub async fn renew(
    State(state): State<Arc<FarmState>>,
    headers: HeaderMap,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // Extract and verify the existing farm token from the Authorization header.
    let token_str = extract_bearer(&headers)?;
    let farm_pubkey = state.public_key_hex();
    let old_payload = verify_token(&farm_pubkey, token_str)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid farm token: {e}")))?;

    // Issue a fresh session with a new jti and a new 30-day window.
    let now = unix_now();
    let new_jti = {
        let mut bytes = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let new_exp = now + SESSION_TTL;

    sqlx::query(
        "INSERT INTO farm_sessions (jti, public_key, issued_at, expires_at, scope)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&new_jti)
    .bind(&old_payload.sub)
    .bind(now)
    .bind(new_exp)
    .bind(&old_payload.scope)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let new_payload = FarmTokenPayload {
        v: 1,
        iss: state.farm_url.clone(),
        iss_pk: farm_pubkey,
        sub: old_payload.sub,
        master: old_payload.master,
        jti: new_jti,
        iat: now,
        exp: new_exp,
        scope: old_payload.scope,
    };

    let token = sign_token(&state.keypair, &new_payload);
    Ok(Json(TokenResponse { token }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalise_scope(s: Option<&str>) -> String {
    match s {
        Some("lobby") => "lobby".to_string(),
        _ => "member".to_string(),
    }
}

fn extract_bearer(headers: &HeaderMap) -> Result<&str, (StatusCode, String)> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header".to_string()))
}
