//! Farm admin panel authentication: Ed25519 challenge-signing + TOTP.
//!
//! Flow:
//!   POST /farm/admin/auth/challenge      → challenge_id, challenge_hex, deep_link
//!   desktop signs, POSTs to:
//!   POST /farm/admin/auth/signed         → verifies sig, checks admin_pubkey, stores state
//!   browser polls:
//!   POST /farm/admin/auth/poll           → returns state
//!   POST /farm/admin/auth/totp/enroll-begin  (first login)
//!   POST /farm/admin/auth/totp           → verifies TOTP, sets session cookie
//!   POST /farm/admin/auth/logout
//!   GET  /farm/admin/auth/me

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::state::FarmState;

// ─────────────────────────── helpers ────────────────────────────────────────

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Parse "Cookie: …; vxadm_farm_session=<id>; …" and return the session id.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("vxadm_farm_session=") {
            let val = val.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Validate the farm admin session cookie and return the (id, pubkey) pair.
pub async fn extract_admin_session(
    headers: &HeaderMap,
    state: &FarmState,
) -> Result<(String, String), (StatusCode, &'static str)> {
    let session_id = extract_session_cookie(headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No admin session cookie"))?;

    let now = now_secs();
    let row: Option<(String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, pubkey, expires_at, revoked_at
         FROM farm_admin_sessions
         WHERE id = ?",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;

    match row {
        None => Err((StatusCode::UNAUTHORIZED, "Session not found")),
        Some((id, pubkey, expires_at, revoked_at)) => {
            if revoked_at.is_some() {
                return Err((StatusCode::UNAUTHORIZED, "Session revoked"));
            }
            if now >= expires_at {
                return Err((StatusCode::UNAUTHORIZED, "Session expired"));
            }
            Ok((id, pubkey))
        }
    }
}

/// Resolve the canonical pubkey from a signing pubkey + optional subkey cert.
/// If a cert is provided: verify the cert signature, confirm subkey_pubkey == signing pubkey,
/// and return (master_pubkey, Some(subkey_pubkey)). Otherwise return (pubkey, None).
fn resolve_canonical(
    pubkey: &str,
    subkey_cert: Option<&voxply_identity::SubkeyCert>,
) -> Result<String, (StatusCode, String)> {
    match subkey_cert {
        None => Ok(pubkey.to_string()),
        Some(cert) => {
            if cert.subkey_pubkey != pubkey {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "subkey_cert.subkey_pubkey does not match signing pubkey".into(),
                ));
            }
            let signing_bytes = cert.to_signing_bytes();
            let sig_bytes = hex::decode(&cert.signature)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid cert signature hex".into()))?;
            voxply_identity::verify_signature(&cert.master_pubkey, &signing_bytes, &sig_bytes)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Subkey cert signature invalid".into()))?;
            Ok(cert.master_pubkey.clone())
        }
    }
}

/// Load admin_pubkey from the farms singleton row.
async fn get_admin_pubkey(db: &sqlx::SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

// ─────────────────────────── challenge ──────────────────────────────────────

#[derive(Serialize)]
pub struct ChallengeOut {
    pub challenge_id: String,
    pub challenge_hex: String,
    pub callback_url: String,
    pub deep_link: String,
}

/// POST /farm/admin/auth/challenge
pub async fn challenge(
    State(state): State<Arc<FarmState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ChallengeOut>, (StatusCode, &'static str)> {
    // Per-IP rate limit: max 10 in-flight unexpired challenges per IP.
    let ip = addr.ip().to_string();
    let now = now_secs();
    let window_start = now - 60;

    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM farm_admin_pending_challenge
         WHERE pubkey = ? AND created_at > ? AND state = 'pending'",
    )
    .bind(format!("ip:{ip}"))
    .bind(window_start)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if recent >= 10 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
    }

    let challenge_id = random_hex(16);
    let challenge_hex = random_hex(32);
    let expires_at = now + 90;

    sqlx::query(
        "INSERT INTO farm_admin_pending_challenge
         (challenge_id, challenge_hex, state, pubkey, created_at, expires_at)
         VALUES (?, ?, 'pending', ?, ?, ?)",
    )
    .bind(&challenge_id)
    .bind(&challenge_hex)
    .bind(format!("ip:{ip}"))
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;

    let origin = {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        format!("{scheme}://{host}")
    };

    let callback_url = format!("{origin}/farm/admin/auth/signed");
    let deep_link = format!(
        "voxply://sign-admin?challenge={challenge_hex}&challenge_id={challenge_id}&callback={callback_url}"
    );

    Ok(Json(ChallengeOut {
        challenge_id,
        challenge_hex,
        callback_url,
        deep_link,
    }))
}

// ─────────────────────────── signed ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct SignedBody {
    pub challenge_id: String,
    pub pubkey: String,
    pub signature: String,
    pub subkey_cert: Option<voxply_identity::SubkeyCert>,
}

/// POST /farm/admin/auth/signed — called by the desktop app after signing.
pub async fn signed(
    State(state): State<Arc<FarmState>>,
    Json(body): Json<SignedBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let now = now_secs();

    // Load the pending challenge.
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT challenge_hex, state, expires_at
         FROM farm_admin_pending_challenge
         WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (challenge_hex, ch_state, expires_at) = match row {
        None => return Err((StatusCode::NOT_FOUND, "Challenge not found".into())),
        Some(r) => r,
    };

    if ch_state != "pending" {
        return Err((StatusCode::CONFLICT, "Challenge already used".into()));
    }
    if now >= expires_at {
        return Err((StatusCode::GONE, "Challenge expired".into()));
    }

    // Verify Ed25519 signature.
    let challenge_bytes = hex::decode(&challenge_hex)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Bad challenge hex in DB".into()))?;
    let sig_bytes = hex::decode(&body.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".into()))?;

    voxply_identity::verify_signature(&body.pubkey, &challenge_bytes, &sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Signature verification failed".into()))?;

    // Resolve canonical pubkey (handles subkey certs).
    let canonical_pubkey = resolve_canonical(&body.pubkey, body.subkey_cert.as_ref())
        .map_err(|(s, m)| (s, m))?;

    // Authorization: canonical pubkey must equal farms.admin_pubkey.
    let admin_pubkey = get_admin_pubkey(&state.db).await;
    if admin_pubkey.as_deref() != Some(canonical_pubkey.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            "Not authorized as farm admin".into(),
        ));
    }

    // Check whether the pubkey has a confirmed TOTP secret.
    let has_totp: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM farm_admin_totp
         WHERE pubkey = ? AND confirmed_at IS NOT NULL",
    )
    .bind(&canonical_pubkey)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    let new_state = if has_totp {
        "awaiting_totp"
    } else {
        "awaiting_enrollment"
    };

    sqlx::query(
        "UPDATE farm_admin_pending_challenge
         SET state = ?, pubkey = ?
         WHERE challenge_id = ?",
    )
    .bind(new_state)
    .bind(&canonical_pubkey)
    .bind(&body.challenge_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})))
}

// ─────────────────────────── poll ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct PollBody {
    pub challenge_id: String,
}

/// POST /farm/admin/auth/poll — browser polls this every 1s.
pub async fn poll(
    State(state): State<Arc<FarmState>>,
    Json(body): Json<PollBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM farm_admin_pending_challenge
         WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error"))?;

    let (ch_state, pubkey, expires_at) = match row {
        None => return Err((StatusCode::NOT_FOUND, "Challenge not found")),
        Some(r) => r,
    };

    if now >= expires_at && ch_state != "done" {
        return Ok(Json(serde_json::json!({"state": "expired"})));
    }

    // Check enrolled status for the pubkey.
    let enrolled = if let Some(ref pk) = pubkey {
        if pk.starts_with("ip:") {
            false
        } else {
            sqlx::query_scalar::<_, bool>(
                "SELECT COUNT(*) > 0 FROM farm_admin_totp
                 WHERE pubkey = ? AND confirmed_at IS NOT NULL",
            )
            .bind(pk)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false)
        }
    } else {
        false
    };

    let pubkey_out = pubkey.filter(|p| !p.starts_with("ip:"));

    Ok(Json(serde_json::json!({
        "state": ch_state,
        "enrolled": enrolled,
        "pubkey": pubkey_out,
        "role": "farm_admin",
    })))
}

// ─────────────────────────── enroll-begin ───────────────────────────────────

#[derive(Deserialize)]
pub struct EnrollBeginBody {
    pub challenge_id: String,
}

#[derive(Serialize)]
pub struct EnrollBeginOut {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

/// POST /farm/admin/auth/totp/enroll-begin
pub async fn enroll_begin(
    State(state): State<Arc<FarmState>>,
    headers: HeaderMap,
    Json(body): Json<EnrollBeginBody>,
) -> Result<Json<EnrollBeginOut>, (StatusCode, String)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM farm_admin_pending_challenge
         WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (ch_state, pubkey_opt, expires_at) = match row {
        None => return Err((StatusCode::NOT_FOUND, "Challenge not found".into())),
        Some(r) => r,
    };

    if ch_state != "awaiting_enrollment" {
        return Err((
            StatusCode::CONFLICT,
            format!("Challenge in state '{ch_state}', expected 'awaiting_enrollment'"),
        ));
    }
    if now >= expires_at {
        return Err((StatusCode::GONE, "Challenge expired".into()));
    }

    let pubkey = pubkey_opt.ok_or((StatusCode::BAD_REQUEST, "No pubkey on challenge".into()))?;

    // Generate a 20-byte TOTP secret.
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    // Build the otpauth URI.
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("farm");
    let otpauth_uri = format!(
        "otpauth://totp/Voxply%20Admin%3A{host}?secret={secret_base32}&issuer=Voxply"
    );

    // Upsert into farm_admin_totp — replace any unconfirmed secret for this pubkey,
    // leave any confirmed secret alone until this code is confirmed.
    sqlx::query(
        "INSERT INTO farm_admin_totp (pubkey, secret_base32, created_at, confirmed_at, last_used_step)
         VALUES (?, ?, ?, NULL, NULL)
         ON CONFLICT(pubkey) DO UPDATE SET
           secret_base32 = CASE WHEN confirmed_at IS NULL THEN excluded.secret_base32 ELSE farm_admin_totp.secret_base32 END,
           created_at    = CASE WHEN confirmed_at IS NULL THEN excluded.created_at    ELSE farm_admin_totp.created_at END",
    )
    .bind(&pubkey)
    .bind(&secret_base32)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EnrollBeginOut {
        secret_base32,
        otpauth_uri,
    }))
}

// ─────────────────────────── totp verify ────────────────────────────────────

#[derive(Deserialize)]
pub struct TotpBody {
    pub challenge_id: String,
    pub code: String,
}

/// POST /farm/admin/auth/totp — verify TOTP code; on success issue session cookie.
pub async fn totp_verify(
    State(state): State<Arc<FarmState>>,
    headers: HeaderMap,
    Json(body): Json<TotpBody>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM farm_admin_pending_challenge
         WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (ch_state, pubkey_opt, expires_at) = match row {
        None => return Err((StatusCode::NOT_FOUND, "Challenge not found".into())),
        Some(r) => r,
    };

    if ch_state != "awaiting_totp" && ch_state != "awaiting_enrollment" {
        return Err((
            StatusCode::CONFLICT,
            format!("Challenge in state '{ch_state}'"),
        ));
    }
    if now >= expires_at {
        return Err((StatusCode::GONE, "Challenge expired".into()));
    }

    let pubkey = pubkey_opt.ok_or((StatusCode::BAD_REQUEST, "No pubkey on challenge".into()))?;

    // Load TOTP row.
    let totp_row: Option<(String, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT secret_base32, confirmed_at, last_used_step
         FROM farm_admin_totp WHERE pubkey = ?",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (secret_base32, confirmed_at, last_used_step) =
        totp_row.ok_or((StatusCode::NOT_FOUND, "No TOTP secret found".into()))?;

    // Build TOTP verifier.
    let secret_bytes = Secret::Encoded(secret_base32.clone())
        .to_bytes()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("TOTP secret decode: {e}"),
            )
        })?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("TOTP init: {e}")))?;

    let current_step = (now as u64) / 30;

    // Check steps: current-1, current, current+1 (clock-skew window).
    let mut matched_step: Option<u64> = None;
    for offset in [-1i64, 0i64, 1i64] {
        let step = (current_step as i64 + offset) as u64;
        let step_ts = step * 30;
        let code_for_step = totp.generate(step_ts).to_string();
        if code_for_step == body.code.trim() {
            matched_step = Some(step);
            break;
        }
    }

    let matched_step = matched_step
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid TOTP code".to_string()))?;

    // Replay guard.
    if let Some(last) = last_used_step {
        if matched_step <= last as u64 {
            return Err((StatusCode::UNAUTHORIZED, "TOTP code already used".into()));
        }
    }

    // Confirm enrollment if this is the first code for a new secret.
    let confirm_now = if confirmed_at.is_none() {
        Some(now)
    } else {
        confirmed_at
    };

    sqlx::query(
        "UPDATE farm_admin_totp
         SET confirmed_at = ?, last_used_step = ?
         WHERE pubkey = ?",
    )
    .bind(confirm_now)
    .bind(matched_step as i64)
    .bind(&pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Issue session.
    let session_id = random_hex(32);
    let expires_at_sess = now + 43200; // 12 hours

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    sqlx::query(
        "INSERT INTO farm_admin_sessions (id, pubkey, created_at, expires_at, user_agent)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(&pubkey)
    .bind(now)
    .bind(expires_at_sess)
    .bind(&user_agent)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Advance challenge to done.
    sqlx::query(
        "UPDATE farm_admin_pending_challenge SET state = 'done' WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cookie = format!(
        "vxadm_farm_session={session_id}; HttpOnly; SameSite=Strict; Path=/farm/admin; Max-Age=43200"
    );

    let body_json = serde_json::json!({"ok": true, "role": "farm_admin"});
    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", &cookie)
        .body(axum::body::Body::from(
            serde_json::to_string(&body_json).unwrap(),
        ))
        .unwrap();

    Ok(response)
}

// ─────────────────────────── logout ─────────────────────────────────────────

/// POST /farm/admin/auth/logout
pub async fn logout(
    State(state): State<Arc<FarmState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let now = now_secs();

    if let Ok((session_id, _pubkey)) = extract_admin_session(&headers, &state).await {
        let _ = sqlx::query(
            "UPDATE farm_admin_sessions SET revoked_at = ? WHERE id = ?",
        )
        .bind(now)
        .bind(&session_id)
        .execute(&state.db)
        .await;
    }

    let clear_cookie =
        "vxadm_farm_session=; HttpOnly; SameSite=Strict; Path=/farm/admin; Max-Age=0";
    let body_json = serde_json::json!({"ok": true});
    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", clear_cookie)
        .body(axum::body::Body::from(
            serde_json::to_string(&body_json).unwrap(),
        ))
        .unwrap();

    Ok(response)
}

// ─────────────────────────── me ─────────────────────────────────────────────

/// GET /farm/admin/auth/me
pub async fn me(
    State(state): State<Arc<FarmState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let (_session_id, pubkey) = extract_admin_session(&headers, &state).await?;

    Ok(Json(serde_json::json!({
        "pubkey": pubkey,
        "role": "farm_admin",
    })))
}
