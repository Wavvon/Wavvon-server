//! Admin panel authentication: Ed25519 challenge-signing + TOTP.
//!
//! Flow:
//!   POST /admin/auth/challenge  → challenge_id, challenge_hex, deep_link
//!   desktop signs, POSTs to:
//!   POST /admin/auth/signed     → verifies sig, checks role, stores state
//!   browser polls:
//!   POST /admin/auth/poll       → returns state
//!   POST /admin/auth/totp/enroll-begin  (first login)
//!   POST /admin/auth/totp       → verifies TOTP, sets session cookie
//!   POST /admin/auth/logout
//!   GET  /admin/auth/me
//!   POST /admin/auth/token-login (v1 stub — farm tokens only, not yet)

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::handlers::resolve_canonical_identity;
use crate::state::AppState;

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

/// Parse "Cookie: …; vxadm_session=<id>; …" and return the session id.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("vxadm_session=") {
            let val = val.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Validate the session cookie and return the (id, pubkey) pair.
pub async fn extract_admin_session(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(String, String), (StatusCode, &'static str)> {
    let session_id = extract_session_cookie(headers)
        .ok_or((StatusCode::UNAUTHORIZED, "No admin session cookie"))?;

    let now = now_secs();
    let row: Option<(String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, pubkey, expires_at, revoked_at
         FROM admin_panel_sessions
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

// ─────────────────────────── challenge ──────────────────────────────────────

#[derive(Serialize)]
pub struct ChallengeOut {
    pub challenge_id: String,
    pub challenge_hex: String,
    pub callback_url: String,
    pub deep_link: String,
}

/// POST /admin/auth/challenge
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ChallengeOut>, (StatusCode, &'static str)> {
    // Per-IP rate limit: max 10 in-flight unexpired challenges per IP.
    // We implement this by counting recent rows rather than a separate in-memory
    // structure, keeping the implementation simple and crash-safe.
    let ip = addr.ip().to_string();
    let now = now_secs();
    let window_start = now - 60;

    // We tag challenge rows with the IP by re-using the challenge_id prefix.
    // Instead, count rows created_at > now-60 per IP using a naming convention:
    // we store ip in an unused field — but admin_pending_challenge has no ip
    // column. Use pubkey column (NULL until signed) to store ip temporarily
    // as "ip:<addr>" so we can count rate-limit violations cheaply.
    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM admin_pending_challenge
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
        "INSERT INTO admin_pending_challenge
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

    // Derive the server origin from the Host header so the callback URL is
    // correct regardless of whether TLS is in front or not.
    let origin = {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost");
        // If request came over TLS axum would normally know, but we can't
        // tell here. Use the scheme from the X-Forwarded-Proto header if
        // present, otherwise default to http (proxy should rewrite to https).
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        format!("{scheme}://{host}")
    };

    let callback_url = format!("{origin}/admin/auth/signed");
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

/// POST /admin/auth/signed — called by the desktop app after signing.
pub async fn signed(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignedBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let now = now_secs();

    // Load the pending challenge.
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT challenge_hex, state, expires_at
         FROM admin_pending_challenge
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
    let (canonical_pubkey, _master) =
        resolve_canonical_identity(&state.db, &body.pubkey, body.subkey_cert.as_ref())
            .await
            .map_err(|(s, m)| (s, m))?;

    // Authorization: builtin-owner OR any role with 'admin' permission.
    let is_owner: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM user_roles
         WHERE user_public_key = ? AND role_id = 'builtin-owner'",
    )
    .bind(&canonical_pubkey)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    let has_admin_role: bool = if !is_owner {
        sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM role_permissions rp
             JOIN user_roles ur ON ur.role_id = rp.role_id
             WHERE ur.user_public_key = ? AND rp.permission = 'admin'",
        )
        .bind(&canonical_pubkey)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false)
    } else {
        false
    };

    if !is_owner && !has_admin_role {
        return Err((StatusCode::FORBIDDEN, "Not authorized as hub admin".into()));
    }

    // Check whether the pubkey has a confirmed TOTP secret.
    let has_totp: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM admin_totp
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
        "UPDATE admin_pending_challenge
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

/// POST /admin/auth/poll — browser polls this every 1s.
pub async fn poll(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PollBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM admin_pending_challenge
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
        // Filter out ip: tagged rows
        if pk.starts_with("ip:") {
            false
        } else {
            sqlx::query_scalar::<_, bool>(
                "SELECT COUNT(*) > 0 FROM admin_totp
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
        "role": "hub_admin",
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

/// POST /admin/auth/totp/enroll-begin
pub async fn enroll_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<EnrollBeginBody>,
) -> Result<Json<EnrollBeginOut>, (StatusCode, String)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM admin_pending_challenge
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
        return Err((StatusCode::CONFLICT, format!("Challenge in state '{ch_state}', expected 'awaiting_enrollment'")));
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
        .unwrap_or("hub");
    let otpauth_uri = format!(
        "otpauth://totp/Voxply%20Admin%3A{host}?secret={secret_base32}&issuer=Voxply"
    );

    // Upsert into admin_totp — replace any unconfirmed secret for this pubkey,
    // leave any confirmed secret alone until this code is confirmed (handled in totp_verify).
    sqlx::query(
        "INSERT INTO admin_totp (pubkey, secret_base32, created_at, confirmed_at, last_used_step)
         VALUES (?, ?, ?, NULL, NULL)
         ON CONFLICT(pubkey) DO UPDATE SET
           secret_base32 = CASE WHEN confirmed_at IS NULL THEN excluded.secret_base32 ELSE admin_totp.secret_base32 END,
           created_at    = CASE WHEN confirmed_at IS NULL THEN excluded.created_at    ELSE admin_totp.created_at END",
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

/// POST /admin/auth/totp — verify TOTP code; on success issue session cookie.
pub async fn totp_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TotpBody>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let now = now_secs();

    let row: Option<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT state, pubkey, expires_at
         FROM admin_pending_challenge
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
        return Err((StatusCode::CONFLICT, format!("Challenge in state '{ch_state}'")));
    }
    if now >= expires_at {
        return Err((StatusCode::GONE, "Challenge expired".into()));
    }

    let pubkey = pubkey_opt.ok_or((StatusCode::BAD_REQUEST, "No pubkey on challenge".into()))?;

    // Load TOTP row.
    let totp_row: Option<(String, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT secret_base32, confirmed_at, last_used_step
         FROM admin_totp WHERE pubkey = ?",
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("TOTP secret decode: {e}")))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("TOTP init: {e}")))?;

    let current_step = (now as u64) / 30;

    // Check steps: current-1, current, current+1 (clock-skew window).
    let mut matched_step: Option<u64> = None;
    for offset in [-1i64, 0i64, 1i64] {
        let step = (current_step as i64 + offset) as u64;
        // totp_rs generate_current gives us the code for "now"; we need per-step.
        // Use generate() with the step-derived timestamp.
        let step_ts = step * 30;
        let code_for_step = totp
            .generate(step_ts)
            .to_string();
        if code_for_step == body.code.trim() {
            matched_step = Some(step);
            break;
        }
    }

    let matched_step = matched_step.ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, "Invalid TOTP code".to_string())
    })?;

    // Replay guard.
    if let Some(last) = last_used_step {
        if matched_step <= last as u64 {
            return Err((StatusCode::UNAUTHORIZED, "TOTP code already used".into()));
        }
    }

    // Confirm enrollment if this is the first code for a new secret.
    let confirm_now = if confirmed_at.is_none() { Some(now) } else { confirmed_at };

    sqlx::query(
        "UPDATE admin_totp
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
        "INSERT INTO admin_panel_sessions (id, pubkey, created_at, expires_at, user_agent)
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
        "UPDATE admin_pending_challenge SET state = 'done' WHERE challenge_id = ?",
    )
    .bind(&body.challenge_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cookie = format!(
        "vxadm_session={session_id}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=43200"
    );

    let body_json = serde_json::json!({"ok": true, "role": "hub_admin"});
    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", &cookie)
        .body(axum::body::Body::from(serde_json::to_string(&body_json).unwrap()))
        .unwrap();

    Ok(response)
}

// ─────────────────────────── logout ─────────────────────────────────────────

/// POST /admin/auth/logout
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let now = now_secs();

    if let Ok((session_id, _pubkey)) = extract_admin_session(&headers, &state).await {
        let _ = sqlx::query(
            "UPDATE admin_panel_sessions SET revoked_at = ? WHERE id = ?",
        )
        .bind(now)
        .bind(&session_id)
        .execute(&state.db)
        .await;
    }

    let clear_cookie = "vxadm_session=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0";
    let body_json = serde_json::json!({"ok": true});
    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", clear_cookie)
        .body(axum::body::Body::from(serde_json::to_string(&body_json).unwrap()))
        .unwrap();

    Ok(response)
}

// ─────────────────────────── me ─────────────────────────────────────────────

/// GET /admin/auth/me
pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let (_session_id, pubkey) = extract_admin_session(&headers, &state).await?;

    Ok(Json(serde_json::json!({
        "pubkey": pubkey,
        "role": "hub_admin",
    })))
}

// ─────────────────────────── token-login (v1 stub) ──────────────────────────

#[derive(Deserialize)]
pub struct TokenLoginBody {
    pub token: String,
}

/// POST /admin/auth/token-login — farm FarmTokenPayload-style signed blob.
/// v1: standalone hub (no farm configured) always returns 503.
/// Farm-backed token validation is deferred to v2.
pub async fn token_login(
    State(state): State<Arc<AppState>>,
    Json(_body): Json<TokenLoginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    if state.farm_url.is_none() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Farm not configured"));
    }
    // v2: verify FarmTokenPayload with admin_panel: true claim against farm pubkey.
    Err((StatusCode::NOT_IMPLEMENTED, "Farm token login not yet implemented"))
}
