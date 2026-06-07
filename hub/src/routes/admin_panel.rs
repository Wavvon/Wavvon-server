use std::sync::Arc;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::routes::admin_auth::extract_admin_session;

#[derive(Deserialize)]
pub struct PanelUsersQuery {
    pub q: Option<String>,
}

#[derive(Deserialize)]
pub struct PanelReportsQuery {
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct PanelAuditQuery {
    pub limit: Option<i64>,
}

pub async fn panel_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PanelUsersQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let rows = if let Some(search) = q.q {
        let like = format!("%{search}%");
        sqlx::query_as::<_, (String, Option<String>, i64)>(
            "SELECT public_key, display_name, first_seen_at FROM users
             WHERE display_name LIKE ? OR public_key LIKE ?
             ORDER BY first_seen_at DESC LIMIT 100",
        )
        .bind(&like)
        .bind(&like)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, (String, Option<String>, i64)>(
            "SELECT public_key, display_name, first_seen_at FROM users
             ORDER BY first_seen_at DESC LIMIT 100",
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let online = state.online_users.read().await;
    let users: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(pk, name, seen)| {
            serde_json::json!({
                "public_key": pk,
                "display_name": name,
                "first_seen_at": seen,
                "online": online.contains(&pk),
            })
        })
        .collect();
    Ok(Json(serde_json::json!(users)))
}

pub async fn panel_list_channels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let rows = sqlx::query_as::<_, (String, String, bool)>(
        "SELECT id, name, is_category FROM channels ORDER BY sort_order, name LIMIT 200",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let channels: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, name, is_cat)| serde_json::json!({"id": id, "name": name, "is_category": is_cat}))
        .collect();
    Ok(Json(serde_json::json!(channels)))
}

pub async fn panel_list_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PanelReportsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let status = q.status.unwrap_or_else(|| "pending".into());
    let rows = sqlx::query(
        "SELECT r.id, r.message_id, m.content as message_content,
                r.reporter_pubkey, r.reason, r.reported_at, r.status
         FROM message_reports r
         JOIN messages m ON m.id = r.message_id
         WHERE r.status = ?
         ORDER BY r.reported_at DESC LIMIT 50",
    )
    .bind(&status)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let reports: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            use sqlx::Row;
            serde_json::json!({
                "id": r.try_get::<String, _>("id").unwrap_or_default(),
                "message_id": r.try_get::<String, _>("message_id").unwrap_or_default(),
                "message_content": r.try_get::<String, _>("message_content").unwrap_or_default(),
                "reporter_pubkey": r.try_get::<Option<String>, _>("reporter_pubkey").unwrap_or_default(),
                "reason": r.try_get::<Option<String>, _>("reason").unwrap_or_default(),
                "reported_at": r.try_get::<i64, _>("reported_at").unwrap_or_default(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!(reports)))
}

pub async fn panel_review_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("dismiss");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if action == "delete_message" {
        let msg_id: Option<String> = sqlx::query_scalar("SELECT message_id FROM message_reports WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(mid) = msg_id {
            sqlx::query("DELETE FROM messages WHERE id = ?")
                .bind(&mid)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    sqlx::query("UPDATE message_reports SET status = 'reviewed', reviewed_at = ? WHERE id = ?")
        .bind(now)
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn panel_audit_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PanelAuditQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let limit = q.limit.unwrap_or(50).min(200).max(1);
    let rows = sqlx::query(
        "SELECT event_type, actor_pubkey, target_pubkey, at
         FROM hub_audit_log
         ORDER BY at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entries: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            use sqlx::Row;
            serde_json::json!({
                "event_type": r.try_get::<String, _>("event_type").unwrap_or_default(),
                "actor_pubkey": r.try_get::<Option<String>, _>("actor_pubkey").unwrap_or_default(),
                "target_pubkey": r.try_get::<Option<String>, _>("target_pubkey").unwrap_or_default(),
                "at": r.try_get::<i64, _>("at").unwrap_or_default(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"entries": entries})))
}

#[derive(Serialize)]
pub struct OwnerResponse {
    pub owner: Option<String>,
}

#[derive(Deserialize)]
pub struct SetOwnerRequest {
    pub public_key: String,
}

/// GET /admin/panel — serves the admin panel HTML page.
/// Valid session cookie → authenticated panel; no session → login page.
pub async fn serve_panel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let authenticated = extract_admin_session(&headers, &state).await.is_ok();
    if authenticated {
        axum::response::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(axum::body::Body::from(PANEL_HTML))
            .unwrap()
    } else {
        axum::response::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(axum::body::Body::from(LOGIN_HTML))
            .unwrap()
    }
}

/// GET /admin/stats — returns quick hub stats for the panel dashboard
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;

    let online_users = state.online_users.read().await.len();
    let voice_sessions = state.voice_channels.read().await.len();
    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db).await.unwrap_or(0);
    let total_messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&state.db).await.unwrap_or(0);
    let total_channels: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category=0")
        .fetch_one(&state.db).await.unwrap_or(0);
    let db_size = std::fs::metadata("hub.db").map(|m| m.len()).unwrap_or(0);
    let uptime_secs = state.started_at.elapsed().as_secs();

    Ok(Json(serde_json::json!({
        "online_users": online_users,
        "voice_sessions": voice_sessions,
        "total_users": total_users,
        "total_messages": total_messages,
        "total_channels": total_channels,
        "db_size_bytes": db_size,
        "uptime_seconds": uptime_secs,
    })))
}

/// GET /admin/owner — returns the current hub owner public key
pub async fn get_owner(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OwnerResponse>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(OwnerResponse { owner }))
}

/// POST /admin/owner — sets the hub owner to the given public key
pub async fn set_owner(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetOwnerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;

    let pk = req.public_key.to_lowercase();
    if pk.len() != 64 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "Invalid public key: must be 64 hex characters".into()));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Ensure a minimal user record exists so the FK constraint is satisfied.
    sqlx::query(
        "INSERT OR IGNORE INTO users (public_key, first_seen_at) VALUES (?, ?)",
    )
    .bind(&pk)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query(
        "INSERT OR REPLACE INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, 'builtin-owner', ?)",
    )
    .bind(&pk)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "ok": true, "owner": pk })))
}

pub async fn panel_ban_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    extract_admin_session(&headers, &state).await
        .map_err(|(s, m)| (s, m.to_string()))?;
    let pk = body.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
    if pk.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "public_key required".into()));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    sqlx::query(
        "INSERT OR IGNORE INTO bans (target_public_key, reason, banned_at) VALUES (?, 'Admin panel ban', ?)",
    )
    .bind(pk)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})))
}

// ─────────────────────────── HTML ────────────────────────────────────────────

const LOGIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Voxply Admin</title>
<style>
*{box-sizing:border-box;}
body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#1e1f22;color:#dbdee1;}
.card{background:#2b2d31;padding:36px;border-radius:10px;min-width:340px;max-width:420px;width:100%;border:1px solid #3a3d44;}
h2{margin:0 0 6px;font-size:20px;text-align:center;}
.sub{color:#96989d;font-size:13px;text-align:center;margin-bottom:24px;}
.btn{display:block;width:100%;padding:11px;border-radius:5px;border:none;background:#5865f2;color:#fff;cursor:pointer;font-size:14px;font-weight:600;text-align:center;transition:background .15s;}
.btn:hover{background:#4752c4;}
.btn.secondary{background:#3a3d44;color:#dbdee1;margin-top:8px;}
.btn.secondary:hover{background:#4a4d54;}
.spinner{width:36px;height:36px;border:3px solid #3a3d44;border-top-color:#5865f2;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px;}
@keyframes spin{to{transform:rotate(360deg);}}
.hint{font-size:12px;color:#96989d;text-align:center;margin-top:12px;}
.hint a{color:#5865f2;cursor:pointer;text-decoration:none;}
label{font-size:13px;color:#96989d;display:block;margin-bottom:4px;}
input[type=number],textarea{width:100%;padding:9px;border-radius:4px;border:1px solid #3a3d44;background:#1e1f22;color:#dbdee1;font-size:14px;margin-bottom:12px;}
input[type=number]::-webkit-outer-spin-button,input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none;}
input[type=number]{-moz-appearance:textfield;}
.error{color:#ed4245;font-size:12px;margin-top:-8px;margin-bottom:8px;}
code{background:#1e1f22;padding:4px 8px;border-radius:4px;font-size:13px;word-break:break-all;}
.secret-row{display:flex;gap:8px;align-items:center;margin-bottom:12px;}
.copy-btn{padding:4px 10px;border-radius:4px;border:none;background:#3a3d44;color:#dbdee1;cursor:pointer;font-size:12px;white-space:nowrap;}
a.otpauth{display:block;color:#5865f2;font-size:13px;margin-bottom:12px;word-break:break-all;text-decoration:none;}
a.otpauth:hover{text-decoration:underline;}
#state-all>div{display:none;}
#state-all>div.active{display:block;}
</style></head>
<body>
<div class="card">
  <div id="state-all">
    <!-- State 0: start -->
    <div id="s0" class="active">
      <h2>Voxply Admin</h2>
      <p class="sub">Sign in with your desktop app and authenticator.</p>
      <button class="btn" id="sign-btn">Sign with Desktop App</button>
      <div class="hint"><a onclick="showState(4)">Use a remote access token instead</a></div>
    </div>
    <!-- State 1: waiting -->
    <div id="s1">
      <div class="spinner"></div>
      <p style="text-align:center;margin:0 0 8px;">Approve the request in your desktop app.</p>
      <div class="hint">Didn't get a prompt? <a onclick="showState(4)">Use a remote access token</a> or <a onclick="cancelFlow()">cancel</a>.</div>
    </div>
    <!-- State 2: totp -->
    <div id="s2">
      <h2 style="margin-bottom:16px;">Two-Factor Auth</h2>
      <label for="totp-code">Authenticator code</label>
      <input type="number" id="totp-code" maxlength="6" placeholder="000000" autocomplete="one-time-code">
      <div class="error" id="totp-err" style="display:none;"></div>
      <button class="btn" id="totp-verify-btn">Verify</button>
    </div>
    <!-- State 3: enrollment -->
    <div id="s3">
      <h2 style="margin-bottom:8px;">Set up two-factor auth</h2>
      <p style="font-size:13px;color:#96989d;margin-bottom:12px;">Scan the link below with your authenticator app, then enter the 6-digit code to confirm.</p>
      <a class="otpauth" id="otpauth-link" href="#" target="_blank">Open in authenticator app</a>
      <label>Manual entry secret</label>
      <div class="secret-row">
        <code id="secret-display" style="flex:1;"></code>
        <button class="copy-btn" onclick="copySecret()">Copy</button>
      </div>
      <label for="enroll-code">Confirm code from app</label>
      <input type="number" id="enroll-code" maxlength="6" placeholder="000000" autocomplete="one-time-code">
      <div class="error" id="enroll-err" style="display:none;"></div>
      <button class="btn" id="enroll-confirm-btn">Confirm</button>
    </div>
    <!-- State 4: remote token -->
    <div id="s4">
      <h2 style="margin-bottom:8px;">Remote Access Token</h2>
      <p style="font-size:13px;color:#96989d;margin-bottom:12px;">Generate a token in the desktop app and paste it below.</p>
      <textarea id="token-input" rows="4" placeholder="Paste token from desktop app" style="resize:vertical;"></textarea>
      <button class="btn" id="token-continue-btn">Continue</button>
      <button class="btn secondary" onclick="showState(0)">Back</button>
    </div>
    <!-- State 5: error -->
    <div id="s5">
      <h2 style="margin-bottom:8px;color:#ed4245;">Error</h2>
      <p id="err-text" style="color:#96989d;font-size:13px;text-align:center;"></p>
      <button class="btn" onclick="showState(0)">Try again</button>
    </div>
  </div>
</div>

<script>
let currentChallengeId = null;
let pollTimer = null;
let pollStarted = null;

function showState(n) {
  document.querySelectorAll('#state-all > div').forEach(d => d.classList.remove('active'));
  document.getElementById('s' + n).classList.add('active');
}

function cancelFlow() {
  clearInterval(pollTimer);
  pollTimer = null;
  currentChallengeId = null;
  showState(0);
}

async function api(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  return {ok: r.ok, status: r.status, data: await r.json().catch(() => ({}))};
}

document.getElementById('sign-btn').addEventListener('click', async () => {
  const res = await api('/admin/auth/challenge', {});
  if (!res.ok) { showState(5); document.getElementById('err-text').textContent = 'Failed to start login. Try again.'; return; }
  currentChallengeId = res.data.challenge_id;
  window.location.href = res.data.deep_link;
  showState(1);
  startPolling(currentChallengeId);
});

function startPolling(challengeId) {
  pollStarted = Date.now();
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (Date.now() - pollStarted > 90000) {
      clearInterval(pollTimer);
      showState(5);
      document.getElementById('err-text').textContent = 'Timed out waiting for desktop app.';
      return;
    }
    const res = await api('/admin/auth/poll', {challenge_id: challengeId});
    if (!res.ok) return;
    const state = res.data.state;
    if (state === 'awaiting_totp') {
      clearInterval(pollTimer);
      showState(2);
    } else if (state === 'awaiting_enrollment') {
      clearInterval(pollTimer);
      const eb = await api('/admin/auth/totp/enroll-begin', {challenge_id: challengeId});
      if (!eb.ok) { showState(5); document.getElementById('err-text').textContent = 'Enrollment failed.'; return; }
      document.getElementById('otpauth-link').href = eb.data.otpauth_uri;
      document.getElementById('otpauth-link').textContent = eb.data.otpauth_uri;
      document.getElementById('secret-display').textContent = eb.data.secret_base32;
      showState(3);
    } else if (state === 'done') {
      clearInterval(pollTimer);
      location.reload();
    } else if (state === 'expired') {
      clearInterval(pollTimer);
      showState(5);
      document.getElementById('err-text').textContent = 'Login session expired. Try again.';
    }
  }, 1000);
}

document.getElementById('totp-verify-btn').addEventListener('click', async () => {
  const code = document.getElementById('totp-code').value.trim();
  const errEl = document.getElementById('totp-err');
  errEl.style.display = 'none';
  const res = await api('/admin/auth/totp', {challenge_id: currentChallengeId, code});
  if (res.ok) {
    location.reload();
  } else {
    errEl.textContent = res.data.message || 'Invalid code. Try again.';
    errEl.style.display = 'block';
  }
});

document.getElementById('enroll-confirm-btn').addEventListener('click', async () => {
  const code = document.getElementById('enroll-code').value.trim();
  const errEl = document.getElementById('enroll-err');
  errEl.style.display = 'none';
  const res = await api('/admin/auth/totp', {challenge_id: currentChallengeId, code});
  if (res.ok) {
    location.reload();
  } else {
    errEl.textContent = res.data.message || 'Invalid code. Try again.';
    errEl.style.display = 'block';
  }
});

document.getElementById('token-continue-btn').addEventListener('click', async () => {
  const token = document.getElementById('token-input').value.trim();
  if (!token) return;
  const res = await api('/admin/auth/token-login', {token});
  if (res.ok && res.data.challenge_id) {
    currentChallengeId = res.data.challenge_id;
    startPolling(currentChallengeId);
    showState(1);
  } else if (res.status === 503) {
    showState(5);
    document.getElementById('err-text').textContent = 'Farm not configured on this hub.';
  } else {
    showState(5);
    document.getElementById('err-text').textContent = 'Token login failed.';
  }
});

function copySecret() {
  const t = document.getElementById('secret-display').textContent;
  navigator.clipboard.writeText(t).catch(() => {});
}
</script>
</body></html>"##;

const PANEL_HTML: &str = r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Voxply Admin Panel</title>
<style>
*{box-sizing:border-box;} body{font-family:sans-serif;margin:0;background:#1e1f22;color:#dbdee1;display:flex;min-height:100vh;}
nav{width:200px;background:#2b2d31;padding:16px;display:flex;flex-direction:column;gap:4px;border-right:1px solid #3a3d44;}
nav a{color:#dbdee1;text-decoration:none;padding:8px 12px;border-radius:4px;font-size:14px;}
nav a:hover,nav a.active{background:#3a3d44;}
main{flex:1;padding:24px;overflow-y:auto;}
h1{margin:0 0 16px;font-size:20px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:24px;}
.stat{background:#2b2d31;border-radius:8px;padding:16px;border:1px solid #3a3d44;}
.stat-value{font-size:28px;font-weight:700;color:#5865f2;}
.stat-label{font-size:12px;color:#96989d;margin-top:4px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #3a3d44;}
th{color:#96989d;font-weight:600;}
button.action{padding:4px 10px;border-radius:4px;border:none;background:#ed4245;color:#fff;cursor:pointer;font-size:12px;}
.section{background:#2b2d31;border-radius:8px;padding:16px;border:1px solid #3a3d44;margin-bottom:16px;}
</style></head>
<body>
<nav>
<strong style="font-size:15px;padding:8px 12px;display:block;margin-bottom:8px;">Admin</strong>
<a href="#" onclick="loadSection('overview',event)" class="active">Overview</a>
<a href="#" onclick="loadSection('ownership',event)">Ownership</a>
<a href="#" onclick="loadSection('users',event)">Users</a>
<a href="#" onclick="loadSection('channels',event)">Channels</a>
<a href="#" onclick="loadSection('reports',event)">Reports</a>
<a href="#" onclick="loadSection('audit',event)">Audit Log</a>
<a href="#" onclick="doLogout(event)" style="margin-top:auto;color:#ed4245;">Sign out</a>
</nav>
<main id="main"><h1>Overview</h1><div id="content"><div class="stats-grid" id="stats"></div></div></main>
<script>
// Cookie-based auth — no token in localStorage, no Authorization header needed.
const api = (path, opts={}) => fetch(path, opts).then(r => {
  if (r.status === 401) { location.reload(); throw new Error('session expired'); }
  return r.json();
});

async function loadStats() {
  const d = await api('/admin/stats');
  document.getElementById('stats').innerHTML = [
    ['Online Users',d.online_users],['Voice Sessions',d.voice_sessions],
    ['Total Users',d.total_users],['Messages',d.total_messages],
    ['Channels',d.total_channels],['Uptime (s)',d.uptime_seconds]
  ].map(([l,v])=>`<div class="stat"><div class="stat-value">${v}</div><div class="stat-label">${l}</div></div>`).join('');
}

async function loadSection(s, evt) {
  document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));
  if(evt && evt.target) evt.target.classList.add('active');
  const el = document.getElementById('content');
  if(s==='overview'){
    document.querySelector('h1').textContent='Overview';
    el.innerHTML='<div class="stats-grid" id="stats"></div>';
    loadStats();
  }
  else if(s==='ownership'){
    document.querySelector('h1').textContent='Hub Ownership';
    const d = await api('/admin/owner');
    const cur = d.owner ? d.owner : null;
    el.innerHTML=`<div class="section">
      <p style="margin:0 0 12px">Current owner: <code style="background:#1e1f22;padding:2px 6px;border-radius:3px;">${cur ? cur.slice(0,20)+'&hellip;' : '<em>None set</em>'}</code></p>
      <p style="margin:0 0 12px;color:#96989d;font-size:13px;">Paste the owner's Ed25519 public key (64 hex characters). The owner has full admin access to this hub.</p>
      <div style="display:flex;gap:8px;">
        <input id="owner-pk" type="text" placeholder="64-character hex public key" style="flex:1;padding:8px;border-radius:4px;border:1px solid #3a3d44;background:#1e1f22;color:#dbdee1;font-family:monospace;font-size:13px;">
        <button onclick="setOwner()" style="padding:8px 16px;border-radius:4px;border:none;background:#5865f2;color:#fff;cursor:pointer;">Set Owner</button>
      </div>
      <p id="owner-result" style="margin-top:10px;font-size:13px;"></p>
    </div>`;
  }
  else if(s==='users'){
    document.querySelector('h1').textContent='Users';
    const d = await api('/admin/panel/users');
    const rows = (Array.isArray(d)?d:[]).map(u=>`<tr><td style="font-family:monospace;font-size:12px;">${(u.public_key||'').slice(0,16)}&hellip;</td><td>${u.display_name||''}</td><td>${u.online?'&#x1f7e2;':''}</td><td><button class="action" onclick="banUser('${u.public_key}')">Ban</button></td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Pubkey</th><th>Name</th><th>Online</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan=4>No users</td></tr>'}</tbody></table></div>`;
  }
  else if(s==='channels'){
    document.querySelector('h1').textContent='Channels';
    const d = await api('/admin/panel/channels');
    const rows=(Array.isArray(d)?d:[]).filter(c=>!c.is_category).map(c=>`<tr><td>#${c.name}</td><td style="font-family:monospace;font-size:12px;">${(c.id||'').slice(0,8)}&hellip;</td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Name</th><th>ID</th></tr></thead><tbody>${rows||'<tr><td colspan=2>No channels</td></tr>'}</tbody></table></div>`;
  }
  else if(s==='reports'){
    document.querySelector('h1').textContent='Pending Reports';
    const d = await api('/admin/panel/reports?status=pending');
    const rows=(Array.isArray(d)?d:[]).map(r=>`<tr><td>${r.reason||'(no reason)'}</td><td>${(r.message_content||'').slice(0,60)}</td><td>
      <button class="action" onclick="reviewReport('${r.id}','dismiss')">Dismiss</button>
      <button class="action" onclick="reviewReport('${r.id}','delete_message')">Delete</button>
    </td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Reason</th><th>Message</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan=3>No pending reports</td></tr>'}</tbody></table></div>`;
  }
  else if(s==='audit'){
    document.querySelector('h1').textContent='Audit Log';
    const d = await api('/admin/panel/audit');
    const rows=(d&&Array.isArray(d.entries)?d.entries:[]).map(e=>`<tr><td>${e.event_type}</td><td style="font-family:monospace;font-size:12px;">${(e.actor_pubkey||'').slice(0,16)}</td><td>${new Date(e.at*1000).toLocaleString()}</td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Event</th><th>Actor</th><th>Time</th></tr></thead><tbody>${rows||'<tr><td colspan=3>No log entries</td></tr>'}</tbody></table></div>`;
  }
}

async function setOwner() {
  const pk = (document.getElementById('owner-pk').value||'').trim().toLowerCase();
  const res = document.getElementById('owner-result');
  if(pk.length!==64||!/^[0-9a-f]+$/.test(pk)){res.style.color='#ed4245';res.textContent='Invalid public key: must be 64 hex characters.';return;}
  const r=await fetch('/admin/owner',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_key:pk})});
  if(r.ok){res.style.color='#3ba55c';res.textContent='Owner updated. The new owner can now log in with that identity.';}
  else{res.style.color='#ed4245';res.textContent=await r.text();}
}

async function banUser(pk) {
  if(!confirm('Ban '+pk.slice(0,16)+'?')) return;
  await fetch('/admin/panel/ban', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({public_key:pk})});
  loadSection('users', null);
}

async function reviewReport(id, action) {
  await fetch(`/admin/panel/reports/${id}/review`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
  loadSection('reports', null);
}

async function doLogout(evt) {
  evt.preventDefault();
  await fetch('/admin/auth/logout', {method:'POST'});
  location.reload();
}

loadStats();
</script>
</body></html>"##;
