use std::sync::Arc;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct PanelQuery { pub token: Option<String> }

/// GET /admin/panel — serves the admin panel HTML page
/// Auth: ?token=<web_admin_token> query param or Authorization: Bearer header
pub async fn serve_panel(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PanelQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let expected_token: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'web_admin_token'"
    )
    .fetch_optional(&state.db).await.ok().flatten();

    let expected = expected_token.unwrap_or_default();
    if expected.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Admin panel not configured"));
    }

    let provided = q.token.clone().or_else(|| {
        headers.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()))
    });

    if provided.as_deref() != Some(&expected) {
        // Return login form when no token provided at all
        if provided.is_none() {
            return Ok(axum::response::Response::builder()
                .header("content-type", "text/html; charset=utf-8")
                .body(axum::body::Body::from(LOGIN_HTML))
                .unwrap());
        }
        return Err((StatusCode::UNAUTHORIZED, "Invalid token"));
    }

    Ok(axum::response::Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .body(axum::body::Body::from(PANEL_HTML))
        .unwrap())
}

/// GET /admin/stats — returns quick hub stats for the panel dashboard
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_admin_token(&state, &headers).await?;

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

async fn check_admin_token(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let expected: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'web_admin_token'"
    )
    .fetch_optional(&state.db).await.ok().flatten();
    let expected = expected.unwrap_or_default();
    let provided = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string()));
    if provided.as_deref() != Some(&expected) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token".into()));
    }
    Ok(())
}

const LOGIN_HTML: &str = r##"<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Voxply Admin</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#1e1f22;color:#dbdee1;}
form{background:#2b2d31;padding:32px;border-radius:8px;display:flex;flex-direction:column;gap:12px;min-width:320px;}
input{padding:8px;border-radius:4px;border:1px solid #3a3d44;background:#1e1f22;color:#dbdee1;font-size:14px;}
button{padding:10px;border-radius:4px;border:none;background:#5865f2;color:#fff;cursor:pointer;font-size:14px;}
h2{margin:0;text-align:center;}</style></head>
<body><form onsubmit="location.href='/admin/panel?token='+document.getElementById('t').value;return false;">
<h2>Voxply Admin</h2>
<input id="t" type="password" placeholder="Admin token" autofocus>
<button type="submit">Sign in</button>
</form></body></html>"##;

const PANEL_HTML: &str = r##"<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Voxply Admin Panel</title>
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
<a href="#" onclick="loadSection('users',event)">Users</a>
<a href="#" onclick="loadSection('channels',event)">Channels</a>
<a href="#" onclick="loadSection('reports',event)">Reports</a>
<a href="#" onclick="loadSection('audit',event)">Audit Log</a>
</nav>
<main id="main"><h1>Overview</h1><div id="content"><div class="stats-grid" id="stats"></div></div></main>
<script>
const TOKEN = new URLSearchParams(location.search).get('token') || localStorage.getItem('vxadm') || '';
if(TOKEN) localStorage.setItem('vxadm', TOKEN);
const api = (path, opts={}) => fetch(path, {headers:{'Authorization':'Bearer '+TOKEN,...(opts.headers||{})}, ...opts}).then(r=>r.json());

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
  else if(s==='users'){
    document.querySelector('h1').textContent='Users';
    const d = await api('/users?limit=50');
    const rows = (d||[]).map(u=>`<tr><td>${(u.public_key||'').slice(0,16)}…</td><td>${u.display_name||''}</td><td><button class="action" onclick="banUser('${u.public_key}')">Ban</button></td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Pubkey</th><th>Name</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  else if(s==='channels'){
    document.querySelector('h1').textContent='Channels';
    const d = await api('/channels');
    const rows=(d||[]).filter(c=>!c.is_category).map(c=>`<tr><td>#${c.name}</td><td>${(c.id||'').slice(0,8)}…</td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Name</th><th>ID</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  else if(s==='reports'){
    document.querySelector('h1').textContent='Pending Reports';
    const d = await api('/admin/reports?status=pending');
    const rows=(d||[]).map(r=>`<tr><td>${r.reason||'(no reason)'}</td><td>${(r.message_content||'').slice(0,60)}</td><td>
      <button class="action" onclick="reviewReport('${r.id}','dismiss')">Dismiss</button>
      <button class="action" onclick="reviewReport('${r.id}','delete_message')">Delete</button>
    </td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Reason</th><th>Message</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan=3>No pending reports</td></tr>'}</tbody></table></div>`;
  }
  else if(s==='audit'){
    document.querySelector('h1').textContent='Audit Log';
    const d = await api('/admin/audit-log?limit=50');
    const rows=(d&&d.entries||[]).map(e=>`<tr><td>${e.event_type}</td><td>${e.actor_pubkey||''}</td><td>${new Date(e.at*1000).toLocaleString()}</td></tr>`).join('');
    el.innerHTML=`<div class="section"><table><thead><tr><th>Event</th><th>Actor</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
}

async function banUser(pk) {
  if(!confirm('Ban '+pk.slice(0,16)+'?')) return;
  await fetch('/moderation/bans', {method:'POST',headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'},body:JSON.stringify({target_public_key:pk,reason:'Admin panel ban'})});
  loadSection('users', null);
}

async function reviewReport(id, action) {
  await fetch(`/admin/reports/${id}/review`, {method:'POST',headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'},body:JSON.stringify({action})});
  loadSection('reports', null);
}

loadStats();
</script>
</body></html>"##;
