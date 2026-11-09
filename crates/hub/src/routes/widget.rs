//! The public online widget (Wavvon-server#341): who is online, for a
//! community's own website. The first thing a hub shows to non-members, so:
//! off by default, the admin picks how much it shows, an invisible member or
//! one who opted out never appears, and it carries display names and avatars,
//! never a public key.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, HUB_SETTINGS};
use crate::routes::hub::{read_setting, upsert_setting};
use crate::state::AppState;

/// How much the widget shows.
const MODES: &[&str] = &["off", "counts", "names", "voice"];

#[derive(Serialize, Deserialize)]
pub struct WidgetSettings {
    /// "off" (default), "counts", "names" or "voice" (names plus who is in
    /// which voice room).
    pub mode: String,
    /// The invite code the widget's Join button opens, if any.
    #[serde(default)]
    pub invite_code: Option<String>,
}

async fn load(db: &sqlx::PgPool) -> WidgetSettings {
    WidgetSettings {
        mode: read_setting(db, "widget_mode")
            .await
            .filter(|m| MODES.contains(&m.as_str()))
            .unwrap_or_else(|| "off".to_string()),
        invite_code: read_setting(db, "widget_invite_code")
            .await
            .filter(|c| !c.is_empty()),
    }
}

/// GET /admin/settings/widget
pub async fn get_widget_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<WidgetSettings>, (StatusCode, String)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(HUB_SETTINGS)?;
    Ok(Json(load(&state.db).await))
}

/// PUT /admin/settings/widget
pub async fn put_widget_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<WidgetSettings>,
) -> Result<Json<WidgetSettings>, (StatusCode, String)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(HUB_SETTINGS)?;
    if !MODES.contains(&req.mode.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "mode must be off, counts, names or voice".to_string(),
        ));
    }
    let code = req.invite_code.as_deref().unwrap_or("").trim();
    if code.len() > 64
        || !code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((StatusCode::BAD_REQUEST, "invalid invite_code".to_string()));
    }
    upsert_setting(&state.db, "widget_mode", &req.mode).await?;
    upsert_setting(&state.db, "widget_invite_code", code).await?;
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    Ok(Json(load(&state.db).await))
}

#[derive(Serialize, Clone)]
pub struct WidgetMember {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct WidgetVoiceRoom {
    pub channel: String,
    pub members: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct WidgetData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub online_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<WidgetMember>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice: Option<Vec<WidgetVoiceRoom>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_url: Option<String>,
}

/// The last answer, reused for a few seconds: the endpoint is public, and a
/// popular community's page would otherwise query the hub per visitor.
static CACHE: Mutex<Option<(Instant, Option<WidgetData>)>> = Mutex::new(None);
const CACHE_TTL: Duration = Duration::from_secs(10);

/// What the widget shows now, or None when it is off.
async fn widget_data(state: &AppState) -> Option<WidgetData> {
    if let Some((at, data)) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        if at.elapsed() < CACHE_TTL {
            return data;
        }
    }
    let data = compute(state).await;
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), data.clone()));
    data
}

async fn compute(state: &AppState) -> Option<WidgetData> {
    let settings = load(&state.db).await;
    if settings.mode == "off" {
        return None;
    }
    let online: Vec<String> = state.online_users.read().await.keys().cloned().collect();
    // Invisible stays invisible, an opted-out member is left out, and only
    // members count at all.
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT public_key, display_name, avatar FROM users
         WHERE public_key = ANY($1) AND is_member
           AND NOT widget_hidden
           AND COALESCE(presence_status, '') <> 'invisible'
         ORDER BY LOWER(COALESCE(display_name, ''))",
    )
    .bind(&online)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let name_of = |pk: &str| -> Option<String> {
        rows.iter().find(|(k, _, _)| k == pk).map(|(_, n, _)| {
            n.clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "Member".to_string())
        })
    };
    let branding = crate::routes::hub::read_branding(state).await;
    let members = matches!(settings.mode.as_str(), "names" | "voice").then(|| {
        rows.iter()
            .map(|(_, n, a)| WidgetMember {
                name: n
                    .clone()
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| "Member".to_string()),
                avatar: a.clone().filter(|a| !a.is_empty()),
            })
            .collect()
    });
    let voice = if settings.mode == "voice" {
        let rooms: Vec<(String, Vec<String>)> = state
            .voice_channels
            .read()
            .await
            .iter()
            .map(|(id, parts)| (id.clone(), parts.keys().cloned().collect()))
            .collect();
        let names: Vec<(String, String)> = sqlx::query_as("SELECT id, name FROM channels")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        let mut out: Vec<WidgetVoiceRoom> = rooms
            .into_iter()
            .filter_map(|(id, pks)| {
                let members: Vec<String> = pks.iter().filter_map(|pk| name_of(pk)).collect();
                let channel = names.iter().find(|(c, _)| *c == id)?.1.clone();
                (!members.is_empty()).then_some(WidgetVoiceRoom { channel, members })
            })
            .collect();
        out.sort_by(|a, b| a.channel.cmp(&b.channel));
        Some(out)
    } else {
        None
    };
    let public_url = state.canonical_url.read().await.clone();
    Some(WidgetData {
        name: branding.name,
        icon: branding.icon.filter(|i| !i.is_empty()),
        online_count: rows.len(),
        members,
        voice,
        invite_url: settings
            .invite_code
            .zip(public_url)
            .map(|(code, url)| format!("{}/join/{code}", url.trim_end_matches('/'))),
    })
}

/// GET /public/widget.json — 404 when the widget is off, so a hub that has
/// not turned it on reveals nothing.
pub async fn widget_json(State(state): State<Arc<AppState>>) -> Response {
    match widget_data(&state).await {
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Some(data) => {
            let mut resp = Json(data).into_response();
            let h = resp.headers_mut();
            h.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            );
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=10"),
            );
            resp
        }
    }
}

#[derive(Deserialize)]
pub struct WidgetPageQuery {
    #[serde(default)]
    theme: Option<String>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// GET /widget — a small page for an <iframe>, rendered on the hub with no
/// script. The only response here that may be framed: the client's pages
/// keep `frame-ancestors 'none'`.
pub async fn widget_page(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WidgetPageQuery>,
) -> Response {
    let Some(data) = widget_data(&state).await else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    let dark = q.theme.as_deref() == Some("dark");
    let (bg, fg, muted) = if dark {
        ("#16171a", "#e8e8ea", "#9a9ba1")
    } else {
        ("#ffffff", "#1b1c1f", "#6b6c72")
    };
    let mut body = format!(
        "<h1>{}</h1><p class=m>{} online</p>",
        esc(&data.name),
        data.online_count
    );
    if let Some(voice) = &data.voice {
        for room in voice {
            body.push_str(&format!(
                "<h2>{}</h2><ul>{}</ul>",
                esc(&room.channel),
                room.members
                    .iter()
                    .map(|m| format!("<li>{}</li>", esc(m)))
                    .collect::<String>()
            ));
        }
    }
    if let Some(members) = &data.members {
        body.push_str(&format!(
            "<ul>{}</ul>",
            members
                .iter()
                .map(|m| format!("<li>{}</li>", esc(&m.name)))
                .collect::<String>()
        ));
    }
    if let Some(url) = &data.invite_url {
        body.push_str(&format!(
            "<a class=j href=\"{}\" target=_blank rel=noopener>Join</a>",
            esc(url)
        ));
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
         <style>body{{margin:0;padding:12px;font:14px system-ui,sans-serif;background:{bg};color:{fg}}}\
         h1{{font-size:16px;margin:0}}h2{{font-size:13px;margin:10px 0 2px}}.m{{color:{muted};margin:2px 0 8px}}\
         ul{{margin:0;padding-left:18px}}.j{{display:inline-block;margin-top:10px;padding:6px 12px;border-radius:6px;\
         background:#d99a2b;color:#111;text-decoration:none;font-weight:600}}</style></head><body>{body}</body></html>"
    );
    let mut resp = (StatusCode::OK, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors *",
        ),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=10"),
    );
    resp
}
