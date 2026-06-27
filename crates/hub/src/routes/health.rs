use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::routes::badges::BadgeEnvelope;
use crate::routes::certs::CertRequirement;
use crate::state::AppState;

#[derive(Serialize)]
pub struct GetHealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub db_status: String,
}

pub async fn get_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs();

    let db_status = match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("error: {e}"),
    };

    (
        StatusCode::OK,
        Json(GetHealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds,
            db_status,
        }),
    )
}

pub async fn info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let min_security_level: u32 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_security_level'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let min_pow_level: u8 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'min_pow_level'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let invite_only: bool =
        sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'invite_only'")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|v| v == "true")
            .unwrap_or(false);

    let challenge_mode: String = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'challenge_mode'",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| "off".to_string());

    let self_tags = crate::routes::tags::load_tags(&state)
        .await
        .unwrap_or_default();
    let nsfw = crate::routes::tags::load_nsfw(&state).await;
    let badges = crate::routes::badges::load_active_badges(&state).await;

    let branding = crate::routes::hub::read_branding(&state).await;
    let cert_requirement = crate::routes::certs::load_cert_requirement(&state).await;

    let emoji_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hub_emojis")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or(0);

    // Include the hub key rotation payload if one is active.
    let rotation: Option<serde_json::Value> = std::fs::read_to_string("hub_rotation.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    Json(InfoResponse {
        name: branding.name,
        description: branding.description,
        icon: branding.icon,
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_key: state.hub_identity.public_key_hex(),
        min_security_level,
        min_pow_level,
        invite_only,
        challenge_mode,
        farm_url: state.farm_url.clone(),
        self_tags,
        nsfw,
        badges,
        cert_requirement,
        screen_share_v2: true,
        sfu_url: std::env::var("WAVVON_SFU_URL").ok(),
        emoji_count,
        rotation,
    })
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    pub version: String,
    pub public_key: String,
    pub min_security_level: u32,
    /// Minimum PoW level required to authenticate via the structured
    /// `pow_proof` field in `/auth/verify`. 0 means no PoW required.
    pub min_pow_level: u8,
    pub invite_only: bool,
    #[serde(default)]
    pub challenge_mode: String,
    /// URL of the farm this hub is paired with, or null for self-contained auth.
    /// Clients see this field and route `/auth/*` calls to the farm when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub farm_url: Option<String>,
    /// Hub-authoritative self-tags (free-form search keywords, not trust marks).
    #[serde(default)]
    pub self_tags: Vec<String>,
    /// Whether this hub is marked NSFW by its operator.
    #[serde(default)]
    pub nsfw: bool,
    /// Accepted, non-expired badge envelopes (signed by issuer hubs).
    #[serde(default)]
    pub badges: Vec<BadgeEnvelope>,
    /// Cert admission requirement, or null when cert_mode = 'none'.
    /// Clients read this pre-auth to know which certs to present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_requirement: Option<CertRequirement>,
    /// Signals to clients that this hub supports WebRTC screen-share v2
    /// signaling (SDP/ICE relay). Always true on this build.
    pub screen_share_v2: bool,
    /// Optional URL of an SFU (Selective Forwarding Unit) for this hub.
    /// When set, clients capable of SFU-based video should connect there
    /// instead of doing full mesh WebRTC. Read from `WAVVON_SFU_URL` env var.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sfu_url: Option<String>,
    /// Number of custom emojis uploaded to this hub. Clients can skip
    /// fetching the emoji list when this is 0.
    pub emoji_count: i64,
    /// Hub key rotation payload, present during the transition window after
    /// a `rotate-key` ceremony. Peers verify the old-key signature and
    /// re-pin the new pubkey. Absent when no rotation is in progress.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<serde_json::Value>,
}
