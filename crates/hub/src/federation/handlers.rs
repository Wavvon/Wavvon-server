use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::federation::models::{AddPeerRequest, PeerInfo};
use crate::permissions;
use crate::state::AppState;

pub async fn add_peer(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AddPeerRequest>,
) -> Result<(StatusCode, Json<PeerInfo>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ALLIANCES_PEERS)?;

    let url = req.url.trim_end_matches('/').to_string();

    // Discover the remote hub
    let info = state
        .federation_client
        .get_info(&url)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Cannot reach peer: {e}")))?;

    // Authenticate our hub to the remote hub
    let token = state
        .federation_client
        .authenticate(&url, &state.hub_identity)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Handshake failed: {e}")))?;

    let now = crate::auth::handlers::unix_timestamp();

    // Store the peer in DB
    sqlx::query(
        "INSERT INTO peers (public_key, name, url, added_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT(public_key) DO UPDATE SET name = $5, url = $6",
    )
    .bind(&info.public_key)
    .bind(&info.name)
    .bind(&url)
    .bind(now)
    .bind(&info.name)
    .bind(&url)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Cache the session token in memory
    state
        .peer_tokens
        .write()
        .await
        .insert(info.public_key.clone(), token);

    tracing::info!(
        "Peered with hub '{}' ({})",
        info.name,
        &info.public_key[..16]
    );

    Ok((
        StatusCode::CREATED,
        Json(PeerInfo {
            public_key: info.public_key,
            name: info.name,
            url,
            added_at: now,
        }),
    ))
}

pub async fn list_peers(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<PeerInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, PeerRow>(
        "SELECT public_key, name, url, added_at FROM peers ORDER BY added_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let peers = rows
        .into_iter()
        .map(|r| PeerInfo {
            public_key: r.public_key,
            name: r.name,
            url: r.url,
            added_at: r.added_at,
        })
        .collect();

    Ok(Json(peers))
}

// ---------------------------------------------------------------------------
// Federation: badge-offer endpoint (unauthenticated, signature is the auth)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct BadgeOfferRequest {
    /// Hex Ed25519 public key of the hub sending the offer.
    pub from_hub_pubkey: String,
    /// Self-reported URL of the issuer hub (informational, not trusted for routing).
    pub from_hub_url: String,
    /// Human-readable badge label.
    pub label: String,
    /// Optional human-readable note from the issuer.
    pub note: Option<String>,
    /// Canonical JSON payload (BadgePayload serialised deterministically).
    pub payload: String,
    /// Hex Ed25519 signature over `payload` bytes.
    pub signature: String,
}

/// POST /federation/badge-offer
///
/// Unauthenticated endpoint: anyone can POST here, but we require a valid
/// Ed25519 signature from `from_hub_pubkey` over `payload` bytes, and we
/// verify that `payload.subject_pubkey` matches this hub's own public key.
/// Valid offers land in `badge_offers` for the admin to accept or decline.
pub async fn receive_badge_offer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BadgeOfferRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Rate limit: 20 badge offers per hour per sender hub pubkey.
    {
        let mut map = state
            .rate_limiters
            .badge_offer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(3600);
        const EVICTION_THRESHOLD: usize = 2_000;
        if map.len() >= EVICTION_THRESHOLD {
            map.retain(|_, (_, ts)| now.duration_since(*ts) <= window);
        }
        let entry = map.entry(req.from_hub_pubkey.clone()).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (0, now);
        }
        if entry.0 >= 20 {
            return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()));
        }
        entry.0 += 1;
    }

    // 1. Parse and validate payload shape.
    let payload: crate::routes::badges::BadgePayload =
        serde_json::from_str(&req.payload).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Malformed badge payload JSON".to_string(),
            )
        })?;

    // 2. Verify that the subject is this hub.
    let our_pubkey = state.hub_identity.public_key_hex();
    if payload.subject_pubkey != our_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "Badge subject_pubkey does not match this hub".to_string(),
        ));
    }

    // 3. Verify Ed25519 signature: from_hub_pubkey signs the payload bytes.
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    wavvon_identity::verify_signature(&req.from_hub_pubkey, req.payload.as_bytes(), &sig_bytes)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Badge signature verification failed".to_string(),
            )
        })?;

    // 4. Also validate that the issuer_pubkey in the payload matches from_hub_pubkey.
    if payload.issuer_pubkey != req.from_hub_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "payload.issuer_pubkey does not match from_hub_pubkey".to_string(),
        ));
    }

    // Reject duplicate: same hub + identical payload already pending admin review.
    let duplicate_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM badge_offers WHERE from_hub_pubkey = $1 AND payload = $2",
    )
    .bind(&req.from_hub_pubkey)
    .bind(&req.payload)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    if duplicate_count > 0 {
        return Ok(StatusCode::ACCEPTED);
    }

    let id = Uuid::new_v4().to_string();
    let created_at: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    sqlx::query(
        "INSERT INTO badge_offers
         (id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&req.from_hub_pubkey)
    .bind(&req.from_hub_url)
    .bind(&req.label)
    .bind(&req.note)
    .bind(&req.payload)
    .bind(&req.signature)
    .bind(created_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Received badge offer '{}' from {} ({})",
        req.label,
        req.from_hub_url,
        &req.from_hub_pubkey[..16.min(req.from_hub_pubkey.len())]
    );

    Ok(StatusCode::CREATED)
}

// Helpers

#[derive(sqlx::FromRow)]
struct PeerRow {
    public_key: String,
    name: String,
    url: String,
    added_at: i64,
}
