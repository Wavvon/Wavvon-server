use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::hub::{read_branding, upsert_setting};
use crate::state::AppState;

#[derive(Serialize)]
pub struct ListingResponse {
    pub name: String,
    pub description: Option<String>,
    pub public_key: String,
    pub hub_url: String,
    pub tags: Vec<String>,
    pub member_count_approx: i64,
    pub listed: bool,
}

#[derive(Deserialize)]
pub struct PatchListingRequest {
    pub listed: bool,
}

/// GET /federation/listing — public, no auth required.
///
/// Returns hub metadata useful for discovery without going through the
/// central directory.  When `listed` is false the endpoint still returns
/// 200 with all fields populated so clients can probe any hub URL without
/// special-casing 404.
pub async fn get_listing(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListingResponse>, (StatusCode, String)> {
    let branding = read_branding(&state).await;

    let hub_url = std::env::var("WAVVON_HUB_URL").unwrap_or_default();

    let tags = crate::routes::tags::load_tags(&state).await?;

    // Round member count DOWN to the nearest 10 to avoid leaking exact churn.
    let raw_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE approval_status = 'approved'")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let member_count_approx = (raw_count / 10) * 10;

    let listed: bool =
        sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_listed'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .map(|v| v == "true")
            .unwrap_or(false);

    Ok(Json(ListingResponse {
        name: branding.name,
        description: branding.description,
        public_key: state.hub_identity.public_key_hex(),
        hub_url,
        tags,
        member_count_approx,
        listed,
    }))
}

/// PATCH /admin/settings/listing — requires ADMIN.
///
/// Body: `{ "listed": true | false }`
/// Upserts the `hub_listed` key in `hub_settings`.
pub async fn patch_listing(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PatchListingRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    upsert_setting(
        &state.db,
        "hub_listed",
        if req.listed { "true" } else { "false" },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
