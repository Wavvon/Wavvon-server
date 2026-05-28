use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::state::FarmState;

#[derive(Serialize)]
pub struct FarmInfoResponse {
    pub kind: &'static str,
    pub version: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub public_key: String,
    pub directory_public: bool,
    pub auth: AuthUrls,
}

#[derive(Serialize)]
pub struct AuthUrls {
    pub challenge_url: &'static str,
    pub verify_url: &'static str,
    pub renew_url: &'static str,
}

pub async fn farm_info(State(state): State<Arc<FarmState>>) -> Json<FarmInfoResponse> {
    // Read name/description from the farms singleton row (id=1).
    // If the row doesn't exist yet (first request before bootstrap completes)
    // fall back to sensible defaults.
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT name, description FROM farms WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let (name, description) = row.unwrap_or_else(|| ("My Farm".to_string(), None));

    let directory_public: bool =
        sqlx::query_scalar::<_, i64>("SELECT directory_public FROM farms WHERE id = 1")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|v| v != 0)
            .unwrap_or(false);

    Json(FarmInfoResponse {
        kind: "voxply-farm",
        version: env!("CARGO_PKG_VERSION"),
        name,
        description,
        public_key: state.public_key_hex(),
        directory_public,
        auth: AuthUrls {
            challenge_url: "/auth/challenge",
            verify_url: "/auth/verify",
            renew_url: "/auth/renew",
        },
    })
}
