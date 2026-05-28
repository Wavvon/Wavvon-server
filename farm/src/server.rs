use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::FarmState;

pub fn create_router(state: Arc<FarmState>) -> Router {
    Router::new()
        // Public probe endpoint — the hub fetches this on startup to cache the pubkey.
        .route("/farm/info", get(routes::health::farm_info))
        // Auth endpoints — same wire shape as the hub's existing auth routes.
        .route("/auth/challenge", post(routes::auth::challenge))
        .route("/auth/verify", post(routes::auth::verify))
        .route("/auth/renew", post(routes::auth::renew))
        // Belt-and-braces revocation check for hubs.
        .route("/farm/auth/revoke-check", post(routes::revoke::revoke_check))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
