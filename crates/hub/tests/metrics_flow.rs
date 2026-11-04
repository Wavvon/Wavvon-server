use std::sync::Arc;

use axum_test::TestServer;
use wavvon_hub::server;
use wavvon_hub::state::AppState;

#[path = "common.rs"]
mod common;

// `GET /metrics` is opt-in (decisions.md, "Observability"): a hub that has
// not set WAVVON_METRICS answers as if the route did not exist.
async fn metrics_status(enabled: bool) -> axum::http::StatusCode {
    let (db, _guard) = common::create_test_db().await;
    let state = Arc::new(AppState {
        metrics_enabled: enabled,
        ..common::base_state(db)
    });
    let server = TestServer::new(server::create_router(state));
    server.get("/metrics").await.status_code()
}

#[tokio::test]
async fn metrics_are_not_served_by_default() {
    assert_eq!(metrics_status(false).await, 404);
}

#[tokio::test]
async fn metrics_are_served_when_the_operator_opts_in() {
    assert_eq!(metrics_status(true).await, 200);
}
