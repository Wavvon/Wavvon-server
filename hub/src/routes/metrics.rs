use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct MetricsResponse {
    pub uptime_secs: u64,
    pub db_pool_size: u32,
    pub db_connections_idle: u32,
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> Json<MetricsResponse> {
    let uptime = state.started_at.elapsed().as_secs();
    Json(MetricsResponse {
        uptime_secs: uptime,
        db_pool_size: state.db.size(),
        db_connections_idle: state.db.num_idle() as u32,
    })
}
