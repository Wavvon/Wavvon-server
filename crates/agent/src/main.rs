mod agent;
mod hub_manager;
mod settings;

use hub_manager::HubManager;
use settings::Settings;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cfg = Settings::load().expect("Failed to load config");
    let manager = Arc::new(HubManager::new(cfg.hub_binary.clone(), cfg.base_port));

    loop {
        if let Err(e) = agent::run(&cfg, manager.clone()).await {
            tracing::warn!(error = %e, "Agent disconnected, reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
