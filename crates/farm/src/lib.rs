pub mod db;
pub mod hub_manager;
pub mod monitor;
pub mod proxy;
pub mod routes;
pub mod server;
pub mod settings;
pub mod state;
pub mod token;

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
