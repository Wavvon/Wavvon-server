use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PeerInfo {
    pub public_key: String,
    pub name: String,
    pub url: String,
    pub added_at: i64,
}

#[derive(Deserialize)]
pub struct AddPeerRequest {
    pub url: String,
}
