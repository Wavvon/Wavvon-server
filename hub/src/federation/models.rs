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

#[derive(Serialize, Deserialize)]
pub struct FederatedChannelResponse {
    pub id: String,
    pub peer_public_key: String,
    pub remote_id: String,
    pub name: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct FederatedMessageResponse {
    pub id: String,
    pub remote_id: String,
    pub sender: String,
    pub content: String,
    pub created_at: i64,
}
