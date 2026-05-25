use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i64>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct InviteResponse {
    pub code: String,
    pub created_by: String,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}
