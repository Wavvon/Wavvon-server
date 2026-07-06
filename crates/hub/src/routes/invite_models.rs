use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i64>,
    pub expires_in_seconds: Option<i64>,
    /// Role to grant the joining user in addition to `builtin-everyone`
    /// (task #34). Must exist and must be strictly below the creator's own
    /// max role priority — see `routes::invites::create_invite`.
    pub grant_role_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct InviteResponse {
    pub code: String,
    pub created_by: String,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub grant_role_id: Option<String>,
}
