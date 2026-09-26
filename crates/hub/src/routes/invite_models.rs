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
    /// `"live"`, `"expired"` or `"used_up"`, computed from the two columns
    /// that can retire an invite. An operator reading the list wants to know
    /// which way in is open, and working that out row by row from `uses`,
    /// `max_uses` and a Unix timestamp is what the admin panel used to ask of
    /// them. Advertised as the `invites.status` capability.
    pub status: String,
}

/// Which of the two ways an invite has retired, or neither.
///
/// `uses >= max_uses` and `expires_at <= now` are exactly the conditions
/// `validate_and_use_invite` refuses on, so this answers what the redemption
/// path would, before anyone spends a code finding out.
pub fn invite_status(
    uses: i64,
    max_uses: Option<i64>,
    expires_at: Option<i64>,
    now: i64,
) -> &'static str {
    if max_uses.is_some_and(|max| uses >= max) {
        "used_up"
    } else if expires_at.is_some_and(|at| at <= now) {
        "expired"
    } else {
        "live"
    }
}
