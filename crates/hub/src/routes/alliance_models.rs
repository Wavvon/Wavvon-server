use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateAllianceRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct AllianceResponse {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct AllianceDetailResponse {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
    pub members: Vec<AllianceMemberInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AllianceMemberInfo {
    pub hub_public_key: String,
    pub hub_name: String,
    pub hub_url: String,
    pub joined_at: i64,
}

#[derive(Deserialize)]
pub struct ShareChannelRequest {
    pub channel_id: String,
    /// When true, sharing this channel also shares its whole subtree
    /// (categories/sub-categories/channels beneath it), computed live at
    /// read time rather than snapshotted. Defaults to false so sharing a
    /// single leaf channel behaves exactly as before.
    #[serde(default)]
    pub include_descendants: bool,
    /// Federated-forum-write policy for this share (forum.md §9
    /// "Threat-model deltas"): `"none"` | `"replies_only"` |
    /// `"posts_and_replies"`. `None` leaves the existing value untouched on
    /// a re-share (or applies the DB default, `"replies_only"`, on first
    /// share) rather than forcing every caller to always restate it.
    #[serde(default)]
    pub forum_remote_write: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SharedChannelResponse {
    pub channel_id: String,
    pub channel_name: String,
    pub hub_public_key: String,
    pub hub_name: String,
    /// "text" | "forum" | "banner" | "spawner". Always "text" for
    /// categories. Defaults to "text" so responses from peers that haven't
    /// upgraded yet still parse.
    #[serde(default = "default_channel_type")]
    pub channel_type: String,
    /// Null unless the parent is itself in the effective shared set, so
    /// entries always form well-rooted trees on the receiving side.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Whether this entry is a container (category) rather than a leaf.
    #[serde(default)]
    pub is_category: bool,
    /// Federated-forum-write policy in effect for this share (forum.md §9):
    /// `"none"` | `"replies_only"` | `"posts_and_replies"`. Defaults to
    /// `"replies_only"` so responses from peers that haven't upgraded yet
    /// still parse under the same default the migration applies.
    #[serde(default = "default_forum_remote_write")]
    pub forum_remote_write: String,
}

fn default_channel_type() -> String {
    "text".to_string()
}

fn default_forum_remote_write() -> String {
    "replies_only".to_string()
}

#[derive(Serialize, Deserialize)]
pub struct AllianceInviteResponse {
    pub token: String,
    pub alliance_id: String,
    pub alliance_name: String,
    pub hub_url: String,
}

#[derive(Deserialize)]
pub struct JoinAllianceRequest {
    pub invite_token: String,
    pub hub_url: String,
}

/// Request body for the joining-side endpoint: this hub's user pastes the
/// invite, we call out to the inviter to register, then mirror the alliance
/// into our own DB so it shows up in our list.
#[derive(Deserialize)]
pub struct JoinAllianceLocalRequest {
    pub inviter_hub_url: String,
    pub alliance_id: String,
    pub invite_token: String,
    pub own_hub_url: String,
}

/// Admin-initiated push invite: Hub A sends this to trigger an outbound invite
/// directly to Hub B's federation endpoint.
#[derive(Deserialize)]
pub struct PushInviteRequest {
    pub target_hub_url: String,
    pub own_hub_url: String,
    pub message: Option<String>,
}

/// Accept a pending push invite. Hub B must supply its own publicly reachable
/// URL so Hub A can call back to fetch hub info and register the join.
#[derive(Deserialize)]
pub struct AcceptPendingInviteRequest {
    pub own_hub_url: String,
}

/// Payload sent from Hub A to Hub B's `/federation/alliance-invite` endpoint.
#[derive(Serialize, Deserialize)]
pub struct FederationAllianceInvitePayload {
    pub id: String,
    pub alliance_id: String,
    pub alliance_name: String,
    pub from_hub_url: String,
    pub from_hub_name: String,
    pub from_hub_public_key: String,
    pub invite_token: String,
    pub message: Option<String>,
}

/// A row from `pending_alliance_invites` as returned to the client.
#[derive(Serialize, Deserialize)]
pub struct PendingAllianceInviteRow {
    pub id: String,
    pub alliance_id: String,
    pub alliance_name: String,
    pub from_hub_url: String,
    pub from_hub_name: String,
    pub from_hub_public_key: String,
    pub invite_token: String,
    pub created_at: i64,
    pub message: Option<String>,
}
