use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub priority: i64,
    #[serde(default)]
    pub display_separately: bool,
    pub created_at: i64,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub category_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub priority: i64,
    #[serde(default)]
    pub display_separately: bool,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub category_id: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub priority: Option<i64>,
    pub display_separately: Option<bool>,
    /// Tri-state: absent = don't touch, `Some(Some(v))` = set, `Some(None)` = clear.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub color: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub icon: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub category_id: Option<Option<String>>,
}

/// A display-only grouping container for roles. Carries no permissions —
/// see docs/docs/role-categories.md §1.
#[derive(Serialize, Deserialize)]
pub struct RoleCategoryResponse {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub position: i64,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct CreateRoleCategoryRequest {
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub position: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateRoleCategoryRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub color: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub icon: Option<Option<String>>,
    pub position: Option<i64>,
}

/// Lets us distinguish "field missing" from "field explicitly null" in JSON
/// (mirrors the helper in `chat_models.rs`).
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// `#RRGGBB`, case-insensitive hex digits. See docs/docs/role-categories.md §3.
pub fn is_valid_color(color: &str) -> bool {
    let bytes = color.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

/// A single emoji grapheme, max 16 bytes, no whitespace/control characters.
/// We don't attempt full grapheme-cluster segmentation (see
/// docs/docs/role-categories.md §5) — byte-length + char-class checks are
/// enough to keep the column a decoration rather than a text field.
pub fn is_valid_icon(icon: &str) -> bool {
    !icon.is_empty()
        && icon.len() <= 16
        && !icon.chars().any(|c| c.is_whitespace() || c.is_control())
}
