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
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub priority: i64,
    #[serde(default)]
    pub display_separately: bool,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub priority: Option<i64>,
    pub display_separately: Option<bool>,
}
