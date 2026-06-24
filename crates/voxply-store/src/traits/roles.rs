use crate::error::StoreError;
use crate::row_types::{NewRole, RoleRow, UserPerms};
use async_trait::async_trait;

#[async_trait]
pub trait RoleStore: Send + Sync {
    /// Insert a new role.
    async fn create_role(&self, r: &NewRole) -> Result<(), StoreError>;

    /// List all roles ordered by priority DESC.
    async fn list_roles(&self) -> Result<Vec<RoleRow>, StoreError>;

    /// Fetch a single role by ID.
    async fn get_role(&self, role_id: &str) -> Result<Option<RoleRow>, StoreError>;

    /// Delete a role (caller removes user_roles first).
    async fn delete_role(&self, role_id: &str) -> Result<(), StoreError>;

    /// Update role name.
    async fn set_role_name(&self, role_id: &str, name: &str) -> Result<(), StoreError>;

    /// Update role priority.
    async fn set_role_priority(&self, role_id: &str, priority: i64) -> Result<(), StoreError>;

    /// Update display_separately flag.
    async fn set_display_separately(&self, role_id: &str, flag: bool) -> Result<(), StoreError>;

    /// Fetch permissions granted to a role.
    async fn role_permissions(&self, role_id: &str) -> Result<Vec<String>, StoreError>;

    /// Replace the permission set for a role (DELETE + INSERT).
    async fn set_role_permissions(&self, role_id: &str, perms: &[String])
        -> Result<(), StoreError>;

    /// Assign a role to a user (INSERT … ON CONFLICT DO NOTHING).
    async fn assign_role(&self, pubkey: &str, role_id: &str, now: i64) -> Result<(), StoreError>;

    /// Remove a role from a user.
    async fn remove_role(&self, pubkey: &str, role_id: &str) -> Result<(), StoreError>;

    /// Return all roles held by a user.
    async fn user_roles(&self, pubkey: &str) -> Result<Vec<RoleRow>, StoreError>;

    /// Return all pubkeys holding a given role.
    async fn role_members(&self, role_id: &str) -> Result<Vec<String>, StoreError>;

    /// Count members holding a given role.
    async fn role_member_count(&self, role_id: &str) -> Result<i64, StoreError>;

    /// Return the effective permission set for a user (union of all assigned roles).
    async fn user_permissions(&self, pubkey: &str) -> Result<UserPerms, StoreError>;
}
