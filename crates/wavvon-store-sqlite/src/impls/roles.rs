use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{NewRole, RoleRow, RoleStore, StoreError, UserPerms};

use crate::error_map::map_err;
use crate::SqliteStore;

fn row_to_role(r: sqlx::any::AnyRow) -> RoleRow {
    RoleRow {
        id: r.get("id"),
        name: r.get("name"),
        priority: r.get("priority"),
        display_separately: r.get("display_separately"),
        created_at: r.get("created_at"),
        talk_power: r.try_get("talk_power").unwrap_or(0),
    }
}

#[async_trait]
impl RoleStore for SqliteStore {
    async fn create_role(&self, r: &NewRole) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO roles (id, name, priority, display_separately, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&r.id)
        .bind(&r.name)
        .bind(r.priority)
        .bind(if r.display_separately { 1i64 } else { 0 })
        .bind(r.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;

        for perm in &r.permissions {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
                .bind(&r.id)
                .bind(perm)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
        }
        Ok(())
    }

    async fn list_roles(&self) -> Result<Vec<RoleRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, priority, display_separately, created_at, talk_power
             FROM roles ORDER BY priority DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_role).collect())
    }

    async fn get_role(&self, role_id: &str) -> Result<Option<RoleRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, priority, display_separately, created_at, talk_power
             FROM roles WHERE id = ?",
        )
        .bind(role_id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_role))
    }

    async fn delete_role(&self, role_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_role_name(&self, role_id: &str, name: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE roles SET name = ? WHERE id = ?")
            .bind(name)
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_role_priority(&self, role_id: &str, priority: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE roles SET priority = ? WHERE id = ?")
            .bind(priority)
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_display_separately(&self, role_id: &str, flag: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE roles SET display_separately = ? WHERE id = ?")
            .bind(if flag { 1i64 } else { 0 })
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn role_permissions(&self, role_id: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT permission FROM role_permissions WHERE role_id = ?")
            .bind(role_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)
    }

    async fn set_role_permissions(
        &self,
        role_id: &str,
        perms: &[String],
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        for perm in perms {
            sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES (?, ?)")
                .bind(role_id)
                .bind(perm)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
        }
        Ok(())
    }

    async fn assign_role(&self, pubkey: &str, role_id: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
             VALUES (?, ?, ?) ON CONFLICT (user_public_key, role_id) DO NOTHING",
        )
        .bind(pubkey)
        .bind(role_id)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_role(&self, pubkey: &str, role_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM user_roles WHERE user_public_key = ? AND role_id = ?")
            .bind(pubkey)
            .bind(role_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn user_roles(&self, pubkey: &str) -> Result<Vec<RoleRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT r.id, r.name, r.priority, r.display_separately, r.created_at, r.talk_power
             FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_public_key = ?
             ORDER BY r.priority DESC",
        )
        .bind(pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_role).collect())
    }

    async fn role_members(&self, role_id: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT user_public_key FROM user_roles WHERE role_id = ?")
            .bind(role_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)
    }

    async fn role_member_count(&self, role_id: &str) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_roles WHERE role_id = ?")
            .bind(role_id)
            .fetch_one(self.pool())
            .await
            .map_err(map_err)
    }

    async fn user_permissions(&self, pubkey: &str) -> Result<UserPerms, StoreError> {
        let roles = self.user_roles(pubkey).await?;
        let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();

        let effective: HashSet<String> = if role_ids.is_empty() {
            HashSet::new()
        } else {
            let placeholders = role_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT DISTINCT permission FROM role_permissions WHERE role_id IN ({placeholders})"
            );
            let mut q = sqlx::query_scalar::<_, String>(&sql);
            for id in &role_ids {
                q = q.bind(*id);
            }
            q.fetch_all(self.pool())
                .await
                .map_err(map_err)?
                .into_iter()
                .collect()
        };

        let max_priority = roles.iter().map(|r| r.priority).max().unwrap_or(0);

        Ok(UserPerms {
            roles,
            effective,
            max_priority,
        })
    }
}
