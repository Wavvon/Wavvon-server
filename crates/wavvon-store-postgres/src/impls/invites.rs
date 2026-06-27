use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{InviteRow, InviteStore, StoreError};

use crate::error_map::map_err;
use crate::PostgresStore;

fn row_to_invite(r: sqlx::postgres::PgRow) -> InviteRow {
    InviteRow {
        code: r.get("code"),
        created_by: r.get("created_by"),
        max_uses: r.get("max_uses"),
        uses: r.get("uses"),
        expires_at: r.get("expires_at"),
        created_at: r.get("created_at"),
    }
}

#[async_trait]
impl InviteStore for PostgresStore {
    async fn create_invite(
        &self,
        code: &str,
        by: &str,
        max_uses: Option<i64>,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at)
             VALUES ($1, $2, $3, 0, $4, $5)",
        )
        .bind(code)
        .bind(by)
        .bind(max_uses)
        .bind(expires_at)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_invite(&self, code: &str) -> Result<Option<InviteRow>, StoreError> {
        let row = sqlx::query(
            "SELECT code, created_by, max_uses, uses, expires_at, created_at
             FROM invites WHERE code = $1",
        )
        .bind(code)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_invite))
    }

    async fn list_invites(&self) -> Result<Vec<InviteRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT code, created_by, max_uses, uses, expires_at, created_at
             FROM invites ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_invite).collect())
    }

    async fn consume_invite(&self, code: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE invites SET uses = uses + 1 WHERE code = $1")
            .bind(code)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_invite(&self, code: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM invites WHERE code = $1")
            .bind(code)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }
}
