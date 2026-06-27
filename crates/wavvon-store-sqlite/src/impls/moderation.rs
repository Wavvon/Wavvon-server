use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{BanRow, ModerationStore, MuteRow, NewReport, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

#[async_trait]
impl ModerationStore for SqliteStore {
    async fn ban_user(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bans (target_public_key, banned_by, reason, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(target_public_key) DO UPDATE SET
               banned_by = excluded.banned_by,
               reason = excluded.reason,
               created_at = excluded.created_at",
        )
        .bind(target)
        .bind(by)
        .bind(reason)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn unban_user(&self, target: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM bans WHERE target_public_key = ?")
            .bind(target)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_banned(&self, target: &str) -> Result<bool, StoreError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM bans WHERE target_public_key = ?")
                .bind(target)
                .fetch_one(self.pool())
                .await
                .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn list_bans(&self) -> Result<Vec<BanRow>, StoreError> {
        let rows = sqlx::query("SELECT target_public_key, banned_by, reason, created_at FROM bans")
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BanRow {
                target_public_key: r.get("target_public_key"),
                banned_by: r.get("banned_by"),
                reason: r.get("reason"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn mute_user(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO mutes (target_public_key, muted_by, reason, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(target_public_key) DO UPDATE SET
               muted_by = excluded.muted_by,
               reason = excluded.reason,
               expires_at = excluded.expires_at",
        )
        .bind(target)
        .bind(by)
        .bind(reason)
        .bind(expires_at)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn unmute_user(&self, target: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM mutes WHERE target_public_key = ?")
            .bind(target)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_muted(&self, target: &str) -> Result<bool, StoreError> {
        // Muted if a row exists and either expires_at is NULL or in the future.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mutes
             WHERE target_public_key = ?
               AND (expires_at IS NULL OR expires_at > strftime('%s','now'))",
        )
        .bind(target)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn list_mutes(&self) -> Result<Vec<MuteRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT target_public_key, muted_by, reason, expires_at, created_at FROM mutes",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| MuteRow {
                target_public_key: r.get("target_public_key"),
                muted_by: r.get("muted_by"),
                reason: r.get("reason"),
                expires_at: r.get("expires_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn voice_mute(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO voice_mutes (target_public_key, muted_by, reason, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(target_public_key) DO UPDATE SET
               muted_by = excluded.muted_by,
               reason = excluded.reason",
        )
        .bind(target)
        .bind(by)
        .bind(reason)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn voice_unmute(&self, target: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM voice_mutes WHERE target_public_key = ?")
            .bind(target)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_voice_muted(&self, target: &str) -> Result<bool, StoreError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM voice_mutes WHERE target_public_key = ?")
                .bind(target)
                .fetch_one(self.pool())
                .await
                .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn channel_ban(
        &self,
        channel_id: &str,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channel_bans (channel_id, target_public_key, banned_by, reason, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(channel_id, target_public_key) DO UPDATE SET
               banned_by = excluded.banned_by,
               reason = excluded.reason",
        )
        .bind(channel_id)
        .bind(target)
        .bind(by)
        .bind(reason)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn channel_unban(&self, channel_id: &str, target: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM channel_bans WHERE channel_id = ? AND target_public_key = ?")
            .bind(channel_id)
            .bind(target)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_channel_banned(&self, channel_id: &str, target: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_bans
             WHERE channel_id = ? AND target_public_key = ?",
        )
        .bind(channel_id)
        .bind(target)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn create_report(&self, r: &NewReport) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO message_reports
             (id, message_id, reporter_pubkey, reason, reported_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&r.id)
        .bind(&r.message_id)
        .bind(&r.reporter_pubkey)
        .bind(&r.reason)
        .bind(r.reported_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_reports(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NewReport>, StoreError> {
        let rows = if let Some(s) = status {
            sqlx::query(
                "SELECT id, message_id, reporter_pubkey, reason, reported_at
                 FROM message_reports WHERE status = ? ORDER BY reported_at DESC LIMIT ? OFFSET ?",
            )
            .bind(s)
            .bind(limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?
        } else {
            sqlx::query(
                "SELECT id, message_id, reporter_pubkey, reason, reported_at
                 FROM message_reports ORDER BY reported_at DESC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?
        };
        Ok(rows
            .into_iter()
            .map(|r| NewReport {
                id: r.get("id"),
                message_id: r.get("message_id"),
                reporter_pubkey: r.get("reporter_pubkey"),
                reason: r.get("reason"),
                reported_at: r.get("reported_at"),
            })
            .collect())
    }
}
