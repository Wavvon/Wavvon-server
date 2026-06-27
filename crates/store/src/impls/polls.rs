use crate::{PollRow, PollStore, PollVoteRow, StoreError};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

fn row_to_poll(r: sqlx::postgres::PgRow) -> PollRow {
    PollRow {
        id: r.get("id"),
        channel_id: r.get("channel_id"),
        creator_pubkey: r.get("creator_pubkey"),
        question: r.get("question"),
        options: r.get("options"),
        ends_at: r.get("ends_at"),
        max_choices: r.get("max_choices"),
        created_at: r.get("created_at"),
    }
}

#[async_trait]
impl PollStore for PostgresStore {
    async fn create_poll(&self, p: &PollRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO polls
             (id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&p.id)
        .bind(&p.channel_id)
        .bind(&p.creator_pubkey)
        .bind(&p.question)
        .bind(&p.options)
        .bind(p.ends_at)
        .bind(p.max_choices)
        .bind(p.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_poll(&self, id: &str) -> Result<Option<PollRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at
             FROM polls WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_poll))
    }

    async fn list_polls(&self, channel_id: &str) -> Result<Vec<PollRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at
             FROM polls WHERE channel_id = $1 ORDER BY created_at DESC",
        )
        .bind(channel_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_poll).collect())
    }

    async fn delete_poll(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM polls WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn cast_vote(
        &self,
        poll_id: &str,
        user_pubkey: &str,
        option_ids: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO poll_votes (poll_id, user_pubkey, option_ids)
             VALUES ($1, $2, $3)
             ON CONFLICT(poll_id, user_pubkey) DO UPDATE SET option_ids = excluded.option_ids",
        )
        .bind(poll_id)
        .bind(user_pubkey)
        .bind(option_ids)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_vote(
        &self,
        poll_id: &str,
        user_pubkey: &str,
    ) -> Result<Option<PollVoteRow>, StoreError> {
        let row = sqlx::query(
            "SELECT poll_id, user_pubkey, option_ids FROM poll_votes
             WHERE poll_id = $1 AND user_pubkey = $2",
        )
        .bind(poll_id)
        .bind(user_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| PollVoteRow {
            poll_id: r.get("poll_id"),
            user_pubkey: r.get("user_pubkey"),
            option_ids: r.get("option_ids"),
        }))
    }

    async fn list_votes(&self, poll_id: &str) -> Result<Vec<PollVoteRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT poll_id, user_pubkey, option_ids FROM poll_votes WHERE poll_id = $1",
        )
        .bind(poll_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| PollVoteRow {
                poll_id: r.get("poll_id"),
                user_pubkey: r.get("user_pubkey"),
                option_ids: r.get("option_ids"),
            })
            .collect())
    }

    async fn delete_vote(&self, poll_id: &str, user_pubkey: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM poll_votes WHERE poll_id = $1 AND user_pubkey = $2")
            .bind(poll_id)
            .bind(user_pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }
}
