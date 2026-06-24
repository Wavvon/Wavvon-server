use async_trait::async_trait;
use sqlx::Row;
use voxply_store::{StoreError, UploadFileRow, UploadStore};

use crate::error_map::map_err;
use crate::SqliteStore;

fn row_to_upload(r: sqlx::any::AnyRow) -> UploadFileRow {
    UploadFileRow {
        id: r.get("id"),
        filename: r.get("filename"),
        original_name: r.get("original_name"),
        mime_type: r.get("mime_type"),
        size_bytes: r.get("size_bytes"),
        uploader_pubkey: r.get("uploader_pubkey"),
        channel_id: r.get("channel_id"),
        created_at: r.get("created_at"),
    }
}

#[async_trait]
impl UploadStore for SqliteStore {
    async fn insert_upload(&self, f: &UploadFileRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO upload_files
             (id, filename, original_name, mime_type, size_bytes, uploader_pubkey, channel_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&f.id)
        .bind(&f.filename)
        .bind(&f.original_name)
        .bind(&f.mime_type)
        .bind(f.size_bytes)
        .bind(&f.uploader_pubkey)
        .bind(&f.channel_id)
        .bind(f.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_upload(&self, id: &str) -> Result<Option<UploadFileRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, filename, original_name, mime_type, size_bytes,
                    uploader_pubkey, channel_id, created_at
             FROM upload_files WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_upload))
    }

    async fn list_uploads(&self, channel_id: &str) -> Result<Vec<UploadFileRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, filename, original_name, mime_type, size_bytes,
                    uploader_pubkey, channel_id, created_at
             FROM upload_files WHERE channel_id = ? ORDER BY created_at DESC",
        )
        .bind(channel_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_upload).collect())
    }

    async fn delete_upload(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM upload_files WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_valid_image_upload(&self, id: &str, channel_id: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM upload_files
             WHERE id = ? AND channel_id = ?
               AND mime_type IN ('image/png','image/jpeg','image/gif','image/webp')",
        )
        .bind(id)
        .bind(channel_id)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }
}
