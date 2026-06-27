use crate::error::StoreError;
use crate::row_types::UploadFileRow;
use async_trait::async_trait;

#[async_trait]
pub trait UploadStore: Send + Sync {
    async fn insert_upload(&self, f: &UploadFileRow) -> Result<(), StoreError>;

    async fn get_upload(&self, id: &str) -> Result<Option<UploadFileRow>, StoreError>;

    async fn list_uploads(&self, channel_id: &str) -> Result<Vec<UploadFileRow>, StoreError>;

    async fn delete_upload(&self, id: &str) -> Result<(), StoreError>;

    /// Verify that `id` is a valid image upload in the given channel.
    async fn is_valid_image_upload(&self, id: &str, channel_id: &str) -> Result<bool, StoreError>;
}
