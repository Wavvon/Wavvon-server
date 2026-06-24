pub mod null_search;
pub mod tantivy_search;

#[derive(Debug, Clone)]
pub struct IndexedMessage {
    pub id: String,
    pub channel_id: String,
    pub author_pubkey: String,
    pub content: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct SearchParams {
    pub q: String,
    pub channel_ids: Vec<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchHit {
    pub message_id: String,
    pub channel_id: String,
    pub content_preview: String,
    pub timestamp: i64,
    pub author_pubkey: String,
    pub score: f32,
}

pub trait MessageSearch: Send + Sync {
    fn index<'a>(
        &'a self,
        msg: &'a IndexedMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>;

    fn delete<'a>(
        &'a self,
        msg_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>;

    fn query<'a>(
        &'a self,
        params: &'a SearchParams,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Vec<SearchHit>>> + Send + 'a>,
    >;

    /// Drop the entire index and re-index the provided messages from scratch.
    ///
    /// Used by the admin reindex endpoint. Implementations that don't support
    /// reindexing (e.g. NullSearch) should return `Ok(())` silently.
    fn reindex_all<'a>(
        &'a self,
        messages: Vec<IndexedMessage>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>>;
}
