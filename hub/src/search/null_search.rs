use crate::search::{IndexedMessage, MessageSearch, SearchHit, SearchParams};

pub struct NullSearch;

impl MessageSearch for NullSearch {
    fn index<'a>(
        &'a self,
        _msg: &'a IndexedMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn delete<'a>(
        &'a self,
        _msg_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn query<'a>(
        &'a self,
        _params: &'a SearchParams,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Vec<SearchHit>>> + Send + 'a>,
    > {
        Box::pin(async { Ok(vec![]) })
    }

    fn reindex_all<'a>(
        &'a self,
        _messages: Vec<crate::search::IndexedMessage>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
