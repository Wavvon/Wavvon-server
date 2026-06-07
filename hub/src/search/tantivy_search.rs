use std::sync::Arc;

use tantivy::collector::TopDocs;
use tantivy::doc;
use tantivy::query::{BooleanQuery, Occur, QueryParser, TermQuery};
use tantivy::schema::{Field, IndexRecordOption, Schema, Value, FAST, STORED, STRING, TEXT};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};

use crate::search::{IndexedMessage, MessageSearch, SearchHit, SearchParams};

pub struct TantivySearch {
    index: Index,
    writer: Arc<std::sync::Mutex<IndexWriter>>,
    reader: IndexReader,
    id_field: Field,
    channel_field: Field,
    author_field: Field,
    content_field: Field,
    ts_field: Field,
}

impl TantivySearch {
    pub fn open(index_path: &std::path::Path) -> anyhow::Result<Self> {
        let (index, id_field, channel_field, author_field, content_field, ts_field) =
            if index_path.join("meta.json").exists() {
                let index = Index::open_in_dir(index_path)?;
                let schema = index.schema();
                let id_field = schema.get_field("id").unwrap();
                let channel_field = schema.get_field("channel_id").unwrap();
                let author_field = schema.get_field("author").unwrap();
                let content_field = schema.get_field("content").unwrap();
                let ts_field = schema.get_field("ts").unwrap();
                (index, id_field, channel_field, author_field, content_field, ts_field)
            } else {
                std::fs::create_dir_all(index_path)?;
                let mut builder = Schema::builder();
                let id_field = builder.add_text_field("id", STRING | STORED);
                let channel_field = builder.add_text_field("channel_id", STRING | STORED);
                let author_field = builder.add_text_field("author", STRING | STORED);
                let content_field = builder.add_text_field("content", TEXT | STORED);
                let ts_field = builder.add_i64_field("ts", FAST | STORED);
                let schema = builder.build();
                let index = Index::create_in_dir(index_path, schema)?;
                (index, id_field, channel_field, author_field, content_field, ts_field)
            };

        let writer = index.writer(64_000_000)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;

        Ok(Self {
            index,
            writer: Arc::new(std::sync::Mutex::new(writer)),
            reader,
            id_field,
            channel_field,
            author_field,
            content_field,
            ts_field,
        })
    }
}

impl MessageSearch for TantivySearch {
    fn index<'a>(
        &'a self,
        msg: &'a IndexedMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        let writer = self.writer.clone();
        let reader = self.reader.clone();
        let id_field = self.id_field;
        let channel_field = self.channel_field;
        let author_field = self.author_field;
        let content_field = self.content_field;
        let ts_field = self.ts_field;

        // Clone owned data to move into spawn_blocking
        let id = msg.id.clone();
        let channel_id = msg.channel_id.clone();
        let author_pubkey = msg.author_pubkey.clone();
        let content = msg.content.clone();
        let timestamp = msg.timestamp;

        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let doc = doc!(
                    id_field => id.as_str(),
                    channel_field => channel_id.as_str(),
                    author_field => author_pubkey.as_str(),
                    content_field => content.as_str(),
                    ts_field => timestamp,
                );
                let mut w = writer.lock().unwrap();
                w.add_document(doc)?;
                w.commit()?;
                drop(w);
                reader.reload()?;
                Ok::<_, tantivy::TantivyError>(())
            })
            .await
            .unwrap()
            .map_err(anyhow::Error::from)
        })
    }

    fn delete<'a>(
        &'a self,
        msg_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        let writer = self.writer.clone();
        let id_field = self.id_field;
        let msg_id = msg_id.to_string();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let term = Term::from_field_text(id_field, &msg_id);
                let mut w = writer.lock().unwrap();
                w.delete_term(term);
                w.commit()?;
                Ok::<_, tantivy::TantivyError>(())
            })
            .await
            .unwrap()
            .map_err(anyhow::Error::from)
        })
    }

    fn query<'a>(
        &'a self,
        params: &'a SearchParams,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Vec<SearchHit>>> + Send + 'a>,
    > {
        let reader = self.reader.clone();
        let index = self.index.clone();
        let id_field = self.id_field;
        let channel_field = self.channel_field;
        let author_field = self.author_field;
        let content_field = self.content_field;
        let ts_field = self.ts_field;
        let q_str = params.q.clone();
        let channel_ids = params.channel_ids.clone();
        let limit = params.limit;

        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let searcher = reader.searcher();
                let query_parser = QueryParser::for_index(&index, vec![content_field]);
                let text_q = query_parser.parse_query(&q_str)?;

                let final_query: Box<dyn tantivy::query::Query> = if channel_ids.is_empty() {
                    Box::new(text_q)
                } else {
                    let channel_clauses: Vec<(Occur, Box<dyn tantivy::query::Query>)> = channel_ids
                        .iter()
                        .map(|ch| {
                            let term = Term::from_field_text(channel_field, ch);
                            (
                                Occur::Should,
                                Box::new(TermQuery::new(term, IndexRecordOption::Basic))
                                    as Box<dyn tantivy::query::Query>,
                            )
                        })
                        .collect();
                    let channel_filter = BooleanQuery::new(channel_clauses);
                    Box::new(BooleanQuery::new(vec![
                        (
                            Occur::Must,
                            Box::new(text_q) as Box<dyn tantivy::query::Query>,
                        ),
                        (
                            Occur::Must,
                            Box::new(channel_filter) as Box<dyn tantivy::query::Query>,
                        ),
                    ]))
                };

                let top_docs = searcher.search(&final_query, &TopDocs::with_limit(limit))?;

                let hits: Vec<SearchHit> = top_docs
                    .iter()
                    .filter_map(|(score, addr)| {
                        let doc: tantivy::TantivyDocument = searcher.doc(*addr).ok()?;
                        let get_text = |f: Field| {
                            doc.get_first(f)?.as_str().map(|s: &str| s.to_string())
                        };
                        let get_i64 = |f: Field| doc.get_first(f)?.as_i64();

                        let content = get_text(content_field)?;
                        let preview = if content.len() > 200 {
                            let end = content
                                .char_indices()
                                .map(|(i, _)| i)
                                .take_while(|&i| i <= 197)
                                .last()
                                .unwrap_or(0);
                            format!("{}\u{2026}", &content[..end])
                        } else {
                            content
                        };

                        Some(SearchHit {
                            message_id: get_text(id_field)?,
                            channel_id: get_text(channel_field)?,
                            author_pubkey: get_text(author_field)?,
                            content_preview: preview,
                            timestamp: get_i64(ts_field)?,
                            score: *score,
                        })
                    })
                    .collect();

                Ok::<_, tantivy::TantivyError>(hits)
            })
            .await
            .unwrap()
            .map_err(anyhow::Error::from)
        })
    }
}
