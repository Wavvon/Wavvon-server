use serde::Deserialize;

/// Page size when a client asks for none.
pub const DEFAULT_LIMIT: i64 = 100;
/// Hard ceiling, so a client cannot ask for the whole table in one round-trip.
pub const MAX_LIMIT: i64 = 500;

/// The hub's list dialect: `limit` plus a keyset `cursor` holding the id of
/// the last row of the previous page. One shared shape rather than one
/// `Deserialize` struct per handler — the endpoints differ in what the cursor
/// resolves against, not in how it arrives.
///
/// Keyset rather than OFFSET on purpose: these lists are ordered by a
/// timestamp and rows are inserted at the head, so an OFFSET page shifts under
/// a reader mid-scroll and duplicates or skips a row.
#[derive(Deserialize, Default)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

impl PageQuery {
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }

    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}
