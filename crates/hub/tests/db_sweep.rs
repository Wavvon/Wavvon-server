//! Manual maintenance entry point — NOT part of the normal test run.
//!
//! Drops every leftover `wavvon_test_*` database on the target Postgres
//! server. Useful after a backlog has built up (e.g. from runs predating
//! the per-test `TestDbGuard` teardown, or from a hard-killed test binary
//! that never got to run its `Drop` impls).
//!
//! Run explicitly with:
//!   cargo test -p wavvon-hub --test db_sweep -- --ignored --nocapture

#[path = "common.rs"]
mod common;

#[tokio::test]
#[ignore]
async fn sweep_stale_test_databases() {
    let dropped = common::sweep_stale_test_databases().await;
    println!("dropped {dropped} stale wavvon_test_* database(s)");
}
