//! `db move` — copying a hub's database to another PostgreSQL.
//!
//! Run against the **bundled** PostgreSQL rather than a system one, which is
//! the point of having bundled it: no client tools to install, and the server
//! and the `pg_dump`/`pg_restore` doing the work are the same version by
//! construction — the one thing a dump/restore is most sensitive to. It also
//! means this file cannot skip itself on a machine without PostgreSQL, and a
//! test that can skip is a test that eventually does.
//!
//! What is checked is what can only go wrong between two databases: a
//! destination that already holds somebody's hub, a move onto itself, and
//! counts that must match on the far side or the move was partial.

use std::path::PathBuf;
use std::sync::OnceLock;

use tokio::sync::{Mutex, MutexGuard};

use wavvon_hub::db::{dump, migrations};
use wavvon_hub::embedded_pg::{self, EmbeddedPostgres};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best effort: PostgreSQL may still hold the directory open on
        // Windows when the test ends.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `WAVVON_PG_BIN_DIR` is process-wide and each instance installs its client
/// tools inside its own scratch directory, which the test then deletes — so two
/// of these alive at once means one test can be pointed at the other's
/// `pg_dump`, and at a deleted directory once that test finishes. Two of the
/// three tests here failed exactly that way on a 4-thread runner while passing
/// locally. One instance at a time, and the hint always names the live one.
fn pg_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// One bundled server per test, with its own data directory. The guard comes
/// back first so it outlives the instance and its scratch directory.
async fn embedded() -> (MutexGuard<'static, ()>, EmbeddedPostgres, Scratch) {
    let guard = pg_lock().lock().await;
    let dir = std::env::temp_dir().join(format!(
        "wavvon-dbmove-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let pg = embedded_pg::start(&dir).await.expect("bundled PostgreSQL");
    // Each test runs its own instance in its own directory, and a finished
    // test takes its directory with it — so the process-wide hint the hub sets
    // once at startup has to be re-pointed at whichever server is alive now.
    std::env::set_var("WAVVON_PG_BIN_DIR", pg.bin_dir());
    (guard, pg, Scratch(dir))
}

async fn connect(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect")
}

async fn seeded_hub(pool: &sqlx::PgPool) {
    migrations::run(pool).await.expect("migrations");
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at) VALUES ('owner', 0, 0)",
    )
    .execute(pool)
    .await
    .expect("a user");
    sqlx::query(
        "INSERT INTO channels (id, name, created_by, created_at) VALUES ('c1', 'general', 'owner', 0)",
    )
    .execute(pool)
    .await
    .expect("a channel");
}

#[tokio::test]
async fn a_move_copies_the_data_and_leaves_the_source_alone() {
    let (_pg_lock, pg, _scratch) = embedded().await;
    let source_url = pg.create_database("move_source").await.expect("source db");
    let target_url = pg.create_database("move_target").await.expect("target db");

    let source = connect(&source_url).await;
    let target = connect(&target_url).await;
    seeded_hub(&source).await;

    let report = dump::move_database(&source_url, &target_url, false)
        .await
        .expect("a move into an empty destination must succeed");
    assert!(report.tables > 0 && report.rows > 0);

    let name: String = sqlx::query_scalar("SELECT name FROM channels WHERE id = 'c1'")
        .fetch_one(&target)
        .await
        .expect("the row must be on the far side");
    assert_eq!(name, "general");

    // Copies, and stops. The whole reason this is safe to try is that the
    // source is still there when the destination disappoints you.
    let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(&source)
        .await
        .expect("the source must still answer");
    assert_eq!(still_there, 1, "a move must not empty the source");

    source.close().await;
    target.close().await;
    pg.stop().await.expect("stop");
}

/// The destination already holds somebody's hub. Writing into it merges two
/// communities into one, and there is no undo for that.
#[tokio::test]
async fn a_destination_that_already_holds_a_hub_is_refused() {
    let (_pg_lock, pg, _scratch) = embedded().await;
    let source_url = pg
        .create_database("refuse_source")
        .await
        .expect("source db");
    let target_url = pg
        .create_database("refuse_target")
        .await
        .expect("target db");

    let source = connect(&source_url).await;
    let target = connect(&target_url).await;
    seeded_hub(&source).await;
    seeded_hub(&target).await;

    let err = match dump::move_database(&source_url, &target_url, false).await {
        Ok(_) => panic!("a non-empty destination must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("already has tables"), "got: {err}");

    // --force is the operator saying they meant this one.
    dump::move_database(&source_url, &target_url, true)
        .await
        .expect("--force must go through");

    source.close().await;
    target.close().await;
    pg.stop().await.expect("stop");
}

/// Moving a database onto itself is a typo, not an operation — and one that
/// would run `pg_restore` over the database it is dumping.
#[tokio::test]
async fn moving_a_database_onto_itself_is_refused() {
    let (_pg_lock, pg, _scratch) = embedded().await;
    let url = pg.create_database("self_move").await.expect("db");
    assert!(dump::move_database(&url, &url, true).await.is_err());
    pg.stop().await.expect("stop");
}
