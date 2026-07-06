//! Shared ephemeral-database harness for seed integration tests.
//!
//! Mirrors hub's `tests/common.rs` `TestDbGuard` (hub `e203106`): the test
//! database is dropped when the last guard handle goes out of scope, so
//! `seed_test_*` databases no longer leak into the target Postgres.
//! Teardown runs on a dedicated OS thread with its own runtime (Drop can't
//! be async, and the dropping thread may be inside a current-thread tokio
//! runtime), and uses `DROP DATABASE ... WITH (FORCE)` so leaked pool
//! connections can't block cleanup.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

fn base_db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string())
}

struct TestDbGuardInner {
    db_name: String,
    base_url: String,
}

impl Drop for TestDbGuardInner {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        let base_url = self.base_url.clone();

        let join_result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let admin_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&format!("{base_url}/postgres"))
                    .await?;
                sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                ))
                .execute(&admin_pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
        })
        .join();

        match join_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!(
                    "warning: failed to drop test database {}: {err}",
                    self.db_name
                );
            }
            Err(_) => {
                eprintln!(
                    "warning: teardown thread panicked while dropping test database {}",
                    self.db_name
                );
            }
        }
    }
}

/// Cheaply cloneable handle whose last drop tears down the ephemeral test
/// database. Hold on to it (even via `let _guard = ...`) for as long as the
/// pool/server backed by that database is in use.
#[derive(Clone)]
#[must_use = "dropping this immediately tears down the test database while it may still be in use"]
pub struct TestDbGuard(#[allow(dead_code)] Arc<TestDbGuardInner>);

/// Create a new, isolated `seed_test_<uuid>` database and return the pool
/// together with its teardown guard. Callers run their own migrations.
pub async fn create_test_db() -> (PgPool, TestDbGuard) {
    let base_url = base_db_url();

    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base_url}/postgres"))
        .await
        .expect("Failed to connect to PostgreSQL (admin)");

    let db_name = format!("seed_test_{}", uuid::Uuid::new_v4().simple());

    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin_pool)
        .await
        .expect("Failed to create test database");

    let guard = TestDbGuard(Arc::new(TestDbGuardInner {
        db_name: db_name.clone(),
        base_url: base_url.clone(),
    }));

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("Failed to connect to test database");

    (pool, guard)
}
