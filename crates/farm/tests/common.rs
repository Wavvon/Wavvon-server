//! Shared ephemeral-database harness for farm integration tests.
//!
//! Mirrors hub's `tests/common.rs` `TestDbGuard` (hub `e203106`): the test
//! database is dropped when the last guard handle goes out of scope, so
//! `wavvon_farm_test_*` databases no longer leak into the target Postgres.
//! Teardown runs on a dedicated OS thread with its own runtime (Drop can't
//! be async, and the dropping thread may be inside a current-thread tokio
//! runtime), and uses `DROP DATABASE ... WITH (FORCE)` so leaked pool
//! connections can't block cleanup.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// The PostgreSQL server the suite runs against.
///
/// Public because a farm harness has to hand it to `HubManager`: creating a
/// hub now provisions that hub its own database, and refuses the creation if
/// it cannot — starting a hub on the shared default is the bug per-hub
/// databases replaced, so there is no "skip it in tests" path that still
/// exercises the real code.
pub fn base_db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string())
}

/// The database a hub `db_url` names, when the name is one this harness is
/// allowed to drop. Schema-isolated hubs share the farm database and so name
/// it instead — that one is dropped by name anyway, and `IF EXISTS` makes the
/// second attempt a no-op.
fn hub_db_name(db_url: &str) -> Option<String> {
    let name = db_url
        .rsplit('/')
        .next()?
        .split(['?', '#'])
        .next()?
        .to_string();
    name.starts_with("wavvon_hub_").then_some(name)
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
                // Hub databases provisioned during the test (db/provision.rs
                // creates one per created hub). They are not children of the
                // farm database and nothing else would ever remove them, so
                // they would pile up on the test server exactly the way the
                // per-test farm databases used to.
                //
                // Read which ones are ours *before* dropping the farm database
                // that records them. This used to be a
                // `LIKE 'wavvon_hub_%'` sweep of the whole server, which meant
                // every finishing test force-dropped the hub databases of every
                // test still running — the sibling lost its database mid-request
                // and answered 500, so `farm_hub_e2e` failed whenever two tests
                // overlapped in the wrong order. A developer running the suite
                // against a Postgres that also hosts real farm-managed hubs lost
                // those too: the names match.
                let admin_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&format!("{base_url}/postgres"))
                    .await?;

                let ours: Vec<String> = match PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&format!("{base_url}/{db_name}"))
                    .await
                {
                    Ok(farm_pool) => {
                        let urls: Vec<String> =
                            sqlx::query_scalar("SELECT db_url FROM hubs WHERE db_url IS NOT NULL")
                                .fetch_all(&farm_pool)
                                .await
                                .unwrap_or_default();
                        farm_pool.close().await;
                        urls.iter().filter_map(|u| hub_db_name(u)).collect()
                    }
                    // No farm database, or no schema in it: nothing to collect.
                    Err(_) => Vec::new(),
                };

                sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                ))
                .execute(&admin_pool)
                .await?;

                for name in ours {
                    let _ =
                        sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
                            .execute(&admin_pool)
                            .await;
                    // A hub's login role is named after its database
                    // (`hub_db_role = 'per_hub'`). Dropping the database
                    // removes the grants but never the role, and a role is
                    // server-wide: left behind they pile up forever, and the
                    // next test to reuse a hub id inherits a password nobody
                    // holds.
                    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{name}\""))
                        .execute(&admin_pool)
                        .await;
                }
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

/// Create a new, isolated `wavvon_farm_test_<uuid>` database and return the
/// pool together with its teardown guard. Callers run their own migrations.
pub async fn create_test_db() -> (PgPool, TestDbGuard) {
    let base_url = base_db_url();

    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base_url}/postgres"))
        .await
        .expect("Failed to connect to PostgreSQL (admin)");

    let db_name = format!("wavvon_farm_test_{}", uuid::Uuid::new_v4().simple());

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
