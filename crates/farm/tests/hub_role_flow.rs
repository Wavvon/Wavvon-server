//! A PostgreSQL role per hub, against a real server.
//!
//! What the isolation layouts alone do **not** give you: containment. A
//! database each and a schema each both stop hubs colliding, and neither stops
//! a compromised hub reading its siblings — every hub connects as the farm's
//! own role. These tests are about the part that does: a login role per hub,
//! granted its own space and nothing else.
//!
//! The assertion that matters is the refusal. "Hub A can use its database" is
//! satisfied by handing out the farm's superuser role, which is exactly the
//! situation this replaces.

use sqlx::postgres::PgPoolOptions;
use wavvon_farm::db::provision::{
    database_name, provision_hub, provision_hub_role, role_name, with_credentials, Isolation,
};

#[path = "common.rs"]
mod common;

/// Drop the databases and roles a test provisioned directly.
///
/// The suite's own guard sweeps hub databases recorded on `hubs` rows; these
/// were provisioned by calling `provision_hub` itself, so nothing else knows
/// about them — and a role outlives every database on the server.
async fn cleanup(hub_ids: &[&str]) {
    let admin = match try_connect(&format!("{}/postgres", common::base_db_url())).await {
        Ok(pool) => pool,
        Err(_) => return,
    };
    for id in hub_ids {
        let _ = sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            database_name(id)
        ))
        .execute(&admin)
        .await;
        let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{}\"", role_name(id)))
            .execute(&admin)
            .await;
    }
    admin.close().await;
}

/// Connect with whatever credentials the URL carries, without the pool
/// retrying: a refusal is the answer, not a wait.
async fn try_connect(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
}

#[tokio::test]
async fn a_hub_role_can_use_its_own_database_and_not_its_siblings() {
    let (farm_pool, _guard) = common::create_test_db().await;
    let base = common::base_db_url();

    let a_url = provision_hub(&farm_pool, &base, "roletesta", Isolation::Database)
        .await
        .expect("hub A gets a database");
    let b_url = provision_hub(&farm_pool, &base, "roletestb", Isolation::Database)
        .await
        .expect("hub B gets a database");

    let a_as_role = provision_hub_role(&farm_pool, &base, &a_url, "roletesta", Isolation::Database)
        .await
        .expect("hub A gets a role");
    let _b_as_role =
        provision_hub_role(&farm_pool, &base, &b_url, "roletestb", Isolation::Database)
            .await
            .expect("hub B gets a role");

    assert!(
        a_as_role.contains(&role_name("roletesta")),
        "the hub must be handed a URL that connects as its own role, got {a_as_role}"
    );

    // Its own database: the hub creates every table it uses, so CREATE has to
    // work or the grant is theatre.
    let own = try_connect(&a_as_role)
        .await
        .expect("hub A connects as itself");
    sqlx::query("CREATE TABLE probe (id INT)")
        .execute(&own)
        .await
        .expect("a hub must be able to create its own tables");
    own.close().await;

    // Its sibling's database, same role. This is the whole point.
    let a_into_b = with_credentials(
        &b_url,
        &role_name("roletesta"),
        // The password is inside a_as_role; parse it back out rather than
        // regenerating, since each provision issues a fresh one.
        url::Url::parse(&a_as_role).unwrap().password().unwrap(),
    )
    .unwrap();
    let refused = try_connect(&a_into_b).await;
    cleanup(&["roletesta", "roletestb"]).await;
    assert!(
        refused.is_err(),
        "hub A's role connected to hub B's database — the separation is nominal"
    );
}

/// Re-spawning an existing hub must not fail on "role already exists", and the
/// URL it gets back must still work.
#[tokio::test]
async fn provisioning_a_role_twice_reissues_rather_than_failing() {
    let (farm_pool, _guard) = common::create_test_db().await;
    let base = common::base_db_url();

    let hub_url = provision_hub(&farm_pool, &base, "roletestc", Isolation::Database)
        .await
        .expect("hub gets a database");

    let first = provision_hub_role(
        &farm_pool,
        &base,
        &hub_url,
        "roletestc",
        Isolation::Database,
    )
    .await
    .expect("first provision");
    let second = provision_hub_role(
        &farm_pool,
        &base,
        &hub_url,
        "roletestc",
        Isolation::Database,
    )
    .await
    .expect("second provision must not fail on an existing role");

    assert_ne!(
        first, second,
        "a re-provision issues a fresh password rather than reusing one"
    );
    let pool = try_connect(&second)
        .await
        .expect("the latest credentials must work");
    pool.close().await;
    cleanup(&["roletestc"]).await;
}

/// Schema isolation: the role may connect to the shared database, and reach
/// exactly one schema in it.
#[tokio::test]
async fn a_schema_isolated_hub_role_is_confined_to_its_schema() {
    let (farm_pool, _guard) = common::create_test_db().await;
    let base = common::base_db_url();
    let farm_db_url: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&farm_pool)
        .await
        .map(|name: String| format!("{base}/{name}"))
        .expect("the farm's own database URL");

    let a_url = provision_hub(&farm_pool, &farm_db_url, "roletestd", Isolation::Schema)
        .await
        .expect("hub A gets a schema");
    provision_hub(&farm_pool, &farm_db_url, "roletestx", Isolation::Schema)
        .await
        .expect("hub B gets a schema");

    let a_as_role = provision_hub_role(
        &farm_pool,
        &farm_db_url,
        &a_url,
        "roletestd",
        Isolation::Schema,
    )
    .await
    .expect("hub A gets a role");

    let own = try_connect(&a_as_role)
        .await
        .expect("hub A connects to the shared database");
    sqlx::query("CREATE TABLE probe (id INT)")
        .execute(&own)
        .await
        .expect("search_path puts this in the hub's own schema");

    // The sibling's schema is named explicitly, so this bypasses search_path
    // entirely — which is what a hostile hub would do.
    let reach = sqlx::query("CREATE TABLE \"hub_roletestx\".probe (id INT)")
        .execute(&own)
        .await;
    assert!(
        reach.is_err(),
        "a hub reached into its sibling's schema — schema isolation without a role per hub is \
         a naming convention, not a boundary"
    );
    own.close().await;

    // Roles are server-wide; the test database's teardown only knows about the
    // ones it recorded on hub rows, and these were provisioned directly.
    for id in ["roletestd", "roletestx"] {
        let _ = sqlx::query(&format!("DROP ROLE IF EXISTS \"{}\"", role_name(id)))
            .execute(&farm_pool)
            .await;
    }
}
