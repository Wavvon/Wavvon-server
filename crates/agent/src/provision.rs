//! Somewhere of its own for each hub **on this node**.
//!
//! The farm provisions databases on its own PostgreSQL, which is the right
//! answer for the hubs it runs itself and the wrong one for a hub over here:
//! per-node PostgreSQL is the whole point of the multi-node data plane
//! (farm-model.md), and a node's database credentials are supposed to stay on
//! the node.
//!
//! So when this agent holds a connection template, it creates the hub's
//! database here and hands the hub a URL into it. When it does not, it uses
//! whatever URL the farm sent — correct when the agent runs on the farm's own
//! machine, which is the single-node shape.
//!
//! What must never happen is what happened before either: no database
//! configuration at all, so every hub this agent spawned fell back to the
//! hub's default URL and they **all shared one database**, reading and writing
//! each other's communities. That is why `resolve` returns an error rather
//! than an `Option`.

use anyhow::{bail, Context, Result};
use sqlx::postgres::PgPoolOptions;

/// The placeholder a template must contain.
const DB_PLACEHOLDER: &str = "{db}";

/// True when `name` is safe to interpolate into an identifier.
///
/// `CREATE DATABASE` takes no bind parameters. The farm derives these names
/// from its own hex hub ids, so this can never fail today — it is here so that
/// a farm which one day sends something else breaks loudly instead of quietly
/// becoming an injection point. Same guard, same reason, as the farm's own
/// `is_safe_id`.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Substitute the hub's database name into a template.
pub fn fill_template(template: &str, db_name: &str) -> Result<String> {
    if !template.contains(DB_PLACEHOLDER) {
        bail!("database template must contain {DB_PLACEHOLDER}");
    }
    if !is_safe_name(db_name) {
        bail!("database name {db_name:?} is not a safe identifier");
    }
    Ok(template.replace(DB_PLACEHOLDER, db_name))
}

/// Create `db_name` on this node's PostgreSQL if it is not there yet.
///
/// Idempotent: an existing database is reused, so a restart or a re-spawn does
/// not fail and does not wipe anything.
async fn ensure_database(template: &str, db_name: &str) -> Result<()> {
    // The maintenance database on the same server, reached with the same
    // credentials: `CREATE DATABASE` cannot run from inside the database it
    // creates.
    let admin_url = fill_template(template, "postgres")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .context("could not connect to this node's PostgreSQL")?;

    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(db_name)
        .fetch_optional(&admin)
        .await
        .context("could not check whether the hub database already exists")?;

    if exists.is_none() {
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await
            .with_context(|| {
                format!(
                    "could not create database {db_name} on this node. The role in \
                     WAVVON_NODE_DB_TEMPLATE needs CREATEDB, or hubs here would have to share \
                     one database."
                )
            })?;
        tracing::info!(database = %db_name, "Provisioned hub database on this node");
    }

    admin.close().await;
    Ok(())
}

/// Decide the database URL for a hub this node is about to start.
///
/// In order: this node's own template (credentials stay here, which is the
/// point), then the template the farm holds for this server, then the URL the
/// farm resolved itself. An error rather than a fallback — a hub started
/// without a database of its own reads another community's data, and it does
/// it silently.
pub async fn resolve(
    node_template: Option<&str>,
    farm_template: Option<&str>,
    farm_db_url: Option<&str>,
    db_name: Option<&str>,
) -> Result<String> {
    // This node's own template first: its credentials never have to reach the
    // farm, which is the point of per-node PostgreSQL.
    if let Some(template) = node_template.or(farm_template) {
        let Some(db_name) = db_name else {
            bail!("a database template needs the hub's database name, and the farm sent none");
        };
        let url = fill_template(template, db_name)?;
        ensure_database(template, db_name).await?;
        return Ok(url);
    }

    match farm_db_url {
        Some(url) if !url.trim().is_empty() => Ok(url.to_string()),
        _ => bail!(
            "no database for this hub: set WAVVON_NODE_DB_TEMPLATE on this node, or run the \
             agent on the farm's own machine where the farm-provisioned URL reaches"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_substitutes_the_database_name() {
        assert_eq!(
            fill_template("postgres://u:p@localhost:5432/{db}", "wavvon_hub_a1").unwrap(),
            "postgres://u:p@localhost:5432/wavvon_hub_a1"
        );
    }

    #[test]
    fn a_template_without_the_placeholder_is_refused() {
        // Otherwise every hub on this node would land in the one database the
        // template names — the bug this module exists to prevent, wearing the
        // appearance of configuration.
        assert!(fill_template("postgres://u:p@localhost:5432/wavvon", "wavvon_hub_a1").is_err());
    }

    #[test]
    fn names_that_could_break_out_of_an_identifier_are_refused() {
        for name in [
            "a\"; DROP DATABASE postgres; --",
            "has space",
            "",
            &"a".repeat(64),
        ] {
            assert!(
                fill_template("postgres://u@h/{db}", name).is_err(),
                "{name:?} should be refused"
            );
        }
    }

    /// The single-node shape: no template anywhere, so the URL the farm
    /// resolved on its own machine is the answer.
    #[tokio::test]
    async fn the_farms_url_is_used_when_this_node_has_no_template() {
        let url = resolve(
            None,
            None,
            Some("postgres://u@h/wavvon_hub_a1"),
            Some("wavvon_hub_a1"),
        )
        .await
        .unwrap();
        assert_eq!(url, "postgres://u@h/wavvon_hub_a1");
    }

    /// Nothing to go on is an error, never the hub's default: that default is
    /// shared, and a hub silently reading another community's data is the
    /// failure this whole path exists to avoid.
    #[tokio::test]
    async fn no_database_at_all_refuses_the_spawn() {
        assert!(resolve(None, None, None, Some("wavvon_hub_a1"))
            .await
            .is_err());
        assert!(resolve(None, None, Some("  "), Some("wavvon_hub_a1"))
            .await
            .is_err());
    }

    /// The variant that has to be *executed* rather than reasoned about: with
    /// a template, this node creates the database itself and the URL it hands
    /// back actually connects. A version of this that only checked the string
    /// would pass while every hub failed to start.
    #[tokio::test]
    async fn a_template_provisions_the_database_on_this_node() {
        let base = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string());
        let template = format!("{base}/{{db}}");
        let db_name = format!(
            "wavvon_agent_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let url = resolve(Some(&template), None, None, Some(&db_name))
            .await
            .expect("a template must provision and resolve");
        assert!(url.ends_with(&db_name), "got {url}");

        // Idempotent: a restart re-runs this against a database that exists.
        resolve(Some(&template), None, None, Some(&db_name))
            .await
            .expect("provisioning twice must not fail");

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("the URL handed to the hub must connect");
        pool.close().await;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&fill_template(&template, "postgres").unwrap())
            .await
            .unwrap();
        let _ = sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
        ))
        .execute(&admin)
        .await;
    }
}
