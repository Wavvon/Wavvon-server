use sqlx::AnyPool;
use voxply_hub::db;

#[tokio::test]
async fn migrations_idempotent_on_fresh_db() {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Running twice in a row should not fail
    db::migrations::run(&pool).await.unwrap();
    db::migrations::run(&pool).await.unwrap();

    // All expected columns exist on channels
    let cols: Vec<(String,)> = sqlx::query_as("SELECT name FROM pragma_table_info('channels')")
        .fetch_all(&pool)
        .await
        .unwrap();
    let names: Vec<&str> = cols.iter().map(|(n,)| n.as_str()).collect();

    assert!(names.contains(&"id"));
    assert!(names.contains(&"name"));
    assert!(names.contains(&"created_by"));
    assert!(names.contains(&"parent_id"));
    assert!(names.contains(&"is_category"));
    assert!(names.contains(&"created_at"));
}

#[tokio::test]
async fn migrations_data_survives_rerun() {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // First run: fresh schema
    db::migrations::run(&pool).await.unwrap();

    // Insert a user so the FK on channels.created_by is satisfied
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at) VALUES ('user-anon', 1000000, 1000000)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Insert a channel row to represent existing data
    sqlx::query(
        "INSERT INTO channels (id, name, created_by, created_at) VALUES ('ch-survives', 'general', 'user-anon', 1000000)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Running migrations again must not destroy existing data
    db::migrations::run(&pool).await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE id = 'ch-survives'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "channel row must survive migration rerun");
}

#[tokio::test]
async fn migrations_create_all_core_tables() {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    db::migrations::run(&pool).await.unwrap();

    // Every table we expect to exist
    let expected = [
        "users",
        "sessions",
        "channels",
        "messages",
        "peers",
        "federated_channels",
        "federated_messages",
        "roles",
        "role_permissions",
        "user_roles",
        "bans",
        "mutes",
        "invites",
        "hub_settings",
        "alliances",
        "alliance_members",
        "alliance_shared_channels",
        "channel_bans",
        "voice_mutes",
        "channel_settings",
        "conversations",
        "conversation_members",
        "friends",
    ];

    for table in expected {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(count, 1, "Table '{table}' should exist after migrations");
    }
}
