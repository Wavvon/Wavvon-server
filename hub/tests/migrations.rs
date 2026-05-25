use sqlx::sqlite::SqlitePoolOptions;
use voxply_hub::db;

#[tokio::test]
async fn migrations_idempotent_on_fresh_db() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Running twice in a row should not fail
    db::migrations::run(&pool).await.unwrap();
    db::migrations::run(&pool).await.unwrap();

    // All expected columns exist on channels
    let cols: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM pragma_table_info('channels')")
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
async fn migrations_add_new_columns_to_old_schema() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    // Simulate an old DB: pre-existing channels table WITHOUT parent_id/is_category
    sqlx::query(
        "CREATE TABLE users (
            public_key TEXT PRIMARY KEY,
            display_name TEXT,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE channels (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_by TEXT NOT NULL REFERENCES users(public_key),
            created_at INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Run migrations on this "old" schema
    db::migrations::run(&pool).await.unwrap();

    // Verify new columns were added
    let cols: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM pragma_table_info('channels')")
            .fetch_all(&pool)
            .await
            .unwrap();
    let names: Vec<&str> = cols.iter().map(|(n,)| n.as_str()).collect();

    assert!(names.contains(&"parent_id"), "parent_id column missing after migration");
    assert!(names.contains(&"is_category"), "is_category column missing after migration");
}

#[tokio::test]
async fn migrations_create_all_core_tables() {
    let pool = SqlitePoolOptions::new()
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
