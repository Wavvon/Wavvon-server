use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// A ban list names its issuer in the payload. The worker took that name on
// trust and never checked the signature, so one source could claim another
// source's key and replace that source's bans with its own.

async fn serve(body: serde_json::Value) -> String {
    let app = axum::Router::new().route(
        "/federation/banlist",
        axum::routing::get(move || {
            let b = body.clone();
            async move { axum::Json(b) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

fn list(issuer: &Identity, signer: &Identity, target: &str) -> serde_json::Value {
    let payload = json!({
        "issuer_pubkey": issuer.public_key_hex(),
        "issued_at": 1,
        "entries": [{ "master_pubkey": target, "reason": null, "added_at": 1 }],
    });
    let sig = signer.sign(serde_json::to_string(&payload).unwrap().as_bytes());
    json!({ "payload": payload, "signature": hex::encode(sig.to_bytes()) })
}

async fn synced(state: &wavvon_hub::state::AppState, url: &str, issuer: &Identity) -> i64 {
    sqlx::query(
        "INSERT INTO federated_ban_sources (url, policy, added_at) VALUES ($1, 'soft-flag', 0)",
    )
    .bind(url)
    .execute(&state.db)
    .await
    .unwrap();
    wavvon_hub::banlist_worker::sync_one_source(state, url).await;
    sqlx::query_scalar("SELECT COUNT(*) FROM federated_bans WHERE source_hub_pubkey = $1")
        .bind(issuer.public_key_hex())
        .fetch_one(&state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_list_signed_by_its_issuer_is_synced() {
    let (db, _guard) = common::create_test_db().await;
    let state = common::base_state(db);
    let hub = Identity::generate();
    let url = serve(list(&hub, &hub, &"a".repeat(64))).await;
    assert_eq!(synced(&state, &url, &hub).await, 1);
}

#[tokio::test]
async fn a_list_claiming_someone_elses_key_is_ignored() {
    let (db, _guard) = common::create_test_db().await;
    let state = common::base_state(db);
    let victim = Identity::generate();
    let forger = Identity::generate();
    let url = serve(list(&victim, &forger, &"b".repeat(64))).await;
    assert_eq!(synced(&state, &url, &victim).await, 0);
}
