use std::sync::Arc;

use axum_test::TestServer;
use wavvon_hub::server;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// A failed query used to answer with the database's own error text. The body
// now carries only the request id, and the id matches the response header.
#[tokio::test]
async fn a_500_carries_the_request_id_and_no_database_text() {
    let (db, _guard) = common::create_test_db().await;
    let state = Arc::new(common::base_state(db.clone()));
    let server = TestServer::new(server::create_router(state));
    let token = common::authenticate(&server, &Identity::generate()).await;

    db.close().await;
    let resp = server.get("/me").authorization_bearer(&token).await;

    resp.assert_status_internal_server_error();
    let id = resp.header("x-request-id");
    let body = resp.text();
    assert_eq!(
        body,
        format!("Internal server error (request {})", id.to_str().unwrap())
    );
}
