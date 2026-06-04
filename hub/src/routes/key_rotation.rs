use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;

/// GET /key-rotation
///
/// Serves the signed `hub_rotation.json` payload if present, so federation
/// peers can follow a hub key rotation without an out-of-band channel.
/// Returns 204 No Content when no rotation file exists.
pub async fn get_key_rotation() -> Response {
    match std::fs::read_to_string("hub_rotation.json") {
        Ok(s) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(s))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
    }
}
