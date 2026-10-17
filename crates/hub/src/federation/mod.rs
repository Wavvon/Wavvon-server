pub mod client;
pub mod handlers;
pub mod models;

use crate::state::AppState;

/// A federation token for the hub at `url`, from the cache or freshly
/// obtained. Keyed by the URL: a token belongs to the server that issued it,
/// while the key a hub reports about itself over `/info` is only a claim --
/// keying by that let one address overwrite another hub's entry. `None`
/// means it could not be authenticated to, and the caller moves on.
pub async fn peer_token(state: &AppState, url: &str) -> Option<String> {
    if let Some(t) = state.peer_tokens.read().await.get(url).cloned() {
        return Some(t);
    }
    let t = state
        .federation_client
        .authenticate(url, &state.hub_identity)
        .await
        .ok()?;
    state
        .peer_tokens
        .write()
        .await
        .insert(url.to_string(), t.clone());
    Some(t)
}

/// Drop a cached token that stopped working -- the remote ended our session
/// (ban, leave, recovery) and nothing else would ever replace it.
pub async fn forget_peer_token(state: &AppState, url: &str) {
    state.peer_tokens.write().await.remove(url);
}
