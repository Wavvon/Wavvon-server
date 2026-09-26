//! `GET /info` advertises what this hub can do.
//!
//! Clients branch on membership in `capabilities`, never on `version` — see
//! decisions.md ("Hub capabilities are advertised, not inferred from a version
//! number"). The unit tests in `capabilities.rs` pin the list's shape; these
//! pin that it actually reaches the wire, unauthenticated, where a client
//! reads it before it has a token.

use wavvon_hub::capabilities::CAPABILITIES;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn info_advertises_capabilities_unauthenticated() {
    let server = common::setup().await;

    let info: serde_json::Value = server.get("/info").await.json();
    let caps: Vec<String> = serde_json::from_value(info["capabilities"].clone())
        .expect("capabilities must be a string array on /info");

    assert_eq!(
        caps,
        CAPABILITIES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "/info must advertise exactly what the build declares"
    );
}

/// The list is a growing contract, not a free-for-all: a client that shipped
/// against `voice.wt` keeps working only if the string never changes spelling.
/// Renaming one is a removal, and removals wait for a major.
#[tokio::test]
async fn known_capabilities_keep_their_spelling() {
    let server = common::setup().await;
    let info: serde_json::Value = server.get("/info").await.json();
    let caps: Vec<String> = serde_json::from_value(info["capabilities"].clone()).unwrap();

    for expected in [
        "list.cursor",
        "list.cursor.lists",
        "pairing.subkey",
        "recovery.attestation",
        "screenshare.v2",
        "voice.wt",
    ] {
        assert!(
            caps.iter().any(|c| c == expected),
            "capability {expected:?} disappeared from /info — that is a breaking \
             change for every client already testing for it"
        );
    }
}
