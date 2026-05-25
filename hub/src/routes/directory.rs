use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::state::AppState;

/// Build the canonical nonce: current UTC time rounded down to the minute,
/// formatted as ISO-8601 without seconds, e.g. "2026-05-10T20:15Z".
///
/// No chrono dependency — computed directly from the UNIX timestamp.
fn current_nonce() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Round down to the nearest minute.
    let secs = (secs / 60) * 60;

    // Decompose into date/time components without external crates.
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;

    // Gregorian calendar from a Julian Day Number approach.
    // days_since_epoch is relative to 1970-01-01.
    let jdn = days_since_epoch + 2_440_588; // JDN of 1970-01-01 is 2440588

    // Algorithm from https://en.wikipedia.org/wiki/Julian_day#Julian_day_number_calculation
    let l = jdn + 68_569;
    let n = (4 * l) / 146_097;
    let l = l - (146_097 * n + 3) / 4;
    let year_i = (4_000 * (l + 1)) / 1_461_001;
    let l = l - (1_461 * year_i) / 4 + 31;
    let month_i = (80 * l) / 2_447;
    let day = l - (2_447 * month_i) / 80;
    let l = month_i / 11;
    let month = month_i + 2 - 12 * l;
    let year = 100 * (n - 49) + year_i + l;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}Z", year, month, day, hour, minute)
}

/// Build the canonical JSON payload exactly as the discovery API expects.
///
/// Keys are in alphabetical order: bio, hub_url, language, nonce, tags.
/// Tags are sorted alphabetically for determinism.
fn build_canonical_payload(
    bio: &str,
    hub_url: &str,
    language: &str,
    nonce: &str,
    tags: &[String],
) -> String {
    let mut sorted_tags = tags.to_vec();
    sorted_tags.sort();

    // Build JSON with manually ordered keys to guarantee alphabetical order
    // regardless of serde_json's internal map ordering.
    let tags_json: Vec<serde_json::Value> = sorted_tags
        .iter()
        .map(|t| serde_json::Value::String(t.clone()))
        .collect();

    let obj = serde_json::json!({
        "bio": bio,
        "hub_url": hub_url,
        "language": language,
        "nonce": nonce,
        "tags": tags_json,
    });

    // serde_json::json! uses an IndexMap-backed object when the
    // "preserve_order" feature is enabled, but the default Map uses BTreeMap
    // which sorts keys alphabetically. Either way, the keys above are already
    // in alphabetical order. Serialize to compact JSON.
    serde_json::to_string(&obj).expect("canonical payload serialization is infallible")
}

#[derive(Deserialize)]
pub struct DirectorySignRequest {
    pub hub_url: String,
    pub tags: Vec<String>,
    pub language: String,
    pub bio: String,
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Serialize)]
pub struct DirectorySignResponse {
    pub canonical_payload: String,
    pub hub_pubkey: String,
    pub signature: String,
}

/// POST /admin/directory-sign
///
/// Builds the canonical listing payload, signs it with the hub's own
/// Ed25519 private key, and returns the payload + pubkey + signature so
/// the Tauri client can forward them to the directory API.
///
/// Requires admin or owner role.
pub async fn sign_for_directory(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<DirectorySignRequest>,
) -> Result<Json<DirectorySignResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let nonce = current_nonce();
    let canonical_payload = build_canonical_payload(
        &req.bio,
        &req.hub_url,
        &req.language,
        &nonce,
        &req.tags,
    );

    let signature = state.hub_identity.sign(canonical_payload.as_bytes());
    let hub_pubkey = state.hub_identity.public_key_hex();
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(Json(DirectorySignResponse {
        canonical_payload,
        hub_pubkey,
        signature: signature_hex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_payload_key_order_and_tag_sort() {
        let payload = build_canonical_payload(
            "A community hub",
            "https://hub.example.com",
            "en",
            "2026-05-10T20:15Z",
            &["rust".to_string(), "gaming".to_string(), "art".to_string()],
        );

        // Must deserialize to a Value so we can inspect field order.
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let obj = v.as_object().unwrap();

        // Keys in the serialized JSON must be alphabetical.
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["bio", "hub_url", "language", "nonce", "tags"]);

        // Tags must be sorted.
        let tags: Vec<&str> = obj["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert_eq!(tags, vec!["art", "gaming", "rust"]);
    }

    #[test]
    fn nonce_format_matches_iso8601_minute() {
        let nonce = current_nonce();
        // e.g. "2026-05-10T20:15Z"
        // 17 chars: YYYY-MM-DDTHH:MMZ
        assert_eq!(nonce.len(), 17, "nonce={}", nonce);
        assert!(nonce.ends_with('Z'), "nonce={}", nonce);
        assert_eq!(&nonce[10..11], "T", "nonce={}", nonce);
        assert_eq!(&nonce[13..14], ":", "nonce={}", nonce);
        // No seconds component.
        assert_eq!(&nonce[16..17], "Z", "nonce={}", nonce);
    }
}
