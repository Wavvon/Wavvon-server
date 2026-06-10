/// Farm session token — a self-describing signed blob that hubs verify locally.
///
/// Wire format: `base64url(payload_json) + "." + base64url(ed25519_sig_over_payload_bytes)`
///
/// The payload is serialised with sorted keys and no whitespace so that the same
/// logical token always produces the same bytes under the signature. We use
/// `serde_json::to_vec` which emits compact (no-whitespace) JSON; key order is
/// insertion order, which we fix by struct field declaration order.
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Base64url engine (no padding) — same alphabet as JWT/URL-safe base64.
fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
}

/// The payload carried inside every farm token.
///
/// Field order here is canonical — serde_json serialises struct fields in declaration
/// order, so adding fields to the END is safe without a version bump as long as
/// verifiers tolerate unknown fields in the JSON. Changing order bumps `v`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FarmTokenPayload {
    /// Schema version. Always 1 for this shape.
    pub v: u8,
    /// Farm URL — e.g. `"https://farm.example.com"`.
    pub iss: String,
    /// Farm public key hex — defence-in-depth so the hub can check `iss_pk` matches
    /// its cached pubkey without a second field lookup.
    pub iss_pk: String,
    /// Canonical user pubkey hex (resolved via `resolve_canonical_identity`).
    pub sub: String,
    /// Master pubkey hex if the user authenticated via a subkey cert; null otherwise.
    pub master: Option<String>,
    /// Unique token ID — 16-byte random hex. Used for revocation checks.
    pub jti: String,
    /// Issued-at unix timestamp.
    pub iat: i64,
    /// Expiry unix timestamp. Default 30 days from issuance.
    pub exp: i64,
    /// Scope: `"member"` or `"lobby"`.
    pub scope: String,
}

/// Sign a payload and return the wire token string.
///
/// Panics if serialisation fails (should be impossible for this fixed struct).
pub fn sign_token(keypair: &SigningKey, payload: &FarmTokenPayload) -> String {
    let payload_bytes = serde_json::to_vec(payload).expect("FarmTokenPayload serialisation failed");
    let signature: Signature = keypair.sign(&payload_bytes);
    let engine = b64();
    format!(
        "{}.{}",
        engine.encode(&payload_bytes),
        engine.encode(signature.to_bytes())
    )
}

/// Parse and verify a farm token string, returning the decoded payload.
///
/// Checks:
/// 1. Split on exactly one `.`.
/// 2. Base64url-decode both parts.
/// 3. Ed25519 signature valid over the payload bytes.
/// 4. `exp` is in the future.
/// 5. `iss_pk` matches `farm_pubkey_hex`.
pub fn verify_token(farm_pubkey_hex: &str, token_str: &str) -> Result<FarmTokenPayload> {
    let dot = token_str
        .find('.')
        .ok_or_else(|| anyhow!("Token missing '.' separator"))?;
    let payload_b64 = &token_str[..dot];
    let sig_b64 = &token_str[dot + 1..];

    let engine = b64();
    let payload_bytes = engine
        .decode(payload_b64)
        .context("Invalid base64url in token payload")?;
    let sig_bytes = engine
        .decode(sig_b64)
        .context("Invalid base64url in token signature")?;

    // Verify the Ed25519 signature.
    let pub_bytes = hex::decode(farm_pubkey_hex).context("Invalid farm pubkey hex")?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow!("Farm pubkey must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array).context("Invalid farm pubkey")?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(&payload_bytes, &signature)
        .context("Token signature verification failed")?;

    // Deserialise after signature check so we never trust unsigned fields.
    let payload: FarmTokenPayload =
        serde_json::from_slice(&payload_bytes).context("Failed to deserialise token payload")?;

    // Check expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if now >= payload.exp {
        return Err(anyhow!("Token has expired"));
    }

    // Check iss_pk matches the known farm pubkey (defence-in-depth vs key rotation).
    if payload.iss_pk != farm_pubkey_hex {
        return Err(anyhow!("Token iss_pk does not match cached farm pubkey"));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sample_payload(keypair: &SigningKey) -> FarmTokenPayload {
        use ed25519_dalek::VerifyingKey;
        let pubkey_hex = hex::encode(VerifyingKey::from(keypair).as_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        FarmTokenPayload {
            v: 1,
            iss: "https://farm.test".to_string(),
            iss_pk: pubkey_hex.clone(),
            sub: "aaaa".repeat(16),
            master: None,
            jti: "deadbeef".repeat(4),
            iat: now,
            exp: now + 86400,
            scope: "member".to_string(),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = make_keypair();
        let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&kp).as_bytes());
        let payload = sample_payload(&kp);
        let token = sign_token(&kp, &payload);
        let decoded = verify_token(&pubkey_hex, &token).unwrap();
        assert_eq!(decoded.sub, payload.sub);
        assert_eq!(decoded.scope, "member");
    }

    #[test]
    fn rejects_tampered_payload() {
        let kp = make_keypair();
        let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&kp).as_bytes());
        let payload = sample_payload(&kp);
        let token = sign_token(&kp, &payload);

        // Flip one byte in the payload section.
        let dot = token.find('.').unwrap();
        let mut payload_b64 = token[..dot].to_string();
        let last = payload_b64.pop().unwrap();
        payload_b64.push(if last == 'A' { 'B' } else { 'A' });
        let bad_token = format!("{}.{}", payload_b64, &token[dot + 1..]);

        assert!(verify_token(&pubkey_hex, &bad_token).is_err());
    }

    #[test]
    fn rejects_wrong_pubkey() {
        let kp = make_keypair();
        let other_kp = make_keypair();
        let wrong_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&other_kp).as_bytes());
        let payload = sample_payload(&kp);
        let token = sign_token(&kp, &payload);
        assert!(verify_token(&wrong_pubkey, &token).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let kp = make_keypair();
        let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&kp).as_bytes());
        let mut payload = sample_payload(&kp);
        // Set exp in the past.
        payload.exp = 1_000_000;
        let token = sign_token(&kp, &payload);
        assert!(verify_token(&pubkey_hex, &token).is_err());
    }
}
