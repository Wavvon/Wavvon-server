use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

const ECIES_INFO: &[u8] = b"voxply/ecies/v1";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Wrap a 32-byte blob key for a recipient identified by their Ed25519 pubkey.
///
/// Returns a 184-char hex string encoding:
///   eph_x25519_pub[32] || aes_gcm_nonce[12] || aes_gcm_ciphertext_and_tag[48]
/// (total 92 bytes → 184 hex chars)
pub fn wrap_blob_key(
    blob_key: &[u8; 32],
    recipient_ed25519_pubkey_hex: &str,
) -> Result<String> {
    // 1. Decode recipient pubkey hex → 32 bytes
    let pubkey_bytes = hex::decode(recipient_ed25519_pubkey_hex)
        .map_err(|e| anyhow!("invalid pubkey hex: {e}"))?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;

    // 2. Ed25519 pubkey → X25519 pubkey via Montgomery form
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&pubkey_bytes)
        .map_err(|_| anyhow!("invalid compressed Edwards point length"))?;
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow!("invalid ed25519 point"))?;
    let montgomery = point.to_montgomery();
    let x25519_pub = x25519_dalek::PublicKey::from(montgomery.to_bytes());

    // 3. Generate ephemeral X25519 keypair
    let eph_priv = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph_priv);

    // 4. ECDH
    let shared = eph_priv.diffie_hellman(&x25519_pub);

    // 5. HKDF-SHA256: ikm=shared, salt=eph_pub, info="voxply/ecies/v1" → 32-byte enc key
    let hk = Hkdf::<Sha256>::new(Some(eph_pub.as_bytes()), shared.as_bytes());
    let mut enc_key = [0u8; 32];
    hk.expand(ECIES_INFO, &mut enc_key)
        .map_err(|e| anyhow!("HKDF expand: {e}"))?;

    // 6. AES-256-GCM encrypt
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&enc_key).map_err(|e| anyhow!("AES key: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), blob_key.as_ref())
        .map_err(|e| anyhow!("AES-GCM encrypt: {e}"))?;
    // ciphertext = 32 bytes plaintext + 16 bytes tag = 48 bytes

    // 7. Concatenate and hex-encode: eph_pub[32] || nonce[12] || ct[48] = 92 bytes
    let mut out = Vec::with_capacity(92);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), 92);

    Ok(hex::encode(out))
}

/// Unwrap a wrapped blob key using the recipient's Ed25519 seed (32-byte secret).
pub fn unwrap_blob_key(
    wrapped_hex: &str,
    recipient_ed25519_seed: &[u8; 32],
) -> Result<[u8; 32]> {
    // 1. Decode hex → 92 bytes
    let bytes = hex::decode(wrapped_hex)
        .map_err(|e| anyhow!("invalid wrapped_hex: {e}"))?;
    if bytes.len() != 92 {
        return Err(anyhow!("wrapped blob key must be 92 bytes, got {}", bytes.len()));
    }

    // 2. Parse fields
    let eph_pub_bytes: [u8; 32] = bytes[0..32].try_into().unwrap();
    let nonce_bytes: [u8; 12] = bytes[32..44].try_into().unwrap();
    let ct = &bytes[44..92]; // 48 bytes (32 + 16 tag)

    // 3. Ed25519 seed → X25519 scalar (standard conversion)
    let hash = Sha512::digest(recipient_ed25519_seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let x25519_priv = x25519_dalek::StaticSecret::from(scalar);

    // 4. ECDH
    let eph_pub = x25519_dalek::PublicKey::from(eph_pub_bytes);
    let shared = x25519_priv.diffie_hellman(&eph_pub);

    // 5. Same HKDF (salt = eph_pub_bytes)
    let hk = Hkdf::<Sha256>::new(Some(&eph_pub_bytes), shared.as_bytes());
    let mut enc_key = [0u8; 32];
    hk.expand(ECIES_INFO, &mut enc_key)
        .map_err(|e| anyhow!("HKDF expand: {e}"))?;

    // 6. AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&enc_key).map_err(|e| anyhow!("AES key: {e}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ct)
        .map_err(|e| anyhow!("AES-GCM decrypt: {e}"))?;

    let blob_key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow!("decrypted plaintext is not 32 bytes"))?;
    Ok(blob_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    fn pubkey_hex_from_seed(seed: &[u8; 32]) -> String {
        let sk = SigningKey::from_bytes(seed);
        hex::encode(sk.verifying_key().as_bytes())
    }

    #[test]
    fn round_trip_wrap_unwrap() {
        let recipient_seed = random_seed();
        let recipient_pubkey_hex = pubkey_hex_from_seed(&recipient_seed);

        let mut blob_key = [0u8; 32];
        OsRng.fill_bytes(&mut blob_key);

        let wrapped = wrap_blob_key(&blob_key, &recipient_pubkey_hex)
            .expect("wrap should succeed");

        // 92 bytes → 184 hex chars
        assert_eq!(wrapped.len(), 184);

        let unwrapped = unwrap_blob_key(&wrapped, &recipient_seed)
            .expect("unwrap should succeed");

        assert_eq!(blob_key, unwrapped);
    }

    #[test]
    fn zero_key_rejected() {
        // All-zero seed is technically a valid Ed25519 seed; we test that a
        // tampered / all-zero *wrapped* payload (92 bytes of zeros) fails
        // gracefully rather than panicking.
        let recipient_seed = [0u8; 32];
        let zero_wrapped = hex::encode([0u8; 92]);
        // Decryption will fail — ciphertext won't authenticate.
        let result = unwrap_blob_key(&zero_wrapped, &recipient_seed);
        assert!(result.is_err(), "all-zero wrapped blob should fail to decrypt");
    }

    #[test]
    fn wrong_recipient_cannot_unwrap() {
        let sender_seed = random_seed();
        let recipient_seed = random_seed();
        let attacker_seed = random_seed();

        let recipient_pubkey_hex = pubkey_hex_from_seed(&recipient_seed);
        let _ = sender_seed; // wrap uses only recipient pubkey

        let mut blob_key = [0u8; 32];
        OsRng.fill_bytes(&mut blob_key);

        let wrapped = wrap_blob_key(&blob_key, &recipient_pubkey_hex).expect("wrap");
        let result = unwrap_blob_key(&wrapped, &attacker_seed);
        assert!(result.is_err(), "wrong recipient should fail to unwrap");
    }
}
