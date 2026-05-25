pub mod ecies;
mod master;
mod pow;
mod recovery;
mod subkey;
mod wire;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use x25519_dalek;

pub use ecies::{unwrap_blob_key, wrap_blob_key};
pub use master::MasterIdentity;
pub use pow::{compute_security_level, leading_zero_bits, verify_security_level};
pub use subkey::DeviceSubkey;
pub use wire::{
    DhKeyRecord, HomeHubList, PairingClaim, PairingComplete, PairingOffer, PairingStatus,
    PublicHubEntry, PublicHubProfile, RevocationEntry, SignedPrefsBlob, SubkeyCert,
};

pub struct Identity {
    signing_key: SigningKey,
    pub security_nonce: u64,
    pub security_level: u32,
}

impl Identity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            signing_key,
            security_nonce: 0,
            security_level: 0,
        }
    }

    pub fn public_key_hex(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        hex::encode(verifying_key.as_bytes())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = SavedIdentity {
            secret_key: hex::encode(self.signing_key.to_bytes()),
            security_nonce: Some(self.security_nonce),
            security_level: Some(self.security_level),
        };
        let json = serde_json::to_string_pretty(&data)?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create identity directory")?;
        }

        fs::write(path, json).context("Failed to write identity file")?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path).context("Failed to read identity file")?;
        let data: SavedIdentity =
            serde_json::from_str(&json).context("Failed to parse identity file")?;
        let secret_bytes = hex::decode(&data.secret_key).context("Invalid hex in identity file")?;

        let secret_array: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Secret key must be exactly 32 bytes"))?;

        let signing_key = SigningKey::from_bytes(&secret_array);
        Ok(Self {
            signing_key,
            security_nonce: data.security_nonce.unwrap_or(0),
            security_level: data.security_level.unwrap_or(0),
        })
    }

    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            let identity = Self::load(path)?;
            Ok((identity, false))
        } else {
            let identity = Self::generate();
            identity.save(path)?;
            Ok((identity, true))
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Improve security level by computing more proof-of-work.
    /// Starts from current nonce and tries to find a higher level.
    /// Returns the new level reached.
    pub fn improve_security_level(&mut self, target_level: u32) -> u32 {
        let pub_key = self.public_key_hex();
        let (nonce, level) = compute_security_level(&pub_key, self.security_nonce, target_level);
        self.security_nonce = nonce;
        self.security_level = level;
        level
    }

    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        Ok(home.join(".voxply").join("identity.json"))
    }

    /// Derive the master keypair from this identity's secret bytes.
    /// Phase-1 helper toward multi-device pairing — the secret bytes
    /// double as BIP39 entropy and as the seed input to HKDF.
    pub fn master(&self) -> Result<MasterIdentity> {
        let entropy = self.signing_key.to_bytes();
        MasterIdentity::derive_from_entropy(&entropy)
    }

    /// Wrap this identity as subkey 0 with a user-facing label.
    /// Non-upgraded hubs see the same pubkey they always saw.
    pub fn as_subkey_zero(&self, label: String) -> DeviceSubkey {
        let entropy = self.signing_key.to_bytes();
        DeviceSubkey::subkey_zero_from_entropy(&entropy, label)
    }

    /// Derive the X25519 DH keypair from this identity's Ed25519 seed.
    /// Uses the standard ed25519→x25519 conversion:
    /// SHA-512(seed)[0..32] → clamp → X25519 scalar.
    pub fn dh_keypair(&self) -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
        use sha2::{Sha512, Digest};
        let seed = self.signing_key.to_bytes();
        let hash = Sha512::digest(&seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        // X25519 clamping
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let secret = x25519_dalek::StaticSecret::from(scalar);
        let public = x25519_dalek::PublicKey::from(&secret);
        (secret, public)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key_hex())
    }
}

pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
    let pub_bytes = hex::decode(public_key_hex).context("Invalid public key hex")?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).context("Invalid public key bytes")?;

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message, &signature)
        .context("Signature verification failed")?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    secret_key: String,
    #[serde(default)]
    security_nonce: Option<u64>,
    #[serde(default)]
    security_level: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let identity = Identity::generate();
        let message = b"hello voxply";

        let signature = identity.sign(message);
        let pub_key_hex = identity.public_key_hex();

        let result = verify_signature(&pub_key_hex, message, &signature.to_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let identity = Identity::generate();
        let signature = identity.sign(b"correct message");
        let pub_key_hex = identity.public_key_hex();

        let result = verify_signature(&pub_key_hex, b"wrong message", &signature.to_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn proof_of_work_computes_and_verifies() {
        let mut identity = Identity::generate();
        assert_eq!(identity.security_level, 0);

        let level = identity.improve_security_level(8);
        assert!(level >= 8);

        // Verify it
        let valid = verify_security_level(
            &identity.public_key_hex(),
            identity.security_nonce,
            identity.security_level,
        );
        assert!(valid);
    }

    #[test]
    fn recovery_phrase_roundtrip() {
        let identity = Identity::generate();
        let phrase = identity.recovery_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let restored = Identity::from_recovery_phrase(&phrase).unwrap();
        assert_eq!(identity.public_key_hex(), restored.public_key_hex());
    }

    #[test]
    fn recovery_phrase_rejects_invalid() {
        let result = Identity::from_recovery_phrase("not a valid recovery phrase");
        assert!(result.is_err());
    }

    #[test]
    fn proof_of_work_rejects_fake_nonce() {
        let identity = Identity::generate();
        // Fake nonce should not verify at level 20
        let valid = verify_security_level(&identity.public_key_hex(), 12345, 20);
        assert!(!valid);
    }

    #[test]
    fn master_derivation_is_deterministic() {
        let identity = Identity::generate();
        let m1 = identity.master().unwrap();
        let m2 = identity.master().unwrap();
        assert_eq!(m1.public_key_hex(), m2.public_key_hex());
    }

    #[test]
    fn master_pubkey_distinct_from_subkey_zero() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        assert_ne!(master.public_key_hex(), identity.public_key_hex());
    }

    #[test]
    fn subkey_zero_preserves_existing_pubkey() {
        let identity = Identity::generate();
        let subkey = identity.as_subkey_zero("test-device".to_string());
        assert_eq!(subkey.public_key_hex(), identity.public_key_hex());
    }

    #[test]
    fn master_from_phrase_matches_master_from_identity() {
        let identity = Identity::generate();
        let phrase = identity.recovery_phrase();
        let m_from_phrase = MasterIdentity::derive_from_phrase(&phrase).unwrap();
        let m_from_identity = identity.master().unwrap();
        assert_eq!(m_from_phrase.public_key_hex(), m_from_identity.public_key_hex());
    }

    #[test]
    fn master_sign_and_verify() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let message = b"phase 1 wiring";
        let signature = master.sign(message);

        let result = verify_signature(
            &master.public_key_hex(),
            message,
            &signature.to_bytes(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn dh_keypair_is_deterministic() {
        let identity = Identity::generate();
        let (_, pub1) = identity.dh_keypair();
        let (_, pub2) = identity.dh_keypair();
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn dh_key_agreement_works() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (alice_sec, _) = alice.dh_keypair();
        let (bob_sec, bob_pub) = bob.dh_keypair();
        let (_, alice_pub) = alice.dh_keypair();
        let shared_alice = alice_sec.diffie_hellman(&bob_pub);
        let shared_bob = bob_sec.diffie_hellman(&alice_pub);
        assert_eq!(shared_alice.as_bytes(), shared_bob.as_bytes());
    }

    #[test]
    fn subkey_generate_is_random() {
        let a = DeviceSubkey::generate("a".to_string());
        let b = DeviceSubkey::generate("b".to_string());
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn subkey_secret_bytes_roundtrip() {
        let original = DeviceSubkey::generate("phone".to_string());
        let secret = original.secret_bytes();
        let restored = DeviceSubkey::from_secret_bytes(&secret, "phone".to_string());
        assert_eq!(restored.public_key_hex(), original.public_key_hex());

        // Both should produce the same signature on the same message.
        let msg = b"identity check";
        let sig_a = original.sign(msg).to_bytes();
        let sig_b = restored.sign(msg).to_bytes();
        assert_eq!(sig_a, sig_b);
    }

    #[test]
    fn home_hub_list_sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let master_pubkey = master.public_key_hex();
        let hubs = vec!["https://a.example".to_string(), "https://b.example".to_string()];
        let issued_at = 1_700_000_000;
        let sequence = 1;

        let bytes = HomeHubList::signing_bytes(&master_pubkey, &hubs, issued_at, sequence);
        let signature = hex::encode(master.sign(&bytes).to_bytes());

        let entry = HomeHubList { master_pubkey, hubs, issued_at, sequence, signature };
        assert!(entry.verify().is_ok());
    }

    #[test]
    fn home_hub_list_rejects_tampered_payload() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let master_pubkey = master.public_key_hex();
        let hubs = vec!["https://a.example".to_string()];

        let bytes = HomeHubList::signing_bytes(&master_pubkey, &hubs, 1, 1);
        let signature = hex::encode(master.sign(&bytes).to_bytes());

        let mut entry = HomeHubList { master_pubkey, hubs, issued_at: 1, sequence: 1, signature };
        entry.hubs.push("https://attacker.example".to_string());
        assert!(entry.verify().is_err());
    }

    #[test]
    fn subkey_cert_sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let master_pubkey = master.public_key_hex();
        let subkey = DeviceSubkey::generate("phone".to_string());
        let subkey_pubkey = subkey.public_key_hex();

        let bytes = SubkeyCert::signing_bytes(
            &master_pubkey,
            &subkey_pubkey,
            "phone",
            1_700_000_000,
            None,
            &[],
        );
        let signature = hex::encode(master.sign(&bytes).to_bytes());

        let cert = SubkeyCert {
            master_pubkey,
            subkey_pubkey,
            device_label: "phone".to_string(),
            issued_at: 1_700_000_000,
            not_after: None,
            fallback_hubs: vec![],
            signature,
        };
        assert!(cert.verify().is_ok());
    }

    #[test]
    fn revocation_entry_sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let master_pubkey = master.public_key_hex();
        let revoked_subkey = DeviceSubkey::generate("compromised".to_string()).public_key_hex();

        let bytes = RevocationEntry::signing_bytes(&master_pubkey, &revoked_subkey, 1_700_000_500);
        let signature = hex::encode(master.sign(&bytes).to_bytes());

        let entry = RevocationEntry {
            master_pubkey,
            subkey_pubkey: revoked_subkey,
            revoked_at: 1_700_000_500,
            signature,
        };
        assert!(entry.verify().is_ok());
    }

    #[test]
    fn signed_prefs_blob_sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let master = identity.master().unwrap();
        let master_pubkey = master.public_key_hex();
        let ciphertext = b"opaque ciphertext bytes";
        let bytes = SignedPrefsBlob::signing_bytes(&master_pubkey, 7, ciphertext);
        let signature = hex::encode(master.sign(&bytes).to_bytes());

        let blob = SignedPrefsBlob {
            master_pubkey,
            blob_version: 7,
            ciphertext_hex: hex::encode(ciphertext),
            signature,
        };
        assert!(blob.verify().is_ok());
    }
}
