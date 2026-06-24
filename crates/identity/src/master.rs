use anyhow::{anyhow, Context, Result};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

const MASTER_HKDF_INFO: &[u8] = b"voxply/master/v1";

pub struct MasterIdentity {
    signing_key: SigningKey,
}

impl MasterIdentity {
    /// Derive the master keypair from BIP39 entropy. The same 32 bytes
    /// also back subkey 0 directly (legacy compatibility); HKDF
    /// domain-separates this output so the master pubkey is distinct.
    pub fn derive_from_entropy(entropy: &[u8; 32]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, entropy);
        let mut okm = [0u8; 32];
        hk.expand(MASTER_HKDF_INFO, &mut okm)
            .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&okm),
        })
    }

    pub fn derive_from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic =
            Mnemonic::parse_in(Language::English, phrase).context("Invalid recovery phrase")?;
        let entropy = mnemonic.to_entropy();
        let entropy_array: [u8; 32] = entropy
            .try_into()
            .map_err(|_| anyhow!("Recovery phrase must produce exactly 32 bytes"))?;
        Self::derive_from_entropy(&entropy_array)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Raw 32-byte seed of the master signing key.
    /// Used to derive the prefs blob encryption key.
    pub fn secret_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}
