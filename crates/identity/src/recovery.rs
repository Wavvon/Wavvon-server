use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::Identity;

impl Identity {
    /// Generate a 24-word recovery phrase from the secret key.
    /// These words can be used to reconstruct the keypair.
    pub fn recovery_phrase(&self) -> Zeroizing<String> {
        let secret_bytes = Zeroizing::new(self.signing_key.to_bytes());
        let mnemonic = Mnemonic::from_entropy_in(Language::English, secret_bytes.as_ref())
            .expect("32 bytes should always produce a valid mnemonic");
        Zeroizing::new(mnemonic.to_string())
    }

    /// Restore an identity from a 24-word recovery phrase.
    pub fn from_recovery_phrase(phrase: &str) -> Result<Self> {
        let mnemonic =
            Mnemonic::parse_in(Language::English, phrase).context("Invalid recovery phrase")?;

        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let secret_array = <[u8; 32]>::try_from(entropy.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| anyhow::anyhow!("Recovery phrase must produce exactly 32 bytes"))?;

        let signing_key = SigningKey::from_bytes(&secret_array);
        Ok(Self {
            signing_key,
            security_nonce: 0,
            security_level: 0,
        })
    }
}
