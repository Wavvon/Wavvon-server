use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::verify_signature;

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    write_u32_le(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn write_str_vec(buf: &mut Vec<u8>, v: &[String]) {
    write_u32_le(buf, v.len() as u32);
    for s in v {
        write_str(buf, s);
    }
}

fn check_sig(master_pubkey_hex: &str, signing_bytes: &[u8], signature_hex: &str) -> Result<()> {
    let sig = hex::decode(signature_hex).context("Invalid signature hex")?;
    verify_signature(master_pubkey_hex, signing_bytes, &sig)
}

/// Master-signed list of the user's home hubs, ordered by preference.
/// Slot 0 is the preferred read/write target; consumers fall through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeHubList {
    pub master_pubkey: String,
    pub hubs: Vec<String>,
    pub issued_at: u64,
    pub sequence: u64,
    pub signature: String,
}

impl HomeHubList {
    pub fn signing_bytes(
        master_pubkey: &str,
        hubs: &[String],
        issued_at: u64,
        sequence: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/home-hub-list/v1\0");
        write_str(&mut buf, master_pubkey);
        write_str_vec(&mut buf, hubs);
        write_u64_le(&mut buf, issued_at);
        write_u64_le(&mut buf, sequence);
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.master_pubkey,
            &self.hubs,
            self.issued_at,
            self.sequence,
        )
    }

    pub fn verify(&self) -> Result<()> {
        check_sig(
            &self.master_pubkey,
            &self.to_signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubkeyCert {
    pub master_pubkey: String,
    pub subkey_pubkey: String,
    pub device_label: String,
    pub issued_at: u64,
    #[serde(default)]
    pub not_after: Option<u64>,
    #[serde(default)]
    pub fallback_hubs: Vec<String>,
    pub signature: String,
}

impl SubkeyCert {
    pub fn signing_bytes(
        master_pubkey: &str,
        subkey_pubkey: &str,
        device_label: &str,
        issued_at: u64,
        not_after: Option<u64>,
        fallback_hubs: &[String],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/subkey-cert/v1\0");
        write_str(&mut buf, master_pubkey);
        write_str(&mut buf, subkey_pubkey);
        write_str(&mut buf, device_label);
        write_u64_le(&mut buf, issued_at);
        match not_after {
            Some(t) => {
                buf.push(1);
                write_u64_le(&mut buf, t);
            }
            None => buf.push(0),
        }
        write_str_vec(&mut buf, fallback_hubs);
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.master_pubkey,
            &self.subkey_pubkey,
            &self.device_label,
            self.issued_at,
            self.not_after,
            &self.fallback_hubs,
        )
    }

    pub fn verify(&self) -> Result<()> {
        check_sig(
            &self.master_pubkey,
            &self.to_signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub master_pubkey: String,
    pub subkey_pubkey: String,
    pub revoked_at: u64,
    pub signature: String,
}

impl RevocationEntry {
    pub fn signing_bytes(master_pubkey: &str, subkey_pubkey: &str, revoked_at: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/revocation/v1\0");
        write_str(&mut buf, master_pubkey);
        write_str(&mut buf, subkey_pubkey);
        write_u64_le(&mut buf, revoked_at);
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(&self.master_pubkey, &self.subkey_pubkey, self.revoked_at)
    }

    pub fn verify(&self) -> Result<()> {
        check_sig(
            &self.master_pubkey,
            &self.to_signing_bytes(),
            &self.signature,
        )
    }
}

/// Encrypted prefs blob with a master-signed envelope. The hub stores
/// the ciphertext opaquely; the signature binds (master, version,
/// blob hash) so the hub can detect rollback and the client can prove
/// authorship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrefsBlob {
    pub master_pubkey: String,
    pub blob_version: u64,
    /// Hex-encoded ciphertext. Hub never decrypts.
    pub ciphertext_hex: String,
    pub signature: String,
}

impl SignedPrefsBlob {
    pub fn signing_bytes(master_pubkey: &str, blob_version: u64, ciphertext: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        let digest = hasher.finalize();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/prefs-blob/v1\0");
        write_str(&mut buf, master_pubkey);
        write_u64_le(&mut buf, blob_version);
        buf.extend_from_slice(&digest);
        buf
    }

    pub fn to_signing_bytes(&self) -> Result<Vec<u8>> {
        let ciphertext = hex::decode(&self.ciphertext_hex)
            .map_err(|e| anyhow!("Invalid ciphertext hex: {e}"))?;
        Ok(Self::signing_bytes(
            &self.master_pubkey,
            self.blob_version,
            &ciphertext,
        ))
    }

    pub fn verify(&self) -> Result<()> {
        let bytes = self.to_signing_bytes()?;
        check_sig(&self.master_pubkey, &bytes, &self.signature)
    }
}

/// QR-encoded pairing offer created by the existing device (E) and
/// posted to every hub in the user's home hub list. The home hub
/// stores it short-lived, keyed by `pairing_token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingOffer {
    pub master_pubkey: String,
    pub home_hubs: Vec<String>,
    pub pairing_token: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl PairingOffer {
    pub fn signing_bytes(
        master_pubkey: &str,
        home_hubs: &[String],
        pairing_token: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/pairing-offer/v1\0");
        write_str(&mut buf, master_pubkey);
        write_str_vec(&mut buf, home_hubs);
        write_str(&mut buf, pairing_token);
        write_u64_le(&mut buf, issued_at);
        write_u64_le(&mut buf, expires_at);
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.master_pubkey,
            &self.home_hubs,
            &self.pairing_token,
            self.issued_at,
            self.expires_at,
        )
    }

    pub fn verify(&self) -> Result<()> {
        check_sig(
            &self.master_pubkey,
            &self.to_signing_bytes(),
            &self.signature,
        )
    }
}

/// New device's claim against an offer. Signed by the new device's
/// subkey to prove possession of the corresponding private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingClaim {
    pub pairing_token: String,
    pub subkey_pubkey: String,
    pub device_label: String,
    pub proof: String,
}

impl PairingClaim {
    pub fn signing_bytes(pairing_token: &str, subkey_pubkey: &str, device_label: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/pairing-claim/v1\0");
        write_str(&mut buf, pairing_token);
        write_str(&mut buf, subkey_pubkey);
        write_str(&mut buf, device_label);
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(&self.pairing_token, &self.subkey_pubkey, &self.device_label)
    }

    pub fn verify(&self) -> Result<()> {
        check_sig(&self.subkey_pubkey, &self.to_signing_bytes(), &self.proof)
    }
}

/// Existing device finalizes pairing by attaching the master-signed
/// cert and the prefs-blob key wrapped for the new device's pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingComplete {
    pub pairing_token: String,
    pub cert: SubkeyCert,
    pub wrapped_blob_key_hex: String,
    /// The canonical (subkey-0/entropy) DM DH X25519 **scalar** (not the
    /// Ed25519 seed), ECIES-wrapped for the claiming subkey with the same
    /// `wrap_blob_key` primitive as `wrapped_blob_key_hex`. Lets the paired
    /// device agree on E2E DM keys as the canonical identity without ever
    /// holding a signing seed. `None` for hubs/clients that predate this
    /// field — plain JSON addition, no signing-bytes impact (`PairingComplete`
    /// itself is not signed; only the nested `cert` is).
    #[serde(default)]
    pub wrapped_dh_seed_hex: Option<String>,
}

/// Status returned by the pairing status endpoint. Both sides poll
/// this to advance the protocol. The pairing token is the
/// unguessable secret that gates access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PairingStatus {
    Pending,
    Claimed {
        subkey_pubkey: String,
        device_label: String,
    },
    Complete {
        cert: SubkeyCert,
        wrapped_blob_key_hex: String,
        #[serde(default)]
        wrapped_dh_seed_hex: Option<String>,
    },
    Expired,
}

/// Published DH key for a user. Stored on the user's home hub(s).
/// Signing prefix: "wavvon/dh-key/v1\0"
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DhKeyRecord {
    pub pubkey: String,        // Ed25519 pubkey (owner)
    pub dh_pubkey_hex: String, // X25519 pubkey hex
    pub signature_hex: String, // Ed25519 sig over signing_bytes()
    pub published_at: i64,
}

impl DhKeyRecord {
    pub fn signing_bytes(pubkey: &str, dh_pubkey_hex: &str) -> Vec<u8> {
        let mut out = b"wavvon/dh-key/v1\0".to_vec();
        let pk = pubkey.as_bytes();
        out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        out.extend_from_slice(pk);
        let dh = dh_pubkey_hex.as_bytes();
        out.extend_from_slice(&(dh.len() as u32).to_le_bytes());
        out.extend_from_slice(dh);
        out
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        let msg = Self::signing_bytes(&self.pubkey, &self.dh_pubkey_hex);
        crate::verify_signature(&self.pubkey, &msg, &hex::decode(&self.signature_hex)?)
    }
}

/// Signing bytes for a 1:1 encrypted DM envelope
/// (`EncryptedDmEnvelope`). Signed by the sender's identity key; both
/// the sender and the hub compute these bytes.
pub fn dm_envelope_signing_bytes(
    conv_id: &str,
    ciphertext_hex: &str,
    nonce_hex: &str,
    dh_pubkey_hex: &str,
) -> Vec<u8> {
    let mut buf = b"wavvon/dm-ciphertext/v1\0".to_vec();
    write_str(&mut buf, conv_id);
    write_str(&mut buf, ciphertext_hex);
    write_str(&mut buf, nonce_hex);
    write_str(&mut buf, dh_pubkey_hex);
    buf
}

/// Signing bytes for a Double Ratchet (v2) encrypted DM envelope.
/// Domain tag: "wavvon/dm-ciphertext/v2\0"
/// Fields: conv_id, message_index (u32 LE), prev_count (u32 LE),
///         ciphertext_hex, dh_pubkey_hex.
/// No nonce_hex — the nonce is derived from the message key, not transmitted.
pub fn dr_envelope_signing_bytes(
    conv_id: &str,
    message_index: u32,
    prev_count: u32,
    ciphertext_hex: &str,
    dh_pubkey_hex: &str,
) -> Vec<u8> {
    let mut buf = b"wavvon/dm-ciphertext/v2\0".to_vec();
    write_str(&mut buf, conv_id);
    write_u32_le(&mut buf, message_index);
    write_u32_le(&mut buf, prev_count);
    write_str(&mut buf, ciphertext_hex);
    write_str(&mut buf, dh_pubkey_hex);
    buf
}

/// Signing bytes for a group encrypted DM envelope
/// (`GroupEncryptedEnvelope`). The u32 fields are encoded as
/// length-prefixed **decimal strings**, not raw integers.
pub fn group_dm_envelope_signing_bytes(
    conv_id: &str,
    sender_key_version: u32,
    iteration: u32,
    ciphertext_hex: &str,
    nonce_hex: &str,
) -> Vec<u8> {
    let mut buf = b"wavvon/group-dm-ciphertext/v1\0".to_vec();
    write_str(&mut buf, conv_id);
    write_str(&mut buf, &sender_key_version.to_string());
    write_str(&mut buf, &iteration.to_string());
    write_str(&mut buf, ciphertext_hex);
    write_str(&mut buf, nonce_hex);
    buf
}

/// Canonical signing bytes for a plaintext federated DM.
///
/// Covers the fields the client knows at send time:
/// `conversation_id || conv_type || content`.
/// Domain tag: `"wavvon/federated-dm/v1\0"`.
///
/// `message_id` and `created_at` are hub-assigned and therefore excluded from
/// the signed payload; the client cannot know them before the hub responds.
/// The conversation_id + conv_type + content triple is sufficient to prevent a
/// remote hub from injecting a message with a forged `sender` field — an
/// attacker claiming `sender=victim` cannot produce victim's Ed25519 signature
/// over these bytes.
pub fn federated_plaintext_dm_signing_bytes(
    conversation_id: &str,
    conv_type: &str,
    content: &str,
) -> Vec<u8> {
    let mut buf = b"wavvon/federated-dm/v1\0".to_vec();
    write_str(&mut buf, conversation_id);
    write_str(&mut buf, conv_type);
    write_str(&mut buf, content);
    buf
}

/// Signing bytes for a sender-key distribution push
/// (`PushSenderKeyRequest`). Each recipient is a
/// `(recipient_pubkey, wrapped_key_hex)` pair; pairs are sorted by
/// `recipient_pubkey` before encoding so the signature is independent
/// of submission order.
pub fn sender_key_dist_signing_bytes(
    conv_id: &str,
    sender_key_version: u32,
    recipients: &[(String, String)],
) -> Vec<u8> {
    let mut buf = b"wavvon/group-key-dist/v1\0".to_vec();
    write_str(&mut buf, conv_id);
    write_str(&mut buf, &sender_key_version.to_string());
    let mut sorted: Vec<&(String, String)> = recipients.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (pubkey, wrapped_hex) in sorted {
        write_str(&mut buf, pubkey);
        write_str(&mut buf, wrapped_hex);
    }
    buf
}

/// Shared encoder for the recovery-rotation bundle (hub_pubkey, old_pubkey,
/// new_pubkey), parameterized by domain tag so distinct signers (new-key
/// proof vs. contact attestation) can never have their signatures replayed
/// as each other's.
fn recovery_bundle_bytes(
    tag: &[u8],
    hub_pubkey: &str,
    old_pubkey: &str,
    new_pubkey: &str,
) -> Vec<u8> {
    let mut buf = tag.to_vec();
    write_str(&mut buf, hub_pubkey);
    write_str(&mut buf, old_pubkey);
    write_str(&mut buf, new_pubkey);
    buf
}

/// Signing bytes for the requester's new-key proof, submitted inline with
/// `POST /recovery/rotate-key` (recovery-attestation.md §4 "New-key proof:
/// required"). Signed by `new_pubkey`, proving the requester holds the key
/// they're rotating to. No `request_nonce` here — the hub hasn't minted one
/// yet at the moment this is produced (the nonce is generated by the hub
/// only once the request row exists); binding to `hub_pubkey` still blocks
/// cross-hub replay of the proof.
pub fn recovery_request_signing_bytes(
    hub_pubkey: &str,
    old_pubkey: &str,
    new_pubkey: &str,
) -> Vec<u8> {
    recovery_bundle_bytes(
        b"wavvon/recovery-request/v1\0",
        hub_pubkey,
        old_pubkey,
        new_pubkey,
    )
}

/// Signing bytes for a recovery-contact attestation
/// (recovery-attestation.md §2 "How a contact attests"). A designated
/// recovery contact signs these bytes with their **master** key to vouch
/// for an open key-rotation request. `hub_pubkey` binds the attestation to
/// one hub; the hub-generated per-request `request_nonce` binds it to one
/// request, so neither a cross-hub nor a cross-request replay of the same
/// contact's signature is possible.
pub fn recovery_attestation_signing_bytes(
    hub_pubkey: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    request_nonce: &str,
) -> Vec<u8> {
    let mut buf = recovery_bundle_bytes(
        b"wavvon/recovery-attestation/v1\0",
        hub_pubkey,
        old_pubkey,
        new_pubkey,
    );
    write_str(&mut buf, request_nonce);
    buf
}

/// One entry in a user's public hub list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicHubEntry {
    pub hub_url: String,
    pub hub_name: String,
    pub joined_at: u64,
}

/// Master-signed public profile declaring which hubs a user wants others
/// to discover them on. Stored by hubs and served without authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicHubProfile {
    /// The user's identity public key (hex). This is the stable user ID on hubs.
    pub pubkey: String,
    pub display_name: String,
    #[serde(default)]
    pub avatar: Option<String>,
    pub public_hubs: Vec<PublicHubEntry>,
    pub issued_at: u64,
    pub signature: String,
}

impl PublicHubProfile {
    pub fn signing_bytes(pubkey: &str, public_hubs: &[PublicHubEntry], issued_at: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"wavvon/public-hub-profile/v1\0");
        write_str(&mut buf, pubkey);
        write_u64_le(&mut buf, issued_at);
        write_u32_le(&mut buf, public_hubs.len() as u32);
        for entry in public_hubs {
            write_str(&mut buf, &entry.hub_url);
            write_str(&mut buf, &entry.hub_name);
            write_u64_le(&mut buf, entry.joined_at);
        }
        buf
    }

    pub fn to_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(&self.pubkey, &self.public_hubs, self.issued_at)
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        check_sig(&self.pubkey, &self.to_signing_bytes(), &self.signature)
    }
}
