//! E2E DM crypto: the key derivations and AEAD behind 1:1 and group DMs
//! (`docs/docs/e2e-encryption.md`, `docs/docs/sdk-dm.md`). Pure Rust, no I/O,
//! no randomness: callers pass nonces and ephemeral scalars in, so every
//! function is pinned by the `dm_key_v1`, `dr_session`, `group_ratchet` and
//! `group_key_wrap` vectors in `wire-vectors.json`.
//!
//! This is the construction the desktop shell (`dm.rs`) and the web client
//! (`crypto.ts`) already implement, not a new design. Secrets and public keys
//! are raw 32-byte X25519 values (see `Identity::dh_keypair`). Every
//! ciphertext is AES-256-GCM with the tag appended.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    *StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*public))
        .as_bytes()
}

fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn hkdf64(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| anyhow!("AES-GCM encrypt: {e}"))
}

fn open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(anyhow!("nonce must be 12 bytes"));
    }
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("decryption failed"))
}

// ---------------------------------------------------------------------------
// 1:1 v1 (static key, `dm-ciphertext/v1`; receive-only for new clients)
// ---------------------------------------------------------------------------

/// `HKDF-SHA256(X25519(my, peer), salt = conv_id UTF-8, info "wavvon/dm-key/v1")`.
pub fn dm_key_v1(my_dh_secret: &[u8; 32], peer_dh_pub: &[u8; 32], conv_id: &str) -> [u8; 32] {
    hkdf32(
        &dh(my_dh_secret, peer_dh_pub),
        Some(conv_id.as_bytes()),
        b"wavvon/dm-key/v1",
    )
}

pub fn dm_v1_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal(key, nonce, plaintext)
}

pub fn dm_v1_open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    open(key, nonce, ciphertext)
}

// ---------------------------------------------------------------------------
// 1:1 v2 double ratchet (`dm-ciphertext/v2`)
// ---------------------------------------------------------------------------

/// `rk0 = HKDF(X25519(my static, their static), salt = conv_id, info "wavvon/dr-init/v2")`.
pub fn dr_root_key(
    my_static_secret: &[u8; 32],
    their_static_pub: &[u8; 32],
    conv_id: &str,
) -> [u8; 32] {
    hkdf32(
        &dh(my_static_secret, their_static_pub),
        Some(conv_id.as_bytes()),
        b"wavvon/dr-init/v2",
    )
}

/// KDF_RK: `(new_rk, new_ck) = HKDF(ikm = dh_output, salt = rk, info "wavvon/dr-rk/v2", 64 bytes)`.
pub fn dr_kdf_rk(rk: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    hkdf64(dh_output, Some(rk), b"wavvon/dr-rk/v2")
}

/// KDF_CK: `(msg_key, next_ck) = HKDF(ikm = ck, no salt, info "wavvon/dr-ck-step/v2", 64 bytes)`.
pub fn dr_kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    hkdf64(ck, None, b"wavvon/dr-ck-step/v2")
}

/// The AES-GCM nonce for a message key:
/// `HKDF(ikm = msg_key, no salt, info "wavvon/dr-nonce/v2", 12 bytes)`.
pub fn dr_derive_nonce(msg_key: &[u8; 32]) -> [u8; 12] {
    let mut out = [0u8; 12];
    Hkdf::<Sha256>::new(None, msg_key)
        .expand(b"wavvon/dr-nonce/v2", &mut out)
        .expect("12 bytes is a valid HKDF-SHA256 output length");
    out
}

pub fn dr_message_seal(msg_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal(msg_key, &dr_derive_nonce(msg_key), plaintext)
}

pub fn dr_message_open(msg_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    open(msg_key, &dr_derive_nonce(msg_key), ciphertext)
}

/// A session as the initiator leaves it before its first message.
pub struct DrInitiator {
    pub rk: [u8; 32],
    /// Sending chain key.
    pub cks: [u8; 32],
    /// The ratchet public key sent as `dh_pubkey_hex` on the first message.
    pub eph_pub: [u8; 32],
}

/// Initiator session: `(rk, cks) = KDF_RK(rk0, X25519(eph, their static))`.
pub fn dr_initiator_init(
    my_static_secret: &[u8; 32],
    their_static_pub: &[u8; 32],
    conv_id: &str,
    eph_secret: &[u8; 32],
) -> DrInitiator {
    let rk0 = dr_root_key(my_static_secret, their_static_pub, conv_id);
    let (rk, cks) = dr_kdf_rk(&rk0, &dh(eph_secret, their_static_pub));
    DrInitiator {
        rk,
        cks,
        eph_pub: *PublicKey::from(&StaticSecret::from(*eph_secret)).as_bytes(),
    }
}

/// A session as the responder holds it after the first inbound envelope.
pub struct DrResponder {
    pub rk: [u8; 32],
    /// Receiving chain key; equals the initiator's `cks`.
    pub ckr: [u8; 32],
    /// Sending chain key, seeded by the responder's own fresh ratchet key.
    pub cks: [u8; 32],
    pub eph_pub: [u8; 32],
}

/// Responder session from the first envelope's `dh_pubkey_hex` (`incoming_dhr`):
/// `(rk1, ckr) = KDF_RK(rk0, X25519(my static, incoming))`, then
/// `(rk, cks) = KDF_RK(rk1, X25519(eph, incoming))`.
pub fn dr_responder_init(
    my_static_secret: &[u8; 32],
    their_static_pub: &[u8; 32],
    conv_id: &str,
    incoming_dhr: &[u8; 32],
    eph_secret: &[u8; 32],
) -> DrResponder {
    let rk0 = dr_root_key(my_static_secret, their_static_pub, conv_id);
    let (rk1, ckr) = dr_kdf_rk(&rk0, &dh(my_static_secret, incoming_dhr));
    let (rk, cks) = dr_kdf_rk(&rk1, &dh(eph_secret, incoming_dhr));
    DrResponder {
        rk,
        ckr,
        cks,
        eph_pub: *PublicKey::from(&StaticSecret::from(*eph_secret)).as_bytes(),
    }
}

/// X25519 shared secret, the `dh_output` of a DH-ratchet step for [`dr_kdf_rk`].
pub fn dr_dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    dh(secret, public)
}

// ---------------------------------------------------------------------------
// Group sender-key ratchet (`group-dm-ciphertext/v1`)
// ---------------------------------------------------------------------------

/// `HKDF(chain_key, salt = iteration BE, info "wavvon/group-msg/v1")`.
pub fn group_msg_key(chain_key: &[u8; 32], iteration: u32) -> [u8; 32] {
    hkdf32(
        chain_key,
        Some(&iteration.to_be_bytes()),
        b"wavvon/group-msg/v1",
    )
}

/// The chain key for `iteration + 1`: info `"wavvon/group-chain/v1"`.
pub fn group_next_chain_key(chain_key: &[u8; 32], iteration: u32) -> [u8; 32] {
    hkdf32(
        chain_key,
        Some(&iteration.to_be_bytes()),
        b"wavvon/group-chain/v1",
    )
}

/// The iteration, big-endian in the last four of twelve zero bytes.
pub fn group_nonce(iteration: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&iteration.to_be_bytes());
    nonce
}

/// Encrypt one message at `iteration`. Returns `(ciphertext, nonce, next_chain_key)`;
/// the caller stores the next key and `iteration + 1` before reusing the chain.
pub fn group_message_seal(
    chain_key: &[u8; 32],
    iteration: u32,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12], [u8; 32])> {
    let nonce = group_nonce(iteration);
    let ct = seal(&group_msg_key(chain_key, iteration), &nonce, plaintext)?;
    Ok((ct, nonce, group_next_chain_key(chain_key, iteration)))
}

/// Decrypt a message at `iteration` from a chain key held at `held_iteration`.
/// A message before the held iteration is unreadable by design.
pub fn group_message_open(
    chain_key: &[u8; 32],
    held_iteration: u32,
    iteration: u32,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if iteration < held_iteration {
        return Err(anyhow!("chain_advanced_past_message"));
    }
    let mut ck = *chain_key;
    for i in held_iteration..iteration {
        ck = group_next_chain_key(&ck, i);
    }
    open(&group_msg_key(&ck, iteration), nonce, ciphertext)
}

// ---------------------------------------------------------------------------
// Group key wrap (`PUT /conversations/{id}/sender-keys`)
// ---------------------------------------------------------------------------

fn group_wrap_key(my_dh_secret: &[u8; 32], peer_dh_pub: &[u8; 32], conv_id: &str) -> [u8; 32] {
    hkdf32(
        &dh(my_dh_secret, peer_dh_pub),
        Some(conv_id.as_bytes()),
        b"wavvon/group-key-dist/v1",
    )
}

/// Wrap `chain_key || iteration BE` for one member. The caller picks a random
/// 12-byte nonce and sends it alongside the ciphertext.
pub fn group_key_wrap(
    my_dh_secret: &[u8; 32],
    recipient_dh_pub: &[u8; 32],
    conv_id: &str,
    chain_key: &[u8; 32],
    iteration: u32,
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    let mut plaintext = [0u8; 36];
    plaintext[..32].copy_from_slice(chain_key);
    plaintext[32..].copy_from_slice(&iteration.to_be_bytes());
    seal(
        &group_wrap_key(my_dh_secret, recipient_dh_pub, conv_id),
        nonce,
        &plaintext,
    )
}

/// Inverse of [`group_key_wrap`]: `(chain_key, iteration)`.
pub fn group_key_unwrap(
    my_dh_secret: &[u8; 32],
    sender_dh_pub: &[u8; 32],
    conv_id: &str,
    nonce: &[u8],
    wrapped: &[u8],
) -> Result<([u8; 32], u32)> {
    let plain = open(
        &group_wrap_key(my_dh_secret, sender_dh_pub, conv_id),
        nonce,
        wrapped,
    )?;
    if plain.len() < 36 {
        return Err(anyhow!("bad wrapped chain key"));
    }
    let mut ck = [0u8; 32];
    ck.copy_from_slice(&plain[..32]);
    Ok((ck, u32::from_be_bytes(plain[32..36].try_into().unwrap())))
}
