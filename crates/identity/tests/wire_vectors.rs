//! Wire-format test vectors for every envelope type.
//!
//! The vectors are data, not code: `wire-vectors.json` (next to Cargo.toml) is
//! the single authority, published as a release asset so SDKs in other
//! languages assert the same file. This test computes every output from the
//! JSON inputs with the crate's own functions and compares against the JSON's
//! expected outputs; no expected hex lives in this file.
//!
//! To add or change a vector, edit the JSON. A failing assertion prints the
//! computed hex, so a deliberate wire change is: bump the version tag in the
//! crate, paste the new output into the JSON, and mirror the vector in the TS
//! and desktop crates. See docs/docs/wire-format.md for the field layouts.
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::Value;
use sha2::{Digest, Sha512};
use std::sync::OnceLock;
use wavvon_identity::{
    auth_challenge_signing_bytes, dm_envelope_signing_bytes, dm_member_change_signing_bytes,
    federated_plaintext_dm_signing_bytes, group_dm_envelope_signing_bytes,
    outgoing_webhook_signing_key, recovery_attestation_signing_bytes,
    recovery_request_signing_bytes, sender_key_dist_signing_bytes, unwrap_blob_key,
    voice_grant_signing_bytes, voice_key_unwrap, voice_key_wrap_with_nonce, voice_packet_open,
    voice_packet_seal, webhook_delivery_signing_bytes, webhook_hmac_sha256, wrap_blob_key,
    DhKeyRecord, HomeHubList, MasterIdentity, PairingClaim, PairingComplete, PairingOffer,
    PairingStatus, RevocationEntry, SignedPrefsBlob, SubkeyCert,
};

fn doc() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let v: Value = serde_json::from_str(include_str!("../wire-vectors.json")).unwrap();
        assert_eq!(v["format"], 1, "unknown wire-vectors.json format");
        v
    })
}

/// A string leaf, with `@name` replaced by the named fixture.
fn r(v: &Value) -> String {
    let s = v.as_str().unwrap_or_else(|| panic!("not a string: {v}"));
    match s.strip_prefix('@') {
        Some(name) => r(&doc()["fixtures"][name]),
        None => s.to_string(),
    }
}

fn vec_(name: &str) -> &'static Value {
    let v = &doc()["vectors"][name];
    assert!(!v.is_null(), "no vector {name}");
    v
}

fn inp(v: &Value, key: &str) -> Value {
    let x = &v["inputs"][key];
    assert!(!x.is_null() || key == "not_after", "missing input {key}");
    x.clone()
}

fn s(v: &Value, key: &str) -> String {
    r(&inp(v, key))
}

fn n(v: &Value, key: &str) -> u64 {
    inp(v, key).as_u64().unwrap()
}

fn strings(x: &Value) -> Vec<String> {
    x.as_array().unwrap().iter().map(r).collect()
}

fn bytes(x: &str) -> Vec<u8> {
    hex::decode(x).unwrap()
}

fn arr<const N: usize>(x: &str) -> [u8; N] {
    bytes(x).try_into().unwrap()
}

fn key_from_seed(seed_hex: &str) -> SigningKey {
    SigningKey::from_bytes(&arr::<32>(seed_hex))
}

fn pub_of(seed_hex: &str) -> String {
    hex::encode(key_from_seed(seed_hex).verifying_key().as_bytes())
}

/// Standard ed25519 -> x25519 derivation: SHA-512(seed)[0..32], clamped.
fn x25519_scalar(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

fn x25519_pub(seed: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(x25519_scalar(seed));
    *x25519_dalek::PublicKey::from(&secret).as_bytes()
}

fn expect(name: &str, field: &str, got: &[u8]) {
    assert_eq!(
        hex::encode(got),
        r(&vec_(name)[field]),
        "vector {name}.{field}"
    );
}

/// Asserts `signing_bytes` and the signature (field `sig_field`) of a vector
/// whose inputs name a `signer_seed`; returns the signature hex.
fn check_signed(name: &str, sig_field: &str, sb: &[u8]) -> String {
    let v = vec_(name);
    expect(name, "signing_bytes", sb);
    let sig = key_from_seed(&s(v, "signer_seed")).sign(sb);
    expect(name, sig_field, &sig.to_bytes());
    r(&v[sig_field])
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

#[test]
fn master_pubkey_vector() {
    let v = vec_("master_pubkey");
    assert_eq!(pub_of(&s(v, "seed")), r(&v["public_key"]));
}

#[test]
fn new_key_pubkey_vector() {
    let v = vec_("new_key_pubkey");
    assert_eq!(pub_of(&s(v, "seed")), r(&v["public_key"]));
}

#[test]
fn subkey_pubkey_vector() {
    let v = vec_("subkey_pubkey");
    assert_eq!(pub_of(&s(v, "seed")), r(&v["public_key"]));
}

#[test]
fn master_from_entropy_vector() {
    let v = vec_("master_from_entropy");
    let master = MasterIdentity::derive_from_entropy(&arr::<32>(&s(v, "entropy"))).unwrap();
    assert_eq!(master.public_key_hex(), r(&v["public_key"]));
}

#[test]
fn master_dh_pubkey_vector() {
    let v = vec_("master_dh_pubkey");
    assert_eq!(
        hex::encode(x25519_pub(&arr(&s(v, "seed")))),
        r(&v["dh_pubkey"])
    );
}

// ---------------------------------------------------------------------------
// Multi-device envelopes
// ---------------------------------------------------------------------------

#[test]
fn home_hub_list_vector() {
    let v = vec_("home_hub_list");
    let hubs = strings(&inp(v, "hubs"));
    let (master_pub, ts, seq) = (s(v, "master_pubkey"), n(v, "issued_at"), n(v, "sequence"));
    let sb = HomeHubList::signing_bytes(&master_pub, &hubs, ts, seq);
    let signature = check_signed("home_hub_list", "signature", &sb);
    let entry = HomeHubList {
        master_pubkey: master_pub,
        hubs,
        issued_at: ts,
        sequence: seq,
        signature,
    };
    assert!(entry.verify().is_ok());
}

#[test]
fn subkey_cert_vector() {
    let v = vec_("subkey_cert");
    assert!(inp(v, "not_after").is_null());
    assert!(strings(&inp(v, "fallback_hubs")).is_empty());
    let (master_pub, subkey_pub, label, ts) = (
        s(v, "master_pubkey"),
        s(v, "subkey_pubkey"),
        s(v, "device_label"),
        n(v, "issued_at"),
    );
    let sb = SubkeyCert::signing_bytes(&master_pub, &subkey_pub, &label, ts, None, &[]);
    let signature = check_signed("subkey_cert", "signature", &sb);
    let cert = SubkeyCert {
        master_pubkey: master_pub,
        subkey_pubkey: subkey_pub,
        device_label: label,
        issued_at: ts,
        not_after: None,
        fallback_hubs: vec![],
        signature,
    };
    assert!(cert.verify().is_ok());
}

#[test]
fn revocation_vector() {
    let v = vec_("revocation");
    let (master_pub, subkey_pub, at) = (
        s(v, "master_pubkey"),
        s(v, "subkey_pubkey"),
        n(v, "revoked_at"),
    );
    let sb = RevocationEntry::signing_bytes(&master_pub, &subkey_pub, at);
    let signature = check_signed("revocation", "signature", &sb);
    let entry = RevocationEntry {
        master_pubkey: master_pub,
        subkey_pubkey: subkey_pub,
        revoked_at: at,
        signature,
    };
    assert!(entry.verify().is_ok());
}

#[test]
fn prefs_blob_vector() {
    let v = vec_("prefs_blob");
    let (master_pub, ct_hex, version) = (
        s(v, "master_pubkey"),
        s(v, "ciphertext"),
        n(v, "blob_version"),
    );
    let sb = SignedPrefsBlob::signing_bytes(&master_pub, version, &bytes(&ct_hex));
    let signature = check_signed("prefs_blob", "signature", &sb);
    let blob = SignedPrefsBlob {
        master_pubkey: master_pub,
        blob_version: version,
        ciphertext_hex: ct_hex,
        signature,
    };
    assert!(blob.verify().is_ok());
}

#[test]
fn pairing_offer_vector() {
    let v = vec_("pairing_offer");
    let hubs = strings(&inp(v, "home_hubs"));
    let (master_pub, token, issued, expires) = (
        s(v, "master_pubkey"),
        s(v, "pairing_token"),
        n(v, "issued_at"),
        n(v, "expires_at"),
    );
    let sb = PairingOffer::signing_bytes(&master_pub, &hubs, &token, issued, expires);
    let signature = check_signed("pairing_offer", "signature", &sb);
    let offer = PairingOffer {
        master_pubkey: master_pub,
        home_hubs: hubs,
        pairing_token: token,
        issued_at: issued,
        expires_at: expires,
        signature,
    };
    assert!(offer.verify().is_ok());
}

#[test]
fn pairing_claim_vector() {
    let v = vec_("pairing_claim");
    let (token, subkey_pub, label) = (
        s(v, "pairing_token"),
        s(v, "subkey_pubkey"),
        s(v, "device_label"),
    );
    let sb = PairingClaim::signing_bytes(&token, &subkey_pub, &label);
    let proof = check_signed("pairing_claim", "proof", &sb);
    let claim = PairingClaim {
        pairing_token: token,
        subkey_pubkey: subkey_pub,
        device_label: label,
        proof,
    };
    assert!(claim.verify().is_ok());
}

#[test]
fn dh_key_record_vector() {
    let v = vec_("dh_key_record");
    let (pubkey, dh_pub, at) = (s(v, "pubkey"), s(v, "dh_pubkey"), n(v, "published_at"));
    let sb = DhKeyRecord::signing_bytes(&pubkey, &dh_pub);
    let signature_hex = check_signed("dh_key_record", "signature", &sb);
    let record = DhKeyRecord {
        pubkey,
        dh_pubkey_hex: dh_pub,
        signature_hex,
        published_at: at as i64,
    };
    assert!(record.verify().is_ok());
}

// ---------------------------------------------------------------------------
// PairingComplete.wrapped_dh_seed_hex — serde-compatibility checks, not
// signature vectors: `PairingComplete` carries no signing bytes of its own
// (only the nested cert is signed), so the field is a plain JSON addition.
// ---------------------------------------------------------------------------

fn sample_cert() -> SubkeyCert {
    let v = vec_("subkey_cert");
    SubkeyCert {
        master_pubkey: s(v, "master_pubkey"),
        subkey_pubkey: s(v, "subkey_pubkey"),
        device_label: s(v, "device_label"),
        issued_at: n(v, "issued_at"),
        not_after: None,
        fallback_hubs: vec![],
        signature: r(&v["signature"]),
    }
}

#[test]
fn pairing_complete_without_wrapped_dh_seed_parses_as_none() {
    let json = serde_json::json!({
        "pairing_token": "tok123",
        "cert": sample_cert(),
        "wrapped_blob_key_hex": "deadbeef",
    });
    let complete: PairingComplete = serde_json::from_value(json).unwrap();
    assert_eq!(complete.wrapped_dh_seed_hex, None);
}

#[test]
fn pairing_complete_round_trips_wrapped_dh_seed_hex() {
    let complete = PairingComplete {
        pairing_token: "tok123".to_string(),
        cert: sample_cert(),
        wrapped_blob_key_hex: "deadbeef".to_string(),
        wrapped_dh_seed_hex: Some("cafef00d".to_string()),
    };
    let json = serde_json::to_value(&complete).unwrap();
    let round_tripped: PairingComplete = serde_json::from_value(json).unwrap();
    assert_eq!(
        round_tripped.wrapped_dh_seed_hex,
        Some("cafef00d".to_string())
    );
}

#[test]
fn pairing_status_complete_round_trips_wrapped_dh_seed_hex() {
    let status = PairingStatus::Complete {
        cert: sample_cert(),
        wrapped_blob_key_hex: "deadbeef".to_string(),
        wrapped_dh_seed_hex: Some("cafef00d".to_string()),
    };
    let json = serde_json::to_value(&status).unwrap();
    let round_tripped: PairingStatus = serde_json::from_value(json).unwrap();
    match round_tripped {
        PairingStatus::Complete {
            wrapped_dh_seed_hex,
            ..
        } => assert_eq!(wrapped_dh_seed_hex, Some("cafef00d".to_string())),
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn pairing_status_complete_without_wrapped_dh_seed_parses_as_none() {
    let json = serde_json::json!({
        "state": "complete",
        "cert": sample_cert(),
        "wrapped_blob_key_hex": "deadbeef",
    });
    let status: PairingStatus = serde_json::from_value(json).unwrap();
    match status {
        PairingStatus::Complete {
            wrapped_dh_seed_hex,
            ..
        } => assert_eq!(wrapped_dh_seed_hex, None),
        other => panic!("expected Complete, got {other:?}"),
    }
}

/// The enrolling device wraps the canonical X25519 scalar (not the Ed25519
/// seed) with `wrap_blob_key` for the claiming subkey, which unwraps it with
/// its own seed — the same primitive `wrapped_blob_key_hex` uses.
#[test]
fn wrapped_dh_scalar_round_trips_through_existing_ecies_primitive() {
    let master_seed: [u8; 32] = arr(&r(&doc()["fixtures"]["master_seed"]));
    let scalar = x25519_scalar(&master_seed);
    let subkey_seed = r(&doc()["fixtures"]["subkey_seed"]);

    let wrapped_hex = wrap_blob_key(&scalar, &pub_of(&subkey_seed))
        .expect("wrapping the DH scalar should succeed");
    let unwrapped = unwrap_blob_key(&wrapped_hex, &arr::<32>(&subkey_seed))
        .expect("the claiming subkey should unwrap its own wrapped scalar");

    assert_eq!(unwrapped, scalar);
}

// ---------------------------------------------------------------------------
// DMs
// ---------------------------------------------------------------------------

#[test]
fn dm_envelope_vector() {
    let v = vec_("dm_envelope");
    let sb = dm_envelope_signing_bytes(
        &s(v, "conversation_id"),
        &s(v, "ciphertext"),
        &s(v, "nonce"),
        &s(v, "sender_dh_pubkey"),
    );
    check_signed("dm_envelope", "signature", &sb);
}

#[test]
fn group_dm_envelope_vector() {
    let v = vec_("group_dm_envelope");
    let sb = group_dm_envelope_signing_bytes(
        &s(v, "conversation_id"),
        n(v, "sender_key_version") as u32,
        n(v, "iteration") as u32,
        &s(v, "ciphertext"),
        &s(v, "nonce"),
    );
    check_signed("group_dm_envelope", "signature", &sb);
}

#[test]
fn sender_key_dist_vector() {
    let v = vec_("sender_key_dist");
    let recipients: Vec<(String, String)> = inp(v, "recipients")
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (r(&p[0]), r(&p[1])))
        .collect();
    let sb = sender_key_dist_signing_bytes(
        &s(v, "conversation_id"),
        n(v, "version") as u32,
        &recipients,
    );
    check_signed("sender_key_dist", "signature", &sb);
}

#[test]
fn federated_plaintext_dm_vector() {
    let v = vec_("federated_plaintext_dm");
    let sb = federated_plaintext_dm_signing_bytes(
        &s(v, "conversation_id"),
        &s(v, "kind"),
        &s(v, "content"),
    );
    check_signed("federated_plaintext_dm", "signature", &sb);
}

#[test]
fn dm_member_change_vector() {
    let v = vec_("dm_member_change");
    let sb = dm_member_change_signing_bytes(
        &s(v, "conversation_id"),
        &s(v, "actor"),
        &strings(&inp(v, "added")),
        &strings(&inp(v, "removed")),
        n(v, "timestamp"),
    );
    check_signed("dm_member_change", "signature", &sb);
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[test]
fn recovery_request_vector() {
    let v = vec_("recovery_request");
    let sb = recovery_request_signing_bytes(
        &s(v, "hub_pubkey"),
        &s(v, "old_pubkey"),
        &s(v, "new_pubkey"),
    );
    check_signed("recovery_request", "proof", &sb);
}

#[test]
fn recovery_attestation_vector() {
    let v = vec_("recovery_attestation");
    let sb = recovery_attestation_signing_bytes(
        &s(v, "hub_pubkey"),
        &s(v, "old_pubkey"),
        &s(v, "new_pubkey"),
        &s(v, "request_nonce"),
    );
    check_signed("recovery_attestation", "signature", &sb);
}

/// The same (hub, old, new) triple signed for two purposes must never yield
/// the same bytes, or a request proof could be replayed as an attestation.
#[test]
fn recovery_request_and_attestation_bytes_differ() {
    let v = vec_("recovery_attestation");
    let (hub, old, new) = (s(v, "hub_pubkey"), s(v, "old_pubkey"), s(v, "new_pubkey"));
    assert_ne!(
        recovery_request_signing_bytes(&hub, &old, &new),
        recovery_attestation_signing_bytes(&hub, &old, &new, &s(v, "request_nonce"))
    );
}

// ---------------------------------------------------------------------------
// Hub-signed and hub-to-program material
// ---------------------------------------------------------------------------

#[test]
fn auth_challenge_vector() {
    let v = vec_("auth_challenge");
    let sb = auth_challenge_signing_bytes(&bytes(&s(v, "challenge"))).unwrap();
    check_signed("auth_challenge", "signature", &sb);

    for len in [0, 31, 33, 64] {
        assert!(auth_challenge_signing_bytes(&vec![0u8; len]).is_err());
    }
}

#[test]
fn voice_grant_vector() {
    let v = vec_("voice_grant");
    let sb = voice_grant_signing_bytes(s(v, "payload_json").as_bytes());
    check_signed("voice_grant", "signature", &sb);
}

/// Slash/component dispatch: Ed25519 by the hub key over the V1 bytes.
#[test]
fn webhook_delivery_hub_vector() {
    let name = "webhook_delivery_hub";
    let v = vec_(name);
    let hub = key_from_seed(&s(v, "hub_seed"));
    let body = s(v, "body");
    let sb = webhook_delivery_signing_bytes(n(v, "timestamp"), body.as_bytes());
    expect(name, "signing_bytes", &sb);
    expect(name, "signature_v1", &hub.sign(&sb).to_bytes());
    assert_eq!(
        hex::encode(hub.verifying_key().as_bytes()),
        r(&v["hub_pubkey"])
    );
    let sig = ed25519_dalek::Signature::from_slice(&bytes(&r(&v["signature_v1"]))).unwrap();
    assert!(hub.verifying_key().verify(&sb, &sig).is_ok());
    check_headers(v);
}

/// The header names in the JSON are the constants the hub sends with.
fn check_headers(v: &Value) {
    let h = &v["headers"];
    for (key, constant) in [
        ("hub_pubkey", wavvon_identity::HEADER_HUB_PUBKEY),
        ("signature_v1", wavvon_identity::HEADER_SIGNATURE_V1),
        ("timestamp", wavvon_identity::HEADER_TIMESTAMP),
    ] {
        assert_eq!(h[key].as_str(), Some(constant), "header {key}");
    }
    if let Some(id) = h.get("webhook_id") {
        assert_eq!(id.as_str(), Some(wavvon_identity::HEADER_WEBHOOK_ID));
    }
}

/// Outgoing webhook: secret -> HKDF key -> HMAC-SHA256 over the V1 bytes.
#[test]
fn webhook_delivery_outgoing_vector() {
    use base64::Engine;
    let name = "webhook_delivery_outgoing";
    let v = vec_(name);
    let raw = bytes(&s(v, "raw_secret"));
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s(v, "secret_as_shown"))
            .unwrap(),
        raw
    );
    assert_eq!(s(v, "hkdf_salt"), "wavvon-webhook-signing");
    assert_eq!(s(v, "hkdf_info"), "");
    let key = outgoing_webhook_signing_key(&raw);
    expect(name, "signing_key", &key);

    let body = s(v, "body");
    let sb = webhook_delivery_signing_bytes(n(v, "timestamp"), body.as_bytes());
    expect(name, "signing_bytes", &sb);
    expect(
        name,
        "signature_v1",
        &webhook_hmac_sha256(&key, &sb).unwrap(),
    );
    check_headers(v);
}

// ---------------------------------------------------------------------------
// Voice transport v2
// ---------------------------------------------------------------------------

fn wrap_with_vector_inputs() -> Vec<u8> {
    let v = vec_("voice_key_wrap");
    let recipient_pub = x25519_pub(&arr(&s(v, "recipient_seed")));
    voice_key_wrap_with_nonce(
        &arr(&s(v, "sender_seed")),
        &recipient_pub,
        &s(v, "channel_id"),
        &arr(&s(v, "sender_key")),
        &arr(&s(v, "nonce_salt")),
        n(v, "key_id") as u32,
        &arr(&s(v, "wrap_nonce")),
    )
    .unwrap()
}

#[test]
fn voice_key_wrap_vector() {
    expect("voice_key_wrap", "ciphertext", &wrap_with_vector_inputs());
}

#[test]
fn voice_key_unwrap_vector() {
    let v = vec_("voice_key_wrap");
    let sender_pub = x25519_pub(&arr(&s(v, "sender_seed")));
    let (sender_key, nonce_salt, key_id) = voice_key_unwrap(
        &arr(&s(v, "recipient_seed")),
        &sender_pub,
        &s(v, "channel_id"),
        &bytes(&r(&v["ciphertext"])),
        &arr(&s(v, "wrap_nonce")),
    )
    .unwrap();
    assert_eq!(hex::encode(sender_key), s(v, "sender_key"));
    assert_eq!(hex::encode(nonce_salt), s(v, "nonce_salt"));
    assert_eq!(key_id as u64, n(v, "key_id"));
}

fn seal_vector(name: &str) -> Vec<u8> {
    let v = vec_(name);
    voice_packet_seal(
        &arr(&s(v, "sender_key")),
        &arr(&s(v, "nonce_salt")),
        n(v, "key_id") as u32,
        n(v, "counter"),
        n(v, "timestamp") as u32,
        &bytes(&s(v, "opus")),
    )
}

#[test]
fn voice_packet_vectors() {
    for name in ["voice_packet_ctr0", "voice_packet_ctr7"] {
        let v = vec_(name);
        let packet = seal_vector(name);
        expect(name, "packet", &packet);

        let (key_id, ctr, ts, opus) = voice_packet_open(
            &arr(&s(v, "sender_key")),
            &arr(&s(v, "nonce_salt")),
            &bytes(&r(&v["packet"])),
        )
        .unwrap();
        assert_eq!(key_id as u64, n(v, "key_id"), "{name}");
        assert_eq!(ctr, n(v, "counter"), "{name}");
        assert_eq!(ts as u64, n(v, "timestamp"), "{name}");
        assert_eq!(hex::encode(opus), s(v, "opus"), "{name}");
    }
}

#[test]
fn voice_packet_open_rejects_tampered_header() {
    let v = vec_("voice_packet_ctr0");
    let mut packet = seal_vector("voice_packet_ctr0");
    packet[0] ^= 0xff;
    let result = voice_packet_open(
        &arr(&s(v, "sender_key")),
        &arr(&s(v, "nonce_salt")),
        &packet,
    );
    assert!(result.is_err());
}
