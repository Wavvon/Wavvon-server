/// Canonical hex test vectors for every wire-format envelope type.
///
/// Inputs are fully deterministic — fixed key seeds and a fixed timestamp —
/// so any reimplementation (client or server) can reproduce the same bytes.
///
/// Fixed inputs:
///   master seed: 0x01 0x02 … 0x20  (32 bytes, little-endian index+1)
///   subkey seed: 0x21 0x22 … 0x40  (32 bytes)
///   timestamp  : 1_700_000_000  (unix seconds, u64 little-endian)
///
/// To regenerate: run the commented gen_vectors() test in a scratch file and
/// paste the output hex back here. The signing-bytes layout is authoritative;
/// see docs/wire-format.md for the complete field-by-field specification.
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use wavvon_identity::{
    dm_envelope_signing_bytes, group_dm_envelope_signing_bytes, recovery_attestation_signing_bytes,
    recovery_request_signing_bytes, sender_key_dist_signing_bytes, unwrap_blob_key, wrap_blob_key,
    DhKeyRecord, HomeHubList, PairingClaim, PairingComplete, PairingOffer, PairingStatus,
    RevocationEntry, SignedPrefsBlob, SubkeyCert,
};

const TS: u64 = 1_700_000_000;

fn master_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    SigningKey::from_bytes(&seed)
}

fn subkey_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 0x21) as u8;
    }
    SigningKey::from_bytes(&seed)
}

/// A third fixed identity — stands in for the "new key" being rotated to in
/// the recovery-attestation vectors. Continues the incrementing seed pattern
/// (master 0x01..0x20, subkey 0x21..0x40, this one 0x41..0x60).
fn new_key_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i + 0x41) as u8;
    }
    SigningKey::from_bytes(&seed)
}

fn hex_pubkey(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().as_bytes())
}

/// Standard ed25519→x25519 derivation: SHA-512(seed)[0..32] → clamp.
/// Mirrors `Identity::dh_keypair()`; replicated here so the derivation
/// itself is pinned by the MASTER_DH_PUB vector.
fn master_dh_pub_hex() -> String {
    let hash = Sha512::digest(master_key().to_bytes());
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let secret = x25519_dalek::StaticSecret::from(scalar);
    hex::encode(x25519_dalek::PublicKey::from(&secret).as_bytes())
}

// ---------------------------------------------------------------------------
// Canonical vectors
// ---------------------------------------------------------------------------

const MASTER_PUB: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
const SUBKEY_PUB: &str = "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";

// HomeHubList
const HOME_HUB_LIST_SIGNING_BYTES: &str =
    "776176766f6e2f686f6d652d6875622d6c6973742f7631004000000037396235353632653866653635346639343037386231313265386139386261373930316638353361653639356265643765306533393130626164303439363634010000001300000068747470733a2f2f6875622e6578616d706c6500f15365000000000100000000000000";
const HOME_HUB_LIST_SIG: &str =
    "193d446382d6dde14c0d85cf3b92a13858c7daa702bf284688af0514019de5665dbe52be683d41f85fa004c2b0c8be329ac608dbb18a4c03e9e0fd4380db0907";

// SubkeyCert
const SUBKEY_CERT_SIGNING_BYTES: &str =
    "776176766f6e2f7375626b65792d636572742f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630060000006c6170746f7000f15365000000000000000000";
const SUBKEY_CERT_SIG: &str =
    "ba99a98b72bef53d3dfc4767728806ca27cd247ecc11383453696d0011fc586e9eaf583c9632ff2805358dfda0de59f0cc8ca9aad33a5877be0d680b40513209";

// RevocationEntry
const REVOCATION_SIGNING_BYTES: &str =
    "776176766f6e2f7265766f636174696f6e2f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630f4f2536500000000";
const REVOCATION_SIG: &str =
    "6020787fb48d42085cbc7dbd8b3c78c7a4d1bcaa390baf2a9248af5d1d4b240813e2775acb86820f4ec106ae3b36df01a65c1db784fc40b36f279af50e0d910d";

// SignedPrefsBlob
const PREFS_CIPHERTEXT_HEX: &str = "63697068657274657874";
const PREFS_SIGNING_BYTES: &str =
    "776176766f6e2f70726566732d626c6f622f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636340100000000000000305531dcc50ebca31cf1d5b31e9fc76ed51f66b3b6dd5a030c6539ae6532f979";
const PREFS_SIG: &str =
    "7c463797b5cc76b3d8f47e6f86eff82bdbb8797bb538efcecfb8f743aed0c621d71d62612bd7aa750745710f0b3796ac60c8b4aefaeeb0f98883c5f47c8a1b0c";

// PairingOffer
const PAIRING_OFFER_SIGNING_BYTES: &str =
    "776176766f6e2f70616972696e672d6f666665722f7631004000000037396235353632653866653635346639343037386231313265386139386261373930316638353361653639356265643765306533393130626164303439363634010000001300000068747470733a2f2f6875622e6578616d706c6506000000746f6b31323300f15365000000002cf2536500000000";
const PAIRING_OFFER_SIG: &str =
    "93add8ced681c4dda4060417ba2f7301bff6a64876d015c30fa976307edeec75b69ff0af42a9415a50ce605ef2c561a70d19de0820334c16054336f904ec540f";

// PairingClaim (signed by subkey, not master)
const PAIRING_CLAIM_SIGNING_BYTES: &str =
    "776176766f6e2f70616972696e672d636c61696d2f76310006000000746f6b3132334000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630060000006c6170746f70";
const PAIRING_CLAIM_PROOF: &str =
    "cea1002c8bcad922848865158e5e7b2a7241929fcb13ce4a288e52cfecf912b71e2527ee0929198c2450027fb06ae04ac5f82acfffca28494feca7d253e22709";

// X25519 DH pubkey derived from the master seed (SHA-512 + clamp)
const MASTER_DH_PUB: &str = "4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38";

// DhKeyRecord
const DH_KEY_RECORD_SIGNING_BYTES: &str =
    "776176766f6e2f64682d6b65792f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000034613338303764303634643037373138316363303730393839653736383931643230646361353535393534386463326337376331613530323733383832623338";
const DH_KEY_RECORD_SIG: &str =
    "6fbb512c648347920f714a831b0e1b13266c60fef157fd93922092e04bb281ecc2918d6bd6ffce7e6602463753188fde022d04763bc30cd5d720829ddcff5603";

// Shared DM-envelope fixed inputs
const DM_CONV_ID: &str = "conv123";
const DM_CIPHERTEXT_HEX: &str = "63697068657274657874"; // hex("ciphertext")
const DM_NONCE_HEX: &str = "0102030405060708090a0b0c";

// EncryptedDmEnvelope (1:1)
const DM_ENVELOPE_SIGNING_BYTES: &str =
    "776176766f6e2f646d2d636970686572746578742f76310007000000636f6e76313233140000003633363937303638363537323734363537383734180000003031303230333034303530363037303830393061306230634000000034613338303764303634643037373138316363303730393839653736383931643230646361353535393534386463326337376331613530323733383832623338";
const DM_ENVELOPE_SIG: &str =
    "6d41d6b3f9f4c5b5d87a7d819f4e9b2e1a1340c3aa97cf044037f926c63710dd3edeb5bc66d9dfa89fc0d9fe2a67b8a28c6c5908f42b947b3551c04dbf113709";

// GroupEncryptedEnvelope — sender_key_version = 1, iteration = 2
const GROUP_DM_ENVELOPE_SIGNING_BYTES: &str =
    "776176766f6e2f67726f75702d646d2d636970686572746578742f76310007000000636f6e763132330100000031010000003214000000363336393730363836353732373436353738373418000000303130323033303430353036303730383039306130623063";
const GROUP_DM_ENVELOPE_SIG: &str =
    "d2788d4211a7fae57b17eae2cb74b56bd8a587ee9a9a57fd1ff0f048d0a86e256786bbdbc486f7754a6dac4975c2b25a2f9b0a7c73c288056e4b4938d6878b07";

// Sender-key distribution — version 1, recipients supplied unsorted
// (subkey first) to exercise the canonical sort by recipient_pubkey.
const SENDER_KEY_DIST_SIGNING_BYTES: &str =
    "776176766f6e2f67726f75702d6b65792d646973742f76310007000000636f6e76313233010000003140000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636340800000031313232333334344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630080000003535363637373838";
const SENDER_KEY_DIST_SIG: &str =
    "b3edd408f6a0700da3a9445be38cc6de2dcee4a927049b98e9f423e9654ee0b9c6adf9ff9ff4364f8ccd4f629d672b0c9cb517a0bb5b4e4de200f8a66f88fd04";

// Recovery-attestation bundle (recovery-attestation.md §2, §4). HUB_PUB and
// OLD_PUB reuse the existing MASTER_PUB/SUBKEY_PUB fixtures (any fixed
// pubkey-shaped string works — the encoder treats them as opaque); NEW_PUB
// is the third fixed identity above.
const HUB_PUB: &str = MASTER_PUB;
const OLD_PUB: &str = SUBKEY_PUB;
const REQUEST_NONCE: &str = "req-nonce-0001";

// Requester's new-key proof — signed by NEW_PUB's key, no nonce (see the
// doc comment on `recovery_request_signing_bytes`: the hub hasn't minted a
// nonce yet at proof time).
const RECOVERY_REQUEST_SIGNING_BYTES: &str =
    "776176766f6e2f7265636f766572792d726571756573742f763100400000003739623535363265386665363534663934303738623131326538613938626137393031663835336165363935626564376530653339313062616430343936363440000000653766313632613130626563353539616665613139356534646365383462363935363864356432636230393633656234343663303638356532623137663266304000000061646331343031316638326431633536643935366161346639643733643838353833363161363036303438353235653064303863363338646337356464386337";
const RECOVERY_REQUEST_PROOF: &str =
    "31d6892113f05da64c22ee7b3a108bf61e4df1592f820d53de0eeb15a7d3a1c50859df4dc08e72d4997047f590b001b2fa3378e77a64d678e277c5edc78a160b";

// Contact attestation — signed by the contact's master key (stood in for by
// master_key(), same convention every other envelope in this file uses).
const RECOVERY_ATTESTATION_SIGNING_BYTES: &str =
    "776176766f6e2f7265636f766572792d6174746573746174696f6e2f7631004000000037396235353632653866653635346639343037386231313265386139386261373930316638353361653639356265643765306533393130626164303439363634400000006537663136326131306265633535396166656131393565346463653834623639353638643564326362303936336562343436633036383565326231376632663040000000616463313430313166383264316335366439353661613466396437336438383538333631613630363034383532356530643038633633386463373564643863370e0000007265712d6e6f6e63652d30303031";
const RECOVERY_ATTESTATION_SIG: &str =
    "878bd554b21b60e63d1725db9a829d0107830e58ed0d8e80149368a833f1c09948490afd7cba160f34bc808092b15cf99141a86656c0d383fbaf04151edfb302";

fn new_pub() -> String {
    hex_pubkey(&new_key_signing_key())
}

fn dist_recipients() -> Vec<(String, String)> {
    vec![
        (SUBKEY_PUB.to_string(), "55667788".to_string()),
        (MASTER_PUB.to_string(), "11223344".to_string()),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_master_pubkey_vector() {
    assert_eq!(hex_pubkey(&master_key()), MASTER_PUB);
}

// The master signing key derived from the canonical entropy (0x01..0x20) via
// HKDF-SHA256(info="wavvon/master/v1"). Pins the derivation cross-language so
// the TS port (packages/core) can reproduce the same master pubkey.
const MASTER_FROM_ENTROPY_PUB: &str =
    "8fbafd0f662f225430eed18b132b3de956dc7d75c95b26baa97ada69aab51565";

#[test]
fn master_from_entropy_vector() {
    let mut entropy = [0u8; 32];
    for (i, b) in entropy.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let master = wavvon_identity::MasterIdentity::derive_from_entropy(&entropy).unwrap();
    assert_eq!(master.public_key_hex(), MASTER_FROM_ENTROPY_PUB);
}

#[test]
fn test_subkey_pubkey_vector() {
    assert_eq!(hex_pubkey(&subkey_signing_key()), SUBKEY_PUB);
}

#[test]
fn home_hub_list_signing_bytes_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let sb = HomeHubList::signing_bytes(MASTER_PUB, &hubs, TS, 1);
    assert_eq!(hex::encode(&sb), HOME_HUB_LIST_SIGNING_BYTES);
}

#[test]
fn home_hub_list_signature_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let sb = HomeHubList::signing_bytes(MASTER_PUB, &hubs, TS, 1);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), HOME_HUB_LIST_SIG);
}

#[test]
fn home_hub_list_verify_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let entry = HomeHubList {
        master_pubkey: MASTER_PUB.to_string(),
        hubs,
        issued_at: TS,
        sequence: 1,
        signature: HOME_HUB_LIST_SIG.to_string(),
    };
    assert!(entry.verify().is_ok());
}

#[test]
fn subkey_cert_signing_bytes_vector() {
    let sb = SubkeyCert::signing_bytes(MASTER_PUB, SUBKEY_PUB, "laptop", TS, None, &[]);
    assert_eq!(hex::encode(&sb), SUBKEY_CERT_SIGNING_BYTES);
}

#[test]
fn subkey_cert_signature_vector() {
    let sb = SubkeyCert::signing_bytes(MASTER_PUB, SUBKEY_PUB, "laptop", TS, None, &[]);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), SUBKEY_CERT_SIG);
}

#[test]
fn subkey_cert_verify_vector() {
    let cert = SubkeyCert {
        master_pubkey: MASTER_PUB.to_string(),
        subkey_pubkey: SUBKEY_PUB.to_string(),
        device_label: "laptop".to_string(),
        issued_at: TS,
        not_after: None,
        fallback_hubs: vec![],
        signature: SUBKEY_CERT_SIG.to_string(),
    };
    assert!(cert.verify().is_ok());
}

#[test]
fn revocation_signing_bytes_vector() {
    let sb = RevocationEntry::signing_bytes(MASTER_PUB, SUBKEY_PUB, TS + 500);
    assert_eq!(hex::encode(&sb), REVOCATION_SIGNING_BYTES);
}

#[test]
fn revocation_signature_vector() {
    let sb = RevocationEntry::signing_bytes(MASTER_PUB, SUBKEY_PUB, TS + 500);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), REVOCATION_SIG);
}

#[test]
fn revocation_verify_vector() {
    let entry = RevocationEntry {
        master_pubkey: MASTER_PUB.to_string(),
        subkey_pubkey: SUBKEY_PUB.to_string(),
        revoked_at: TS + 500,
        signature: REVOCATION_SIG.to_string(),
    };
    assert!(entry.verify().is_ok());
}

#[test]
fn prefs_blob_signing_bytes_vector() {
    let ct = hex::decode(PREFS_CIPHERTEXT_HEX).unwrap();
    let sb = SignedPrefsBlob::signing_bytes(MASTER_PUB, 1, &ct);
    assert_eq!(hex::encode(&sb), PREFS_SIGNING_BYTES);
}

#[test]
fn prefs_blob_signature_vector() {
    let ct = hex::decode(PREFS_CIPHERTEXT_HEX).unwrap();
    let sb = SignedPrefsBlob::signing_bytes(MASTER_PUB, 1, &ct);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), PREFS_SIG);
}

#[test]
fn prefs_blob_verify_vector() {
    let blob = SignedPrefsBlob {
        master_pubkey: MASTER_PUB.to_string(),
        blob_version: 1,
        ciphertext_hex: PREFS_CIPHERTEXT_HEX.to_string(),
        signature: PREFS_SIG.to_string(),
    };
    assert!(blob.verify().is_ok());
}

#[test]
fn pairing_offer_signing_bytes_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let sb = PairingOffer::signing_bytes(MASTER_PUB, &hubs, "tok123", TS, TS + 300);
    assert_eq!(hex::encode(&sb), PAIRING_OFFER_SIGNING_BYTES);
}

#[test]
fn pairing_offer_signature_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let sb = PairingOffer::signing_bytes(MASTER_PUB, &hubs, "tok123", TS, TS + 300);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), PAIRING_OFFER_SIG);
}

#[test]
fn pairing_offer_verify_vector() {
    let hubs = vec!["https://hub.example".to_string()];
    let offer = PairingOffer {
        master_pubkey: MASTER_PUB.to_string(),
        home_hubs: hubs,
        pairing_token: "tok123".to_string(),
        issued_at: TS,
        expires_at: TS + 300,
        signature: PAIRING_OFFER_SIG.to_string(),
    };
    assert!(offer.verify().is_ok());
}

#[test]
fn pairing_claim_signing_bytes_vector() {
    let sb = PairingClaim::signing_bytes("tok123", SUBKEY_PUB, "laptop");
    assert_eq!(hex::encode(&sb), PAIRING_CLAIM_SIGNING_BYTES);
}

#[test]
fn pairing_claim_proof_vector() {
    let sb = PairingClaim::signing_bytes("tok123", SUBKEY_PUB, "laptop");
    let sig = subkey_signing_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), PAIRING_CLAIM_PROOF);
}

#[test]
fn pairing_claim_verify_vector() {
    let claim = PairingClaim {
        pairing_token: "tok123".to_string(),
        subkey_pubkey: SUBKEY_PUB.to_string(),
        device_label: "laptop".to_string(),
        proof: PAIRING_CLAIM_PROOF.to_string(),
    };
    assert!(claim.verify().is_ok());
}

// ---------------------------------------------------------------------------
// PairingComplete.wrapped_dh_seed_hex — DM-attribution fix (see
// docs/docs/decisions.md "Paired-device DMs attribute to canonical via
// cert-chained envelopes"). `PairingComplete` itself carries no signing
// bytes (only the nested `cert` is signed), so the new field is a plain
// JSON addition — these are serde-compatibility checks, not signature
// vectors. `wrap_blob_key`/`unwrap_blob_key` are the same ECIES primitive
// `wrapped_blob_key_hex` already uses; the design reuses them verbatim to
// wrap the canonical X25519 DH **scalar** instead of the prefs-blob key,
// so no new primitive needs its own vector.
// ---------------------------------------------------------------------------

fn sample_cert() -> SubkeyCert {
    SubkeyCert {
        master_pubkey: MASTER_PUB.to_string(),
        subkey_pubkey: SUBKEY_PUB.to_string(),
        device_label: "laptop".to_string(),
        issued_at: TS,
        not_after: None,
        fallback_hubs: vec![],
        signature: SUBKEY_CERT_SIG.to_string(),
    }
}

#[test]
fn pairing_complete_without_wrapped_dh_seed_parses_as_none() {
    // Old JSON shape (predates this field) must still deserialize —
    // no wire-vector break for the existing pairing-complete path.
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

/// The wrapped-DH-scalar mechanism (decisions.md Mechanism A): the
/// enrolling device wraps the canonical X25519 **scalar** (not the
/// Ed25519 seed) with `wrap_blob_key` for the claiming subkey; the
/// claiming device unwraps with its own subkey seed via `unwrap_blob_key`.
/// This is the same primitive `wrapped_blob_key_hex` uses — this test
/// pins that it round-trips a DH scalar just as well as a symmetric key.
#[test]
fn wrapped_dh_scalar_round_trips_through_existing_ecies_primitive() {
    let master = master_key();
    let (master_dh_secret, _master_dh_pub) = {
        use sha2::{Digest, Sha512};
        let hash = Sha512::digest(master.to_bytes());
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let secret = x25519_dalek::StaticSecret::from(scalar);
        let public = x25519_dalek::PublicKey::from(&secret);
        (scalar, public)
    };

    let subkey = subkey_signing_key();
    let subkey_pubkey_hex = hex_pubkey(&subkey);

    let wrapped_hex = wrap_blob_key(&master_dh_secret, &subkey_pubkey_hex)
        .expect("wrapping the DH scalar should succeed");

    let unwrapped = unwrap_blob_key(&wrapped_hex, &subkey.to_bytes())
        .expect("the claiming subkey should unwrap its own wrapped scalar");

    assert_eq!(unwrapped, master_dh_secret);
}

#[test]
fn test_master_dh_pubkey_vector() {
    assert_eq!(master_dh_pub_hex(), MASTER_DH_PUB);
}

#[test]
fn dh_key_record_signing_bytes_vector() {
    let sb = DhKeyRecord::signing_bytes(MASTER_PUB, MASTER_DH_PUB);
    assert_eq!(hex::encode(&sb), DH_KEY_RECORD_SIGNING_BYTES);
}

#[test]
fn dh_key_record_signature_vector() {
    let sb = DhKeyRecord::signing_bytes(MASTER_PUB, MASTER_DH_PUB);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), DH_KEY_RECORD_SIG);
}

#[test]
fn dh_key_record_verify_vector() {
    let record = DhKeyRecord {
        pubkey: MASTER_PUB.to_string(),
        dh_pubkey_hex: MASTER_DH_PUB.to_string(),
        signature_hex: DH_KEY_RECORD_SIG.to_string(),
        published_at: TS as i64,
    };
    assert!(record.verify().is_ok());
}

#[test]
fn dm_envelope_signing_bytes_vector() {
    let sb = dm_envelope_signing_bytes(DM_CONV_ID, DM_CIPHERTEXT_HEX, DM_NONCE_HEX, MASTER_DH_PUB);
    assert_eq!(hex::encode(&sb), DM_ENVELOPE_SIGNING_BYTES);
}

#[test]
fn dm_envelope_signature_vector() {
    let sb = dm_envelope_signing_bytes(DM_CONV_ID, DM_CIPHERTEXT_HEX, DM_NONCE_HEX, MASTER_DH_PUB);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), DM_ENVELOPE_SIG);
}

#[test]
fn group_dm_envelope_signing_bytes_vector() {
    let sb = group_dm_envelope_signing_bytes(DM_CONV_ID, 1, 2, DM_CIPHERTEXT_HEX, DM_NONCE_HEX);
    assert_eq!(hex::encode(&sb), GROUP_DM_ENVELOPE_SIGNING_BYTES);
}

#[test]
fn group_dm_envelope_signature_vector() {
    let sb = group_dm_envelope_signing_bytes(DM_CONV_ID, 1, 2, DM_CIPHERTEXT_HEX, DM_NONCE_HEX);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), GROUP_DM_ENVELOPE_SIG);
}

#[test]
fn sender_key_dist_signing_bytes_vector() {
    let sb = sender_key_dist_signing_bytes(DM_CONV_ID, 1, &dist_recipients());
    assert_eq!(hex::encode(&sb), SENDER_KEY_DIST_SIGNING_BYTES);
}

#[test]
fn sender_key_dist_signature_vector() {
    let sb = sender_key_dist_signing_bytes(DM_CONV_ID, 1, &dist_recipients());
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), SENDER_KEY_DIST_SIG);
}

#[test]
fn recovery_request_signing_bytes_vector() {
    let new_pub = new_pub();
    let sb = recovery_request_signing_bytes(HUB_PUB, OLD_PUB, &new_pub);
    assert_eq!(hex::encode(&sb), RECOVERY_REQUEST_SIGNING_BYTES);
}

#[test]
fn recovery_request_proof_vector() {
    let new_pub = new_pub();
    let sb = recovery_request_signing_bytes(HUB_PUB, OLD_PUB, &new_pub);
    let sig = new_key_signing_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), RECOVERY_REQUEST_PROOF);
}

#[test]
fn recovery_attestation_signing_bytes_vector() {
    let new_pub = new_pub();
    let sb = recovery_attestation_signing_bytes(HUB_PUB, OLD_PUB, &new_pub, REQUEST_NONCE);
    assert_eq!(hex::encode(&sb), RECOVERY_ATTESTATION_SIGNING_BYTES);
}

#[test]
fn recovery_attestation_signature_vector() {
    let new_pub = new_pub();
    let sb = recovery_attestation_signing_bytes(HUB_PUB, OLD_PUB, &new_pub, REQUEST_NONCE);
    let sig = master_key().sign(&sb);
    assert_eq!(hex::encode(sig.to_bytes()), RECOVERY_ATTESTATION_SIG);
}

/// Distinct-tag guard: the same (hub, old, new) triple signed for two
/// different purposes (request proof vs. attestation) must never produce
/// the same signing bytes, or a proof signature could be replayed as an
/// attestation (or vice versa).
#[test]
fn recovery_request_and_attestation_bytes_differ() {
    let new_pub = new_pub();
    let request_sb = recovery_request_signing_bytes(HUB_PUB, OLD_PUB, &new_pub);
    let attestation_sb =
        recovery_attestation_signing_bytes(HUB_PUB, OLD_PUB, &new_pub, REQUEST_NONCE);
    assert_ne!(request_sb, attestation_sb);
}

#[test]
#[ignore]
fn gen_recovery_vectors() {
    let new_pub = new_pub();

    let sb = recovery_request_signing_bytes(HUB_PUB, OLD_PUB, &new_pub);
    println!("RECOVERY_REQUEST_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "RECOVERY_REQUEST_PROOF: {}",
        hex::encode(new_key_signing_key().sign(&sb).to_bytes())
    );

    let sb = recovery_attestation_signing_bytes(HUB_PUB, OLD_PUB, &new_pub, REQUEST_NONCE);
    println!("RECOVERY_ATTESTATION_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "RECOVERY_ATTESTATION_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );
}

#[test]
#[ignore]
fn gen_vectors() {
    let hubs = vec!["https://hub.example".to_string()];
    let sb = HomeHubList::signing_bytes(MASTER_PUB, &hubs, TS, 1);
    println!("HOME_HUB_LIST_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "HOME_HUB_LIST_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = SubkeyCert::signing_bytes(MASTER_PUB, SUBKEY_PUB, "laptop", TS, None, &[]);
    println!("SUBKEY_CERT_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "SUBKEY_CERT_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = RevocationEntry::signing_bytes(MASTER_PUB, SUBKEY_PUB, TS + 500);
    println!("REVOCATION_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "REVOCATION_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let ct = hex::decode(PREFS_CIPHERTEXT_HEX).unwrap();
    let sb = SignedPrefsBlob::signing_bytes(MASTER_PUB, 1, &ct);
    println!("PREFS_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "PREFS_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = PairingOffer::signing_bytes(MASTER_PUB, &hubs, "tok123", TS, TS + 300);
    println!("PAIRING_OFFER_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "PAIRING_OFFER_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = PairingClaim::signing_bytes("tok123", SUBKEY_PUB, "laptop");
    println!("PAIRING_CLAIM_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "PAIRING_CLAIM_PROOF: {}",
        hex::encode(subkey_signing_key().sign(&sb).to_bytes())
    );

    let sb = DhKeyRecord::signing_bytes(MASTER_PUB, MASTER_DH_PUB);
    println!("DH_KEY_RECORD_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "DH_KEY_RECORD_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = dm_envelope_signing_bytes(DM_CONV_ID, DM_CIPHERTEXT_HEX, DM_NONCE_HEX, MASTER_DH_PUB);
    println!("DM_ENVELOPE_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "DM_ENVELOPE_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = group_dm_envelope_signing_bytes(DM_CONV_ID, 1, 2, DM_CIPHERTEXT_HEX, DM_NONCE_HEX);
    println!("GROUP_DM_ENVELOPE_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "GROUP_DM_ENVELOPE_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );

    let sb = sender_key_dist_signing_bytes(DM_CONV_ID, 1, &dist_recipients());
    println!("SENDER_KEY_DIST_SIGNING_BYTES: {}", hex::encode(&sb));
    println!(
        "SENDER_KEY_DIST_SIG: {}",
        hex::encode(master_key().sign(&sb).to_bytes())
    );
}
