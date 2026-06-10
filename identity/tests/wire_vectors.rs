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
use voxply_identity::{
    HomeHubList, PairingClaim, PairingOffer, RevocationEntry, SignedPrefsBlob, SubkeyCert,
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

fn hex_pubkey(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().as_bytes())
}

// ---------------------------------------------------------------------------
// Canonical vectors
// ---------------------------------------------------------------------------

const MASTER_PUB: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
const SUBKEY_PUB: &str = "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";

// HomeHubList
const HOME_HUB_LIST_SIGNING_BYTES: &str =
    "766f78706c792f686f6d652d6875622d6c6973742f7631004000000037396235353632653866653635346639343037386231313265386139386261373930316638353361653639356265643765306533393130626164303439363634010000001300000068747470733a2f2f6875622e6578616d706c6500f15365000000000100000000000000";
const HOME_HUB_LIST_SIG: &str =
    "4870a33b56b0379da91cf0c7cf517bb0dc9d0f2c4fbe487cd1b310811b70c2a3ad0bbec3468cf58c4c696a472207e29925b8975f87e68eaeaa4fc3fc449a9f03";

// SubkeyCert
const SUBKEY_CERT_SIGNING_BYTES: &str =
    "766f78706c792f7375626b65792d636572742f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630060000006c6170746f7000f15365000000000000000000";
const SUBKEY_CERT_SIG: &str =
    "90a7abf5cf8915efea90740ab0e0b8f09ed93343584dbddeb7b593a1f0c4c4c883590f88e5ce46d14bd986cb4081e0860850934031c8343f82335699fd95fc04";

// RevocationEntry
const REVOCATION_SIGNING_BYTES: &str =
    "766f78706c792f7265766f636174696f6e2f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630f4f2536500000000";
const REVOCATION_SIG: &str =
    "97b97ed6ef6586d23d20c5dc1f96265611758a7bdccb06455b3a79674b176fbee65a4fd0223e181cd0d10d8c6107eb04fc6ca742814ff017c97ed1a7726ac406";

// SignedPrefsBlob
const PREFS_CIPHERTEXT_HEX: &str = "63697068657274657874";
const PREFS_SIGNING_BYTES: &str =
    "766f78706c792f70726566732d626c6f622f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636340100000000000000305531dcc50ebca31cf1d5b31e9fc76ed51f66b3b6dd5a030c6539ae6532f979";
const PREFS_SIG: &str =
    "6e76b197980a4b0b8794c1c2989663b6045ceffaf3985e5f6b6681f636fbf46750ccfb0424f3aa02b95d504cea19c60d5c27e09905924eb50096a30a2f3ce80c";

// PairingOffer
const PAIRING_OFFER_SIGNING_BYTES: &str =
    "766f78706c792f70616972696e672d6f666665722f7631004000000037396235353632653866653635346639343037386231313265386139386261373930316638353361653639356265643765306533393130626164303439363634010000001300000068747470733a2f2f6875622e6578616d706c6506000000746f6b31323300f15365000000002cf2536500000000";
const PAIRING_OFFER_SIG: &str =
    "e7ed2fb82e5c195e532ce949f8804c2069854697abd744f532c490322fa42af4b8708bb473762a0261dfeb7a8209ef165849e7bc08f653d41f0b8064b89e470a";

// PairingClaim (signed by subkey, not master)
const PAIRING_CLAIM_SIGNING_BYTES: &str =
    "766f78706c792f70616972696e672d636c61696d2f76310006000000746f6b3132334000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630060000006c6170746f70";
const PAIRING_CLAIM_PROOF: &str =
    "e2eeee6d5b5032974c19b6aff42361829846f2e26e7e329985ad709d6b8c6f45e48156adcb75301570759bd14a1e192f4499fa0273adab1ee3db900821663608";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_master_pubkey_vector() {
    assert_eq!(hex_pubkey(&master_key()), MASTER_PUB);
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
