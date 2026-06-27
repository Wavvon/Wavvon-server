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
    dm_envelope_signing_bytes, group_dm_envelope_signing_bytes, sender_key_dist_signing_bytes,
    DhKeyRecord, HomeHubList, PairingClaim, PairingOffer, RevocationEntry, SignedPrefsBlob,
    SubkeyCert,
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

// X25519 DH pubkey derived from the master seed (SHA-512 + clamp)
const MASTER_DH_PUB: &str = "4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38";

// DhKeyRecord
const DH_KEY_RECORD_SIGNING_BYTES: &str =
    "766f78706c792f64682d6b65792f76310040000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636344000000034613338303764303634643037373138316363303730393839653736383931643230646361353535393534386463326337376331613530323733383832623338";
const DH_KEY_RECORD_SIG: &str =
    "055425d9cd0d2488c89bb9b0cc13f7ccb7f8581d20ba767123d4131bff9dd6abbb24b73c111777602d79b4cf4f7f8cc7c9eb0f3b3409bb2f1ab422330a2a7807";

// Shared DM-envelope fixed inputs
const DM_CONV_ID: &str = "conv123";
const DM_CIPHERTEXT_HEX: &str = "63697068657274657874"; // hex("ciphertext")
const DM_NONCE_HEX: &str = "0102030405060708090a0b0c";

// EncryptedDmEnvelope (1:1)
const DM_ENVELOPE_SIGNING_BYTES: &str =
    "766f78706c792f646d2d636970686572746578742f76310007000000636f6e76313233140000003633363937303638363537323734363537383734180000003031303230333034303530363037303830393061306230634000000034613338303764303634643037373138316363303730393839653736383931643230646361353535393534386463326337376331613530323733383832623338";
const DM_ENVELOPE_SIG: &str =
    "cacd0b3e90b7b09c25d0a2ae508470338a1b6c5b73935ba6245125c13c6bdc67bf647f9e108b59ea3ca913c3e7ad55b6c3a3157b9e95afc995ed9c22f9f34506";

// GroupEncryptedEnvelope — sender_key_version = 1, iteration = 2
const GROUP_DM_ENVELOPE_SIGNING_BYTES: &str =
    "766f78706c792f67726f75702d646d2d636970686572746578742f76310007000000636f6e763132330100000031010000003214000000363336393730363836353732373436353738373418000000303130323033303430353036303730383039306130623063";
const GROUP_DM_ENVELOPE_SIG: &str =
    "57c14f56b4367584ca5595586dde46dee09757d95200eeab6044948a2c6e39d3db7faa4a2ed352963c5d5ad76f85fb9b4345e3912bdd9d758583b362786b610f";

// Sender-key distribution — version 1, recipients supplied unsorted
// (subkey first) to exercise the canonical sort by recipient_pubkey.
const SENDER_KEY_DIST_SIGNING_BYTES: &str =
    "766f78706c792f67726f75702d6b65792d646973742f76310007000000636f6e76313233010000003140000000373962353536326538666536353466393430373862313132653861393862613739303166383533616536393562656437653065333931306261643034393636340800000031313232333334344000000065376631363261313062656335353961666561313935653464636538346236393536386435643263623039363365623434366330363835653262313766326630080000003535363637373838";
const SENDER_KEY_DIST_SIG: &str =
    "36325dd1c3e2a36618ceef4b8d91a7c71d4274c441dbbc37cb42bf2e96106d59fecf0721cb3042e1410b575d072b79189c14896bbbfc6a4266de7857e45c7a06";

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
