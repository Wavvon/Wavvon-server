use axum::http::StatusCode;
use wavvon_identity::{
    DeviceSubkey, HomeHubList, Identity, RevocationEntry, SignedPrefsBlob, SubkeyCert,
};

#[path = "common.rs"]
mod common;

fn signed_designation(
    master: &wavvon_identity::MasterIdentity,
    hubs: Vec<String>,
    issued_at: u64,
    sequence: u64,
) -> HomeHubList {
    let master_pubkey = master.public_key_hex();
    let bytes = HomeHubList::signing_bytes(&master_pubkey, &hubs, issued_at, sequence);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    HomeHubList {
        master_pubkey,
        hubs,
        issued_at,
        sequence,
        signature,
    }
}

fn signed_cert(
    master: &wavvon_identity::MasterIdentity,
    subkey_pubkey: &str,
    label: &str,
    issued_at: u64,
) -> SubkeyCert {
    let master_pubkey = master.public_key_hex();
    let bytes =
        SubkeyCert::signing_bytes(&master_pubkey, subkey_pubkey, label, issued_at, None, &[]);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    SubkeyCert {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        device_label: label.to_string(),
        issued_at,
        not_after: None,
        fallback_hubs: vec![],
        signature,
    }
}

/// Make the hub know an identity's master, the way a web client does on its
/// first join: the device authenticates (no cert yet — it has none), then
/// registers the cert that links its roster pubkey to the master a designation
/// is stored under. `PUT`ting a designation for a master the hub has never met
/// is refused, so every designation test has to arrive the way a client does.
async fn join_and_link(
    server: &axum_test::TestServer,
    identity: &Identity,
) -> wavvon_identity::MasterIdentity {
    let master = identity.master().unwrap();
    let token = common::authenticate(server, identity).await;
    let cert = signed_cert(
        &master,
        &identity.public_key_hex(),
        "Test device",
        1_700_000_000,
    );
    server
        .post(&format!("/identity/{}/devices", master.public_key_hex()))
        .authorization_bearer(&token)
        .json(&cert)
        .await
        .assert_status_ok();
    master
}

fn signed_revocation(
    master: &wavvon_identity::MasterIdentity,
    subkey_pubkey: &str,
    revoked_at: u64,
) -> RevocationEntry {
    let master_pubkey = master.public_key_hex();
    let bytes = RevocationEntry::signing_bytes(&master_pubkey, subkey_pubkey, revoked_at);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    RevocationEntry {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        revoked_at,
        signature,
    }
}

fn signed_prefs(
    master: &wavvon_identity::MasterIdentity,
    blob_version: u64,
    ciphertext: &[u8],
) -> SignedPrefsBlob {
    let master_pubkey = master.public_key_hex();
    let bytes = SignedPrefsBlob::signing_bytes(&master_pubkey, blob_version, ciphertext);
    let signature = hex::encode(master.sign(&bytes).to_bytes());
    SignedPrefsBlob {
        master_pubkey,
        blob_version,
        ciphertext_hex: hex::encode(ciphertext),
        signature,
    }
}

#[tokio::test]
async fn designation_roundtrip() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = join_and_link(&server, &identity).await;
    let master_pubkey = master.public_key_hex();

    let designation = signed_designation(
        &master,
        vec!["https://a.example".into(), "https://b.example".into()],
        1_700_000_000,
        1,
    );

    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&designation)
        .await;
    resp.assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/designation"))
        .await;
    resp.assert_status_ok();
    let got: HomeHubList = resp.json();
    assert_eq!(got.hubs, designation.hubs);
    assert_eq!(got.sequence, 1);
    assert!(got.verify().is_ok());
}

#[tokio::test]
async fn designation_rejects_stale_sequence() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = join_and_link(&server, &identity).await;
    let master_pubkey = master.public_key_hex();

    let d1 = signed_designation(&master, vec!["https://a.example".into()], 1, 5);
    server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d1)
        .await
        .assert_status_ok();

    // Same sequence should be rejected
    let d2 = signed_designation(&master, vec!["https://b.example".into()], 2, 5);
    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d2)
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn designation_rejects_url_body_mismatch() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = join_and_link(&server, &identity).await;
    let other = Identity::generate().master().unwrap();

    let d = signed_designation(&master, vec!["https://a.example".into()], 1, 1);
    let resp = server
        .post(&format!("/identity/{}/designation", other.public_key_hex()))
        .json(&d)
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn designation_rejects_bad_signature() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = join_and_link(&server, &identity).await;
    let master_pubkey = master.public_key_hex();

    let mut d = signed_designation(&master, vec!["https://a.example".into()], 1, 1);
    d.hubs.push("https://attacker.example".into()); // tamper post-sign
    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d)
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

/// The write stays unauthenticated — the desktop publishes to every hub in the
/// list and holds a session with at most one of them — so what bounds it is
/// that the hub has met the identity. A signature proves who signed, not that
/// anybody here has any reason to keep the row.
#[tokio::test]
async fn designation_refuses_a_master_the_hub_has_never_met() {
    let server = common::setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let d = signed_designation(&master, vec!["https://a.example".into()], 1, 1);
    let resp = server
        .post(&format!("/identity/{master_pubkey}/designation"))
        .json(&d)
        .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

    // And nothing was stored: the refusal is a refusal, not a slower write.
    let resp = server
        .get(&format!("/identity/{master_pubkey}/designation"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

/// Authenticate as a bare device subkey, the way a paired device does on a hub
/// that has not met it yet: challenge, sign, no cert presented.
async fn auth_as_subkey(server: &axum_test::TestServer, subkey: &DeviceSubkey) -> String {
    let pub_key = subkey.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&serde_json::json!({ "public_key": pub_key }))
        .await;
    let challenge = resp.json::<serde_json::Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let signature = subkey.sign(&hex::decode(&challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&serde_json::json!({
            "public_key": pub_key,
            "challenge": challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_ok();
    resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn device_cert_refuses_an_unauthenticated_caller() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = identity.master().unwrap();
    let master_pubkey = master.public_key_hex();

    let cert = signed_cert(&master, &identity.public_key_hex(), "desktop", 1);
    let resp = server
        .post(&format!("/identity/{master_pubkey}/devices"))
        .json(&cert)
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

/// The attack the session gate exists for. `SubkeyCert::verify` checks the
/// master's signature over bytes in which `subkey_pubkey` is an opaque string,
/// so a throwaway master can name *anybody* as its device. Mallory names
/// Alice's roster pubkey; `master_of` would then resolve Alice to Mallory's
/// master and deliver Alice's direct messages wherever Mallory says.
#[tokio::test]
async fn device_cert_refuses_a_subkey_the_caller_does_not_hold() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let mallory = Identity::generate();
    common::authenticate(&server, &alice).await;
    let mallory_token = common::authenticate(&server, &mallory).await;

    // Free to mint, correctly signed, and about somebody else entirely.
    let mallory_master = mallory.master().unwrap();
    let mallory_master_pubkey = mallory_master.public_key_hex();
    let cert = signed_cert(
        &mallory_master,
        &alice.public_key_hex(),
        "Alice's phone, allegedly",
        1,
    );

    let resp = server
        .post(&format!("/identity/{mallory_master_pubkey}/devices"))
        .authorization_bearer(&mallory_token)
        .json(&cert)
        .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

    // The refusal is a refusal, not a slower write.
    let resp = server
        .get(&format!("/identity/{mallory_master_pubkey}/devices"))
        .await;
    resp.assert_status_ok();
    assert!(resp.json::<Vec<SubkeyCert>>().is_empty());
}

/// A device belongs to one identity. The session gate already stops a stranger
/// claiming somebody else's key, but the holder re-registering under a second
/// master would leave the subkey named by two — and `master_of` picks a row,
/// not an identity.
#[tokio::test]
async fn device_cert_refuses_a_key_already_claimed_by_another_master() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let first = identity.master().unwrap();

    server
        .post(&format!("/identity/{}/devices", first.public_key_hex()))
        .authorization_bearer(&token)
        .json(&signed_cert(
            &first,
            &identity.public_key_hex(),
            "desktop",
            1,
        ))
        .await
        .assert_status_ok();

    let second = Identity::generate().master().unwrap();
    let resp = server
        .post(&format!("/identity/{}/devices", second.public_key_hex()))
        .authorization_bearer(&token)
        .json(&signed_cert(
            &second,
            &identity.public_key_hex(),
            "desktop",
            2,
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn devices_post_and_list() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let master = identity.master().unwrap();
    let master_pubkey = master.public_key_hex();

    let subkey_zero = identity.as_subkey_zero("desktop".into());
    let phone = DeviceSubkey::generate("phone".into());

    let cert0 = signed_cert(&master, &subkey_zero.public_key_hex(), "desktop", 1);
    let cert1 = signed_cert(&master, &phone.public_key_hex(), "phone", 2);

    // Each device registers its own cert, under its own session — which is the
    // only way the certs get here now, and matches what the clients do: the
    // first device at its first auth, the phone at its own.
    let desktop_token = common::authenticate(&server, &identity).await;
    server
        .post(&format!("/identity/{master_pubkey}/devices"))
        .authorization_bearer(&desktop_token)
        .json(&cert0)
        .await
        .assert_status_ok();

    let phone_token = auth_as_subkey(&server, &phone).await;
    server
        .post(&format!("/identity/{master_pubkey}/devices"))
        .authorization_bearer(&phone_token)
        .json(&cert1)
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/devices"))
        .await;
    resp.assert_status_ok();
    let certs: Vec<SubkeyCert> = resp.json();
    assert_eq!(certs.len(), 2);
    assert!(certs.iter().all(|c| c.verify().is_ok()));
    assert!(certs.iter().any(|c| c.device_label == "phone"));
}

#[tokio::test]
async fn revocation_post_and_list() {
    let server = common::setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let compromised = DeviceSubkey::generate("phone".into()).public_key_hex();
    let entry = signed_revocation(&master, &compromised, 42);

    server
        .post(&format!("/identity/{master_pubkey}/revocations"))
        .json(&entry)
        .await
        .assert_status_ok();

    // Idempotent re-post is OK.
    server
        .post(&format!("/identity/{master_pubkey}/revocations"))
        .json(&entry)
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/revocations"))
        .await;
    resp.assert_status_ok();
    let entries: Vec<RevocationEntry> = resp.json();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].verify().is_ok());
}

#[tokio::test]
async fn prefs_blob_roundtrip_with_version_check() {
    let server = common::setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let v1 = signed_prefs(&master, 1, b"first version");
    server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&v1)
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/prefs"))
        .await;
    resp.assert_status_ok();
    let got: SignedPrefsBlob = resp.json();
    assert_eq!(got.blob_version, 1);
    assert!(got.verify().is_ok());

    // Stale version is rejected.
    let stale = signed_prefs(&master, 1, b"replay attempt");
    let resp = server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&stale)
        .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);

    // Newer version is accepted.
    let v2 = signed_prefs(&master, 2, b"second version");
    server
        .put(&format!("/identity/{master_pubkey}/prefs"))
        .json(&v2)
        .await
        .assert_status_ok();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/prefs"))
        .await;
    let got: SignedPrefsBlob = resp.json();
    assert_eq!(got.blob_version, 2);
}

#[tokio::test]
async fn empty_resources_return_404_or_empty() {
    let server = common::setup().await;
    let master = Identity::generate().master().unwrap();
    let master_pubkey = master.public_key_hex();

    let resp = server
        .get(&format!("/identity/{master_pubkey}/designation"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    let resp = server
        .get(&format!("/identity/{master_pubkey}/prefs"))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    let resp = server
        .get(&format!("/identity/{master_pubkey}/devices"))
        .await;
    resp.assert_status_ok();
    let v: Vec<SubkeyCert> = resp.json();
    assert!(v.is_empty());

    let resp = server
        .get(&format!("/identity/{master_pubkey}/revocations"))
        .await;
    resp.assert_status_ok();
    let v: Vec<RevocationEntry> = resp.json();
    assert!(v.is_empty());
}
