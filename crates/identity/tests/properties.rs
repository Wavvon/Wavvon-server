//! Properties over whole input domains, next to the fixed vectors in
//! wire_vectors.rs: a vector proves one input encodes as specified, these
//! prove the round trips hold for any input and that tampering is refused.

use proptest::prelude::*;
use wavvon_identity::{
    auth_challenge_signing_bytes, unwrap_blob_key, voice_key_unwrap, voice_key_wrap_with_nonce,
    voice_packet_open, voice_packet_seal, wrap_blob_key, DeviceSubkey, Identity, MasterIdentity,
};

fn x25519_pub_of(seed: &[u8; 32]) -> [u8; 32] {
    let identity =
        Identity::from_recovery_phrase(&bip39::Mnemonic::from_entropy(seed).unwrap().to_string())
            .unwrap();
    *identity.dh_keypair().1.as_bytes()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The 24 words carry the whole identity: the phrase of any entropy gives
    /// back the same device key and the same master.
    #[test]
    fn a_recovery_phrase_restores_the_identity(entropy in any::<[u8; 32]>()) {
        let phrase = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
        let restored = Identity::from_recovery_phrase(&phrase).unwrap();
        let device = DeviceSubkey::subkey_zero_from_entropy(&entropy, "d".into());
        prop_assert_eq!(restored.public_key_hex(), device.public_key_hex());
        let again = restored.recovery_phrase();
        prop_assert_eq!(again.as_str(), phrase.as_str());
        prop_assert_eq!(
            MasterIdentity::derive_from_phrase(&phrase).unwrap().public_key_hex(),
            MasterIdentity::derive_from_entropy(&entropy).unwrap().public_key_hex()
        );
    }

    /// Pairing's ECIES wrap opens only for the device it was wrapped for.
    #[test]
    fn an_ecies_wrap_opens_for_its_recipient_only(
        secret in any::<[u8; 32]>(),
        recipient in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
    ) {
        prop_assume!(recipient != other);
        let pubkey = DeviceSubkey::from_secret_bytes(&recipient, "r".into()).public_key_hex();
        let wrapped = wrap_blob_key(&secret, &pubkey).unwrap();
        prop_assert_eq!(unwrap_blob_key(&wrapped, &recipient).unwrap(), secret);
        prop_assert!(unwrap_blob_key(&wrapped, &other).is_err());
    }

    /// A voice packet opens to exactly what was sealed, and any flipped bit
    /// makes it unreadable rather than wrong.
    #[test]
    fn a_voice_packet_round_trips_and_refuses_tampering(
        key in any::<[u8; 32]>(),
        salt in any::<[u8; 4]>(),
        key_id in any::<u32>(),
        ctr in any::<u64>(),
        ts in any::<u32>(),
        opus in proptest::collection::vec(any::<u8>(), 0..1500),
        flip in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let packet = voice_packet_seal(&key, &salt, key_id, ctr, ts, &opus);
        let (k, c, t, body) = voice_packet_open(&key, &salt, &packet).unwrap();
        prop_assert_eq!((k, c, t), (key_id, ctr, ts));
        prop_assert_eq!(body, opus);

        let mut tampered = packet.clone();
        let i = flip.index(tampered.len());
        tampered[i] ^= 1 << bit;
        prop_assert!(voice_packet_open(&key, &salt, &tampered).is_err());
    }

    /// A voice sender key wrapped for one recipient unwraps there, for that
    /// channel only.
    #[test]
    fn a_voice_key_wrap_round_trips_for_its_channel(
        sender in any::<[u8; 32]>(),
        recipient in any::<[u8; 32]>(),
        sender_key in any::<[u8; 32]>(),
        salt in any::<[u8; 4]>(),
        key_id in any::<u32>(),
        nonce in any::<[u8; 12]>(),
        channel in "[a-z0-9-]{1,40}",
    ) {
        let wrapped = voice_key_wrap_with_nonce(
            &sender, &x25519_pub_of(&recipient), &channel, &sender_key, &salt, key_id, &nonce,
        ).unwrap();
        let (k, s, id) =
            voice_key_unwrap(&recipient, &x25519_pub_of(&sender), &channel, &wrapped, &nonce).unwrap();
        prop_assert_eq!((k, s, id), (sender_key, salt, key_id));
        let elsewhere = format!("{channel}-other");
        prop_assert!(
            voice_key_unwrap(&recipient, &x25519_pub_of(&sender), &elsewhere, &wrapped, &nonce).is_err()
        );
    }

    /// Only a 32-byte challenge is ever signed.
    #[test]
    fn only_32_byte_challenges_are_signed(challenge in proptest::collection::vec(any::<u8>(), 0..80)) {
        prop_assert_eq!(auth_challenge_signing_bytes(&challenge).is_ok(), challenge.len() == 32);
    }
}
