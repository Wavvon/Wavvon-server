# wavvon-identity

The wire format of [Wavvon](https://github.com/Wavvon), a self-hosted,
federated voice and text community platform: every signed envelope a client,
bot or hub exchanges, the exact bytes each one signs, and the crypto they use.

- Ed25519 identities, BIP39 recovery phrases, per-device subkey certificates
  and pairing.
- Signing bytes for every envelope: home-hub list, revocations, prefs blob,
  DM and group-DM envelopes, sender-key distribution, recovery requests and
  attestations, voice grants, the auth challenge, webhook deliveries.
- X25519 from an Ed25519 seed, AES-256-GCM, voice key wrap and packet seal,
  outgoing-webhook HKDF and HMAC.

Pure Rust, no async, no I/O. This crate is the authority the Wavvon hub uses;
every other implementation must match it byte for byte. The test vectors are
data, in `wire-vectors.json`, shipped with the crate and with each
[Wavvon-server](https://github.com/Wavvon/Wavvon-server) release.

The layout of each envelope is specified in
[wire-format.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/wire-format.md).
To write a bot or an app rather than reimplement the protocol, use
[wavvon-sdk](https://crates.io/crates/wavvon-sdk).

Licensed under Apache-2.0, unlike the rest of Wavvon-server (AGPL-3.0), so
that third-party clients and SDKs can link it.
