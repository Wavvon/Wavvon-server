# Wire Format Specification

This document is the canonical reference for every signed binary envelope
produced by the `identity` crate (`identity/src/wire.rs`).  Client
implementations **must** reproduce these exact byte sequences to interoperate.

The corresponding Rust test vectors live in
`identity/tests/wire_vectors.rs`. Those tests assert the exact hex produced
from the fixed inputs below; the doc and the code must stay in sync.

---

## Primitive encoding helpers

All multi-byte integers are **little-endian**.

| Helper | Encoding |
|--------|----------|
| `write_u32_le(v)` | 4 bytes, LE |
| `write_u64_le(v)` | 8 bytes, LE |
| `write_str(s)` | `write_u32_le(len(s))` + UTF-8 bytes of `s` |
| `write_str_vec(v)` | `write_u32_le(len(v))` + each element as `write_str` |

---

## Fixed inputs for test vectors

```
master seed : 01 02 03 … 20  (bytes 1–32)
subkey seed : 21 22 23 … 40  (bytes 33–64)
timestamp   : 1_700_000_000  (0x65_53_F1_00, u64 LE = 00 f1 53 65 00 00 00 00)
```

Derived public keys (Ed25519, encoded as hex):

```
master_pub : 79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664
subkey_pub : e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0
```

Derived X25519 DH public key (standard ed25519→x25519 conversion:
`SHA-512(master seed)[0..32]` → clamp → `X25519(scalar, basepoint)`):

```
master_dh_pub : 4a3807d064d077181cc070989e76891d20dca5559548dc2c77c1a50273882b38
```

Fixed inputs shared by the DM-envelope vectors below:

```
conv_id        : "conv123"
ciphertext_hex : 63697068657274657874   (hex of "ciphertext")
nonce_hex      : 0102030405060708090a0b0c
```

---

## Envelope layouts

### HomeHubList

Signed by the master key. Fields used for signature:

```
prefix       : "voxply/home-hub-list/v1\0"   (24 bytes incl. NUL)
master_pubkey: write_str(master_pubkey_hex)
hubs         : write_str_vec(hubs)
issued_at    : write_u64_le(issued_at)
sequence     : write_u64_le(sequence)
```

**Test vector** — hubs = `["https://hub.example"]`, sequence = 1:

```
signing_bytes:
  766f78706c792f686f6d652d6875622d6c6973742f7631004000000037396235
  353632653866653635346639343037386231313265386139386261373930316638
  353361653639356265643765306533393130626164303439363634010000001300
  000068747470733a2f2f6875622e6578616d706c6500f153650000000001000000
  00000000

signature (master):
  4870a33b56b0379da91cf0c7cf517bb0dc9d0f2c4fbe487cd1b310811b70c2a
  3ad0bbec3468cf58c4c696a472207e29925b8975f87e68eaeaa4fc3fc449a9f03
```

---

### SubkeyCert

Signed by the master key. Fields used for signature:

```
prefix       : "voxply/subkey-cert/v1\0"   (22 bytes incl. NUL)
master_pubkey: write_str(master_pubkey_hex)
subkey_pubkey: write_str(subkey_pubkey_hex)
device_label : write_str(device_label)
issued_at    : write_u64_le(issued_at)
not_after    : 0x00  if None
               0x01 + write_u64_le(t)  if Some(t)
fallback_hubs: write_str_vec(fallback_hubs)
```

**Test vector** — device_label = `"laptop"`, not_after = None, fallback_hubs = `[]`:

```
signing_bytes:
  766f78706c792f7375626b65792d636572742f76310040000000373962353536
  326538666536353466393430373862313132653861393862613739303166383533
  616536393562656437653065333931306261643034393636344000000065376631
  363261313062656335353961666561313935653464636538346236393536386435
  643263623039363365623434366330363835653262313766326630060000006c61
  70746f7000f15365000000000000000000

signature (master):
  90a7abf5cf8915efea90740ab0e0b8f09ed93343584dbddeb7b593a1f0c4c4c8
  83590f88e5ce46d14bd986cb4081e0860850934031c8343f82335699fd95fc04
```

---

### RevocationEntry

Signed by the master key. Fields used for signature:

```
prefix       : "voxply/revocation/v1\0"   (21 bytes incl. NUL)
master_pubkey: write_str(master_pubkey_hex)
subkey_pubkey: write_str(subkey_pubkey_hex)
revoked_at   : write_u64_le(revoked_at)
```

**Test vector** — revoked_at = `TS + 500 = 1_700_000_500`:

```
signing_bytes:
  766f78706c792f7265766f636174696f6e2f76310040000000373962353536326538
  666536353466393430373862313132653861393862613739303166383533616536393562
  656437653065333931306261643034393636344000000065376631363261313062656335
  353961666561313935653464636538346236393536386435643263623039363365623434
  366330363835653262313766326630f4f2536500000000

signature (master):
  97b97ed6ef6586d23d20c5dc1f96265611758a7bdccb06455b3a79674b176fb
  ee65a4fd0223e181cd0d10d8c6107eb04fc6ca742814ff017c97ed1a7726ac406
```

---

### SignedPrefsBlob

Signed by the master key. Fields used for signature:

```
prefix       : "voxply/prefs-blob/v1\0"   (21 bytes incl. NUL)
master_pubkey: write_str(master_pubkey_hex)
blob_version : write_u64_le(blob_version)
sha256_digest: SHA-256(ciphertext_bytes)   (32 bytes, raw)
```

Note: `ciphertext_hex` in the JSON is the hex of the raw ciphertext. The
hash is computed over the raw bytes, not the hex string.

**Test vector** — blob_version = 1, ciphertext = `"ciphertext"` (UTF-8):

```
ciphertext_hex : 63697068657274657874
signing_bytes:
  766f78706c792f70726566732d626c6f622f76310040000000373962353536326538
  666536353466393430373862313132653861393862613739303166383533616536393562
  656437653065333931306261643034393636340100000000000000305531dcc50ebca31c
  f1d5b31e9fc76ed51f66b3b6dd5a030c6539ae6532f979

signature (master):
  6e76b197980a4b0b8794c1c2989663b6045ceffaf3985e5f6b6681f636fbf46
  750ccfb0424f3aa02b95d504cea19c60d5c27e09905924eb50096a30a2f3ce80c
```

---

### PairingOffer

Signed by the master key. Fields used for signature:

```
prefix        : "voxply/pairing-offer/v1\0"   (24 bytes incl. NUL)
master_pubkey : write_str(master_pubkey_hex)
home_hubs     : write_str_vec(home_hubs)
pairing_token : write_str(pairing_token)
issued_at     : write_u64_le(issued_at)
expires_at    : write_u64_le(expires_at)
```

**Test vector** — home_hubs = `["https://hub.example"]`, token = `"tok123"`,
expires_at = `TS + 300`:

```
signing_bytes:
  766f78706c792f70616972696e672d6f666665722f7631004000000037396235353632
  653866653635346639343037386231313265386139386261373930316638353361653639
  356265643765306533393130626164303439363634010000001300000068747470733a2f
  2f6875622e6578616d706c6506000000746f6b31323300f15365000000002cf2536500000000

signature (master):
  e7ed2fb82e5c195e532ce949f8804c2069854697abd744f532c490322fa42af4
  b8708bb473762a0261dfeb7a8209ef165849e7bc08f653d41f0b8064b89e470a
```

---

### PairingClaim

Signed by the **subkey** (new device), not the master. Fields used for signature:

```
prefix        : "voxply/pairing-claim/v1\0"   (25 bytes incl. NUL)
pairing_token : write_str(pairing_token)
subkey_pubkey : write_str(subkey_pubkey_hex)
device_label  : write_str(device_label)
```

**Test vector** — token = `"tok123"`, device_label = `"laptop"`:

```
signing_bytes:
  766f78706c792f70616972696e672d636c61696d2f76310006000000746f6b313233
  4000000065376631363261313062656335353961666561313935653464636538346236
  393536386435643263623039363365623434366330363835653262313766326630
  060000006c6170746f70

proof (subkey signature):
  e2eeee6d5b5032974c19b6aff42361829846f2e26e7e329985ad709d6b8c6f45
  e48156adcb75301570759bd14a1e192f4499fa0273adab1ee3db900821663608
```

---

### PairingComplete

Not directly signed; it is a container that wraps a `SubkeyCert` (see above)
and an opaque `wrapped_blob_key_hex`. No separate signing bytes.

---

### DhKeyRecord

```
prefix       : "voxply/dh-key/v1\0"   (18 bytes incl. NUL)
pubkey       : write_str(ed25519_pubkey_hex)
dh_pubkey_hex: write_str(x25519_pubkey_hex)
```

Signed by the user's Ed25519 identity key.

**Test vector** — pubkey = `master_pub`, dh_pubkey = `master_dh_pub`:

```
signing_bytes:
  766f78706c792f64682d6b65792f7631004000000037396235353632653866653635
  34663934303738623131326538613938626137393031663835336165363935626564
  37653065333931306261643034393636344000000034613338303764303634643037
  37313831636330373039383965373638393164323064636135353539353438646332
  6337376331613530323733383832623338

signature (master):
  055425d9cd0d2488c89bb9b0cc13f7ccb7f8581d20ba767123d4131bff9dd6abbb24
  b73c111777602d79b4cf4f7f8cc7c9eb0f3b3409bb2f1ab422330a2a7807
```

---

### EncryptedDmEnvelope

Signing bytes for a 1:1 E2E encrypted DM. Signed by the **sender's**
Ed25519 identity key; the hub recomputes these bytes and verifies the
signature before storing the envelope.

```
prefix        : "voxply/dm-ciphertext/v1\0"   (24 bytes incl. NUL)
conv_id       : write_str(conv_id)
ciphertext_hex: write_str(ciphertext_hex)
nonce_hex     : write_str(nonce_hex)
dh_pubkey_hex : write_str(dh_pubkey_hex)
```

Note: the hex fields are length-prefixed **hex strings**, not raw bytes.

**Test vector** — conv_id = `"conv123"`, dh_pubkey = `master_dh_pub`:

```
signing_bytes:
  766f78706c792f646d2d636970686572746578742f76310007000000636f6e763132
  33140000003633363937303638363537323734363537383734180000003031303230
  33303430353036303730383039306130623063400000003461333830376430363464
  30373731383163633037303938396537363839316432306463613535353935343864
  63326337376331613530323733383832623338

signature (master):
  cacd0b3e90b7b09c25d0a2ae508470338a1b6c5b73935ba6245125c13c6bdc67bf64
  7f9e108b59ea3ca913c3e7ad55b6c3a3157b9e95afc995ed9c22f9f34506
```

---

### GroupEncryptedEnvelope

Signing bytes for a group E2E encrypted DM (sender-key scheme). Signed
by the sender's Ed25519 identity key.

```
prefix            : "voxply/group-dm-ciphertext/v1\0"   (30 bytes incl. NUL)
conv_id           : write_str(conv_id)
sender_key_version: write_str(decimal string of u32)
iteration         : write_str(decimal string of u32)
ciphertext_hex    : write_str(ciphertext_hex)
nonce_hex         : write_str(nonce_hex)
```

Note: `sender_key_version` and `iteration` are length-prefixed
**decimal strings** (e.g. `1` → `01000000 31`), not raw integers.

**Test vector** — conv_id = `"conv123"`, sender_key_version = 1,
iteration = 2:

```
signing_bytes:
  766f78706c792f67726f75702d646d2d636970686572746578742f76310007000000
  636f6e76313233010000003101000000321400000036333639373036383635373237
  34363537383734180000003031303230333034303530363037303830393061306230
  63

signature (master):
  57c14f56b4367584ca5595586dde46dee09757d95200eeab6044948a2c6e39d3db7f
  aa4a2ed352963c5d5ad76f85fb9b4345e3912bdd9d758583b362786b610f
```

---

### Sender-key distribution (PushSenderKeyRequest)

Signing bytes for a group sender-key distribution push. Signed by the
sender's Ed25519 identity key.

```
prefix            : "voxply/group-key-dist/v1\0"   (25 bytes incl. NUL)
conv_id           : write_str(conv_id)
sender_key_version: write_str(decimal string of u32)
per recipient     : write_str(recipient_pubkey)
                    write_str(wrapped_key_hex)
```

Recipients are sorted by `recipient_pubkey` (byte-wise ascending)
before encoding, so the signature is independent of submission order.
There is **no count prefix** before the recipient list.

**Test vector** — conv_id = `"conv123"`, sender_key_version = 1,
recipients supplied unsorted as
`[(subkey_pub, "55667788"), (master_pub, "11223344")]`
(canonical sort puts `master_pub` first):

```
signing_bytes:
  766f78706c792f67726f75702d6b65792d646973742f76310007000000636f6e7631
  32330100000031400000003739623535363265386665363534663934303738623131
  32653861393862613739303166383533616536393562656437653065333931306261
  64303439363634080000003131323233333434400000006537663136326131306265
  63353539616665613139356534646365383462363935363864356432636230393633
  65623434366330363835653262313766326630080000003535363637373838

signature (master):
  36325dd1c3e2a36618ceef4b8d91a7c71d4274c441dbbc37cb42bf2e96106d59fecf
  0721cb3042e1410b575d072b79189c14896bbbfc6a4266de7857e45c7a06
```

---

### PublicHubProfile

```
prefix      : "voxply/public-hub-profile/v1\0"   (29 bytes incl. NUL)
pubkey      : write_str(pubkey_hex)
issued_at   : write_u64_le(issued_at)
hub_count   : write_u32_le(len(public_hubs))
per hub     : write_str(hub_url)
              write_str(hub_name)
              write_u64_le(joined_at)
```

Signed by the user's Ed25519 identity key.

---

## Version bump policy

The version tag is part of the signing bytes. Any change to the field layout
**must** use a new tag (e.g. `voxply/subkey-cert/v2\0`) so old verifiers
reject the new format cleanly. Add new vectors to
`identity/tests/wire_vectors.rs` for the new version.
