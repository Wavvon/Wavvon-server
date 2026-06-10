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
