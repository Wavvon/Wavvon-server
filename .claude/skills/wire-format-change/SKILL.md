---
name: wire-format-change
description: Checklist for changing a signed envelope or the backup format — the four implementations that must match byte-for-byte, the version-tag rule, and what "done" means. Use whenever touching crates/identity, an envelope layout, signing bytes, or the .wavvon-backup format.
---

# Changing a wire format

The signing bytes of every Wavvon envelope exist in **four places** that must
agree byte-for-byte. Three of them are in a different repository from this one.
Getting this wrong doesn't produce a compile error — it produces signatures one
side rejects, in production, on someone else's hub.

| Where | Repo | File |
|---|---|---|
| Authority | Wavvon-server (here) | `crates/identity/src/` |
| **Vectors (data)** | Wavvon-server (here) | `crates/identity/wire-vectors.json`, asserted by `tests/wire_vectors.rs` |
| Vendored vectors | Wavvon-clients | `wire-vectors/wire-vectors.json` + `wire-vectors/SOURCE` (the server commit) |
| TypeScript mirror | Wavvon-clients | `packages/core/src/identity/wire.ts` (+ `crypto.ts`, `voice.ts`), tests load the JSON via `wireVectors.ts` |
| Desktop Rust mirror | Wavvon-clients | `apps/desktop/src-tauri/src/identity.rs` (`mod wire_vector_tests`), `voice_keys.rs`, `crates/voice/src/crypto.rs` |
| Human-readable spec | Wavvon-docs | `docs/wire-format.md` |

The `.wavvon-backup` format follows the same discipline: `crates/*/backup` logic
here, `packages/core/src/identity/backup.ts` and
`apps/desktop/src-tauri/src/backup.rs` there, all asserting one fixed vector.

**The vectors are data, with one authority.** Every expected output is in
`crates/identity/wire-vectors.json` (a string starting with `@` names a
fixture); no test spells one out. The file ships as a release asset, the SDKs
assert it, and Wavvon-clients holds a byte-identical copy refreshed only by its
`scripts/sync-wire-vectors.mjs [ref]`, which CI checks against this repo at the
commit recorded in `wire-vectors/SOURCE`.

## The rule that makes this safe

**Never change the layout under an existing version tag.** The tag
(`b"wavvon/<name>/v1\0"`) is part of the signing bytes. A changed layout needs a
**new tag** — `wavvon/subkey-cert/v2\0` — so an old verifier rejects the new
format cleanly instead of computing a different hash over the same bytes and
reporting "invalid signature" for a reason nobody can find.

Deployments are **not** synchronized. Every hub serves its own baked-in copy of
the web client, and that copy talks to other hubs. So at any moment there are
old verifiers and new signers in the same network. A new version must be
introduced additively: emit the old version until the floor moves, accept both.

## Order of operations

1. **Decide whether this needs a new version tag at all.** Adding a field to the layout does. Adding a new envelope type doesn't touch existing ones.
2. **Change `crates/identity/src/`** — the authority. Keep the encoding explicit and length-prefixed; don't reach for a serialization crate that could change its output between versions.
3. **Add vectors to `crates/identity/wire-vectors.json`** for the new version, using the fixed inputs the spec defines, and assert them in `tests/wire_vectors.rs`. Keep the old vectors — they're the proof v1 still round-trips. Land it on `develop` first: the clients sync from a commit.
4. **Update the spec** in Wavvon-docs `docs/wire-format.md`: the envelope layout section and the fixed inputs, so the other two implementations have something to implement *against* rather than reading Rust.
5. **Mirror into Wavvon-clients** — both `wire.ts` and the desktop `identity.rs` — run `node scripts/sync-wire-vectors.mjs [ref]` there to vendor the new JSON, and assert any new vector by computing it from the JSON inputs. Never paste expected hex into a test file.
6. **If a client must know whether a hub speaks the new version**, add a capability string in `crates/hub/src/capabilities.rs` in the same commit. Clients test membership; they never compare version numbers.
7. **Run all three vector suites.** `cargo test -p wavvon-identity` here; in the clients repo `pnpm --filter @wavvon/core test`, `cargo test --workspace` (desktop shell + `crates/voice`) and `node scripts/check-wire-vectors.mjs`.

## What "done" means

All three vector suites green, the spec updated, and — if the change is
observable to a client — a capability string added. A change that compiles on
one side and hasn't been mirrored is **not** done, and saying "the client mirror
still needs updating" out loud is part of the deliverable, not a footnote.

If you cannot reach the clients repo (not checked out, no permission), stop and
say exactly which mirrors are outstanding and which files they live in. Don't
leave it implied.

> This checklist is duplicated in Wavvon-clients as the same skill, on purpose:
> each repo has to be usable alone. If you change one, change both.
