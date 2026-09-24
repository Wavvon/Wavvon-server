# End-to-end against real binaries

`cargo test` builds its own `AppState` and starts no process, so it cannot see
anything that lives in migrations, bootstrap, config or the CLI — which is most
of what an operator meets first.

Every bug this harness has found was invisible to the integration suite for
that reason. The first: `/auth/verify`'s invite gate exempted bots but not
federating hubs, and a fresh hub is `invite_only`, so **two hubs with default
settings could never form an alliance**. The in-process tests never wrote the
setting, so `is_invite_only` answered false there and every assertion passed.

## Running it

```bash
docker start wavvon-pg          # or any PostgreSQL on localhost:5432
cargo build -p wavvon-hub
cargo build -p wavvon-farm      # only for the farm stages

node e2e/run.mjs                # every stage
node e2e/run.mjs permissions    # one
```

`E2E_VERBOSE=1` streams every child process's output. `TEST_DATABASE_URL`
points the harness at a different PostgreSQL.

Two stages want a second binary:

```bash
# pgupgrade walks a real PostgreSQL major upgrade, and a binary bundles exactly
# one archive chosen at build time — so it needs two of them.
POSTGRESQL_VERSION="=17.6.0" cargo build -p wavvon-hub --target-dir target-pg17
```

## The stages

| Stage | What only it can see |
|---|---|
| `hubs` | Two hubs boot with separate identities and databases, and the seeded owner really owns. |
| `alliance` | Two hubs federate and share a channel — the handshake that the invite gate silently blocked. |
| `voice` | An allied hub's member is admitted to a voice room here, and a closed room refuses. |
| `certs` | Certificate issuance and the pull from an issuer this hub trusts. |
| `permissions` | The permission model end to end: validation, the escalation ceiling on all four grant paths, the read/voice split, and the catalogue the hub serves. |
| `pgupgrade` | The major upgrade walked the way the hub's own refusal tells an operator to walk it. |
| `alliancesplit` | Three hubs: a partner in one alliance must not see the other. |
| `alliancedelegate` | Who may act on *one* alliance: the per-alliance grant list, the channel permission sharing also needs, and the widening a delegate must not manage. |
| `alliancestress`, `alliancechurn`, `alliancedrift` | Alliances under load, membership churn, and state drift between hubs. |
| `farm`, `crossfarm` | A farm hosting its own hubs, and an alliance across two farms. |

## What is *not* here

Anything needing a second checkout lives in the monorepo's own `e2e-topology/`,
which imports this directory's `lib.mjs` rather than copying it: the discovery
site (`discovery/`) and the three stages driving a real browser from the
clients repo.

**Several hubs is not cross-repo** — two hubs are two processes of one binary,
which is why most of the harness lives here.

## Writing a stage

`scenario(name, fn)` with `check` / `checkEq` inside; `hub(name, owner)` boots
one with its own database, ports, work directory and seeded owner; `identity()`
and `authenticate()` handle the challenge-response. Everything is torn down by
`teardown()` whether the run passes or not.

Two rules worth keeping:

- **Drive routes, not the database.** A stage that writes a column proves the
  column. One that calls the route proves the feature — an earlier version of
  the alliance-policy check set the column directly and would have passed with
  no route at all.
- **Run a new stage against the unfixed build first.** A stage that is green
  either way tests nothing. Build the previous commit into a second
  `--target-dir` — a `git worktree` at that commit keeps your tree alone — and
  point **`E2E_HUB_BIN`** at the binary it produced:

  ```bash
  git worktree add ../wavvon-before <commit-before-the-fix>
  (cd ../wavvon-before && cargo build -p wavvon-hub --target-dir <abs>/target-before)
  E2E_HUB_BIN=<abs>/target-before/debug/wavvon-hub.exe node e2e/run.mjs <stage>
  ```

  Watch it fail there before you trust it passing here. (`E2E_OLD_HUB_BIN` is a
  different knob: the *previous PostgreSQL major* the `pgupgrade` stage needs.)
