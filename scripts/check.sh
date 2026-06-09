#!/usr/bin/env bash
# Mirrors the CI checks in .github/workflows/build.yml.
# Run from the repo root, or let the pre-push hook call it automatically.
#
# Skip slow tests locally:  SKIP_TESTS=1 scripts/check.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

pass() { echo "  ✓ $*"; }
header() { echo; echo "==> $*"; }

# ── Cargo check ───────────────────────────────────────────────────────────────
header "Cargo check (workspace)"
(cd "$ROOT" && cargo check --workspace)
pass "cargo check"

# ── Cargo test ────────────────────────────────────────────────────────────────
if [ "${SKIP_TESTS:-0}" = "1" ]; then
  echo
  echo "==> Tests skipped (SKIP_TESTS=1)"
else
  header "Cargo test (workspace)"
  (cd "$ROOT" && cargo test --workspace)
  pass "cargo test"
fi

echo
echo "All checks passed."
