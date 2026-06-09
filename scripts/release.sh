#!/usr/bin/env bash
# Prepare a release: update CHANGELOG.md, commit, then tag.
# Usage: scripts/release.sh v0.3.0
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>  (e.g. v0.3.0)" >&2
  exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"

if ! command -v git-cliff >/dev/null 2>&1; then
  echo "git-cliff not found. Install with: cargo install git-cliff" >&2
  exit 1
fi

echo "==> Updating CHANGELOG.md for $VERSION"
(cd "$ROOT" && git-cliff --tag "$VERSION" -o CHANGELOG.md)

echo "==> Committing changelog"
git -C "$ROOT" add CHANGELOG.md
git -C "$ROOT" commit -m "chore: update CHANGELOG.md for $VERSION"

echo "==> Tagging $VERSION"
git -C "$ROOT" tag "$VERSION"

echo
echo "Done. Push with:"
echo "  git push && git push origin $VERSION"
