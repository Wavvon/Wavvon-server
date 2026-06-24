#!/usr/bin/env bash
# Prepare a release commit on develop. Merging to main triggers the rest.
# Usage: scripts/release.sh 0.3.0          (stable)
#        scripts/release.sh 0.3.0-beta.1   (pre-release)
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>  (e.g. 0.3.0 or 0.3.0-beta.1)" >&2
  exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"
HUB_CARGO="$ROOT/crates/hub/Cargo.toml"

if ! command -v git-cliff >/dev/null 2>&1; then
  echo "git-cliff not found. Install with: cargo install git-cliff" >&2
  exit 1
fi

echo "==> Bumping version to $VERSION in hub/Cargo.toml"
sed -i "0,/^version = \".*\"/{s/^version = \".*\"/version = \"$VERSION\"/}" "$HUB_CARGO"

echo "==> Updating CHANGELOG.md"
(cd "$ROOT" && git-cliff --unreleased --tag "v$VERSION" -o CHANGELOG.md)

echo "==> Committing on develop"
git -C "$ROOT" add hub/Cargo.toml CHANGELOG.md
git -C "$ROOT" commit -m "chore: release v$VERSION"

echo
echo "Done. Next steps:"
echo "  1. git push origin develop"
echo "  2. Open a PR: develop → main on GitHub"
echo "  3. Merge the PR — CI will tag v$VERSION and publish the release automatically"
