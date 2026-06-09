#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
HOOK="$ROOT/.git/hooks/pre-push"

cat > "$HOOK" <<'HOOK_BODY'
#!/usr/bin/env bash
set -euo pipefail
exec "$(git rev-parse --show-toplevel)/scripts/check.sh"
HOOK_BODY

chmod +x "$HOOK"
echo "Pre-push hook installed → $HOOK"
echo "Run 'SKIP_TESTS=1 git push' to skip cargo test (check still runs)."
