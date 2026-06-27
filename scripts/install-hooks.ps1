# Install the pre-push git hook for Wavvon-server.
# Run from any directory inside the repo:  .\scripts\install-hooks.ps1
$root = git rev-parse --show-toplevel
$hookDir = "$root/.git/hooks"
$hook = "$hookDir/pre-push"

if (-not (Test-Path $hookDir)) {
    New-Item -ItemType Directory -Force $hookDir | Out-Null
}

@'
#!/usr/bin/env bash
set -euo pipefail
exec "$(git rev-parse --show-toplevel)/scripts/check.sh"
'@ | Set-Content -Encoding utf8NoBOM $hook

Write-Host "Pre-push hook installed -> $hook"
Write-Host "Set `$env:SKIP_TESTS=1 before git push to skip cargo test."
