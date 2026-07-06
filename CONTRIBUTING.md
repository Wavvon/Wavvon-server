# Contributing

See [CONTRIBUTING.md in the Wavvon docs repo](https://github.com/Wavvon/Wavvon-docs/blob/main/CONTRIBUTING.md)
for the full branching model, workflow, and release process.

Quick reference for this repo:

- Branch off `develop` — `feat/`, `fix/`, `chore/`, `docs/`
- PR into `develop` for regular work
- PR `develop → main` to ship a release (CI tags and publishes automatically)
- Install the pre-push hook: `bash scripts/install-hooks.sh` (or `.\scripts\install-hooks.ps1`)
- Cut a release: `bash scripts/release.sh 0.3.0`
