# Contributing

See [CONTRIBUTING.md in the Wavvon docs repo](https://github.com/Wavvon/Wavvon-docs/blob/main/CONTRIBUTING.md)
for the full branching model, workflow, and release process.

Quick reference for this repo:

- Branch off `develop` — `feat/`, `fix/`, `chore/`, `docs/`
- PR into `develop` for regular work
- PR `develop → main` to ship a release (CI tags and publishes automatically)
- Install the pre-push hook: `bash scripts/install-hooks.sh` (or `.\scripts\install-hooks.ps1`)
- Cut a release: `bash scripts/release.sh 0.3.0`

## Working with Claude Code

This repo ships its own Claude Code setup, so there is nothing to configure:
clone it, open Claude Code, and it picks up `CLAUDE.md` (architecture and
project constraints), `.claude/agents/` (role-scoped subagents) and
`.claude/skills/` (task recipes) automatically.

It is entirely optional — ignore the files if you do not use Claude Code. Your
own settings stay local: `.claude/settings.local.json` is gitignored.

If a document or a skill sent you down the wrong path, that is a bug worth a PR
like any other.
