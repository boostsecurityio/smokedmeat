# Changelog

All notable changes to SmokedMeat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-04-15

First public release. GitHub Actions is the supported CI platform for v0.1.0. Other platforms (GitLab CI, Azure DevOps, CircleCI, Jenkins, Bitbucket) are detected during recon but analysis, delivery, exploitation, and pivoting workflows are GitHub Actions only.

### Added
- Server-side GitHub deploy preflight for workflow dispatch (validates workflow existence and required inputs)
- Bounded callback fanout controls for managing multiple concurrent agent sessions
- Selective Kitchen purge controls for targeted state cleanup
- Live analysis progress for large orgs with resilient reconnection on transient failures
- Improved operator command discoverability with phase-aware help and suggestions
- Cross-platform clipboard support for loot and payload copy
- Browser graph tooltip formatting
- Public-facing feature reference in `docs/FEATURES.md`
- Whooli playground guide in `docs/WHOOLI.md`
- Tutorial walkthrough in `TUTORIAL.md` with screenshots

### Changed
- Bumped embedded poutine for major repo analysis speedups and fine-grained PAT org support
- Reworked the README for first-time operators, including quickstart, deployment modes, and public evaluation guidance
- Renamed the playground target to `whooli`
- Polished setup wizard token flow with clearer guidance
- Tightened command input feedback across all TUI phases
- Reproducible release builds for Brisket implant binaries
- Clarified Counter tree filtering with an explicit ON/OFF footer banner and a findings-pane `f:filter` status hint
- Removed internal planning docs that are not meant to ship in the public repo

### Fixed
- GITHUB_TOKEN permission attribution now correctly maps scopes
- Findings tree exploit selection no longer skips certain vulnerability nodes
- GitHub App PEM loot copy works correctly
- App pivot delivery scope warnings no longer show false positives
- Unsupported findings (non-GitHub Actions) are kept as analyze-only instead of being hidden
- Setup analysis retries on transient EOF instead of failing silently

### Known Limitations
- Server-side deploy preflight is partial: dispatch validates workflow existence and inputs, but PR, issue, comment, and LOTP preflight relies on client-side wizard gating. Failed deployments show friendly 403 messages.
- No operator notifications (webhook/Slack/Discord) for agent callbacks or high-value loot. Watch the Counter activity log.
- `cloud shell` and `ssh shell` hand off to external processes via raw exec. An in-app PTY shell takeover is planned.
- Cache poisoning flow requires manual coordination and understanding of GitHub's cache scoping rules.
- Single-operator focus: multiple operators can connect to the same Kitchen, but there is no session management UI for coordinating across agents and pivots.

## [0.0.4] - 2026-03-27

### Added
- End-to-end GitHub Actions cache-poisoning flow with wizard UX, exact-key prediction, and persistent implant support
- Additional goat validation around the writer and victim workflow chain

## [0.0.3] - 2026-03-17

### Added
- SSH pivoting with `pivot ssh`, `pivot ssh org`, `pivot ssh org/repo`, and `ssh shell`
- Cloud post-exploit improvements with durable sessions, `cloud shell`, `cloud export`, and provider quick checks

## [0.0.2] - 2026-02-20

### Added
- GitHub App key pivot from PEM to installation token
- Workflow `if:` gate detection with trigger classification
- Issue deploy comment-mode for `issue_comment` vulnerabilities
- Draft PR support and auto-close on callback
- Server-side dispatch permission pre-checks

### Changed
- Migrated the Counter TUI to Bubble Tea v2 with Ultraviolet layout and compositing
- Split the monolithic `update.go` flow into focused subject files

## [0.0.1] - 2026-01-06

### Added
- Core Counter, Kitchen, and Brisket operator flow for GitHub Actions
- LOTP delivery support for CI/CD payload injection
- Kitchen-side GitHub API proxying
- Docker quickstart flow for local evaluation
- Attack graph browser view and E2E foundation
