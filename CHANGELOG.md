# Changelog

All notable changes to SmokedMeat are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Canonical domain language in `CONTEXT.md` and an ADR for Kitchen schema compatibility.
- Agent-specific guidance for engineering, TUI work, persistence, issue tracking, and triage.
- TROOPERS slide-deck images for project documentation.

### Changed

- Replaced the repository roadmap files with GitHub Issues and the private SmokedMeat Roadmap Project as planning sources of truth.
- Reduced `AGENTS.md` to durable constraints and progressive links to task-specific guidance.
- Rebuilt this changelog from the published GitHub release history.
- Pinned release-backed quickstart to v0.3.1.

## [0.3.1] - 2026-06-23

### Added

- Trusted self-hosted runner harvest results now create normal cloud shell sessions.
- Resident cloud credentials include their expiry window when available.

### Changed

- Docker shell containers mount host user and group databases for reliable UID and GID resolution on macOS and Linux.
- Linux lint coverage includes the resident-harvest path.

### Fixed

- Release-backed Docker SSH shells no longer fail when the container cannot resolve the host UID.
- SSH private keys are canonicalized before containerized clients load them.
- Resident harvest tolerates short-lived process races.
- Trusted runner cloud tokens remain available after resident harvest.

Kitchen schema remains compatible with v0.3.0. No purge is required.

## [0.3.0] - 2026-06-05

### Added

- Authenticated browser-based GitHub source and repository browsing through Kitchen.
- Workflow source inspection from Counter with source-aware findings.
- GitHub Actions Auditor mode for browser-native workflow review.
- Custom Poutine rule packs with configuration, validation, mappings, and Counter rule summaries.

### Changed

- Graph nodes link into the browser source viewer.
- Repository browsing includes richer navigation and control-plane context.
- Cache-poisoning results preserve stronger runtime correlation.

### Fixed

- Gump recovers runtime context on slim runners without the usual process environment path.
- Quickstart state works correctly for same-host multi-user installations.
- SSH shell launch resolves its entrypoint from the current environment.
- Imported Pantry findings use their normalized exploit class.

Kitchen schema advances from 2.4 to 2.5 and remains on major version 2. No purge is required from v0.2.0.

## [0.2.0] - 2026-05-05

### Added

- Self-hosted runners as first-class attack graph and Counter targets.
- Resident Brisket footholds with later-job observation and automatic harvest.
- Workflow dispatch targeting with input review, triggering, and correlated waiting state.
- Counter release update checks.

### Changed

- Waiting, callback, loot, Pantry, graph, tree, and omnibox views carry richer execution context.
- Re-analysis replaces stale repository findings before importing fresh results.
- Open-target actions identify the actual workflow, run, issue, pull request, or comment.

### Fixed

- Public authentication request bodies are size-limited.
- Authentication challenges have per-IP rate limiting and bounded pending state.
- Gitleaks findings are attributed to the correct repository.
- Self-hosted runner signals remain analyze-only until an honest exploit path exists.

Kitchen schema remains on major version 2. No purge is required from v0.1.2.

## [0.1.2] - 2026-04-24

### Added

- Per-source injection variants are persisted with stable discriminators.

### Changed

- Automatic LOTP delivery is limited to payload families with working generators and delivery paths.
- Detected but unsupported LOTP findings remain available as analyze-only findings.
- **Breaking:** Kitchen schema advances from 1.0 to 2.0. Existing v0.1.0 and v0.1.1 volumes must be purged before upgrade.

### Fixed

- Stager metadata is accessed through locked snapshots instead of shared mutable pointers.
- Pip, Yarn, Cargo, and Make prefer callback-bearing payload variants.
- Setup action aliases resolve to honest LOTP generators.

## [0.1.1] - 2026-04-17

### Added

- Bash injection context analysis for command, argument, quoting, and heredoc positions.
- Branch-name payload delivery for `github.head_ref` findings.
- LOTP wizard previews built on Ultraviolet compositing.

### Fixed

- Public quickstart resolves downloads against the pinned release path.

Kitchen schema is unchanged from v0.1.0. No purge is required.

## [0.1.0] - 2026-04-14

First public release. GitHub Actions is the supported analysis, delivery, exploitation, and pivot platform. Other CI providers are detected for runner classification only.

### Added

- Counter operator client, Kitchen teamserver, and Brisket implant flow.
- GitHub Actions analysis for injection paths, dangerous triggers, and unsafe checkout patterns.
- Payload delivery through pull requests, issues, comments, LOTP, and workflow dispatch.
- Runner post-exploitation, secret extraction, token enumeration, and cloud pivots.
- Persistent Pantry attack graph with a live browser view.
- Release-backed and development quickstart flows.
- Whooli playground, tutorial, feature reference, and public deployment documentation.

[Unreleased]: https://github.com/boostsecurityio/smokedmeat/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/boostsecurityio/smokedmeat/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/boostsecurityio/smokedmeat/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/boostsecurityio/smokedmeat/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/boostsecurityio/smokedmeat/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/boostsecurityio/smokedmeat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/boostsecurityio/smokedmeat/releases/tag/v0.1.0
