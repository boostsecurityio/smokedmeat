# SmokedMeat Roadmap

Last updated: 2026-06-02

## Planning Rules

- SmokedMeat shipped publicly on 2026-04-15. This roadmap tracks post-release product work.
- NorthSec 2026 is complete. Demo-specific constraints are no longer active roadmap rules.
- Minimize breaking changes when possible, but explicit DB schema breaks are still acceptable in `v0.1.x` when they materially simplify the model and purge guidance is clear.
- Do not present a capability as deployable unless the backend can actually deliver it.
- Prioritize work that improves live operator decisions: source context, evidence quality, validation state, callback grouping, and session management.

## Recently Completed

| Status | Item | Outcome | Tracking |
|--------|------|---------|----------|
| Done | Self-hosted runner phase 1 | Operator-usable self-hosted runner flow with observed targets, workflow push or copy, callback, resident persistence, and later re-attach. | Task: [tasks/self-hosted-runner-enumeration-and-persistence.md](tasks/self-hosted-runner-enumeration-and-persistence.md) |
| Done | Demo hardening and rehearsal path | NorthSec happy path was locked, rehearsed, and validated by the live demo. | Ref: [WHOOLI.md](WHOOLI.md) |
| Done | Resident runner post-job observation and auto-harvest | Resident runner footholds now have enough later-job observation and harvest behavior to leave the active roadmap. | Task: [tasks/brisket-resident-runner-job-observation-and-auto-harvest.md](tasks/brisket-resident-runner-job-observation-and-auto-harvest.md) |

## Immediate Priorities

| Priority | Status | Item | Why now | Tracking |
|----------|--------|------|---------|----------|
| P1 | Active next | Workflow source viewer | Operators need to inspect vulnerable workflow source at decision time without leaving Counter. The Kitchen fetch path also gives the future browser UI a reusable source API. | Task: [tasks/workflow-source-viewer.md](tasks/workflow-source-viewer.md) |
| P2 | Planned | Self-hosted runner follow-up and validation | Phase 1 is done. The remaining slice is stronger evidence, explicit repo-scoped enumeration, active validation, and clearer target lifecycle state. | Task: [tasks/self-hosted-runner-follow-up-and-validation.md](tasks/self-hosted-runner-follow-up-and-validation.md) |
| P2 | Planned | Grouped callback and session-management UX | Resident runner and later-job work increases callback volume, so Counter needs better arrival grouping, unseen activity markers, and faster sibling switching. | Task: [tasks/grouped-callback-session-management-ux.md](tasks/grouped-callback-session-management-ux.md) |
| P2 | Deferred | Finish LOTP path-aware targeting for the remaining detection-only families | The current support boundary is now honest: auto-supported LOTP families show up in the menu, and other detected LOTP findings stay manual-only in the wizard. The remaining gap is path-aware targeting for directory-sensitive shapes that still cannot be generated cleanly. | Issue [#54](https://github.com/boostsecurityio/smokedmeat/issues/54) |
| P2 | Planned | Bracket-notation secret extraction | Workflow secret inventory and app-action secret extraction still only recognize `secrets.NAME`, so bracket notation stays invisible in recon output and secret typing. | Current analysis path |

## Validated Near-Term Work

The following near-term items are already validated in the current code:

- Current LOTP support boundary
  - Auto-deliverable today: `bash`, `powershell`, `python`, `npm`, `yarn`, `pip`, `cargo`, and `make`.
  - Other detected LOTP families are still intentionally detection-only: they can be opened in the wizard and shown as unsupported for automatic delivery, but they should not take menu priority away from real auto-exploit paths.
  - The current auto-supported set has been validated against `poutineville/lotp-today`, and the detection-only behavior has been validated against `poutineville/gazillion-lotp`.

- Remaining LOTP follow-up
  - `internal/lotp/payload.go` still ignores `lotp_targets` for non-script families and emits fixed filenames such as `setup.py`, `.yarnrc.yml`, `build.rs`, and `Makefile`.
  - `internal/brisket/inject.go` still records only `filepath.Base(rel)` during LOTP detection, so subpath-sensitive catalog entries such as `.bundle/config` or `.cargo/config.toml` cannot be matched reliably.

- Secret reference extraction parity
  - `internal/poutine/analyzer.go` still extracts secrets with dot-notation parsing only.
  - `extractSecretRef()` still strips only `secrets.` and rejects bracket notation forms such as `secrets['NAME']` and `secrets["NAME"]`.

- Native PowerShell LOTP delivery across runner platforms
  - The current PowerShell LOTP path shells out through `sh`, which is good enough for the hosted Linux demo path but is not a trustworthy contract for generic Windows or self-hosted PowerShell runners.
  - A real follow-up should serve a native PowerShell callback path so `pwsh` delivery is honest on Linux, macOS, and Windows without depending on a POSIX shell being present.

## Roadmap Backlog

| Priority | Item | Scope | Tracking |
|----------|------|-------|----------|
| P3 | Operator notifications | Outbound webhook notifications for check-ins, loot, and deploy outcomes. | Task: [tasks/operator-notifications.md](tasks/operator-notifications.md) |
| P3 | Kitchen audit trail and IOC export | Extend history into append-only audit and exportable IOC reporting. | Task: [tasks/kitchen-audit-trail-and-ioc-export.md](tasks/kitchen-audit-trail-and-ioc-export.md) |
| P3 | Goal-oriented kill chain planning | Combine multiple credentials and repo constraints toward a chosen end state. | Task: [tasks/goal-oriented-killchain.md](tasks/goal-oriented-killchain.md) |
| P3 | Native PowerShell LOTP delivery across runner platforms | Replace the current `pwsh -> sh` wrapper with a real PowerShell callback path so LOTP delivery is reliable on Linux, macOS, Windows, and especially self-hosted Windows runners. | Idea |
| P3 | Quoted Bash heredoc exploitation | Useful exploit-coverage expansion, but the current analyze-only behavior is honest enough that this can stay behind the active operator-context work. | Issue [#51](https://github.com/boostsecurityio/smokedmeat/issues/51) |
| P4 | Counter / Kitchen boundary refactor | Move client-neutral logic toward Kitchen and tighten shared contracts. | Task: [tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| P4 | Shared analysis progress constants and payload contract | Keep the Kitchen to Counter protocol in one place so client and server cannot drift. | Ref: [tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| P4 | Embedded shell mode and native Go E2E | Replace the tmux shell boundary with an in-app shell and stronger native E2E coverage. | Task: [tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| P4 | Interactive agent terminal via Kitchen | Move from one-shot exec toward an sshx-like streamed PTY session with attach/detach, resize, reconnect handling, and a future path to read-only observers. | Task: [tasks/interactive-agent-terminal-via-kitchen.md](tasks/interactive-agent-terminal-via-kitchen.md) |
| P4 | Web operator UI | Add a browser-based operator UI after the backend boundary is cleaner. | Task: [tasks/web-operator-ui-and-kitchen-boundary.md](tasks/web-operator-ui-and-kitchen-boundary.md) |
| P5 | Walkthrough recording and replay | Follow-on work once embedded shell and native Go E2E are stable. | Ref: [tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| P5 | Incremental poutine result streaming | Preserve per-repo `PackageInsights` so Kitchen can surface findings and workflows earlier instead of waiting for finalization. | Idea |
| P5 | Pluggable modules | Explore a stable extension surface for community contributions. | Idea |
| P5 | Betterleaks migration watch | Revisit once the replacement project is stable enough as a library and operational fit. | Idea |
| P5 | Anti-forensics UX | Surface the existing `napkin` capability in Counter. | Idea |
