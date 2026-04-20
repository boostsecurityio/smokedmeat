# SmokedMeat Roadmap

Last updated: 2026-04-20

## Planning Rules

- SmokedMeat shipped publicly on 2026-04-15. This roadmap is post-release, not a release-window checklist.
- From 2026-04-20 through NorthSec on 2026-05-14, user-reported bugs and demo stability outrank broad refactors.
- Minimize breaking changes when possible, but explicit DB schema breaks are still acceptable in `v0.1.x` when they materially simplify the model and purge guidance is clear.
- Do not present a capability as deployable unless the backend can actually deliver it.
- Target a demo-stable build by 2026-05-07 so slides, rehearsal, and the live path can settle before the conference.
- Treat self-hosted runner work as the main pre-NorthSec feature track, but only merge slices that provide real operator value.

## Immediate Priorities

| Priority | Status | Item | Why now | Tracking |
|----------|--------|------|---------|----------|
| P0 | In flight | Merge the fix for multi-source injection persistence and quickstart schema fail-fast | Real user bug already has an open PR. Finish it instead of duplicating work. | Issue [#58](https://github.com/boostsecurityio/smokedmeat/issues/58), PR [#59](https://github.com/boostsecurityio/smokedmeat/pull/59) |
| P0 | Next | Make LOTP deployment support honest for callback payloads and capability gating | The current deploy path still offers LOTP for any finding with `lotp_tool` or `lotp_action`, but the backend only supports a narrow set of generators and several non-script families still fall back to literal `id` or the wrong first payload. | Issue [#55](https://github.com/boostsecurityio/smokedmeat/issues/55), issue [#53](https://github.com/boostsecurityio/smokedmeat/issues/53) |
| P0 | Next | Fix the Kitchen stager metadata race | `StagerStore.Get()` still returns a live pointer and deploy handlers mutate `Metadata` outside the store lock. Callback-heavy flows can therefore race on shared state and panic. | Current deploy path |
| P1 | Planned | Self-hosted runner enumeration and persistence | This is the most valuable missing feature for the NorthSec demo. The implementation can land in chunks, but `main` should only take slices that provide real operator value. | Task: [tasks/self-hosted-runner-enumeration-and-persistence.md](tasks/self-hosted-runner-enumeration-and-persistence.md) |
| P1 | Planned | Demo hardening and rehearsal path | The happy path for the talk needs to be stable, repeatable, and covered by the exact repos and flows that will be shown live. | Ref: [WHOOLI.md](WHOOLI.md) |
| P2 | Deferred | Make LOTP targeting and detection path-aware, or hide unsupported shapes | Useful follow-up, but not worth spending pre-NorthSec time on until the demo path is dry-run and the talk prep is under control. | Issue [#54](https://github.com/boostsecurityio/smokedmeat/issues/54) |
| P2 | Planned | Bracket-notation secret extraction | Workflow secret inventory and app-action secret extraction still only recognize `secrets.NAME`, so bracket notation stays invisible in recon output and secret typing. | Current analysis path |
| P2 | Planned | Quoted Bash heredoc exploitation | Valuable exploit-coverage expansion, but current analyze-only behavior is at least honest. | Issue [#51](https://github.com/boostsecurityio/smokedmeat/issues/51) |

## Validated Near-Term Work

The following near-term items are already validated in the current code:

- LOTP callback payload generation and capability gating
  - `internal/lotp/payload.go` still special-cases only `bash`, `powershell`, and `python` in `GenerateFiles()`.
  - `pip`, `yarn`, `cargo`, and `make` still default to `id` when no explicit `Command` is set.
  - `generatePayloadForTechnique()` still returns only the first payload, which is why the callback-capable `requirements.txt` path is not the deployed `pip` payload today.
  - `internal/counter/tui/phase.go` still offers LOTP whenever `lotp_tool` or `lotp_action` metadata exists.
  - `internal/kitchen/github_preflight.go` still treats LOTP like generic PR capability instead of generator-specific support.

- LOTP path-aware targeting and detection
  - `internal/lotp/payload.go` still ignores `lotp_targets` for non-script families and emits fixed filenames such as `setup.py`, `.yarnrc.yml`, `build.rs`, and `Makefile`.
  - `internal/brisket/inject.go` still records only `filepath.Base(rel)` during LOTP detection, so subpath-sensitive catalog entries such as `.bundle/config` or `.cargo/config.toml` cannot be matched reliably.

- Stager metadata concurrency
  - `internal/kitchen/stager.go` still exposes the live `*RegisteredStager` from `Get()`.
  - `internal/kitchen/github.go` still mutates `stager.Metadata[...]` after `Get()`, outside store locking.
  - `internal/kitchen/handlers.go` and persistence paths still read the same map, so the race remains real.

- Secret reference extraction parity
  - `internal/poutine/analyzer.go` still extracts secrets with dot-notation parsing only.
  - `extractSecretRef()` still strips only `secrets.` and rejects bracket notation forms such as `secrets['NAME']` and `secrets["NAME"]`.

## NorthSec Scope

### Must be stable first

- close the in-flight `#58` work by merging PR `#59`
- fix or gate the broken LOTP families
- remove the stager metadata race from the deploy path

The main rule for this window is simple: narrower but trustworthy support is better than broader support that fails during a live demo.

### Self-Hosted Runner Scope

The self-hosted runner work is the main pre-NorthSec feature track.

Implementation can still be broken into small, low-risk chunks, but `main` should only take slices that provide real operator value. The feature should not stop at background plumbing or passive data collection that leaves the operator with no meaningful next step.

The minimum acceptable outcome before NorthSec is an operator-usable self-hosted runner flow that:

1. discovers likely self-hosted runner targets for a repo
2. persists and surfaces those targets cleanly in Counter and the graph
3. gives the operator a meaningful way to validate or act on those targets

The phase breakdown in [tasks/self-hosted-runner-enumeration-and-persistence.md](tasks/self-hosted-runner-enumeration-and-persistence.md) remains useful for implementation order, but it is not itself the merge criterion.

### Demo hardening

- choose the exact demo repos and lock the expected happy path early
- add or tighten automated coverage for the demoed path, even if that means fewer side quests
- do not spend pre-NorthSec time on nice-to-have work such as LOTP path-aware targeting until the slides are materially done and the happy path has been dry-run end to end
- avoid broad refactors after 2026-05-07 unless they directly unblock the talk

## After NorthSec

| Priority | Item | Scope | Tracking |
|----------|------|-------|----------|
| P3 | Grouped callback and session-management UX | Better arrival notifications, grouping, unseen activity markers, and faster sibling switching. | Task: [tasks/grouped-callback-session-management-ux.md](tasks/grouped-callback-session-management-ux.md) |
| P3 | Workflow source viewer | On-demand workflow source viewing in Counter and the browser-facing Kitchen UI. | Task: [tasks/workflow-source-viewer.md](tasks/workflow-source-viewer.md) |
| P3 | Operator notifications | Outbound webhook notifications for check-ins, loot, and deploy outcomes. | Task: [tasks/operator-notifications.md](tasks/operator-notifications.md) |
| P3 | Kitchen audit trail and IOC export | Extend history into append-only audit and exportable IOC reporting. | Task: [tasks/kitchen-audit-trail-and-ioc-export.md](tasks/kitchen-audit-trail-and-ioc-export.md) |
| P3 | Goal-oriented kill chain planning | Combine multiple credentials and repo constraints toward a chosen end state. | Task: [tasks/goal-oriented-killchain.md](tasks/goal-oriented-killchain.md) |
| P4 | Counter / Kitchen boundary refactor | Move client-neutral logic toward Kitchen and tighten shared contracts. | Task: [tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| P4 | Shared analysis progress constants and payload contract | Keep the Kitchen to Counter protocol in one place so client and server cannot drift. | Ref: [tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| P4 | Embedded shell mode and native Go E2E | Replace the tmux shell boundary with an in-app shell and stronger native E2E coverage. | Task: [tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| P4 | Interactive agent terminal via Kitchen | Move from one-shot exec toward a real PTY-backed shell. | Task: [tasks/interactive-agent-terminal-via-kitchen.md](tasks/interactive-agent-terminal-via-kitchen.md) |
| P4 | Web operator UI | Add a browser-based operator UI after the backend boundary is cleaner. | Task: [tasks/web-operator-ui-and-kitchen-boundary.md](tasks/web-operator-ui-and-kitchen-boundary.md) |
| P5 | Walkthrough recording and replay | Follow-on work once embedded shell and native Go E2E are stable. | Ref: [tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| P5 | Incremental poutine result streaming | Preserve per-repo `PackageInsights` so Kitchen can surface findings and workflows earlier instead of waiting for finalization. | Idea |
| P5 | Pluggable modules | Explore a stable extension surface for community contributions. | Idea |
| P5 | Betterleaks migration watch | Revisit once the replacement project is stable enough as a library and operational fit. | Idea |
| P5 | Anti-forensics UX | Surface the existing `napkin` capability in Counter. | Idea |
