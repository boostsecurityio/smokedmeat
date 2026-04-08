# SmokedMeat Roadmap

CI/CD Red Team Framework

Last updated: 2026-04-08

Status: `🔲` planned, `💡` idea
Spec: `Task` = planned in `docs/tasks`, `Ref` = related reference, `Idea` = tracked only

## Product Snapshot

- Core operator flow is shipped: analyze -> exploit -> dwell beacon -> post-exploit -> pivot.
- GitHub Actions exploitation is shipped across PR, issue, comment, LOTP, and `workflow_dispatch`.
- Cloud pivots are shipped for AWS, GCP, and Azure, including durable sessions and shell/export flows.
- SSH pivots, graph view, and the Counter UI migration are shipped.

## Release Window

- Public open source release target: April 15, 2026
- Feature freeze target: April 10, 2026
- Pre-freeze rule: only take work that can ship confidently in small chunks before the freeze date
- Post-freeze working days: April 10, 2026 and April 13-14, 2026
- Post-freeze scope: docs, tutorial, screenshots, screencast, release notes, and packaging only
- Post-freeze tracking: [docs/tasks/release-prep-and-launch-materials.md](tasks/release-prep-and-launch-materials.md)

## Before Feature Freeze

This is the recommended pre-freeze queue. Only items that are realistically shippable and helpful to beta testers before April 10, 2026 should stay here.

| Priority | Item | Status | Scope | Spec |
|----------|------|--------|-------|------|
| 1 | Large-org tree and graph filtering | 🔲 | Large orgs are not practically usable today. Change the existing tree filter to hide nodes with no vuln-bearing path, and default the browser graph to a safer filtered mode above a size threshold. | Task: [docs/tasks/browser-graph-filtering-and-usability.md](tasks/browser-graph-filtering-and-usability.md) |
| 2 | OIDC trust cloud node tree placement | 🔲 | Fix the vuln tree so `oidc_trust/...` cloud nodes attach under their associated workflow job instead of dangling at the bottom as root-level cloud leaves. | Task: [docs/tasks/oidc-trust-cloud-node-tree-placement.md](tasks/oidc-trust-cloud-node-tree-placement.md) |

## Planned Backlog

| Status | Item | Scope | Spec |
|--------|------|-------|------|
| 🔲 | Release prep and launch materials | Tutorial, screenshots, screencast, release notes, blog article inputs, and packaging verification. | Task: [docs/tasks/release-prep-and-launch-materials.md](tasks/release-prep-and-launch-materials.md) |
| 🔲 | Counter / Kitchen boundary refactor | Audit the split, move client-neutral logic toward Kitchen, and tighten shared contracts. | Task: [docs/tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| 🔲 | Shared analysis progress phase constants | Move `workflow_analysis`, `secret_scan`, and `import` into one shared Kitchen ↔ Counter protocol definition so progress rendering cannot drift on string changes. | Ref: [docs/tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| 🔲 | Shared analysis progress payload contract | Deduplicate `AnalysisProgressPayload` across Kitchen and Counter so the WebSocket protocol shape is defined once and the client/server contract stays in lockstep. | Ref: [docs/tasks/counter-kitchen-boundary-refactor.md](tasks/counter-kitchen-boundary-refactor.md) |
| 💡 | Incremental poutine result streaming | Preserve per-repo `PackageInsights` from poutine observer callbacks so Kitchen can post-process findings and workflows as repos finish, instead of waiting for a large end-of-scan finalization step. | Idea |
| 🔲 | Goat wizard E2E validation | Finish the final Whooli post-exploit path and harden the surrounding operator flow. | Ref: [docs/WHOOLI.md](WHOOLI.md) |
| 🔲 | Embedded shell mode + native Go E2E | Replace the tmux shell boundary with an in-app shell and stronger native E2E coverage. | Task: [docs/tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| 🔲 | Interactive agent terminal via Kitchen | Move beyond one-shot `order exec` toward a real PTY-backed remote shell that tunnels through Kitchen, stays native Go, and avoids CGO. | Task: [docs/tasks/interactive-agent-terminal-via-kitchen.md](tasks/interactive-agent-terminal-via-kitchen.md) |
| 🔲 | Grouped callback / session-management UX | Follow on from the shipped bounded-fanout slice with stronger arrival notifications, grouped callback and agent navigation, unseen activity markers, and faster sibling switching. | Task: [docs/tasks/grouped-callback-session-management-ux.md](tasks/grouped-callback-session-management-ux.md) |
| 🔲 | Self-hosted runner enumeration and persistence | Enumerate and validate reusable self-hosted runner footholds using workflow evidence, authenticated web-session metrics, elevated APIs, and active probes. | Task: [docs/tasks/self-hosted-runner-enumeration-and-persistence.md](tasks/self-hosted-runner-enumeration-and-persistence.md) |
| 🔲 | Operator notifications | Generic outbound webhook notifications for new agent check-ins, high-value loot, and deploy outcomes, with Slack and Discord as obvious consumers. | Task: [docs/tasks/operator-notifications.md](tasks/operator-notifications.md) |
| 🔲 | Kitchen audit trail and IOC export | Extend history into append-only audit and exportable IOC reporting. | Task: [docs/tasks/kitchen-audit-trail-and-ioc-export.md](tasks/kitchen-audit-trail-and-ioc-export.md) |
| 🔲 | Goal-oriented kill chain planning | Combine multiple credentials and repo constraints toward a chosen end state. | Task: [docs/tasks/goal-oriented-killchain.md](tasks/goal-oriented-killchain.md) |
| 🔲 | Workflow source viewer | Add on-demand workflow source viewing in Counter and browser-facing Kitchen UI. | Task: [docs/tasks/workflow-source-viewer.md](tasks/workflow-source-viewer.md) |
| 💡 | Pluggable modules | Explore a stable extension surface for community contributions. | Idea |
| 🔲 | Web operator UI | Add a browser-based operator UI over Kitchen after the backend boundary is cleaner. | Task: [docs/tasks/web-operator-ui-and-kitchen-boundary.md](tasks/web-operator-ui-and-kitchen-boundary.md) |
| 🔲 | Walkthrough recording and replay | Follow-on work after embedded shell and native Go E2E are stable. | Ref: [docs/tasks/embedded-shell-and-native-go-e2e.md](tasks/embedded-shell-and-native-go-e2e.md) |
| 💡 | Betterleaks migration watch | Revisit once the replacement project is stable enough as a library and operational fit. | Idea |
| 💡 | Anti-forensics UX | Surface the existing `napkin` capability in Counter. | Idea |
