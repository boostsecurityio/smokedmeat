# SmokedMeat Roadmap

CI/CD Red Team Framework - Implementation Roadmap

**Last Updated:** March 27, 2026

---

## Current State

- Core operator flow is shipped: analyze → select vuln → deploy → wait for dwell beacon → post-exploit → pivot.
- GitHub Actions exploitation is end-to-end across PR, issue, comment, LOTP, and `workflow_dispatch` delivery paths.
- Cloud pivots are end-to-end for AWS, GCP, and Azure with durable local sessions, `cloud shell`, `cloud export`, provider quick checks, quickstart support, and dedicated E2E coverage.
- Remaining work is mostly gap-closing rather than greenfield: the cache-poisoning feature is now in-product, the refreshed goat target proves the writer and victim side of the chain, and the main remaining gap is finishing the later post-exploit goat path.

---

## Current Priorities

| Priority | Feature | Status | Why now |
|----------|---------|--------|---------|
| P1 | F1.2 goat wizard E2E validation | 🔶 Partial | Cache poisoning is implemented in-product, the Whooli target now proves the writer and victim restore path, and the main remaining work is stabilizing the final post-exploit goat flag path. |
| P2 | E3.4 Complete server-side deploy preflight | 🔶 Partial | Removes avoidable failed deployments and brings backend behavior in line with the wizard UX. |
| P3 | E3.6 Embedded shell takeover + native Go E2E | 🔲 Not started | Replaces the tmux-driven shell/testing boundary with an in-app PTY/VT shell takeover, strengthens E2E robustness, and unlocks VHS-exportable walkthrough recording. |

---

## Phase Overview

| Phase | Status | Notes |
|-------|--------|-------|
| Core Infrastructure (1-16) | ✅ Done | Counter, Kitchen, Brisket, Pantry, graph, and persistence are all shipped |
| S1-S3 UX + Layout | ✅ Done | Bubbletea v2 migration and Ultraviolet layout/compositing are shipped |
| E1 Graph Polish | ✅ Done | Live graph and browser view are shipped |
| E2 Pivot Intelligence | ✅ Done | Cloud and SSH pivots are shipped with durable sessions, graph surfacing, and shell workflows |
| E3 Automation & Polish | 🔶 In progress | Backend preflight parity, notifications, and the embedded-shell / native-Go E2E cleanup remain |
| F1 Advanced Persistence | 🔲 Research | No production-ready persistence automation yet |

---

## Shipped Recently

- **E2.2 Cloud CLI shell**
  - `pivot aws/gcp/azure` now resolves Pantry config, `${{ secrets.X }}`, and `${{ vars.X }}`; stores durable cloud sessions; imports discovered cloud resources into Pantry; and unlocks `cloud shell`, `cloud export`, and provider quick checks.
- **E2.4 SSH pivoting**
  - `pivot ssh`, `pivot ssh org`, and `pivot ssh org/repo` are shipped; confirmed repo access is persisted into graph labels; `ssh status` and `ssh shell` are available; and the goat E2E covers the operator path.
- **Cloud pivot operational polish**
  - Quickstart Counter now has embedded cloud tooling, the repo ships `make cloud-shell-image` for local operator runs, and the current goat work has revalidated that the remaining gap is later operator/E2E flow rather than cloud/OIDC support.
- **Deployment workflow polish**
  - Draft PR support, auto-close on callback, comment-mode issue deploys, workflow `if:` gate detection, and dispatch backend preflight are shipped.
- **Counter UI migration**
  - Bubbletea v2 and Ultraviolet layout/compositing are shipped. The old Stickers and bubbletea-overlay stack is no longer the source of truth.

---

## Open Work

### E3.4: Permission Pre-Check

**Status:** 🔶 Partial

Done:

- Wizard gating via `CanUseDelivery()`
- Friendly reactive 403 parsing
- Server-side dispatch preflight via `getWorkflowByFileName`

Remaining:

- PR: repo access and pushability validation
- Issue/comment: issues availability and write permission validation
- LOTP: repo fork/push preflight parity

Task note:

- `docs/tasks/server-side-deploy-preflight.md`

### E3.5: Operator Notifications

**Status:** 🔲 Not started

Goal:

- Webhook on new agent check-in, new high-value loot, and deployment success/failure
- Start with generic webhook payloads; Slack and Discord adapters can sit on top

### E3.6: Embedded Shell Takeover And Native Go E2E

**Status:** 🔲 Not started

Goal:

- replace raw `ExecProcess` shell handoff with an in-app shell takeover
- make `cloud shell` and `ssh shell` testable without tmux
- keep shell state sandboxed and support real completion
- add organic walkthrough recording with export to VHS tape

Task note:

- `docs/tasks/embedded-shell-go-e2e-vhs.md`

---

## Research Backlog

| ID | Feature | Description | Effort |
|----|---------|-------------|--------|
| F1.1 | Self-hosted runner persistence | `RUNNER_TRACKING_ID=0`, service install, or equivalent long-lived foothold | L |
| F1.2 | Cache poisoning | Poison GitHub Actions caches for reinfection on later trusted runs. Product feature is implemented; the remaining work is final goat completion plus follow-up hardening. | XL |
| F1.3 | Session management | Better operator control when multiple agents and pivots coexist | M |
| F1.4 | Goal-oriented kill chain planning | Add repo rules / branch protection metadata, a persistent `set goal` concept, and reasoning that combines multiple credentials toward an end state. Task note: `docs/tasks/goal-oriented-killchain.md` | L |
| F1.5 | Walkthrough recording and replay | Record real operator flows inside SmokedMeat and export them as VHS tapes for replayable demos and GIF generation. Initial design is tracked in `docs/tasks/embedded-shell-go-e2e-vhs.md`. | M |
| F1.6 | Anti-forensics UX (napkin) | The Brisket agent already implements `napkin` (workflow run/log deletion via GitHub API). Needs Counter TUI integration: dedicated command, tab completion, help text, and optional auto-cleanup after express callbacks. | S |

---

## Recommended Next Feature

Land the **final goat post-exploit validation pass** next so the refreshed external Whooli environment completes end-to-end.

The product slice is already in place: writer-side poisoning, victim selection, persistent implants, cache replacement controls, exact-key prediction, and runtime cache staging all exist in SmokedMeat. The external Whooli target and local goat docs now match that design. The next slice is to stabilize the final operator-driven flag path after the trusted victim callback lands.
