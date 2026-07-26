# AGENTS.md

This file is the high-signal entry point for coding agents. Keep it short. Read deeper guidance only when the task touches that area.

## Before You Change Code

1. Read [`CONTEXT.md`](CONTEXT.md) and use its canonical domain language.
2. Read ADRs under [`docs/adr/`](docs/adr/) that affect the change.
3. Read the relevant ticket using [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md).
4. Check `git status` and preserve unrelated user changes.
5. Inspect nearby code and tests before choosing a design.

For repository wayfinding, commands, and verification strategy, see [`docs/agents/engineering.md`](docs/agents/engineering.md).

## Non-Negotiable Rules

### AGPL Headers

Every new source file must begin with:

```go
// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later
```

Place the header before package documentation, package declarations, or build tags as applicable.

### Text Style

Never use em dashes (U+2014). Use a hyphen-minus with spaces (` - `).

### Comments

Prefer self-documenting code. Add comments only for constraints, security reasoning, protocol behavior, or other non-obvious intent.

Do not add:

- narration of what the next line does
- commented-out code
- redundant godoc
- TODO comments unless the task explicitly requires them

### GitHub

Use the `gh` CLI for all GitHub operations in this repository. Do not rely on GitHub App write access.

## Change-Specific Guidance

| Area | Required reading | Focused verification |
|------|------------------|----------------------|
| Counter TUI | [`docs/agents/tui.md`](docs/agents/tui.md) | `go test ./internal/counter/tui` |
| Kitchen persistence or persisted Pantry shapes | [`docs/agents/persistence.md`](docs/agents/persistence.md) and [ADR-0001](docs/adr/0001-separate-kitchen-schema-version-from-application-releases.md) | `go test ./internal/kitchen/db ./internal/kitchen` |
| Brisket | Nearby tests in `internal/brisket/` | `go test ./internal/brisket` |
| Analysis and custom rules | `internal/poutine/` and nearby tests | `go test ./internal/poutine` |
| Payload delivery | `internal/rye/`, `internal/lotp/`, and Kitchen deploy tests | Test every affected package |
| GitHub Actions workflows | Existing workflow conventions | `make pinact` after workflow changes |
| Deployment or release flow | [`docs/deployment.md`](docs/deployment.md) | Use the matching quickstart target |
| Full operator flows | [`docs/WHOOLI.md`](docs/WHOOLI.md) | `make e2e-smoke` or `make e2e-goat` |

## Verification

- Iterate with the smallest test that proves the changed behavior.
- Add tests for behavior, state transitions, error handling, and regressions. Do not add coverage-only tests.
- Run `make test` for cross-package changes.
- Run `make lint` for production code changes.
- Use integration or E2E checks when the behavior crosses process, Docker, GitHub, or terminal boundaries.
- Report checks that were not run and why.

## Agent skills

### Issue tracker

Public work is tracked in GitHub Issues. Maintainer-owned roadmap ideas are draft items in the private SmokedMeat Roadmap Project. See [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md).

### Triage labels

GitHub Issues use the five canonical triage labels. See [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md).

### Domain docs

Domain documentation uses the single-context layout. See [`docs/agents/domain.md`](docs/agents/domain.md).
