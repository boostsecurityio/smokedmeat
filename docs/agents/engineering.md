# Engineering Guide For Agents

Use this guide for repository orientation and verification. Area-specific constraints live in sibling files so agents only load what the task requires.

## Working Method

1. Read `CONTEXT.md` and relevant ADRs.
2. Resolve the ticket and acceptance criteria before editing.
3. Inspect the nearest implementation and tests.
4. Make the smallest coherent change that satisfies the behavior.
5. Verify the narrow behavior first, then widen checks according to risk.
6. Review the final diff for unrelated changes and stale documentation.

Preserve unrelated worktree changes. Do not mix roadmap cleanup, refactors, and product behavior in one change unless they are inseparable.

## Repository Map

| Domain | Location |
|--------|----------|
| Counter operator client | `cmd/counter/`, `internal/counter/`, `internal/counter/tui/` |
| Kitchen teamserver | `cmd/kitchen/`, `internal/kitchen/` |
| Brisket implant | `cmd/brisket/`, `internal/brisket/` |
| Shared protocol models | `internal/models/` |
| Pantry attack graph | `internal/pantry/` |
| NATS messaging | `internal/pass/` |
| Injection payloads and stagers | `internal/rye/` |
| LOTP catalog and payloads | `internal/lotp/` |
| Poutine analysis integration | `internal/poutine/` |
| Secret scanning | `internal/gitleaks/`, `internal/gump/` |
| Integration and operator E2E | `tests/`, `.claude/e2e/` |

## Commands

Run `make help` for the complete current command list.

| Intent | Command |
|--------|---------|
| Focused package test | `go test ./path/to/package` |
| Full unit suite | `make test` |
| Lint | `make lint` |
| Integration tests | `go test -tags=integration ./...` |
| Public exploit smoke path | `make e2e-smoke` |
| Full Whooli chain | `make e2e-goat` |
| Local development stack | `make dev-quickstart` |
| Stable release quickstart | `make quickstart` |
| Rebuild Kitchen during manual E2E | `make e2e-kitchen-rebuild` |
| Build Brisket | `make build-brisket` |

Use `make dev-quickstart-purge` or `make quickstart-purge` only when state is intentionally disposable or a schema-major mismatch requires it.

## Test Selection

- Counter state or rendering changes: focused TUI tests, then `go test ./internal/counter/tui`.
- Kitchen handler or protocol changes: focused handler tests and affected client tests.
- Persisted data changes: DB schema tests plus Kitchen package tests.
- Brisket behavior: platform-appropriate Brisket tests; use integration coverage when process or runner behavior matters.
- Cross-process flows: the smallest relevant E2E target.
- Documentation-only changes: link inspection, `git diff --check`, and any generator check affected by the docs.

Tests should prove user-visible behavior, security boundaries, state transitions, and regressions. Avoid tests whose only purpose is increasing coverage.

## Generated And Release-Sensitive Files

- After changing GitHub Actions workflows, run `make pinact`.
- Update `configs/quickstart-release.mk` only through `make quickstart-pin VERSION=v...`.
- Use `make tag VERSION=v...` only for an intentional signed release.
- Keep `CHANGELOG.md` aligned with published GitHub releases and meaningful unreleased changes.

## Worktrees

For parallel feature work, follow [`docs/worktrees-flow.md`](../worktrees-flow.md). Keep one coherent feature per branch and avoid stacking unless the dependency is real.
