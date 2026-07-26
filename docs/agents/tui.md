# Counter TUI Guide

Read this file before changing `internal/counter/tui/`.

## Ownership

Keep `update.go` as the main Bubble Tea dispatcher. Put behavior in the subject file that owns it:

| Subject | Files |
|---------|-------|
| Setup and authentication | `setup.go`, `token.go` |
| Exploit wizard and delivery | `wizard.go`, `deploy.go` |
| Commands and suggestions | `command.go`, `suggestions.go` |
| Kitchen events and agents | `kitchen.go`, `agent.go` |
| Analysis and pivots | `analysis.go`, `pivot.go` |
| Tree and rendering | `tree.go`, `view.go`, `layout.go` |
| State and messages | `model.go`, `phase.go`, `messages.go` |

Do not grow `update.go` with subject-specific logic.

## Layout Invariants

- Use `ultraviolet/layout` splits with `layout.Percent` or `layout.Fixed`. Do not calculate panel sizes with manual width or height arithmetic.
- Compose overlays with `uv.ScreenBuffer`: draw the background, then draw the modal.
- Do not use Lipgloss `Height()`. Pad content explicitly before rendering.
- Use Lipgloss borders. Do not hand-draw Unicode box borders.
- Pad modal content lines to the full inner width so the right border remains aligned.
- Route terminal dimensions through `image.Rectangle` areas and existing layout helpers.

These are correctness constraints, not style preferences. Violating them causes initial-render duplication, ANSI corruption, or font-dependent alignment failures.

## Interaction And Tests

- Keep state transitions independent of rendering where practical.
- Test keyboard transitions, escape paths, invalid input, reconnect behavior, and small terminal sizes.
- Use table-driven tests for behavior variants.
- Use golden or render tests only when visual structure is the behavior under test.
- Set a stable color profile for output assertions.

Run:

```bash
go test ./internal/counter/tui
```

Use `make e2e-smoke` or `make e2e-goat` when the change crosses Counter, Kitchen, delivery, or shell boundaries.
