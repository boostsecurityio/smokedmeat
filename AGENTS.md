# AGENTS.md

## CRITICAL: AGPLv3 License Headers Required

**ALL new source files MUST include the AGPLv3 header at the top:**

```go
// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later
```

This header goes before any package documentation or package declaration. No exceptions.

## CRITICAL: No Em Dashes

**Never use em dashes (U+2014).** Use a regular hyphen-minus with spaces (` - `) instead.

Good: `Kitchen - C2 teamserver with WebSocket API`
Bad: `Kitchen — C2 teamserver with WebSocket API`

## CRITICAL: No Unnecessary Comments

**DO NOT add explanatory comments to code.** This codebase prefers self-documenting code:

- **NO inline comments** explaining what code does
- **NO commented-out code** - delete it, git has history
- **NO TODO comments** unless explicitly requested
- **NO redundant godoc** like `// New creates a new X`

Good: `// Timeout prevents infinite hangs from malicious payloads`
Bad: `// Create a new context with timeout`

## CRITICAL: GitHub Operations Use `gh` CLI

The GitHub App for Codex is not installed for this repository, and we will not install it.

- Use `gh` CLI for GitHub operations in this repo
- Do not rely on GitHub App write access for PR comments, review-thread resolution, labels, or similar actions
- If a GitHub connector can read metadata but cannot perform the write, fall back to `gh` immediately

## Quick Start (Local Dev)

```bash
# One command  - starts Docker (tunnel + NATS + Kitchen), prewarms cloud shell image, and launches Counter via go run
make dev-quickstart

# Release-backed quickstart uses the pinned version in configs/quickstart-release.mk
make quickstart

# If state gets corrupted:
make dev-quickstart-purge && make dev-quickstart
```

## Make Commands

```bash
# Dev Quick Start (Docker infra + local Counter)
make dev-quickstart            # Start or reuse everything + launch Counter TUI
make dev-quickstart-up         # Start tunnel + NATS + Kitchen (no Counter)
make dev-quickstart-counter    # Launch Counter TUI (after dev-quickstart-up)
make dev-quickstart-down       # Stop containers
make dev-quickstart-purge      # Stop and delete all data

# Release Quick Start (pinned published artifacts)
make quickstart                # Start the pinned release quickstart + Counter TUI
make quickstart-up             # Start pinned release infrastructure only
make quickstart-counter        # Launch pinned release Counter TUI
make quickstart-down           # Stop pinned release containers
make quickstart-purge          # Stop pinned release containers and delete data
make quickstart-version        # Show pinned quickstart release
make quickstart-pin VERSION=v... # Maintainer only - verify and update quickstart pin

# Counter (Remote Kitchen)
make counter               # Run Counter TUI (uses ~/.smokedmeat config)

# Testing
make test                  # Run tests
make lint                  # Run linter

# E2E Testing (Docker + tmux, used by coding agents)
make e2e-exploit           # Full exploit flow test (automated)
make e2e-up                # Start infrastructure
make e2e-down              # Stop containers
make e2e-purge             # Stop and delete all data
make e2e-counter           # Launch Counter in tmux (127x40)
make e2e-capture           # Capture tmux pane output
make e2e-keys KEYS='...'   # Send keystrokes to tmux
make e2e-kitchen-rebuild   # Rebuild Kitchen only (tunnel stays)

# Build
make build-brisket         # Build implant (Linux amd64)
make build-brisket-all     # Build for all platforms
make tag VERSION=v...      # Create, sign, and push a release tag
make pinact                # Pin GitHub Actions (run after workflow changes)
```

## When to Rebuild

| Working on... | Command needed |
|---------------|----------------|
| Counter TUI only | Just restart Counter (no rebuild needed) |
| Kitchen code | `make e2e-kitchen-rebuild` or `make dev-quickstart` |
| Corrupted state | `make dev-quickstart-purge && make dev-quickstart` |

## CRITICAL: Kitchen DB Schema Versioning

Kitchen persistence in `internal/kitchen/db/` must use an explicit schema version stored in DB metadata. Treat the DB schema version as separate from the app release version.

- Start the public `v0.1.x` line at schema `1.0`.
- Patch and minor app releases within the same schema major must be able to open existing quickstart and dev-quickstart Kitchen volumes.
- If a DB file predates schema metadata but already has the known buckets for the current line, treat it as legacy-current and backfill the schema metadata on open.
- On schema major mismatch, fail fast during Kitchen startup with a clear error telling the operator to purge the Kitchen volume with `make quickstart-purge` or `make dev-quickstart-purge`.

### When To Bump Schema Minor

Bump schema minor for additive, backward-compatible on-disk changes that old code can safely ignore or new code can default:

- adding a new bucket that does not change meaning of existing buckets
- adding optional JSON fields to persisted rows or Pantry assets
- adding new Pantry asset properties or relationships that older code can ignore
- adding metadata keys, timestamps, or derived caches that can be rebuilt

### When Not To Bump Schema Version

Do not bump schema version for changes that do not alter the persisted on-disk contract:

- Counter-only rendering, layout, or tree placement changes
- in-memory Pantry logic changes when persisted JSON shape and meaning stay the same
- test-only, docs-only, or logging-only changes
- internal refactors that keep the same buckets, keys, JSON fields, and semantics

### When To Bump Schema Major

Bump schema major for changes where an existing DB might be read incorrectly, written incorrectly, or require migration/purge:

- renaming, deleting, or repurposing a bucket
- changing key layout or record identity rules inside a bucket
- making previously optional fields required for correct behavior
- changing the semantic meaning of persisted values
- changing Pantry serialization in a way older data cannot be interpreted safely
- any change that would require a one-off migrator or operator purge to stay correct

### Rule Of Thumb

If older binaries can still safely read the DB, and newer binaries can safely read older DBs with sane defaults, keep the same schema major. If either direction is unsafe, bump schema major.

## Architecture

| Component | Location | Purpose |
|-----------|----------|---------|
| Counter | `cmd/counter/`, `internal/counter/tui/` | Operator TUI (Bubbletea) |
| Kitchen | `cmd/kitchen/`, `internal/kitchen/` | C2 server (HTTP + WebSocket) |
| Brisket | `cmd/brisket/`, `internal/brisket/` | Implant agent |
| Models | `internal/models/` | Shared types (Order, Coleslaw, ReconResult, ScanResult) |
| Pantry | `internal/pantry/` | Attack graph (hmdsefi/gograph) |
| Pass | `internal/pass/` | NATS JetStream abstractions |
| Rye | `internal/rye/` | Injection contexts & stagers |
| LOTP | `internal/lotp/` | Payload catalog |
| Poutine | `internal/poutine/` | Build pipeline SAST wrapper |
| Gitleaks | `internal/gitleaks/` | Secret scanning (custom rules) |
| Gump | `internal/gump/` | Process memory scanner (secrets from /proc) |

## Counter TUI File Organization

The Counter TUI (`internal/counter/tui/`) uses subject-based file organization. New TUI logic goes in the appropriate subject file, not `update.go`.

| File | Purpose |
|------|---------|
| `update.go` | `Update()` main dispatcher, `handleKeyMsg()`, modal key handlers |
| `setup.go` | Setup wizard (steps 1-7), auth flows, Kitchen verification |
| `wizard.go` | Exploit wizard key handling, step advancement, deployment orchestration |
| `deploy.go` | Deploy methods (PR, issue, comment, LOTP, dispatch), stager registration |
| `command.go` | REPL command router (`executeCommand`), status/session display |
| `kitchen.go` | Kitchen WebSocket connection, `startKitchenConsumers`, listener functions |
| `agent.go` | Beacon/coleslaw handlers, recon/scan results, orders, vuln display |
| `analysis.go` | Analyze/deep-analyze commands, analysis completion, graph, history, timer |
| `model.go` | Model struct definition |
| `messages.go` | Message types |
| `view.go` | View rendering |
| `helpers.go` | Utility functions |
| `token.go` | Token management |
| `pivot.go` | Pivot discovery |
| `tree.go` | Attack tree |
| `suggestions.go` | Command suggestions |

## CRITICAL: TUI Layout & Compositing (Ultraviolet)

The Counter TUI uses Bubbletea v2 with ultraviolet for layout and compositing. **ALWAYS use these  - never patch layout with manual width/height adjustments.**

### Layout (ultraviolet/layout)

All content layout uses `layout.SplitHorizontal`/`SplitVertical` with `layout.Percent` or `layout.Fixed` constraints, operating on `image.Rectangle` areas.

```go
// Correct: ultraviolet layout constraints
area := image.Rect(0, 0, width, height)
leftArea, rightArea := layout.SplitHorizontal(area, layout.Percent(50))

// Wrong: manual width/height arithmetic for panel sizing
treeWidth := m.width * 65 / 100
```

### Modal Compositing (ScreenBuffer)

All modal overlays use `uv.ScreenBuffer` for ANSI-safe compositing: render background first, then draw modal content on top (last-draw-wins).

```go
// Correct: ScreenBuffer compositing
scr := uv.NewScreenBuffer(bgWidth, bgHeight)
uv.NewStyledString(dimBackground(background)).Draw(scr, scr.Bounds())
fgW, fgH := lipgloss.Size(modal)
rect := layout.CenterRect(scr.Bounds(), fgW, fgH)
uv.NewStyledString(modal).Draw(scr, rect)
return scr.Render()

// Wrong: manual line-by-line overlay with ANSI parsing
prefix := extractVisualPrefix(bgLine, modalLeft)
```

### Never Use lipgloss Height()

Lipgloss `Height()` causes content duplication on initial render. Manually pad instead:

```go
// BAD
style := panelStyle.Width(width).Height(height)

// GOOD
for len(lines) < targetHeight {
    lines = append(lines, "")
}
return panelStyle.Width(width).Render(strings.Join(lines, "\n"))
```

### Never Hand-Draw Box Borders with Unicode

Unicode box-drawing characters render at inconsistent widths across terminal fonts. Use lipgloss Border() instead.

```go
// BAD: hand-drawn borders
lines = append(lines, mutedColor.Render("┌─ "+filename+" "+strings.Repeat("─", fill)+"┐"))

// GOOD: lipgloss Border()
style := lipgloss.NewStyle().
    Border(lipgloss.RoundedBorder()).
    BorderForeground(mutedColorVal).
    Width(boxWidth - 2)
```

### Content Lines in Modals Must Be Padded to Full Width

Every content line in modals gets wrapped with left/right borders. Short lines misalign the right border. Always pad to `innerWidth`.

```go
// BAD: short line  - right border appears mid-screen
lines = append(lines, mutedColor.Render("  "+filename))

// GOOD: padded  - right border stays at modal edge
label := mutedColor.Render("  " + filename)
pad := innerWidth - lipgloss.Width(label)
lines = append(lines, label+strings.Repeat(" ", pad))
```

## Key Interfaces

**Models (`internal/models/`):** `Order` (command to agent), `Coleslaw` (response from agent), `ReconResult`, `ScanResult`

**NATS Subjects:**
- `smokedmeat.orders.<agent_id>` - Commands to agents
- `smokedmeat.coleslaw.<agent_id>` - Responses from agents
- `smokedmeat.beacon.<agent_id>` - Heartbeats

**HTTP Endpoints (Kitchen):**
- `POST /auth/challenge`, `POST /auth/verify` - SSH auth
- `GET /health` - Health check (public)
- `GET /ws` - Counter WebSocket
- `POST/GET /b/{agentID}` - Brisket beacon/polling
- `GET/POST /r/{stagerID}` - Stager register/callback
- `GET /agent/{filename}` - Agent binary download
- `POST /analyze` - poutine analysis
- `POST /github/deploy/{pr,issue,comment,lotp,dispatch}` - Deployment operations
- `POST /github/{repos,repos/info,workflows,user,token/info}` - GitHub API proxy
- `GET /pantry` - Attack graph data
- `GET/POST /history` - Operation history
- `GET/POST /known-entities` - Known entity tracking
- `GET /graph` - Cytoscape visualization page
- `GET /graph/data` - Graph JSON data
- `GET /graph/ws` - Graph live updates WebSocket

## Testing

```bash
make test              # Unit tests
make test-verbose      # Verbose output
make test-race         # Race detection
go test -tags=integration ./...  # Integration tests (requires Docker)
```

### Test Philosophy

**Quality over coverage.** Tests should:
- Validate actual behavior users depend on
- Catch regressions that would break workflows
- Cover edge cases and error conditions
- Be readable as documentation of expected behavior

**Bad test** (coverage lipstick):
```go
func TestNewModel(t *testing.T) {
    m := NewModel()
    assert.NotNil(t, m)  // Useless - tests nothing meaningful
}
```

**Good test** (validates behavior):
```go
func TestWizard_EscapeReturnsToFindings(t *testing.T) {
    m := modelInWizardPhase()
    m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
    assert.Equal(t, PhaseRecon, m.phase, "Esc should exit wizard to findings")
    assert.Equal(t, ViewFindings, m.view)
}
```

### What to Test

| Test Type | Purpose | Example |
|-----------|---------|---------|
| State transitions | Phase/view changes work correctly | Wizard step 1→2→3, Esc backs out |
| Error handling | Graceful degradation | Kitchen disconnects, invalid input |
| Edge cases | Boundary conditions | Empty loot stash, zero vulns, terminal resize to 40x10 |
| Parsing | Input/output correctness | Command parsing, poutine result import |
| Rendering | Layout doesn't break | Golden files for wizard modal, tree view |

### Testing Patterns

**Model-layer tests** (fast, test state machine):
```go
func TestChecklist_CompletionUnlocksRecon(t *testing.T) {
    m := NewModel()
    m.checklist.kitchen = true
    m.checklist.token = true
    m.checklist.target = true
    m.checklist.analyzed = true

    m, _ = m.Update(
    assert.Equal(t, PhaseRecon, m.phase, "All items checked should advance phase")
}
```

**Golden file tests** (catch layout regressions):
```go
func TestWizardModal_Renders(t *testing.T) {
    lipgloss.Writer.Profile = colorprofile.Ascii  // CI stability
    m := modelInWizardStep(2)
    tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(80, 24))
    out, _ := io.ReadAll(tm.FinalOutput(t))
    teatest.RequireEqualOutput(t, out)
}
// Regenerate: go test -update
```

**Table-driven for variations**:
```go
func TestDeliveryMethod_Constraints(t *testing.T) {
    tests := []struct {
        name     string
        method   DeliveryMethod
        hasToken bool
        enabled  bool
    }{
        {"auto PR needs token", DeliveryAutoPR, false, false},
        {"auto PR with token", DeliveryAutoPR, true, true},
        {"copy always works", DeliveryCopyOnly, false, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            m := modelWithToken(tt.hasToken)
            assert.Equal(t, tt.enabled, m.canUseDelivery(tt.method))
        })
    }
}
```

### Test File Locations

- Unit tests: `*_test.go` alongside source
- Golden files: `testdata/*.golden`
- Integration tests: `tests/` with `//go:build integration`

## E2E Testing

### Automated (Recommended)

```bash
make e2e-exploit    # Full lifecycle: infra up → analysis → exploit → callback → cleanup
```

Runs `TestFullExploitFlow` in `.claude/e2e/`. Config lives in `.claude/e2e/.env` (not `~/.smokedmeat`).

### Manual Iteration

```bash
make e2e-up                        # Start infrastructure
make e2e-counter                   # Launch Counter in tmux
make e2e-capture                   # See current TUI state
make e2e-keys KEYS='Enter'         # Send input
make e2e-kitchen-rebuild           # Rebuild Kitchen (tunnel stays)
make e2e-down                      # Stop containers
```

### Staging (Remote with Real Domain)

Use the `/e2e-staging-test-run <hostname>` command for full staging E2E testing workflow.
