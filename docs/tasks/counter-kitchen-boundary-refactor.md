# Counter And Kitchen Boundary Refactor

## Why This Exists

SmokedMeat already has two operator-facing clients with different shapes:

- Counter as the terminal UI
- Kitchen-served browser surfaces such as `/graph`

That split is workable today, but too much client-neutral product logic still lives close to Counter state and update flows. This makes the code harder to reason about, harder to test in isolation, and harder to reuse from any future non-TUI client.

This task exists to improve separation of concerns before any major new client work. It stands on its own as code quality, architecture, and maintainability work. It does not require a final web UI design to be useful.

## Current Product Facts

Relevant facts today:

- Kitchen already owns durable state, persistence, deploy operations, analysis, history, graph data, and operator WebSocket traffic
- Counter already talks to Kitchen through `internal/counter/client.go`
- Kitchen already serves authenticated operator routes such as:
  - `/ws`
  - `/graph`
  - `/graph/data`
  - `/graph/ws`
  - `/history`
  - `/callbacks`
  - `/known-entities`
- server-side deploy preflight already proved the right direction:
  - client heuristics moved into Kitchen
  - Counter became a consumer of shared backend truth

At the same time:

- some workflow orchestration and state derivation still live inside Counter
- some Kitchen payloads and message shapes still reflect TUI assumptions
- some product slices are only practical through Counter-specific control flow rather than explicit Kitchen-backed state and actions

## Product Goal

Make the Counter/Kitchen split cleaner, more explicit, and easier to evolve.

The desired shape is:

- Kitchen owns client-neutral domain logic, validation, orchestration, and durable state
- Counter owns terminal interaction, keyboard handling, layout, and local presentation details
- shared behavior is exposed through stable backend APIs and events rather than hidden in TUI state transitions

## Non-Goals

This task is not:

- a commitment to build the web UI immediately
- a rewrite of Counter
- a rewrite of Kitchen's entire API surface in one pass
- a frontend-framework decision
- a cosmetic file shuffle with no behavioral payoff

## Problems To Address

### 1. Client-neutral decisions still leak into TUI code

Examples already seen in the codebase:

- deploy capability logic previously lived in Counter and had to move into Kitchen
- callback, session, and agent workflows still have logic split across backend state and TUI-specific derivation
- some exploit and navigation flows are easier to use than to describe via explicit backend state

### 2. Backend events are not always shaped as a reusable operator model

Kitchen already emits useful state, but some streams still feel optimized for the current Counter implementation rather than a stable, client-neutral event contract.

### 3. The split is not audited systematically

There is no single inventory of:

- what is presentation-only
- what is client orchestration
- what is actually domain logic that belongs in Kitchen

Without that inventory, refactors are reactive instead of deliberate.

### 4. Testing follows the current split too closely

When domain logic stays inside TUI paths, the easiest tests become UI-state tests rather than backend behavior tests. That weakens reuse and makes future client expansion more expensive.

## Refactor Goals

### 1. Audit the current boundary feature by feature

Produce a concrete inventory of Counter-side logic grouped into:

- presentation only
- client orchestration
- Kitchen-worthy domain logic

This should be done by product slice, not by broad package theory.

Candidate slices:

- session and callback management
- exploit planning and wizard state derivation
- workflow browsing and metadata fetch
- analysis progress and history
- audit and purge operations
- known-entity and graph mutations

### 2. Move clear domain logic into Kitchen

When logic is not inherently about terminal interaction, move it toward Kitchen.

Examples:

- grouping and correlation rules
- validation and availability checks
- state transitions that should be shared by multiple clients
- fetch and cache policy for GitHub-backed content
- export and purge planning logic

### 3. Make shared contracts explicit

Kitchen should expose stable contracts for:

- snapshots
- point actions
- live updates
- long-running job progress
- domain-level status and errors

Counter should consume those contracts rather than infer product state from backend side effects.

### 4. Tighten test ownership

After the split is improved:

- Kitchen tests should own client-neutral behavioral rules
- Counter tests should focus on terminal UX, interaction flow, and rendering
- duplicate logic between the two should shrink rather than grow

## Proposed Work Phases

### Phase 1 - Boundary Audit

Review the current operator flows and document:

- which package owns the source of truth
- where state is derived today
- which behaviors are duplicated, implicit, or TUI-coupled
- which APIs are missing or too Counter-shaped

The output should be a concrete checklist, not only a narrative note.

### Phase 2 - Extract low-risk shared logic

Prioritize slices where the backend ownership is already obvious, such as:

- session and callback grouping
- workflow content fetch and cache
- audit/export planning
- purge scope evaluation
- progress reporting contracts

### Phase 3 - Normalize operator-facing Kitchen contracts

Where needed:

- add or refine REST endpoints
- refine WebSocket event payloads
- reduce TUI-only assumptions in backend responses
- make long-running operations observable without polling hacks

### Phase 4 - Simplify Counter around the new boundary

After shared logic moves:

- delete now-redundant TUI-side derivation
- keep Counter focused on interaction and presentation
- ensure command and wizard flows stay readable

## Relationship To Web UI Work

This task is a prerequisite and enabler for any future browser-based operator UI.

That future client should benefit from this work, but this task is still worthwhile even if the web UI is postponed. A cleaner Counter/Kitchen split improves:

- code quality
- testability
- maintainability
- operator feature velocity

## Done Criteria

This task is in good shape when:

- the Counter/Kitchen boundary has been audited explicitly by product slice
- new client-neutral logic defaults to Kitchen by convention
- at least the highest-friction shared behaviors have moved out of TUI-specific flows
- Kitchen contracts are clearer and more reusable for non-TUI clients
- Counter code is more obviously about interaction and presentation rather than hidden backend policy
