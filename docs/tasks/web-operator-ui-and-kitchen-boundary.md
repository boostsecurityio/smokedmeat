# Web Operator UI

## Why This Exists

SmokedMeat already has one browser-delivered surface:

- the Kitchen-served graph view at `/graph`

That proves the product can serve authenticated operator UI from Kitchen directly. The longer-term goal is to offer a full browser-based operator experience as an alternative to the Counter TUI.

In that model:

- Kitchen remains the source of truth
- Counter can remain useful as a CLI for setup, provisioning, and utility flows
- the main operator workflow can also run in the browser

This task exists to define the product work needed for a serious web operator UI after the shared backend boundary is in better shape.

## Current Product Facts

Relevant facts today:

- Kitchen already serves authenticated operator HTTP and WebSocket endpoints
- Kitchen already serves:
  - `/ws`
  - `/graph`
  - `/graph/data`
  - `/graph/ws`
- Counter already uses a Kitchen-backed client abstraction for operator HTTP and WebSocket traffic
- server-side deploy preflight already moved delivery capability logic into Kitchen to avoid TUI-only heuristics
- significant operator logic still lives inside Counter TUI state and update flows

Related prerequisite:

- `docs/tasks/counter-kitchen-boundary-refactor.md`

Implication:

- the product already has the beginnings of a shared backend
- the browser shell itself is not the hardest part
- the main prerequisite is a cleaner Counter/Kitchen boundary

## Product Goal

Enable a browser-based operator UI that reuses the same Kitchen truth and minimizes duplicated client-side logic.

The desired future shape is:

- Kitchen owns durable state, orchestration, validation, and domain decisions
- Counter TUI remains a first-class client
- a web operator UI becomes a second first-class client
- both consume the same backend events and APIs

## Non-Goals

This task is not:

- an immediate rewrite of Counter
- a promise to eliminate the TUI
- a frontend-framework decision
- a full redesign of every Kitchen endpoint before any web work starts

The first slice is a small browser operator shell on top of a cleaner backend boundary.

## Preconditions

This task assumes that shared boundary cleanup is handled by:

- `docs/tasks/counter-kitchen-boundary-refactor.md`

The web UI should build on that work, not quietly absorb it.

## Proposed Direction

### Phase 1 - Define the first browser operator slice

Choose a narrow but useful first slice, such as:

- session and callback inventory
- history and audit browsing
- pantry or workflow browsing

This should prove operator value without requiring exploit-wizard parity immediately.

### Phase 2 - Define client flows on top of Kitchen contracts

Kitchen should expose the state and actions needed by both clients:

- authenticated REST for point actions and snapshots
- authenticated WebSocket for live updates
- stable payloads for callbacks, sessions, history, progress, and graph updates

### Phase 3 - Add a minimal browser operator shell

Build a small authenticated browser operator shell that can prove:

- auth bootstrap from Kitchen
- live updates over WebSocket
- navigation across shared operator state
- reuse of Kitchen-owned business logic rather than client-side reimplementation

### Phase 4 - Expand only after the backend shape proves out

Once the first slice is working cleanly, expand toward:

- richer pantry navigation
- callback and session control
- exploit planning and later wizard support

## Counter's Future Role

Counter should remain useful for:

- initial setup and Kitchen access configuration
- CLI-driven maintenance or troubleshooting
- TUI-first operator workflows for users who prefer terminal operation

The browser UI should be an alternative operator client, not proof that Counter was a mistake.

## Authentication Model

The existing graph pattern is the right starting point:

- Counter can still bootstrap access or provisioning
- Kitchen can issue an authenticated URL or tokenized session for browser use
- the browser UI should use the same operator auth model as other Kitchen-backed routes

## Open Questions

- Do we want one operator WebSocket with broader event types, or separate WebSocket channels by function?
- Which workflow should be the first browser proof slice:
  - session inventory
  - history and audit
  - pantry and workflow browsing
  - exploit planning
- How much client-side state derivation is acceptable before we are recreating Counter logic in another language?
- Should the future web UI live as Kitchen-served assets or as a separate build artifact behind the same auth model?

## Done Criteria

This task is in good shape when:

- the prerequisite boundary cleanup is no longer the main blocker
- a useful browser operator shell can ship without large client-side reimplementation of product rules
- Kitchen-backed auth, REST, and WebSocket flows are sufficient for the chosen browser slice
- the web UI can expand incrementally from a narrow first surface
