# Callback Fanout And Session Management

## Why This Exists

The real gap is not only that multiple agents can coexist. The real gap is that one deployed payload can legitimately fan out into multiple workflow runs, those runs can callback in parallel or out of order, and the operator currently has weak visibility and weak switching once that starts happening.

## Operator Requirements

This task assumes:

- payload delivery is effectively gated to be served once
- multiple workflows may listen on the same event and all run from the same injected payload
- the first callback is not always the one the operator wants
- the interesting secrets may land on the second or third callback, not the first
- the operator needs to be notified when multiple agents arrive
- the operator needs to switch between those agents quickly and confidently

These constraints point to two linked problems:

- callback fanout behavior is too strict
- operator session management after fanout is too weak

Solving only the UI would leave the race in place.
Solving only the server-side callback behavior would still leave the operator blind.

## Current State

Relevant product facts today:

- normal deploys still revolve around a stager callback model in Kitchen
- non-persistent stagers are deleted after the first resolved callback
- persistent callbacks already exist, but they are mainly used for cache poisoning and dwell-oriented flows
- Counter already has:
  - a flat `sessions` view
  - `select <agent_id>`
  - an `implants` / `callbacks` modal
  - callback-to-agent linking in memory
- the current callback modal already shows:
  - callback label
  - repository
  - workflow
  - job
  - hit count
  - linked agents
  - dwell controls

Relevant code paths:

- Kitchen callback state:
  - `internal/kitchen/stager.go`
  - `internal/kitchen/callbacks.go`
- Counter callback and implant UX:
  - `internal/counter/tui/callbacks.go`
  - `internal/counter/tui/callback_render.go`
  - `internal/counter/tui/agent.go`
  - `internal/counter/tui/command.go`

Important current limitation:

- the callback modal is useful for persistent implants after they exist
- it is not yet a strong workflow for "one payload produced three agents, which one should I attach to now?"

## Product Goal

Make SmokedMeat handle multi-callback and multi-agent situations as a first-class operator flow.

The operator should be able to:

- deploy once and tolerate several valid callbacks from that same payload
- see that those callbacks are related
- understand which callback or agent is likely the interesting one
- switch to the desired agent quickly
- avoid losing the second or third callback because the first one arrived first

This must be implemented in a way that can later be reused by a web UI backed by Kitchen, not only by the TUI.

## Non-Goals

This task is not:

- a full general-purpose terminal multiplexer
- a complete rewrite of Counter session handling
- a full planner for all multi-pivot kill chains
- an excuse to make every callback persistent forever

The goal is tighter control over multi-hit callback situations and the resulting agent inventory.

## Core Problem Breakdown

### 1. One-shot callback resolution is too narrow for fanout

Today a normal non-persistent stager is consumed on the first callback resolution.

That is fine for the simple path:

- one payload
- one workflow
- one callback

It is not fine when:

- one payload lands in multiple listening workflows
- one workflow retries
- multiple runners reach the callback close together

In that situation, one-shot resolution creates a race that is hostile to the operator.

### 2. Callback and agent identity are not surfaced strongly enough

SmokedMeat already has pieces of the identity model:

- callback ID
- callback label
- repo / workflow / job metadata
- callback hit count
- linked agents

But the operator experience is still mostly:

- flat sessions list
- one active agent
- a secondary implants modal

That is not enough when multiple valid agents land from related callbacks.

### 3. Switching is not optimized for "related agents"

The current switching model is mostly:

- `sessions`
- `select <agent_id>`

That is workable for a few independent agents, but weak for:

- multiple agents from the same callback
- multiple callbacks from the same deploy attempt
- writer versus victim callback pairs

### 4. Notifications are not strong enough

When additional callbacks or agents arrive, the operator should get an obvious, contextual signal:

- what just arrived
- which repo / workflow it belongs to
- whether it appears related to the same payload
- whether it looks more interesting than the current active agent

## Product Direction

Treat this as a Kitchen-backed inventory and correlation problem with a Counter workflow on top.

Three concepts should be first class:

- callback
  - one registered stager endpoint or implant endpoint that can be hit one or more times
- agent session
  - one running Brisket identity and its live or stale state
- deploy attempt
  - the operator action that created the callback, including vuln, repository, workflow, and delivery method

The operator should be able to navigate along all three:

- deploy attempt -> callbacks -> agents
- callback -> agents
- agent -> originating callback and deploy attempt

## Key Design Decisions

### 1. Kitchen should own callback fanout policy

Counter should not guess whether a payload may be reused.

Kitchen should decide:

- whether a callback is one-shot
- whether it can fan out for a short window
- whether it is a true persistent implant

That keeps the model reusable for a future web UI.

### 2. Normal deploys need a limited fanout mode

We should not jump from one-shot directly to "always persistent".

The better model is a bounded fanout mode for normal deploys:

- allow more than one callback for a short time window or small hit budget
- still expire or self-close
- still create a fresh agent token and agent identity per hit

This directly addresses the callback race without turning every deploy into a long-lived implant.

### 3. The operator needs grouped navigation, not only a flat list

The existing flat session list should remain for compatibility.

But the primary workflow for this feature should become grouped:

- by deploy attempt
- then by callback
- then by linked agents

### 4. Keep notification logic descriptive, not magical

The product should avoid silently switching agents just because a newer callback arrived.

It should instead:

- notify clearly
- show why the new callback matters
- make switching fast

Automatic selection should only happen when the signal is overwhelmingly clear and low risk.

For the first slice, default to operator-controlled switching.

## Proposed Backend Model

### Callback Serve Policy

Introduce an explicit serve policy for registered stagers.

Suggested conceptual states:

- `one_shot`
- `fanout_window`
- `persistent`

Suggested first-slice behavior:

- normal exploit deploys use `fanout_window`
- cache poison and other implant-oriented flows keep `persistent`
- some narrow paths may still use `one_shot` if there is a strong reason

`fanout_window` should be bounded by:

- max callback count
- max reuse duration

The exact defaults can be tuned during implementation, but the key point is bounded reuse rather than infinite reuse.

### Deploy Attempt Metadata

The callback metadata should be enriched so related arrivals can be grouped cleanly.

At minimum:

- repository
- workflow
- job when known
- vulnerability ID
- delivery method
- callback label
- role when meaningful
  - for example `writer` or `victim` in cache poisoning
- deploy attempt ID

This metadata should be carried through Kitchen and exposed to clients.

### Agent Correlation

Each callback hit that creates an agent should preserve:

- callback ID
- callback mode
- deploy attempt ID when available

That makes it possible to group agents deterministically instead of inferring only from repo/workflow strings.

## Proposed Counter UX

### 1. Stronger arrival notifications

When a callback or linked agent arrives, Counter should emit a more useful notification than a raw beacon line.

Examples of the kind of information to surface:

- new callback from `repo/workflow`
- additional agent from the same payload
- callback appears to be `writer` or `victim`
- callback produced secrets
- callback supersedes the current active session in likely value

This is especially important for the cache poison writer/victim path.

### 2. Evolve the implants modal into the main grouped navigator

The existing `implants` / `callbacks` modal is the right base.

First-slice improvements should make it usable as the primary switching tool:

- left pane
  - grouped callbacks or grouped deploy attempts
- right pane
  - linked agents for the selected group
- clear badges
  - active
  - stale
  - secrets found
  - writer
  - victim
  - revoked

The operator should be able to attach to the selected linked agent directly from that modal.

### 3. Preserve the flat sessions list, but demote it

`sessions` should remain available.

But for multi-hit scenarios, the operator should be nudged toward the grouped implants view because that is where the relevant relationship data lives.

### 4. Add fast-switch actions

First-slice actions should be simple:

- select newest linked agent
- select next / previous linked agent in the selected callback group
- jump to the newest callback group with unseen activity

Do not overload the first implementation with a giant command surface.

## Alternatives Considered

### A. Improve only the UI

Rejected.

Reason:

- it would not solve the one-shot callback race

### B. Make all deploy callbacks persistent

Rejected.

Reason:

- too noisy
- too much lingering exposure
- operator would lose the distinction between a bounded exploit callback and a true implant

### C. Auto-switch to every newest agent

Rejected.

Reason:

- surprising
- likely to interrupt operator flow
- wrong often enough to be harmful

## Implementation Slices

### Slice 1. Bounded Fanout In Kitchen

Implement:

- explicit callback serve policy
- bounded fanout for normal deploys
- deploy attempt metadata on callbacks
- callback-hit accounting that survives multiple related hits

Do not yet redesign the entire TUI.

### Slice 2. Counter Notification And Grouping

Implement:

- better callback-arrival notifications
- grouped callback/agent view in the implants modal
- one-key select of the newest or selected linked agent

### Slice 3. Operator Workflow Polish

Implement:

- unseen activity markers
- faster sibling switching
- better writer/victim surfacing for cache poisoning
- any command-level affordances that still feel necessary after the modal improves

## Testing

### Unit And Integration

Add coverage for:

- one-shot versus fanout-window versus persistent callback resolution
- bounded multi-hit behavior
- deploy attempt metadata persistence
- callback-to-agent correlation
- grouped sorting and unseen markers
- quick-switch behavior from the implants modal

### Real Product Validation

The external Whooli and `poutineville` test orgs should both be useful:

- `poutineville` for controlled multi-workflow trigger experiments
- Whooli for the writer/victim operator path

Important acceptance cases:

- multiple workflows triggered by one payload all have a fair chance to callback
- the second callback is not lost just because the first one arrived first
- the operator can identify and switch to the desired sibling agent quickly
- cache poison writer and victim callbacks are visibly distinct
- a future web UI could consume the same Kitchen metadata without reimplementing local heuristics

## Done Criteria

This task is in good shape when:

- one deployed payload can be configured to tolerate bounded multi-callback fanout
- Kitchen exposes enough metadata to group callbacks and agents by deploy attempt
- Counter clearly notifies the operator when additional related callbacks arrive
- the implants view becomes the practical switching surface for multi-agent situations
- the operator can switch to the right sibling agent quickly without manual guesswork
- the design remains reusable by a future web UI backed by Kitchen
