# Operator Command Discoverability

## Why This Exists

Operator commands that already work should be easy to discover from the main input flow.

Right now, commands such as `order exec ...` are part of the product surface, but discoverability is weaker than it should be. If tab completion only exposes these commands in limited contexts, or only after the operator already knows the exact syntax, the product is forcing unnecessary memory load during post-exploit operations.

This task exists to make command discovery, completion, and help output match the real command surface.

## Current Product Facts

Relevant code paths today:

- `internal/counter/tui/command.go` already supports `order <exec|env|recon|cloud-query|oidc|transfer|upload|download>`
- `internal/counter/tui/completion.go` drives tab completion and inline completion hints
- `internal/counter/tui/layout.go` help text already advertises `order exec <cmd>`
- `internal/counter/tui/pivot_recommendations.go` already emits examples such as `order exec aws sts get-caller-identity`

Implication:

- the command capability exists
- examples exist
- help text exists
- completion and discoverability are still not aligned with that capability

## Product Goal

Make the operator command surface self-discovering enough that common post-exploit actions do not depend on memory or external notes.

The operator should be able to:

- tab-complete `order`
- tab-complete the supported order subcommands
- discover `order exec` naturally from the main input
- get compact syntax hints for the active subcommand
- understand which commands are local Counter commands versus remote agent orders

## Non-Goals

This task is not:

- a full interactive shell grammar for arbitrary remote commands
- a replacement for good help text
- a redesign of every command in Counter

The first slice is discoverability and completion parity.

## Core Problems

### 1. Completion does not appear to mirror the real command surface

If `order exec` is supported in `command.go`, completion should expose it in the same places the command can actually be used.

### 2. Local commands and remote orders are easy to conflate

Counter mixes:

- local operator commands
- post-exploit utility commands
- remote agent orders

The UI should make this distinction clearer when suggesting commands.

### 3. Examples are not enough if they are not reachable at the moment of use

Examples in help text or pivot recommendations are useful, but they do not replace inline completion when the operator is actively typing.

## Proposed Direction

### 1. Make `order` a first-class completion root

Completion should expose:

- `order exec`
- `order env`
- `order recon`
- `order cloud-query`
- `order oidc`
- `order transfer`
- `order upload`
- `order download`

### 2. Add subcommand-specific hints

Examples:

- `order exec <cmd>`
- `order upload <local> <remote>`
- `order download <remote> <local>`

These should stay compact enough for the inline hint area.

### 3. Keep context sensitivity, but never hide supported core orders entirely

Context-aware ordering is good. Hard disappearance of supported commands is not.

For example:

- cloud-specific suggestions can remain gated on cloud pivots
- `order exec` should still remain visible as a basic remote command primitive whenever an agent session is selected

### 4. Reflect the distinction in help text and completion text

Suggested grouping:

- local commands
- agent orders
- pivot helpers

This can remain a presentation-layer distinction without changing the command parser.

## Implementation Plan

### Phase 1 - Audit the current completion surface

Deliverables:

- exact list of command roots exposed by `getCompletions`
- exact list of supported `order` subcommands from `command.go`
- mismatch list

Done when:

- the gap is written down concretely

### Phase 2 - Bring completion into parity

Deliverables:

- `order` root completion
- `order` subcommand completion
- compact inline hints for the main subcommands

Done when:

- operators can discover `order exec` and sibling orders with tab completion alone

### Phase 3 - Polish help text and suggestion ranking

Deliverables:

- help text uses the same command grouping as completion
- common post-exploit primitives rank near the top

Done when:

- command discovery feels consistent whether the operator uses help, tab completion, or suggestions

## Acceptance Checks

- typing `ord<Tab>` completes to `order`
- typing `order <Tab>` shows the supported subcommands
- typing `order e<Tab>` completes to `order exec`
- `order exec` stays visible in normal post-exploit agent operation
- unsupported or unavailable commands are clearly distinguished from supported ones

## Done Criteria

This task is in good shape when:

- the supported `order` subcommands in `command.go` are discoverable through completion
- `order exec` is easy to discover without prior product knowledge
- inline hints stay compact and readable
- help text and completion no longer contradict each other
