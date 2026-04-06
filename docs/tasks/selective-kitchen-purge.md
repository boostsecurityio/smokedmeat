# Selective Kitchen Purge

## Why This Exists

Operators need a way to clear operational state without destroying the whole Kitchen volume.

A common case is:

- a large org was analyzed
- nothing interesting was found
- the operator wants to continue with a cleaner view
- audit and other durable records should still remain

Today the clean-slate option is too coarse. The product needs a selective purge model.

## Current Product Facts

Relevant facts today:

- Kitchen persists Pantry state, sessions, orders, stagers, history, known entities, and loot in BBolt
- current reset workflows are effectively environment-level, not target-level
- operation history already exists and should not be treated like disposable state

Implication:

- the system already distinguishes multiple state buckets internally
- the operator does not yet have a safe, flexible purge tool on top of that

## Product Goal

Allow the operator to purge operational state selectively while preserving durable audit records.

The product should support:

- purge by org
- purge by repo
- purge by session or campaign
- purge of analysis artifacts without deleting audit trail
- purge actions themselves being logged

## Non-Goals

This task is not:

- a destructive wipe of all Kitchen data by default
- a way to remove audit trail
- a hidden background garbage collector

The first slice is explicit operator-controlled purge with clear scope.

## Purge Scopes

Initial scopes should include:

- org-scoped Pantry and known-entity data
- repo-scoped Pantry and known-entity data
- session-scoped operational state
- stale callbacks, implants, or other transient state where appropriate

State that should be treated separately:

- audit trail
- durable exported reports
- configuration

## Design Principles

### 1. Purge must be scoped, previewable, and explicit

The operator should know what categories will be removed before confirming.

### 2. Audit is retained

Purge should never remove the formal audit trail. Purge actions themselves should create audit entries.

### 3. Pantry and known-entity cleanup should remain consistent

Deleting one category while leaving dangling references behind is not acceptable. Purge needs to update related stores coherently.

### 4. Kitchen owns the state change

Counter should request purge and present the result. Kitchen should perform the actual scoped deletion.

## Proposed Product Flow

### Counter

- operator invokes a purge command
- chooses scope such as org or repo
- sees a preview of what categories are affected
- confirms

### Kitchen

- computes the affected records
- deletes purgeable state
- leaves audit records intact
- records the purge action in audit trail

## Implementation Plan

### Phase 1 - Define purgeable versus retained state

Deliverables:

- explicit list of buckets and record types
- retention rules
- org and repo scoping rules

Done when:

- the product has a written purge matrix instead of ad hoc assumptions

### Phase 2 - Kitchen purge engine

Deliverables:

- scoped delete routines
- preview or dry-run support
- audit logging for purge

Done when:

- Kitchen can delete a target org or repo cleanly without removing audit data

### Phase 3 - Counter UX

Deliverables:

- purge command
- scope selection
- confirmation step
- result summary

Done when:

- operators can start mostly fresh without destroying the whole environment

## Open Questions

- Should purge support category flags such as "analysis only" versus "loot too"?
- Should session-scoped purge remove agents and callbacks immediately, or only historical operator state?
- Do we want a dry-run report that lists exact counts before deletion?

## Done Criteria

This task is in good shape when:

- operators can purge by org or repo without wiping Kitchen entirely
- Pantry, known entities, and related operational state remain internally consistent after purge
- audit trail survives every purge action
- purge itself is logged as an auditable event
