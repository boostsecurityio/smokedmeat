# Grouped Callback And Session-Management UX

## Why This Exists

The bounded-fanout slice is already shipped to `main`:

- normal deploys can now tolerate a bounded callback budget
- the wizard exposes that budget explicitly
- Kitchen handles stager cleanup correctly for that model

That solved the callback-race part of the problem, but it did not solve the operator UX after several related callbacks or sibling agents arrive.

The remaining gap is that one deployed payload can still lead to several related callbacks and several agents, while the operator experience remains too flat and too manual.

## Current Product Facts

Relevant facts after the shipped fanout slice:

- Counter still mainly relies on:
  - a flat `sessions` view
  - `select <agent_id>`
  - the `implants` / `callbacks` modal
- callback-to-agent linking already exists
- callback rows already carry useful metadata such as:
  - callback label
  - repository
  - workflow
  - job
  - hit count
  - linked agents
- the current modal is informative, but it is not yet the fastest way to answer:
  - which sibling agent just arrived
  - which one is the interesting one
  - how do I switch to it immediately

## Product Goal

Make multi-callback and multi-agent situations easy to operate once the bounded-fanout backend slice has already been shipped.

The operator should be able to:

- see that several callbacks or agents are related to the same deploy attempt
- understand what just arrived and why it matters
- switch to the right sibling agent quickly
- distinguish writer, victim, stale, active, and high-value arrivals more clearly

## Non-Goals

This follow-up is not:

- a redo of the bounded-fanout backend work
- a full terminal multiplexer
- a full planner for every multi-pivot workflow
- automatic agent switching that surprises the operator

The goal is better visibility and faster operator-controlled switching.

## Product Direction

Treat the remaining work as a grouped inventory and navigation problem in Counter.

The key relationships should be easy to follow:

- deploy attempt -> callbacks -> agents
- callback -> linked agents
- agent -> originating callback or deploy attempt when known

The operator should not need to infer those relationships from a flat sessions list.

## Proposed UX

### 1. Stronger arrival notifications

When an additional callback or linked agent arrives, Counter should emit a more useful notification than a raw beacon line.

Useful examples:

- new callback from `repo/workflow`
- additional agent from the same payload
- callback appears to be `writer` or `victim`
- callback produced secrets
- callback seems more interesting than the current active session

### 2. Grouped navigation in the implants modal

The existing `implants` / `callbacks` modal should become the main grouped switching surface for this scenario.

Desired first improvements:

- left pane grouped by callback or deploy attempt
- right pane showing linked agents for the selected group
- clearer badges for:
  - active
  - stale
  - secrets found
  - writer
  - victim
  - revoked

### 3. Faster sibling switching

The operator should be able to:

- select the newest linked agent
- move next or previous within the selected callback group
- jump to the newest callback group with unseen activity

### 4. Keep flat sessions as compatibility, not primary workflow

`sessions` should remain available, but multi-hit workflows should nudge the operator toward the grouped callback view where the relationship data actually lives.

## Testing

Add coverage for:

- grouped callback and agent ordering
- unseen activity markers
- arrival notification wording and routing
- quick-switch behavior from the implants modal
- writer and victim surfacing for cache poisoning

## Acceptance Cases

- When multiple callbacks arrive from one payload, the operator can see they are related.
- The grouped callback view makes it easy to identify linked sibling agents.
- The operator can switch to the newest or selected sibling agent quickly.
- Writer and victim style distinctions are visible when meaningful.
- The flat sessions list still works, but the grouped modal becomes the practical workflow for multi-agent situations.

## Notes

This spec intentionally tracks only the remaining UX work after the bounded-fanout slice shipped.
