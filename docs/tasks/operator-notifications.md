# Operator Notifications

## Why This Exists

SmokedMeat already surfaces important events in the operator UI, but those events are easy to miss when the operator is not staring at the terminal at the exact right moment.

The first need is simple:

- when a new agent checks in, the operator should know
- when an important deploy succeeds or fails, the operator should know
- when clearly high-value loot appears, the operator should know

This should start as a small backend-owned notification path, not as a large integration project.

## Product Goal

Add a minimal outbound notification capability for important operator events.

The first useful slice is:

- generic outbound webhook delivery
- event types for new agent check-in, deploy result, and high-value loot
- enough structure to feed Slack, Discord, or similar destinations without baking them into the core implementation

## Non-Goals

This task is not:

- a full notification rules engine
- channel-specific formatting for many destinations
- pager-style escalation logic
- a replacement for the in-app callback and session views

## Minimal First Slice

### Events

Support these event families first:

- new agent check-in
- deployment success
- deployment failure
- high-value loot discovered

### Delivery

Start with:

- one or more configured generic webhook targets
- a simple JSON payload shape
- examples that are straightforward to route into Slack or Discord
- best-effort delivery with visible failure state for the operator

### Ownership

Kitchen should own:

- event emission
- payload generation
- delivery attempts
- delivery history or failure visibility

Counter should only need:

- configuration surfaces
- operator visibility into notification status

## Done Criteria

This task is in good shape when:

- Kitchen can emit generic webhook notifications for the first event set
- the payloads are stable enough for lightweight Slack or Discord integrations
- the operator can tell whether notifications are configured and whether delivery is succeeding
