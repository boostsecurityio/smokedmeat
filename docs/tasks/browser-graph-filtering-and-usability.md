# Browser Graph Filtering And Usability

## Why This Exists

The browser graph works on small and medium targets, but it becomes hard to use on very large organizations.

Real operator feedback from a large AWS org test:

- org target had about 500 public repos
- graph loaded with about 9812 nodes and 10500 edges
- page load took about 20 seconds before becoming interactive
- `Hierarchical` collapsed into a very long line
- `Radial` became a dense sphere with little operator value
- `Force` was heavy enough to jam the browser runtime

The immediate product gap is not only layout quality. It is that the graph is trying to render too much low-value structure by default.

## Product Goal

Make the browser graph practical on large targets by default.

The operator should be able to:

- open the graph without rendering thousands of low-value nodes by default
- hide repos, workflows, and related nodes that have no vuln-bearing path
- understand when the graph is filtered versus full
- progressively expand scope when they want more context
- avoid browser hangs or layout choices that are obviously poor fits for huge graphs

## Non-Goals

This task is not:

- a full graph-engine rewrite
- a promise that every layout will look good at 10k-node scale
- a replacement for the Counter tree view
- a full search and analytics feature set

The first goal is safe, useful defaults and a graph that stays explorable.

## Current Problems

### 1. Large graphs render everything by default

For very large orgs, the browser graph currently attempts to render the full graph immediately.

That causes:

- long initial load times
- poor default layouts
- heavy browser CPU and memory use
- low signal because the operator sees thousands of nodes with no immediate exploitation value

### 2. Low-value nodes overwhelm the useful ones

Operators often care first about:

- vulnerable workflows
- repos that contain vulnerable workflows
- secrets, pivots, or sessions linked to those workflows

They do not usually need every repo and every workflow node with no vuln-bearing path on first open.

### 3. Layout choice is not scale-aware

Some layouts remain usable only below certain sizes.

On very large graphs:

- hierarchical can degenerate into a long strip
- radial can become an unreadable sphere
- force can become too expensive to be a safe default

## Product Direction

Treat this as a filtering-first problem, not a layout-first problem.

The graph should have two default modes:

- small or medium graph
  - render the full graph by default
- large graph
  - render a filtered graph by default

The filtered default should aim for high operator signal, not completeness.

## Proposed First Slice

### Automatic filtered mode above a graph-size threshold

When the graph exceeds a configurable threshold, the browser UI should switch to filtered mode by default.

Threshold inputs could include:

- total node count
- total edge count
- both

The exact threshold can be tuned during implementation, but the behavior should be deterministic and easy to reason about.

Example intent:

- below threshold: show full graph
- above threshold: show filtered graph and explain why

### Default large-graph filter: hide nodes with no vuln-bearing path

For the first filtered mode, hide nodes that are not connected to any vulnerable workflow or other operator-relevant path.

The first useful definition is conservative:

- keep vulnerable workflow nodes
- keep repos that contain vulnerable workflows
- keep directly related edges
- keep downstream nodes that were produced from those exploitation-relevant paths
- hide repos and workflows that have no vuln-bearing path at all

The product should prefer a slightly narrower but obviously useful view over an exhaustive but unusable one.

### Clear filtered/full toggle

The browser UI should clearly show:

- whether the graph is filtered or full
- what the current filter is doing
- how to switch to full graph mode

The operator should never wonder whether nodes are missing because of a bug or because of an active filter.

### Safer layout defaults for large graphs

When the graph is above the large-graph threshold:

- avoid defaulting to the most expensive layout
- prefer a layout that is stable and cheap enough to stay interactive
- consider disabling or warning on layouts known to behave poorly at that scale

This does not mean removing layouts forever. It means making the default behavior safer when the graph is huge.

## Candidate Filter Controls

First-slice controls should stay small and obvious:

- `Show full graph`
- `Show only vuln-bearing paths`
- `Hide repos with no vulnerable workflows`
- `Hide workflows with no findings`

If the implementation needs one default plus one escape hatch for the first slice, that is acceptable.

## Implementation Notes

Open design choice:

- pre-filter in Kitchen before sending browser data
- send full graph data and filter in the browser
- hybrid approach with summary counts plus filtered data first

The first slice should choose the simplest path that keeps load time and browser cost acceptable on large orgs.

If the browser still has to download the full 10k-node graph before filtering, the UX win will be smaller. This is worth keeping in mind during implementation.

## Acceptance Cases

- Small graphs still open in full mode by default.
- Large graphs open in filtered mode by default.
- On a very large org, the first rendered graph is materially smaller and more readable than the full graph.
- Repos and workflows with no vuln-bearing path are hidden in the default large-graph mode.
- The operator can intentionally switch to full graph mode.
- The UI clearly indicates when filters are active.
- The default large-graph layout stays interactive instead of locking up the browser.

## Follow-On Ideas

Possible later improvements, not required for the first slice:

- search within the graph
- filter chips for secrets, pivots, sessions, or specific vuln classes
- server-provided summary counts before full graph fetch
- remembered operator filter preferences
- scale-aware layout availability or per-layout warnings
