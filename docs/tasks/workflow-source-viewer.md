# Workflow Source Viewer

## Why This Exists

The operator often needs to inspect the vulnerable workflow itself, not just the finding summary.

Today SmokedMeat already stores workflow paths, workflow nodes, and GitHub URLs in the tree and graph, but it does not provide a first-class way to fetch and display workflow source on demand inside the product.

This task exists to define a workflow source viewer for both Counter and a future Kitchen-backed web UI.

## Current Product Facts

Relevant facts today:

- workflow assets already exist in Pantry
- tree and omnibox navigation already surface workflow nodes and GitHub blob URLs
- Kitchen already proxies several GitHub endpoints, including workflow listing
- there is not yet a Kitchen endpoint dedicated to fetching workflow file contents
- there is not yet a Counter modal or browser view dedicated to workflow source

Implication:

- the product already knows which workflow file the operator cares about
- the missing piece is on-demand source retrieval, caching, and display

## Product Goal

Let the operator inspect workflow source quickly from the same interface they use for analysis and exploitation.

The product should support:

- TUI workflow source popup with scrollable content
- browser-side workflow viewer for the graph or future web UI
- optional syntax highlighting
- line targeting when opening from a finding
- local caching so repeated viewing does not hit GitHub every time

## Non-Goals

This task is not:

- a full GitHub clone of repository browsing
- an inline workflow editor
- a promise to fetch the entire repository tree eagerly

The first slice is a workflow-focused read-only viewer.

## Design Constraints

### 1. Fetch on demand

The product should not eagerly cache every workflow file during analyze. Fetch only when the operator requests to view one.

### 2. Cache to disk

Useful cache locations:

- local Counter-side cache under `~/.smokedmeat/cache/...` for TUI and external editor use
- Kitchen-side cache for browser display and future shared UI flows

### 3. Keep Kitchen as the source of truth for remote fetch

The workflow viewer should use Kitchen-backed fetches so:

- access control stays centralized
- remote web UI can reuse the same API
- caching policy is consistent

### 4. Preserve line context

When the operator opens source from a vuln, the viewer should:

- jump to the vulnerable line if known
- highlight the line or a small region
- still allow free scrolling

## Proposed Product Flow

### TUI

- select a workflow node or vuln
- press a key such as `v`
- open a modal with:
  - workflow path
  - repo
  - cached or live status
  - scrollable source
  - line highlight when relevant

### Browser

- select a workflow node or vuln from graph
- open a Kitchen-served source view
- fetch workflow content on demand
- support syntax highlighting and deep-linking to line numbers

## Kitchen Responsibilities

Kitchen should own:

- workflow file fetch from GitHub
- auth and token handling
- content caching
- content metadata such as:
  - repo
  - path
  - ref
  - fetched_at
  - cache key

Suggested future API shape:

- `POST /github/workflow/content`
- or a more general repo content read endpoint if we want this to grow later

## Counter Responsibilities

Counter should own:

- modal state
- scrolling
- line targeting
- fallback display when fetch fails
- deciding whether to open TUI viewer or hand off to browser

## Implementation Plan

### Phase 1 - Kitchen fetch and cache

Deliverables:

- GitHub workflow content fetch endpoint
- disk-backed cache strategy
- content metadata

Done when:

- Counter or browser can request a single workflow file by repo and path

### Phase 2 - TUI viewer

Deliverables:

- modal source viewer
- scrolling
- line targeting and line highlight

Done when:

- a vuln can open directly to its workflow source inside Counter

### Phase 3 - Browser viewer

Deliverables:

- Kitchen-served workflow source page or panel
- syntax highlighting
- line anchors

Done when:

- graph-side workflow inspection does not require leaving SmokedMeat

## Open Questions

- Should Counter cache rendered source locally, or only cache raw content?
- Do we want a generic repo file viewer immediately, or keep the first slice workflow-only?
- Should browser display read only from Kitchen cache, or allow cache miss fetch on demand?

## Done Criteria

This task is in good shape when:

- operators can view a workflow source file on demand from Counter
- workflow content is cached instead of fetched repeatedly
- vulnerable lines can be highlighted directly from a finding
- the same backend fetch path can later support a full web UI
