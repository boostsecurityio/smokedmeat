# Analysis Progress And Streaming

## Why This Exists

The recent `poutine v1.1.2` upgrade improves analysis performance significantly, but large-organization scans can still run for a long time.

When that happens, the current operator experience is weak:

- `analyze` can feel idle until a large result blob arrives
- `deep-analyze` adds gitleaks-based scanning with little operator-visible progress
- the product does not yet stream partial findings or intermediate progress in a way the operator can act on

This task exists to make long-running analysis observable and, where possible, incrementally useful.

## Current Product Facts

Relevant facts in the repo today:

- `internal/poutine/analyzer.go` sets `config.Quiet = true`
- `internal/poutine/analyzer.go` currently calls:
  - `analyzer.AnalyzeOrg(ctx, target, &numWorkers)`
  - `analyzer.AnalyzeRepo(ctx, target, "HEAD")`
- `AnalyzeRemote` currently returns only after the full `AnalysisResult` is assembled
- `internal/kitchen/analyze.go` runs `poutine.AnalyzeRemote(...)` as one blocking step
- `internal/kitchen/analyze.go` then optionally runs `runGitleaksScan(...)`
- `runGitleaksScan(...)` currently loops repos one by one and appends findings only after each repo scan completes
- `internal/gitleaks/scanner.go` embeds gitleaks v8 directly as a library

Implication:

- poutine results are currently consumed in one final batch
- deep-analyze adds more latency after the poutine phase
- the operator does not get meaningful progress for large scans

## Product Goal

Give the operator a trustworthy sense of forward movement during large scans, and improve the backend shape so partial progress can eventually be surfaced incrementally.

The product should support:

- progress during org-level poutine analysis
- progress during deep secret scanning
- bounded partial updates where feasible
- clear indication of which phase is running:
  - repo discovery
- workflow analysis
- secret scanning
- final import

## Upstream Blocker

True repo-complete progress for poutine analysis is currently blocked on the public `poutine` API shape.

Validated against `poutine v1.1.2`:

- the CLI progress you see today comes from internal `progressbar` rendering in `analyze/analyze.go`
- that progress is presentation on stderr, not structured data
- SmokedMeat disables it with `Config.Quiet = true`
- the high-level API still returns only final results

So before SmokedMeat can implement clean repo-complete progress, an upstream change is needed.

### Required upstream change

Poutine needs one narrow structured progress surface on top of `AnalyzeOrg(...)`, and ideally `AnalyzeRepo(...)`, without breaking the current batch API.

The smallest acceptable shape would be one of:

- an optional callback interface
- an optional observer or handler
- an optional channel-based progress sink

### What SmokedMeat needs from that change

At minimum:

- org analysis started
- total repo count when known
- repo analysis started with repo identifier
- repo analysis completed with repo identifier
- optional non-fatal repo error notification

Nice to have, but not required for the first SmokedMeat slice:

- partial finding counts
- package-complete callback carrying the scanned package
- repo-discovery progress separate from repo-analysis progress

### Acceptance criteria for upstream

The upstream change is sufficient when:

- existing CLI behavior still works without code changes to callers that do not opt in
- SmokedMeat can receive structured repo-complete progress without parsing stderr
- the high-level `AnalyzeOrg(...)` path still returns the final aggregate result
- the callback or observer is optional and nil-safe
- SmokedMeat does not need to fork or reimplement the main `AnalyzeOrg(...)` loop just to get progress

## Non-Goals

This task is not:

- a promise that every finding will stream in real time immediately
- a forced fork of poutine or gitleaks on day one
- a switch to a different secret-scanning engine right now

The first slice is visibility and backend readiness.

## Core Problems

### 1. Poutine library consumption is batch-oriented

Validated against `poutine v1.1.2`:

- `analyze.Analyzer.AnalyzeOrg(...)` returns `[]*models.PackageInsights` only after the full org scan completes
- `analyze.Analyzer.AnalyzeRepo(...)` returns only after the full repo scan completes
- the only built-in progress surface is an internal `progressbar` in `analyze/analyze.go`
- that progress is controlled by `Config.Quiet`
- there is no public callback, channel, or observer interface for:
  - repo completion
  - partial package results
  - streaming findings

This means SmokedMeat cannot get repo-complete progress from the current high-level poutine API without either:

- implementing only coarse phase progress on the SmokedMeat side, or
- requesting a small upstream API change

Important nuance:

- poutine's lower-level `ScmClient.GetOrgRepos(ctx, org) <-chan RepoBatch` is public
- repo batches include `TotalCount` on the first batch and then paginated repository slices

So coarse repo-discovery progress is possible today if SmokedMeat chooses to own that phase more explicitly. What is not possible cleanly today is progress tied to actual analysis completion per repo without reimplementing `AnalyzeOrg(...)` internals or getting an upstream callback hook.

### 2. Deep-analyze adds another silent phase

The current gitleaks integration scans one repo at a time after poutine completes. This can be slow on larger orgs and currently has no operator-visible progress beyond final results and logs.

### 3. Progress must be honest

Fake percentages are worse than explicit phase progress.

The UI should prefer:

- current phase
- repo counts completed versus total
- current repo being scanned
- partial counts of findings and secret findings

over made-up progress bars.

## Proposed Direction

### 1. Start with coarse progress that reflects the real phases

Even before upstream changes, Counter should be able to show:

- discovering repos
- analyzing workflows
- scanning secrets
- importing results

Validated scope with `poutine v1.1.2`:

- repo-discovery counts can be surfaced without upstream changes if SmokedMeat uses the lower-level SCM batch API
- analysis-complete counts cannot be surfaced cleanly from the current high-level poutine API
- phase-only progress is therefore achievable immediately, while repo-complete progress still needs either an upstream hook or local reimplementation

### 2. Push for repo-level or package-level progress from poutine

Desired upstream capability from poutine:

- callback or channel for repo completion
- callback or channel for partial findings
- enough metadata to show repo name and running totals

Validated conclusion from `v1.1.2`:

- the current public high-level API cannot do this cleanly
- the narrowest upstream change would be a repo-complete callback, package callback, or observer interface on `AnalyzeOrg(...)`
- that is preferable to copying large parts of poutine's analysis loop into SmokedMeat

### 3. Improve deep-analyze progress independently

Even if poutine stays batch-oriented for a while, the gitleaks phase can still expose useful progress:

- repo `n / total`
- current repo
- secret findings accumulated so far

This does not require waiting for poutine API changes.

### 4. Keep scanner replacement as a separate decision

SmokedMeat currently embeds gitleaks directly. That is acceptable for now.

`betterleaks` should be tracked as a future evaluation target only after:

- its API shape stabilizes
- its output format and rule compatibility are understood
- migration cost is worth the benefits

Progress visibility should not wait on a scanner migration.

## Desired Backend Shape

Kitchen should eventually be able to emit analysis progress events shaped roughly like:

- phase
- target
- current repo
- repos completed
- repos total if known
- findings accumulated
- secret findings accumulated
- warnings or non-fatal errors

Counter can then:

- show phase progress in TUI
- append progress history
- later share the same events with a web UI

## Upstream poutine Change Request

If needed, the change request to poutine should stay narrow.

Ideal additions:

- repo-complete callback
- package result callback
- optional streaming mode that preserves the existing batch API

The goal is not to redesign poutine. The goal is to expose enough progress and partial-result structure for large-org UX.

## Betterleaks Watch Item

SmokedMeat should track `betterleaks` as a future replacement candidate for the current embedded gitleaks library, but not switch yet.

Questions to answer before any migration:

- library API stability
- output compatibility
- rule and ignore-file compatibility
- maintenance posture
- performance improvement in SmokedMeat's actual usage pattern

Until then, the current gitleaks embedding remains the supported engine.

## Implementation Plan

### Phase 1 - Add honest phase progress in Kitchen and Counter

Deliverables:

- visible progress states for:
  - poutine analysis running
  - gitleaks scan running
  - import running
- current repo and repo counts where known

Done when:

- large scans no longer look idle

### Phase 2 - Improve deep-analyze progress

Deliverables:

- repo-by-repo gitleaks progress events
- partial secret-finding counts

Done when:

- deep-analyze gives the operator useful forward movement without waiting for the final aggregate result

### Phase 3 - Request the smallest useful upstream poutine hook

Deliverables:

- written gap analysis of `poutine v1.1.2`
- narrow upstream change request for repo-complete or package-complete progress

Done when:

- the team has confirmed which parts can ship with the existing API and which part needs upstream support

### Phase 4 - Optional partial-result import

Deliverables:

- incremental import design for repos or packages
- clear UI semantics for partial findings

Done when:

- the product can surface early results safely without confusing the operator

## Open Questions

- Should Counter display partial findings as they arrive, or keep progress-only first?
- Should SmokedMeat use poutine's lower-level SCM batching for repo-discovery progress before any upstream hook lands?
- Should deep-analyze scan only repos with findings, or eventually support broader repo selection with the same progress model?
- When `betterleaks` stabilizes, do we want a clean engine abstraction first or a direct swap?

## Done Criteria

This task is in good shape when:

- long-running analysis has visible and honest progress
- deep-analyze shows repo-by-repo movement
- the team has confirmed that `poutine v1.1.2` needs a small upstream API enhancement for repo-complete progress
- a future scanner migration remains optional and separate from progress work
