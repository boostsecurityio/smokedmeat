# Server-Side Deploy Preflight

## Why This Exists

SmokedMeat already has some delivery gating, but the current behavior is still too heuristic:

- `internal/counter/tui/tokeninfo.go` enables issue and comment flows for any fine-grained PAT, even though GitHub does not expose a simple repo-scoped granted-permission map for those tokens
- dispatch is the only delivery path with a real backend preflight today, via `getWorkflowByFileName(...)` in `internal/kitchen/github.go`
- app installation tokens and recovered `GITHUB_TOKEN` permissions are strong signals, but manually entered and pivoted PATs still fall back to coarse guesses

That creates two bad operator outcomes:

- false confidence, where the wizard suggests a path that will fail at deploy time
- false pessimism, where the wizard warns even though the path is actually workable

The beta feedback surfaced both sides of that problem. The next step should not be another TUI-only heuristic pass. The next step should be a real Kitchen-owned preflight model with a clear UX for `pass`, `fail`, and `unknown`.

## Current Product Facts

What exists today:

- Counter opens the exploit wizard immediately and uses local token heuristics to label methods
- Kitchen already owns the actual GitHub delivery operations
- dispatch already has backend preflight:
  - `internal/kitchen/github.go`
  - `handleGitHubDeployDispatch()`
  - `getWorkflowByFileName(...)`
- token info today comes from `GET /user` plus token-prefix detection:
  - `internal/kitchen/github.go`
  - `fetchTokenInfoRawDefault(...)`
- that token-info path returns:
  - token type
  - owner
  - classic PAT scopes, when GitHub exposes them
- that token-info path does not return repo-specific fine-grained PAT grants

Implication:

- a repo-scoped delivery decision cannot be made correctly from the current token-info path alone

## Calibration Run

A read-only probe was run against a throwaway GitHub org, `poutineville`, with:

- `3` tokens
  - classic PAT with `repo` and `workflow`
  - fine-grained PAT with repo access and issues-focused permissions
  - fine-grained PAT with broader repo delivery permissions
- `5` repos
  - `full-delivery-public`
  - `full-delivery-private`
  - `no-fork-private`
  - `no-pr-public`
  - `no-issues-public`

The probe used:

- REST `GET /repos/{owner}/{repo}`
- REST workflow metadata fetch
- GraphQL repository metadata
- GraphQL issue existence
- GraphQL pull-request existence
- GraphQL `viewerPermission`

### Reliable Signals

These signals matched the real repo settings and behaved consistently across token types:

- REST repo metadata:
  - `allow_forking`
  - `has_issues`
  - `has_pull_requests`
- GraphQL repository flags:
  - `hasIssuesEnabled`
  - `hasPullRequestsEnabled`
- REST workflow metadata fetch as an `actions:read` discriminator
- GraphQL issue existence
- GraphQL pull-request existence, when the target number is correct

### Misleading Signals

These signals were not trustworthy for repo-scoped PAT capability inference:

- REST `permissions.push`
- GraphQL `viewerPermission`

Observed behavior from the calibration run:

- `permissions.push` stayed `true` for all tested token and repo combinations
- `viewerPermission` stayed `WRITE` for all tested token and repo combinations
- this included a fine-grained issues-focused PAT on private repos where workflow metadata fetch returned `403`

Conclusion:

- both fields reflect repo role or viewer context well enough to be tempting
- neither field can be treated as proof that the current PAT can create a PR, write contents, or otherwise use a delivery path

### Timing

Average request times from the calibration run:

- token probe: `191.7 ms`
- REST repo metadata: `288.9 ms`
- REST workflow metadata: `219.3 ms`
- GraphQL repo metadata: `286.5 ms`
- GraphQL issue existence: `258.9 ms`
- GraphQL PR existence: `301.3 ms`
- GraphQL viewer probe: `292.3 ms`

Implication:

- a naive sequential preflight would add roughly `1.3s` to `1.7s` before the wizard becomes useful
- Kitchen preflight must run its sub-checks in parallel
- Counter must never block wizard open on preflight completion

### Calibration Caveat

The calibration run also showed that the configured PR number `#1` did not resolve in repos where a PR was expected. That is a test-data issue, not a signal-quality issue, and it should be corrected before final PR-target acceptance testing.

## Decision

Implement a Kitchen-owned hybrid preflight layer with three result states:

- `pass`
- `fail`
- `unknown`

Do not use side-effecting mutation probes as part of preflight.

Do not use `permissions.push` or `viewerPermission` as capability proof.

Do treat successful real deployments as stronger evidence than preflight.

## Why This Design

### Option A - Keep TUI Heuristics

Pros:

- easy to ship quickly
- no new Kitchen API

Cons:

- repeats the current problem
- drifts from backend behavior
- cannot use repo-state signals such as `allow_forking`, `has_pull_requests`, or workflow visibility as the source of truth
- would have to reimplement the same logic for the graph or any future API consumers

Decision:

- reject

### Option B - Side-Effect-Free Server-Side Preflight

Pros:

- keeps delivery truth close to the actual deploy code
- can use real repo-state metadata
- can batch and cache work in Kitchen
- can return `unknown` honestly where GitHub does not expose enough information

Cons:

- still cannot prove every fine-grained PAT write capability
- needs new API and UX state

Decision:

- choose

### Option C - Write-Probe The Repo

Pros:

- strongest proof when it works

Cons:

- creates real artifacts or partial side effects
- hard to guarantee cleanup
- risky on customer repos
- not acceptable as background wizard behavior

Decision:

- reject

## Scope Split

### Setup-Time Global Checks

Run once during initial setup, or when the active token changes:

- token valid
- token owner
- token type
- classic PAT scopes, when present
- GitHub App permission map, when present
- recovered `GITHUB_TOKEN` permission map, when present
- accessible repos list, if already needed by the setup flow

These checks are token-global and should be cached independently from repo-specific preflight.

### Wizard-Time Repo Checks

Run when the wizard opens or when the capability key changes:

- repo accessible
- `has_issues`
- `has_pull_requests`
- `allow_forking`
- workflow file exists, when relevant
- issue exists, when relevant
- PR exists, when relevant

These checks are repo-specific and belong to Kitchen preflight.

## Hybrid Signal Model

Kitchen preflight should use:

- REST for:
  - repo metadata
  - `allow_forking`
  - `has_issues`
  - `has_pull_requests`
  - workflow metadata fetch
- GraphQL for:
  - `hasIssuesEnabled`
  - `hasPullRequestsEnabled`
  - issue existence
  - PR existence

Use the REST and GraphQL repo flags as consistency checks where both are available.

Do not treat either source as a complete granted-permission map for fine-grained PATs.

## Capability Model

Preflight and observed evidence should resolve against capability keys, not just delivery methods.

Suggested capability keys:

- `issue.create`
- `comment.issue`
- `comment.pr`
- `pr.create`
- `lotp.pr`
- `dispatch.workflow:<workflow_file>`

This separation matters because:

- `comment.issue` is not the same capability as `comment.pr`
- `pr.create` is not the same capability as `dispatch.workflow:foo.yml`
- one success should only confirm the exact capability bucket that actually worked

## Evidence Model

Kitchen should track two evidence layers:

- `preflight`
  - `pass | fail | unknown`
- `observed`
  - `confirmed | denied`

Effective wizard state should resolve in this order:

1. `observed.confirmed`
2. `observed.denied`
3. `preflight`

### Observed Success Promotion

Once a real deployment succeeds without returning `401`, `403`, or `404`, Kitchen should promote that capability key to hard confirmation for that token and repo.

Examples:

- successful issue creation confirms `issue.create`
- successful comment on an existing issue confirms `comment.issue`
- successful comment on an existing PR confirms `comment.pr`
- successful PR creation confirms `pr.create`
- successful LOTP PR confirms `lotp.pr`
- successful dispatch confirms `dispatch.workflow:<workflow_file>`

`404` should not confirm anything.

`401` and `403` should record `observed.denied` for the attempted capability, subject to a narrow key match.

This promotion rule is especially important for fine-grained PATs. Those tokens will often remain `unknown` under safe preflight, but a successful real deployment is much better evidence than any read-only probe.

## Kitchen API Shape

Add a dedicated endpoint:

- `POST /github/deploy/preflight`

Suggested request fields:

- `token`
- `owner`
- `repo`
- `workflow_file`, optional
- `delivery_method`
- `comment_target`, optional
- `issue_number`, optional
- `pr_number`, optional
- `lotp_tool`, optional

Suggested response shape:

- `cache_hit`
- `cache_age`
- `token_fingerprint`
- `capability_key`
- `effective`
  - `pass | fail | unknown | confirmed | denied`
- `checks`
  - repo access
  - issues enabled
  - PRs enabled
  - forking allowed
  - workflow visible
  - issue exists
  - PR exists
  - known token permission source
- `reason`
- `details`

Kitchen should own the cache and the evidence merge, not Counter.

## Cache Design

The user preference here is to avoid frequent rechecking. Use a long-lived cache by default.

Recommended first slice:

- TTL: `1 hour`
- no background refresh churn
- no automatic revalidation while a fresh cache entry exists
- explicit refresh only when:
  - the cache key changes
  - the operator asks to revalidate

Cache key fields:

- token fingerprint
- repo
- workflow file, when relevant
- capability key
- issue number, when relevant
- PR number, when relevant

Keep the first slice in memory inside Kitchen.

Do not persist these capability caches to the Pantry DB in the first implementation. The evidence is highly operational, short-lived, and token-derived. Kitchen memory plus a `1 hour` TTL is sufficient for the first slice.

## Counter UX

Counter should remain responsive:

- opening the wizard should be immediate
- `Copy` and `Manual` should remain available immediately
- preflight should start asynchronously
- the wizard should show a visible validation state

Suggested UX states:

- `Validating target...`
- `Validated`
- `Blocked`
- `Unconfirmed`
- `Confirmed by prior success`

Suggested behavior:

- show cached results instantly when present
- do not freeze focus or input while waiting
- if a capability is `unknown`, keep the path selectable but label it honestly
- if a capability is `fail` or `denied`, disable it with a precise reason
- allow a manual refresh action

The wizard should not collapse all comment modes into one undifferentiated state. It needs separate handling for:

- comment on issue
- comment on existing PR
- create stub PR and comment

## Interaction With Existing Deploy Handlers

Existing Kitchen deploy handlers should remain the final authority:

- preflight does not replace deploy-time checks
- deploy-time errors still need human-friendly parsing in Counter
- dispatch should reuse its existing workflow preflight internally

Deploy handlers should feed observed evidence back into the Kitchen cache:

- success confirms the capability key
- `401` or `403` deny the capability key
- `404` remains ambiguous unless the failing check is repo existence itself

## What To Do With The Current Unstaged TUI Diff

Revert it.

Reason:

- the current diff is still a heuristic patch in Counter
- it changes fine-grained PAT delivery assumptions before Kitchen becomes the source of truth
- it introduces comment-target logic that is directionally useful, but still local and incomplete
- carrying it forward would make the branch look half-implemented and increase the risk of keeping the wrong logic after the Kitchen work lands

The useful parts of that diff are design input, not a durable intermediate state.

The path-specific reactive error messages can be reintroduced later as fallback UX after Kitchen preflight exists.

## Acceptance Testing

### Unit And Integration

Add automated coverage for:

- Kitchen preflight classification
- cache hits and expiry
- observed success promotion
- observed denial handling
- Counter wizard async validation state
- comment-target separation
- dispatch workflow-specific capability keys

### Real GitHub Acceptance Matrix

Use the throwaway org setup from calibration:

- tokens
  - classic PAT
  - fine-grained PAT with issues-focused permissions
  - fine-grained PAT with broader delivery permissions
- repos
  - full delivery public
  - full delivery private
  - private repo with forking disabled
  - repo with PRs disabled
  - repo with issues disabled

Acceptance expectations:

- repo flags should block impossible paths deterministically
- private workflow visibility should distinguish issues-focused and full fine-grained PATs
- fine-grained PATs should surface `unknown` instead of false `pass` where GitHub does not expose enough proof
- a successful real deployment should upgrade future wizard opens to `confirmed`
- a `401` or `403` should upgrade future wizard opens to `denied`

Before PR-target acceptance, fix the repo test data so the configured PR numbers actually exist.

## Implementation Order

1. Add Kitchen preflight types, cache, and capability keys.
2. Add `POST /github/deploy/preflight`.
3. Implement parallel REST and GraphQL checks inside Kitchen.
4. Wire dispatch into the shared preflight model instead of its current one-off behavior.
5. Update Counter to request preflight asynchronously on wizard open and on key changes.
6. Update deploy success and failure paths to feed observed evidence into Kitchen.
7. Reintroduce only the reactive fallback UX that still adds value after server-side preflight exists.
8. Run the real GitHub acceptance matrix.

## Done Criteria

This task is in good shape when:

- Kitchen, not Counter heuristics, is the source of truth for repo-scoped delivery validation
- Counter opens the wizard immediately and never blocks on validation
- the wizard can distinguish `pass`, `fail`, `unknown`, `confirmed`, and `denied`
- `permissions.push` and `viewerPermission` are not used as capability proof
- successful real deployments promote capabilities to hard confirmation
- the same behavior applies to manually entered and pivoted tokens
- the throwaway GitHub acceptance matrix passes with the expected outcomes
