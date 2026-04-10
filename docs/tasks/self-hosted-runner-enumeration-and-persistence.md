# Self-Hosted Runner Enumeration And Persistence

## Why This Exists

For non-ephemeral self-hosted runner compromise, an existing vulnerable workflow is not the main prerequisite. The important fact is that a repository may allow an attacker-controlled pull request to add or modify a workflow that uses `on: pull_request` and references a self-hosted runner label in `runs-on`.

If that workflow can run on a reusable self-hosted runner, the first run is still valuable even without secrets:

- the job is still attacker-controlled code execution
- the runner may already have wider host access, cloud IAM, or local residue from other jobs
- if the runner is non-ephemeral, a foothold can survive until a later trusted run brings stronger credentials

For plain `pull_request` from a fork, GitHub's normal security model means the first run should be assumed to have no Actions secrets. The value is the runner itself, its ambient access, and the chance to persist or dwell until a later trusted run lands on the same infrastructure.

That makes self-hosted runner enumeration a Recon problem first, not merely an extension of poutine vulnerability analysis.

SmokedMeat should still use poutine findings as useful evidence, but the product should not require an existing workflow bug before it can reason about self-hosted runner attack surface.

## Threat Model Correction

The relevant question is not only:

- "does an existing workflow already hand us command injection?"

The more important questions are:

- does this repo have access to any self-hosted runners?
- can an attacker-controlled PR reference those runners?
- are org-level runners restricted to selected repos?
- does fork PR policy require maintainer approval before the workflow runs?
- is the runner ephemeral, reusable, or still unknown?

This means the product needs to support cases where:

- there is no existing exploitable workflow finding
- the only initial path is adding a new workflow in a PR
- the first run yields no secrets
- the value comes from persistence or from the runner's ambient privileges

## Current Product Facts

Relevant facts in the repo today:

- `internal/poutine/analyzer.go` already records whether a workflow or job is self-hosted by looking for `self-hosted` in `runs-on`
- `internal/pantry/assets.go` treats `pr_runs_on_self_hosted` as analyze-only
- the Counter exploit wizard is still vulnerability-driven and assumes a finding such as `injection` or `untrusted_checkout_exec`
- the tree and graph already model repo, workflow, job, vuln, agent, token, and cloud nodes, but there is no first-class self-hosted runner target node yet
- post-foothold recon already captures runner facts through `models.RunnerInfo`, including `SelfHosted`, host, workspace, temp dir, and related environment details

Implication:

- SmokedMeat can already confirm self-hosted runner use when it is present in existing workflows
- SmokedMeat cannot yet enumerate self-hosted runner attack surface at repo scope when that surface is not already represented as a vuln
- SmokedMeat cannot yet answer "what self-hosted runner opportunities exist for this repo?" as a first-class Recon question

## Product Goal

Add an optional, repo-scoped self-hosted runner enumeration capability that:

- identifies self-hosted runner targets that a repo can likely reference
- distinguishes repo-level runners from org-level runners
- records whether repo eligibility is known, blocked, or unknown
- records whether fork PR execution is likely allowed, blocked, or unknown
- records whether runner ephemerality is known, inferred, or unknown
- persists the result into Pantry so the tree and graph can display it
- allows the operator to launch a dedicated exploit or validation wizard from the resulting node

This should work even when poutine found no immediate exploitable workflow finding.

## Non-Goals

This task is not:

- a default step in every `analyze org` or `analyze repo`
- a promise that low-privilege tokens can always enumerate runner inventory
- a stealth-first Runner-On-Runner implementation
- a guarantee that ephemerality can always be determined before first execution
- the immediate implementation of long-lived foothold primitives such as `RUNNER_TRACKING_ID=0`

The first job is to make self-hosted runner attack surface visible and operator-actionable.

Observed self-hosted usage found during baseline analysis is still in scope to surface automatically as a weak repo signal or node. What is not in scope as a default step is the heavier repo-scoped enumeration and active validation flow.

## Core Decisions

### 1. Treat self-hosted runner enumeration as orthogonal to poutine

Poutine remains useful for:

- confirming that an existing workflow already uses self-hosted runners
- ranking observed workflows and jobs
- highlighting cases where the current workflow already contains attacker-controlled execution

But poutine should not be the source of truth for whether a repo is a self-hosted persistence candidate.

A repo may be interesting even when:

- no current workflow uses self-hosted runners in a dangerous way
- the attack path is "submit PR that adds a workflow"

### 2. Make enumeration explicit, not default

This should not run automatically during the initial lightweight analysis because:

- it needs extra API calls and pagination
- useful endpoints often require elevated permissions
- the most decisive fallback may be an active PR-based probe, which is noisier

Initial operator entry points should be:

- REPL command: `enumerate-self-hosted-runners repo:org/repo`
- repo-node shortcut: `E`

### 3. Model runner targets separately from confirmed hosts

Before foothold, SmokedMeat often knows only:

- runner labels
- repo eligibility
- org versus repo scope
- observed usage in workflows

That is not the same thing as knowing the exact machine that will execute the job.

The data model should therefore represent a repo-scoped self-hosted runner target first. Only after a foothold should SmokedMeat attach confirmed host facts from Brisket recon.

### 4. Keep unknown as a first-class result

Low-privilege API access will frequently be insufficient.

The product must support:

- `allowed`
- `blocked`
- `unknown`

for repo eligibility, fork PR execution, and ephemerality.

The goal is not to pretend certainty where GitHub does not expose enough data.

### 5. Reserve active validation for operator-driven escalation

When passive evidence is incomplete, the operator should be able to escalate to an active validation step:

- create a draft PR from a fork
- add a benign probe workflow that references a candidate self-hosted runner target
- watch whether the workflow is blocked, queued, approved, or actually scheduled

This is noisier than passive enumeration and should be opt-in.

## Evidence Model

### Tier A - Passive, low-privilege evidence

These signals are often available with normal repo read access:

- existing workflow YAML references self-hosted labels in `runs-on`
- poutine findings such as `pr_runs_on_self_hosted`
- workflow/job metadata already derived during `analyze`
- authenticated web-session Actions usage metrics for a repo, when available
- repo visibility and general PR/fork surface

Important GitHub web-only signal:

- GitHub's Actions usage metrics expose a `runner type` dimension, including self-hosted usage
- repository-level metrics are documented as viewable to users with the base repository role
- in practice, authenticated browser access on some public repos can expose a useful web-only signal even without collaborator access, for example:
  - `/actions/metrics/usage?...&tab=jobs&filters=runner_type:self-hosted`
- this can provide 100% confirmation that the repository used self-hosted runners during the selected time window
- in observed cases, the Jobs view may expose concrete self-hosted label combinations that are stronger than static workflow analysis alone
- this is not a documented REST API surface and should be modeled separately from API-based evidence

Value:

- cheap
- available during normal analysis
- useful for ranking and triage
- stronger than static workflow inspection when the metrics view confirms real historical self-hosted usage

Limits:

- does not prove repo eligibility for org-level runners
- does not prove fork PR approval policy
- does not prove ephemerality
- does not guarantee that the same runner labels are still usable today
- does not prove that a new PR-added workflow will actually land on the intended runner

### Tier B - Passive, elevated API evidence

When the operator has stronger GitHub permissions, Kitchen should gather authoritative facts.

Relevant GitHub REST surfaces include:

- repo self-hosted runner inventory
- org self-hosted runner inventory
- org self-hosted runner policy
- org selected-repo allowlist for self-hosted runners
- repo and org fork PR contributor approval policy

Important facts from the GitHub docs:

- repo runner inventory exists at `GET /repos/{owner}/{repo}/actions/runners`
- org runner inventory exists at `GET /orgs/{org}/actions/runners`, and the response includes runner labels and an `ephemeral` field
- org self-hosted runner policy exists at `GET /orgs/{org}/actions/permissions/self-hosted-runners`
- when org self-hosted runners are restricted to selected repos, GitHub exposes the allowed repo list at `GET /orgs/{org}/actions/permissions/self-hosted-runners/repositories`
- fork PR contributor approval policy is exposed at:
  - `GET /orgs/{org}/actions/permissions/fork-pr-contributor-approval`
  - `GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`
- these runner and policy endpoints require elevated organization or repository administration-style read permissions, so attacker-grade tokens often will not have them

Observed `poutineville` results:

- org owner Classic PAT could read:
  - repo Actions permissions
  - org runner inventory
  - org self-hosted runner policy
  - org fork PR contributor approval policy
- collaborator Classic PAT with normal repo access could read the repo itself but got:
  - `404` on repo admin-style Actions endpoints
  - `403` on org runner and policy endpoints
- collaborator fine-grained PATs got `403`, and `X-Accepted-GitHub-Permissions` made the required permissions explicit:
  - `administration=read` for repo runner and policy endpoints
  - `organization_self_hosted_runners=read` for org runner inventory
  - `organization_administration=read` for org policy endpoints
- a non-owner member fine-grained PAT that appeared to include the relevant admin-read permissions still received `403`
- in practice, these endpoints should be treated as authoritative only when SmokedMeat holds a truly admin-grade principal token
- a recovered Classic PAT from an org owner or real admin remains a high-value lucky path and should be tried opportunistically

Value:

- strongest pre-exploit evidence when available
- can directly expose `ephemeral` for enumerated runners
- can directly expose whether org runners are open to all repos or only selected repos

Limits:

- often unavailable to the tokens SmokedMeat will actually hold
- collaborator-grade tokens may return `404` or `403` on these endpoints even when the repo and org are otherwise visible
- may still not fully answer whether a specific PR-added workflow will run without approval on the first try

### Tier C - Active validation

When passive evidence is still incomplete, SmokedMeat should support an explicit probe:

- create a draft PR from a fork
- add or modify a workflow with `on: pull_request`
- reference one candidate runner label set in `runs-on`
- observe the result

Useful outcomes:

- workflow never appears
- workflow appears but waits for approval
- workflow is rejected by policy
- workflow queues on self-hosted
- workflow actually runs

Value:

- answers the practical question the operator really cares about
- can validate repo eligibility and fork PR gating even without admin APIs

Limits:

- noisy
- creates a real PR and workflow attempt
- still may not prove long-term persistence until after first foothold

### Tier D - Post-foothold verification

After code execution lands, Brisket can collect stronger evidence:

- actual runner hostname and environment
- whether the job ran on self-hosted infrastructure
- filesystem layout and runner installation artifacts
- service configuration or long-lived runner traces
- sentinel checks for later reuse

This is where SmokedMeat can move from "candidate" to "confirmed reusable foothold".

## Proposed Data Model

Introduce a new repo-level asset concept for self-hosted runner targets.

Suggested asset shape:

- type: `self_hosted_runner_target`
- scope: `repo` | `org`
- source:
  - `workflow_observed`
  - `repo_runner_api`
  - `org_runner_api`
  - `active_probe`
  - `post_foothold`
- labels: the label set or label family we believe is relevant
- repo_eligibility:
  - `allowed`
  - `blocked`
  - `unknown`
- fork_pr_execution:
  - `allowed`
  - `blocked`
  - `unknown`
- ephemerality:
  - `persistent_likely`
  - `ephemeral_likely`
  - `unknown`
- existing_usage: whether current workflows already reference this target
- evidence: ordered evidence items with timestamp and source

This should not claim a specific machine unless we actually know the machine.

## Product Flow

### 1. Baseline analysis remains lightweight

`analyze org` and `analyze repo` keep doing what they already do:

- import workflow, job, and vuln information
- surface observed self-hosted usage where it already exists

If baseline analysis already shows self-hosted usage, SmokedMeat can create a weaker repo-level self-hosted signal or node immediately. Explicit enumeration is the step that should enrich that signal into a repo-scoped target with policy, eligibility, and validation state.

This remains valuable, but it is not the whole self-hosted story.

### 2. Enumeration becomes an explicit recon action

When the operator selects a repo:

- `enumerate-self-hosted-runners repo:org/repo`
- or press `E` on the repo node

Kitchen then performs:

- passive local evidence gathering
- elevated API checks when the token allows them
- target-node creation and Pantry persistence

### 3. Tree and graph gain repo-level self-hosted target nodes

Under a repo, SmokedMeat should display one or more nodes such as:

- `[SH-RUNNER] org/linux-x64`
- `[SH-RUNNER] repo/gpu`
- `[SH-RUNNER] unknown-label-set`

These should be visually distinct from workflow and vuln nodes because they represent attack surface, not already-proven workflow bugs.

### 4. Press `x` on a self-hosted runner target node

This should open a dedicated runner-target exploit flow rather than reusing the current vuln-centric wizard unchanged.

Initial operator choices should include:

- passive details only
- active PR probe
- callback-bearing PR
- persistence-oriented follow-up after foothold

This is a better fit than forcing the operator through a fake vuln abstraction.

### 5. Successful footholds enrich the same target node

After a callback lands, SmokedMeat should attach:

- actual runner facts from Brisket recon
- whether the target was really self-hosted
- stronger ephemerality evidence
- later persistence validation results

That keeps the recon and exploit views tied to the same repo-level target.

## What Poutine Should Still Do

Poutine should continue to provide useful corroboration:

- existing workflows that already use self-hosted runners
- jobs whose current code paths already give attacker-controlled execution
- signals that help rank which repos or workflows deserve enumeration first

Useful future enrichment may include:

- better extraction of `runs-on` labels into workflow or job metadata
- a clearer analyze-only signal for "repo already runs attacker-reachable workflows on self-hosted"

But none of that should block repo-scoped enumeration.

## Why This Should Not Be Default During Analyze

Pros of explicit enumeration:

- keeps initial analysis fast
- avoids surprising API failures for low-privilege tokens
- avoids PR-based validation noise unless the operator asks for it
- works cleanly for both TUI and future web UI flows

Cons:

- self-hosted opportunity is not fully surfaced until the operator asks

This tradeoff is acceptable because the action is heavier, more permission-sensitive, and sometimes intentionally noisy.

## Proposed Implementation Phases

### Phase 1 - Define the new runner-target asset and Kitchen API

Deliverables:

- Kitchen endpoint for repo-scoped self-hosted runner enumeration
- Pantry asset shape for repo-level self-hosted runner targets
- evidence schema and tri-state fields

Done when:

- Kitchen can return a structured enumeration response without touching Counter yet

### Phase 2 - Passive enumeration and persistence into Pantry

Deliverables:

- reuse current workflow metadata and poutine findings as supporting evidence
- create repo-level self-hosted target nodes in Pantry
- rebuild tree/graph from that data

Done when:

- a repo with observed self-hosted usage shows a durable `[SH-RUNNER]` node even before any exploit
- explicit enumeration can enrich that node with stronger repo eligibility and policy evidence

### Phase 3 - Elevated GitHub API enrichment

Deliverables:

- add org/repo runner inventory lookups when token permissions allow
- add org self-hosted runner policy lookup
- add selected-repo allowlist lookup
- add fork PR contributor approval policy lookup

Done when:

- enumeration can produce authoritative `allowed`, `blocked`, or `unknown` decisions whenever the token has the necessary GitHub permissions

### Phase 4 - Counter repo-node UX

Deliverables:

- repo-node shortcut `E`
- repo-target enumeration status messaging
- `[SH-RUNNER]` repo subnodes in the tree and graph

Done when:

- the operator can discover and review runner targets from Recon without a synthetic vuln

### Phase 5 - Active probe flow

Deliverables:

- draft PR probe mode
- benign workflow template for candidate label validation
- workflow status observation and result ingestion

Done when:

- the operator can answer "will this repo actually schedule my fork PR workflow on that runner target?" without leaving SmokedMeat

### Phase 6 - Exploit and persistence follow-up

Deliverables:

- runner-target-specific `x:exploit` flow
- callback-bearing PR template
- post-foothold runner validation
- persistence viability update on the target node

Done when:

- a validated self-hosted runner target can graduate from recon candidate to exploit target and then to confirmed reusable foothold

## Acceptance Matrix

Minimum matrix before implementation should be considered solid:

- repo-level self-hosted runner only
- org-level self-hosted runner open to all repos
- org-level self-hosted runner restricted to selected repos
- repo where low-privilege token cannot read any admin runner settings
- repo where collaborator Classic PAT gets only repo visibility and `404` on admin-style Actions endpoints
- repo where collaborator fine-grained PAT gets explicit `403` plus accepted-permission headers
- repo where recovered org-owner or admin-grade token makes the same endpoints authoritative
- repo where fork PR contributor approval is required
- repo where fork PR workflow runs immediately
- non-ephemeral runner surfaced by API
- ephemeral runner surfaced by API
- unknown ephemerality until foothold
- repo with existing self-hosted workflow usage
- repo with no existing self-hosted workflow usage, but where a PR-added workflow can still target a runner

This matrix is more important than adding another Rego rule.

## Open Questions

- Do we need a new Pantry asset type, or can the first slice use a repo-level synthetic workflow-like node before we settle the permanent model?
- Should the first active probe always open a draft PR, or should we also support a local patch preview before the PR is created?
- How much of the active probe should be automated versus requiring explicit operator confirmation at each step?
- Do we want the first exploit flow to be Linux-only once we move from enumeration to persistence?
- Should runner-target nodes appear only after explicit enumeration, or should lightweight observed self-hosted usage from poutine create a weaker version automatically?
- When admin APIs are unavailable, do we want to cache "unknown" aggressively, or re-check on each explicit enumeration request?

## Done Criteria

This task is in good shape when:

- SmokedMeat can enumerate self-hosted runner targets for a selected repo without requiring a pre-existing vuln
- the tree and graph can show repo-level `[SH-RUNNER]` nodes
- Kitchen clearly separates passive evidence, elevated API evidence, active probe results, and post-foothold verification
- repo eligibility, fork PR execution, and ephemerality are all modeled as `allowed`, `blocked`, or `unknown`
- poutine remains a corroborating signal rather than the gate for this feature
- the operator can press `x` on a self-hosted runner target and start an appropriate validation or exploit flow
