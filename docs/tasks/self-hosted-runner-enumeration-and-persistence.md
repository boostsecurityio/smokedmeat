# Self-Hosted Runner Enumeration And Persistence

## Summary

This task adds first-class repo-scoped self-hosted runner targets and two related operator flows:

1. existing vulnerable workflow on a self-hosted runner -> exploit it with the current wizard, with an optional persistence attempt
2. no vulnerable workflow required -> explicitly enumerate runner targets for a repo, then launch a probe PR or callback PR against a selected target

SmokedMeat should not pretend that "self-hosted runner" is just another vuln. Poutine remains useful evidence and ranking input, but it is not the source of truth for self-hosted runner attack surface.

The strongest path is still the quietest one. If a repo already exposes attacker-controlled execution on a reusable self-hosted runner, SmokedMeat should steer the operator toward that path first, then let them opt into persistence from the existing wizard. The noisy "drop a workflow in a fork PR" path is a separate repo-scoped recon and validation flow, not the default recommendation.

This rewrite intentionally freezes the UX contract before implementation. The task is large enough that poor UI choices will create more rework than the backend plumbing.

## Why This Exists

For non-ephemeral self-hosted runner compromise, an existing vulnerable workflow is not the main prerequisite. A repository may allow an attacker-controlled pull request to add or modify a workflow that uses `on: pull_request` and references a self-hosted runner label in `runs-on`.

If that workflow can run on a reusable self-hosted runner, the first run is still valuable even without secrets:

- the job is still attacker-controlled code execution
- the runner may already have wider host access, cloud IAM, or local residue from other jobs
- if the runner is non-ephemeral, a foothold can survive until a later trusted run brings stronger credentials

For plain `pull_request` from a fork, GitHub's normal security model means the first run should be assumed to have no Actions secrets. The value is the runner itself, its ambient access, and the chance to persist or dwell until a later trusted run lands on the same infrastructure.

At the same time, the "fork, add a workflow, open a PR" path only works if several repo and org settings line up. It may also require maintainer approval or a human merge decision that SmokedMeat cannot automate. The product should detect and present that context, not pretend that all self-hosted runner opportunities are equally deployable.

## Product Goals

Add an operator-usable self-hosted runner feature set that:

- identifies repo-scoped self-hosted runner targets that a repo can likely reference
- distinguishes repo-level runner targets from org-level runner targets
- records whether repo eligibility is allowed, blocked, or unknown
- records whether fork PR execution is allowed, approval-gated, blocked, or unknown
- records whether runner ephemerality is known, inferred, or unknown
- persists the result into Pantry so the tree and graph can display it
- lets the operator act on a first-class `[SH-RUNNER]` node without faking a vuln
- lets the operator exploit an existing self-hosted vuln path with an optional persistence attempt
- tracks persistence as a post-job survival question, not just "did I get one callback"

## Non-Goals

This task is not:

- a default step in every `analyze org` or `analyze repo`
- a promise that low-privilege tokens can always enumerate runner inventory
- a promise that SmokedMeat can automate maintainer approval or a typo-fix PR merge
- a stealth-first runner-on-runner framework
- the immediate exposure of low-level persistence primitives in the operator UX
- a license for Brisket to run forever after the callback path is dead
- a requirement to ship multi-target fanout in the first useful slice

The first job is to make self-hosted runner attack surface visible and operator-actionable, while keeping the UX honest about what is automated and what is not.

## Design Principles

### 1. Treat self-hosted runner enumeration as orthogonal to poutine

Poutine remains useful for:

- confirming that an existing workflow already uses self-hosted runners
- ranking observed workflows and jobs
- highlighting cases where the current workflow already contains attacker-controlled execution

But poutine should not be the source of truth for whether a repo is a self-hosted persistence candidate.

A repo may be interesting even when:

- no current workflow uses self-hosted runners in a dangerous way
- the only initial path is "submit a PR that adds a workflow"

### 2. Prefer the strongest operator path first

If a repo already contains a vuln-backed self-hosted workflow path, that path is usually better than generating a new PR that drops a new workflow file. It is quieter, closer to the existing product model, and often easier to explain in a demo.

SmokedMeat should therefore:

- surface that better path
- let the operator stay in the existing vuln wizard
- add persistence as an optional extension of the current wizard

The runner-target flow exists because self-hosted runner opportunity is broader than current workflow bugs, not because the PR path should replace the vuln path.

### 3. Make enumeration explicit, not default

This should not run automatically during the initial lightweight analysis because:

- it needs extra API calls and pagination
- useful endpoints often require elevated permissions
- the most decisive fallback may be an active PR-based probe, which is noisier

Initial operator entry points should be:

- REPL command: `enumerate-self-hosted-runners repo:org/repo`
- repo-node shortcut: `E`

### 4. Model runner targets separately from confirmed hosts

Before foothold, SmokedMeat often knows only:

- runner labels
- repo eligibility
- org versus repo scope
- observed usage in workflows

That is not the same thing as knowing the exact machine that will execute the job.

The product should therefore represent a repo-scoped self-hosted runner target first. Only after a foothold should SmokedMeat attach confirmed host facts from Brisket recon.

### 5. Keep unknown as a first-class result

Low-privilege API access will frequently be insufficient.

SmokedMeat must support real uncertainty. It should not collapse "unknown" into "blocked" or "allowed" just because the API did not answer.

### 6. Distinguish dwell from persistence

These are related but different:

- `Dwell` means "keep the session alive during the current job so the operator can interact with it"
- `Persistence` means "attempt to survive job cleanup and prove it with a later signal"

The UX must not overload one concept into the other.

### 7. Reuse existing Counter surfaces

This work should fit the current Counter shape:

- left attack tree
- right menu, status, and loot panels
- modal wizard overlays
- Waiting view
- Post-Exploit view
- persistent implant inventory

Do not add a brand-new permanent pane just for self-hosted runners. The new work should feel native to the current product.

### 8. Keep persistent lifecycle bounded

Brisket should be resilient to transient callback failure, but it should not run forever if the Kitchen endpoint is gone. A reused quickstart tunnel is the motivating example, not the only one.

The rule is simple:

- retry with bounded exponential backoff and jitter
- stop after a finite retry budget or max wall clock
- exit if the callback path appears dead

## Operator Mental Model

The product should use the following concepts consistently:

- `Observed self-hosted usage`
  - Weak signal from baseline analysis. Useful for ranking, not enough to claim deployability.
- `[SH-RUNNER] target`
  - Repo-scoped attack surface candidate. Not a machine and not a vuln.
- `Probe`
  - A benign PR workflow used to answer "will this repo actually schedule a fork PR workflow on this runner target?"
- `Callback PR`
  - A PR workflow intended to achieve code execution on a selected runner target.
- `Dwell`
  - Stay live during the current job.
- `Persistence attempt`
  - Try to survive job cleanup and report back later.
- `Confirmed reusable foothold`
  - A runner target that has emitted a post-job survival signal after the original workflow should have ended.

## Current Product Facts

Relevant facts in the repo today:

- `internal/poutine/analyzer.go` already records whether a workflow or job is self-hosted by looking for `self-hosted` in `runs-on`
- `internal/pantry/assets.go` currently treats `pr_runs_on_self_hosted` as analyze-only
- the Counter exploit wizard is vulnerability-driven and assumes a finding such as `injection` or `untrusted_checkout_exec`
- `x` in the tree currently requires a `[VULN]` node
- the current wizard Step 3 already supports optional toggles such as dwell, callback budget, draft, auto-close, and cache poisoning
- the tree and graph already model repo, workflow, job, vuln, agent, token, and cloud nodes, but there is no first-class self-hosted runner target node yet
- post-foothold recon already captures runner facts through `models.RunnerInfo`, including `SelfHosted`, host, workspace, temp dir, and related environment details
- Counter already has a persistent implant inventory and callback lifecycle controls

Implication:

- SmokedMeat can already confirm self-hosted runner use when it is present in existing workflows
- SmokedMeat cannot yet enumerate self-hosted runner attack surface at repo scope when that surface is not already represented as a vuln
- SmokedMeat cannot yet answer "what self-hosted runner opportunities exist for this repo?" as a first-class recon question
- SmokedMeat already has most of the UX primitives needed for persistence, but not the runner-target model that ties them together

## UX Contract

### Keep The Current Layout

The self-hosted work should stay inside the current terminal layout. The screenshots linked in the task conversation are the visual reference: left attack tree, right panel(s), bottom activity log and input, modal wizard overlays.

This task should add:

- a new repo action on the tree
- a new node type in the tree and graph
- a dedicated runner-target wizard
- a new optional row in the existing vuln wizard
- persistence status in Post-Exploit and the implants modal

This task should not add:

- a new full-screen self-hosted runner mode
- a separate permanent "runner pane"
- a second exploit wizard that visually ignores the current product language

### Commands And Shortcuts

The new surface area should stay intentionally small:

- `enumerate-self-hosted-runners repo:org/repo`
  - Explicit repo-scoped enumeration action.
- `E` on a `[REPO]` node
  - Shortcut for the same enumeration action.
- `x` on an actionable node
  - `[VULN]` -> existing payload wizard
  - `[SH-RUNNER]` -> runner-target wizard
- `p` inside Step 3 of the existing vuln wizard
  - Toggle persistence attempt when the selected vuln is tied to a self-hosted runner context.

The existing `s` behavior should continue to work so the operator can still set the current target from a selected repo node.

### Tree And Graph

Under a repo, SmokedMeat should display one or more nodes such as:

- `[SH-RUNNER] org/linux-x64`
- `[SH-RUNNER] repo/gpu`
- `[SH-RUNNER] unknown-label-set`

These nodes are visually distinct from workflows and vulns because they represent attack surface, not already-proven workflow bugs.

The tree behavior should be:

- baseline `analyze` may create a weak observed self-hosted node when current workflows already show self-hosted usage
- explicit enumeration enriches the same node or creates stronger runner-target nodes
- selecting a runner-target node should show useful inline context in the tree pane
- `x` should act on it
- the graph should render runner-target nodes as first-class nodes, not as synthetic vulnerabilities

Each runner-target node should summarize:

- scope: repo or org
- label set
- whether current workflows already use it
- repo eligibility
- fork PR execution status
- ephemerality
- evidence quality
- preferred operator path when known

### Existing VULN Path On Self-Hosted Runners

If an existing exploitable workflow path lands on a self-hosted runner, the operator should stay in the current vuln wizard. Do not force them into the runner-target wizard just because the underlying runner is self-hosted.

The existing wizard should gain one new optional Step 3 row when the vuln's workflow or job is known or strongly inferred to be self-hosted:

- `Persistence: Off / Attempt [p]`

Behavior:

- default is `Off`
- turning it on does not expose low-level primitive names
- turning it on means:
  - Brisket should collect runner facts as usual
  - Brisket should attempt the persistence primitive internally if the environment looks suitable
  - Counter should expect a secondary post-job survival signal

The wizard should also surface the runner context clearly, for example:

- `Runner: self-hosted observed in workflow`
- `Runner: self-hosted likely via [SH-RUNNER] org/linux-x64`

This keeps the better stealth path inside the current operator muscle memory.

### Dedicated SH-RUNNER Path

`[SH-RUNNER]` nodes should open a separate runner-target wizard. This is not the vuln wizard with renamed labels. The operator is acting on a repo-scoped target, not on a code injection finding.

The runner-target wizard should be structured as:

1. Target summary
2. Action choice
3. Action-specific configuration

The action choices should be:

- `Passive details`
  - Review the evidence, unknowns, recommended path, and exact label set.
- `Benign probe PR`
  - Create a draft PR with a minimal workflow whose only purpose is to answer scheduling, policy, and approval questions.
- `Callback PR`
  - Create a draft PR with a workflow intended to gain code execution on the selected runner target.

If the selected runner target already has a better existing vuln-backed path, the wizard should say so clearly and recommend it. The runner-target flow still exists, but it should not pretend it is the quietest option when it is not.

### Probe PR Versus Callback PR

The product needs both.

`Benign probe PR` answers:

- will the workflow appear at all
- is approval required
- is scheduling blocked
- does the target label set look usable

`Callback PR` answers:

- can I get code execution on this runner target
- can I keep a session live
- can I attempt persistence

Both flows should:

- default to a single selected label set
- default to draft PRs
- optionally auto-close when the operator chooses that behavior

### Multi-Target Fanout

Multi-target fanout is useful, but it should not be the default.

The operator idea is valid: one generated workflow could create multiple jobs that each target a different label set, and some subset may callback. That is useful for broad runner hunting, but it adds noise, workflow complexity, and result-attribution complexity.

Decision for this task:

- do not make fanout the default
- do not block the feature on fanout
- design the data model so fanout can be added later without rewriting the runner-target contract

If fanout lands later, it should be an explicit advanced option inside the runner-target callback PR flow.

### Waiting, Post-Exploit, And Implants

The operator should not get stuck in Waiting for the whole persistence lifecycle.

Expected flow:

1. first callback lands
2. Counter transitions as usual
   - interactive -> Post-Exploit
   - express-only -> existing express behavior
3. if persistence was armed, Counter keeps tracking a secondary post-job survival signal in the background

When persistence is armed, Post-Exploit should show a visible banner such as:

- `Persistence armed - waiting for post-job survival signal`

The implants inventory should also show this callback as something stronger than a generic persistent callback:

- `survival_pending`
- `survived_post_job`
- `gave_up`

The key rule is that "one callback happened" is not enough to mark a reusable self-hosted foothold as confirmed persistence.

## ASCII Mockups

These mockups are intentionally simple and ASCII-only, but they follow the current Counter layout from the screenshots: left attack tree, right status/menu panels, bottom activity and command bar, and modal overlays.

### Recon After Explicit Enumeration

```text
+--------------------------------------------------------------------------------------------------+
| SmokedMeat Counter                                              Phase:Recon           connected   |
|                                                                                                  |
| whooli [ORG]                                                 The Menu                             |
|   infrastructure-definitions [PRIVATE REPO]                                                      |
|     .github/workflows/deploy.yml [WORKFLOW]                                                     |
|       deploy [JOB]                                                                               |
|     > [SH-RUNNER] org/linux-x64                                                                  |
|         labels: self-hosted, linux, x64                                                          |
|         existing usage: deploy.yml                                                               |
|         repo eligible: unknown   fork PR: approval_required   ephemerality: unknown             |
|     [SH-RUNNER] repo/gpu                                                                         |
|         labels: self-hosted, gpu                                                                 |
|         existing usage: none                                                                     |
|                                                                                                  |
|                                                                  [1] Act on org/linux-x64        |
|                                                                  [2] Act on repo/gpu             |
|                                                                  [3] Run deep-analyze            |
|                                                                                                  |
| Activity                                                                                         |
| 16:34:20  self-hosted enumeration completed for whooli/infrastructure-definitions                |
| 16:34:20  2 runner targets persisted to Pantry                                                   |
| > enumerate-self-hosted-runners repo:whooli/infrastructure-definitions                           |
|                                                                                                  |
| Status: E:enumerate  x:act  s:target  d:deep  g:graph  Esc:cycle  /:jump                        |
+--------------------------------------------------------------------------------------------------+
```

### Runner-Target Wizard

```text
+-----------------------------------------------------------------------------------------------+
| RUNNER TARGET WIZARD                                                                  Step 2/3 |
|                                                                                               |
| [SH-RUNNER] org/linux-x64                                                                     |
| Repository:        whooli/infrastructure-definitions                                          |
| Labels:            self-hosted, linux, x64                                                    |
| Existing usage:    .github/workflows/deploy.yml                                               |
| Repo eligibility:  unknown                                                                    |
| Fork PR:           approval_required                                                          |
| Ephemerality:      unknown                                                                    |
|                                                                                               |
| Action:                                                                                        |
|   [1] Passive details                                                                         |
|   [2] Benign probe PR                                                                         |
|   [3] Callback PR                                                                             |
|                                                                                               |
| Recommended: Existing self-hosted vuln path found in deploy.yml -> prefer that for stealth.   |
|                                                                                               |
| Enter:continue  Esc:cancel                                                                    |
+-----------------------------------------------------------------------------------------------+
```

### Existing VULN Wizard With Persistence Option

```text
+-----------------------------------------------------------------------------------------------+
| PAYLOAD WIZARD                                                                         Step 3/3 |
|                                                                                               |
| Bash injection (comment)                                                                      |
| Repository:      whooli/xyz                                                                   |
| Workflow:        .github/workflows/whooli-analyzer.yml                                        |
| Runner:          self-hosted likely via [SH-RUNNER] org/linux-x64                             |
|                                                                                               |
| Mode:            Dwell 5m [d]                                                                 |
| Callbacks:       2 callbacks [b]                                                              |
| Persistence:     Attempt post-job survival [p]                                                |
| Auto-close:      Yes [a]                                                                      |
|                                                                                               |
| Result:                                                                                       |
| - first callback enters Post-Exploit as usual                                                 |
| - Counter keeps waiting for a secondary post-job survival signal                              |
|                                                                                               |
| Enter:deploy  Esc:back                                                                        |
+-----------------------------------------------------------------------------------------------+
```

### Post-Exploit With Persistence Armed

```text
+--------------------------------------------------------------------------------------------------+
| SmokedMeat Counter                                       Phase:Post-Exploit                      |
|                                                                                                  |
| [ persistence armed - waiting for post-job survival signal for org/linux-x64 ]                  |
|                                                                                                  |
| infrastructure-definitions [PRIVATE REPO]                         Agent Status                   |
|   .github/workflows/deploy.yml -> deploy                           runner-01  SELF-HOSTED       |
|                                                                    live session: 04:12          |
|                                                                    persistence: survival_pending|
|                                                                    last callback: agt_ab12cd34  |
|                                                                                                  |
| The Menu                                                                                         |
|   [1] recon                                                                                      |
|   [2] env                                                                                        |
|   [3] pivot gcp                                                                                  |
|                                                                                                  |
| Implants                                                                                         |
|   cb_7f3a2c  org/linux-x64  survival_pending  next_mode=express                                 |
|                                                                                                  |
| Activity                                                                                         |
| 16:34:07  callback received from runner-01                                                       |
| 16:39:55  post-job survival signal received -> target promoted to confirmed foothold            |
| > order recon                                                                                    |
|                                                                                                  |
| Status: Shift+I:implants  q:quit  r:return  /:jump                                               |
+--------------------------------------------------------------------------------------------------+
```

## Data Model

Introduce a new repo-level asset concept for self-hosted runner targets.

Suggested Pantry asset:

- type: `self_hosted_runner_target`
- scope: `repo` | `org`
- properties:
  - `label_set`
    - Ordered list of runner labels.
  - `label_display`
    - Short operator-facing label such as `org/linux-x64`.
  - `visibility_model`
    - `repo_runner`
    - `org_runner_all_repos`
    - `org_runner_selected_repos`
    - `unknown`
  - `repo_eligibility`
    - `allowed`
    - `blocked`
    - `unknown`
  - `fork_pr_execution`
    - `allowed`
    - `approval_required`
    - `blocked`
    - `unknown`
  - `ephemerality`
    - `persistent_likely`
    - `ephemeral_likely`
    - `unknown`
  - `existing_usage`
    - Whether current workflows already reference this target.
  - `observed_workflow_ids`
    - Workflows and jobs that contribute evidence.
  - `preferred_entry`
    - `existing_vuln`
    - `probe_pr`
    - `callback_pr`
  - `matching_vuln_ids`
    - Existing vuln-backed paths tied to the same target, if any.
  - `target_status`
    - `observed`
    - `enumerated`
    - `validated`
    - `callback_received`
    - `survival_pending`
    - `confirmed_reusable_foothold`
    - `dead_end`
  - `evidence`
    - Ordered evidence items with source, summary, timestamp, and confidence.
  - `confirmed_runner`
    - Post-foothold facts such as host, workspace, temp dir, OS, arch.

Important rule:

- this asset should not claim a specific machine unless SmokedMeat actually has post-foothold confirmation

Relationships:

- repository -> self_hosted_runner_target
- workflow/job -> self_hosted_runner_target
  - evidence relationship, not ownership
- self_hosted_runner_target -> agent
  - only after a foothold lands

The generic Pantry `State` field can still be used, but the runner-target lifecycle should live in explicit target properties. This feature needs more nuance than the base `new / validated / exploited / high_value` states alone.

## Evidence Model

### Tier A - Passive, Low-Privilege Evidence

These signals are often available with normal repo read access:

- existing workflow YAML references self-hosted labels in `runs-on`
- poutine findings such as `pr_runs_on_self_hosted`
- workflow/job metadata already derived during `analyze`
- authenticated web-session Actions usage metrics for a repo, when available
- repo visibility and general PR/fork surface

Value:

- cheap
- available during normal analysis
- useful for ranking and triage

Limits:

- does not prove repo eligibility for org-level runners
- does not prove fork PR approval policy
- does not prove ephemerality
- does not prove that a new PR-added workflow will actually land on the intended runner

### Tier B - Passive, Elevated API Evidence

When the operator has stronger GitHub permissions, Kitchen should gather authoritative facts.

Value:

- strongest pre-exploit evidence when available
- can directly expose enumerated labels
- can directly expose whether org runners are open to all repos or only selected repos
- can directly expose fork PR approval policy

Limits:

- often unavailable to the tokens SmokedMeat will actually hold
- collaborator-grade tokens may return `404` or `403` even when the repo and org are otherwise visible
- may still not fully answer whether a specific PR-added workflow will run without approval on the first try

### Tier C - Active Validation

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

### Tier D - Post-Foothold Verification

After code execution lands, Brisket can collect stronger evidence:

- actual runner hostname and environment
- whether the job ran on self-hosted infrastructure
- filesystem layout and runner installation artifacts
- service configuration or long-lived runner traces
- survival signal after the workflow should have ended

This is where SmokedMeat can move from "candidate" to "confirmed reusable foothold".

## Counter Behavior

### Explicit Enumeration

When the operator selects a repo:

- `enumerate-self-hosted-runners repo:org/repo`
- or press `E` on the repo node

Counter should:

- show progress in the activity log
- refresh the tree and graph when enumeration completes
- surface actionable `[SH-RUNNER]` nodes immediately
- add a menu recommendation when a repo has no known runner targets yet

### `x` Means "Act On Selected Target"

`x` should stop meaning "vuln only".

Instead:

- `x` on `[VULN]` -> existing payload wizard
- `x` on `[SH-RUNNER]` -> runner-target wizard

If the selected node is neither actionable type, Counter should keep the existing helpful error behavior.

### Existing Wizard Integration

The current wizard remains the main surface for vuln-backed exploitation.

Changes:

- show self-hosted runner context when available
- add `Persistence` toggle in Step 3 when relevant
- keep the existing dwell, callback budget, draft, auto-close, and cache poison options intact

### Waiting And Post-Exploit

The current waiting flow should remain simple:

- first callback lands
- Counter transitions the same way it already does
- persistence tracking continues in the background

If persistence was requested, Post-Exploit should show:

- a banner
- a current state
- a path into the implants inventory

Counter should not require the operator to stay on the Waiting screen to learn whether the foothold survived post-job cleanup.

### Implants Inventory

Reuse the current persistent implant inventory.

Add richer labels and states so the operator can understand what a callback is for:

- callback label
- runner target label
- probe versus callback PR
- survival pending
- survived post-job
- gave up

This should remain one inventory, not a separate self-hosted runner inventory.

## Kitchen Behavior

Kitchen needs a runner-target-specific contract. The existing deploy APIs are vuln-centric and should not be forced to represent the repo-scoped runner-target flow by abuse of synthetic vuln objects.

Kitchen should provide:

- repo-scoped self-hosted runner enumeration
- persistence of runner-target assets and evidence into Pantry
- optional elevated API enrichment when the token permits it
- PR probe creation for runner-target validation
- callback PR creation for runner-target exploitation
- workflow observation and result ingestion for probes and callback PRs

The API naming can change during implementation, but the conceptual surfaces are:

- enumerate runner targets for a repo
- launch a benign probe for a selected target
- launch a callback PR for a selected target

Kitchen should also attach enough callback metadata that Counter can correlate:

- callback to runner target
- callback to repo/workflow/job
- first callback to later survival signal

## Brisket Behavior

### Keep The Primitive Internal

Low-level runner persistence primitives are implementation details. The operator should request "attempt persistence", not choose internal environment-variable tricks by name.

### First Callback Behavior

Whenever a self-hosted path is used, Brisket should still collect runner facts on the first callback:

- `SelfHosted`
- host
- workspace
- temp dir
- OS / arch
- any lightweight reusability hints that are already safe to collect

### Persistence Attempt

If persistence was not requested:

- do normal express or dwell behavior

If persistence was requested:

- attempt the persistence primitive internally when the environment looks suitable
- report that the attempt was armed
- if the process survives past job cleanup, emit a secondary post-job survival signal

That secondary signal is the important proof point. A first callback alone is not enough to mark the foothold as reusable persistence.

### Correlation Rule

Counter and Kitchen should correlate persistence by callback metadata and runner target metadata, not only by agent ID. The same agent ID may not be the only stable identity across all future implementation details.

### Retry And Exit Policy

When Brisket is trying to phone home after a workflow should have ended:

- retry with bounded exponential backoff and jitter
- stop after a finite retry budget or max wall clock
- exit cleanly if the callback path looks dead

This covers:

- quickstart tunnel disappeared
- long-lived domain exists but Kitchen is down
- transient network failure

There should be no special operator-facing "quickstart mode". The behavior should simply be sane when the endpoint is gone.

## Stacked PR Plan

This task should be delivered as a stack of small PRs that build on each other. Each PR should:

- compile cleanly and leave the product in a coherent state
- deliver visible operator value or materially improve operator understanding
- have local acceptance criteria that do not depend on the rest of the stack
- avoid broad unrelated refactors
- stay reviewable without requiring the reviewer to hold the whole final design in their head at once

Intermediate PRs are for review and stack integration only. Do not merge them to `main` one by one. The stack should be combined and accepted as a whole before the final merge to `main`.

### Stack Naming Conventions

Suggested branch pattern:

- `stack/self-hosted/<nn>-<slug>`

Suggested PR title pattern:

- `self-hosted: <short outcome>`

Suggested stack discipline:

- branch `02` is based on branch `01`
- branch `03` is based on branch `02`
- continue the same pattern through the stack
- keep each PR description explicit about what earlier stack branch it depends on

### Iteration 0 - Vision Lock

Purpose:

- freeze the product contract, operator language, and UI shape before code churn starts

Value:

- reviewers and implementers are working from one stable vision document instead of oral history

Acceptance:

- this task document is treated as the source of truth for scope, UX, and deferred items

Suggested branch:

- `stack/self-hosted/00-vision-lock`

Suggested PR title:

- `self-hosted: lock the vision document and staged delivery plan`

### Iteration 1 - Weak Runner-Target Nodes From Existing Analysis

Purpose:

- introduce `self_hosted_runner_target` as a first-class Pantry concept
- surface weak observed self-hosted usage from data SmokedMeat already has today

Value:

- self-hosted runner opportunity stops being hidden behind analyze-only findings and becomes visible in the tree and graph

Scope:

- Pantry asset type and relationships
- baseline import from existing workflow/job self-hosted observations
- tree rendering for `[SH-RUNNER]` nodes
- graph rendering for the new node type

Not in scope:

- explicit enumeration command
- `x` on runner-target nodes
- GitHub admin API enrichment
- PR creation

Review focus:

- data model shape
- whether the new node avoids false precision
- whether baseline analyze creates useful but clearly weak signals

Local acceptance:

- analyzing a repo with observed self-hosted workflow usage creates at least one `[SH-RUNNER]` node under the repo
- the node records unknown for eligibility, fork PR execution, and ephemerality unless stronger evidence exists
- the graph renders the same node type without pretending it is a vulnerability
- existing vuln flows remain unchanged

Suggested branch:

- `stack/self-hosted/01-weak-runner-target-nodes`

Suggested PR title:

- `self-hosted: add weak runner-target nodes from existing analysis`

### Iteration 2 - Explicit Enumeration Entry Points And Passive Enrichment

Purpose:

- make runner-target discovery an explicit recon action instead of a passive side effect

Value:

- the operator can ask "enumerate self-hosted runner targets for this repo" from Counter instead of relying only on baseline analysis

Scope:

- `enumerate-self-hosted-runners repo:org/repo`
- repo-node shortcut `E`
- Kitchen passive enumeration response using existing repo/workflow evidence
- activity log and status messaging
- Pantry refresh and enrichment of existing weak nodes

Not in scope:

- GitHub admin endpoints
- runner-target details wizard
- PR creation

Review focus:

- command and keybinding ergonomics
- clear operator feedback on success, failure, and unsupported selections
- enrichment behavior on repeated enumeration

Local acceptance:

- the command works for an explicit repo target
- `E` on a repo node triggers the same action
- explicit enumeration enriches existing runner-target nodes rather than duplicating them
- the operator sees start/completion or error messaging in the activity log

Suggested branch:

- `stack/self-hosted/02-explicit-enumeration-entrypoints`

Suggested PR title:

- `self-hosted: add explicit repo enumeration command and shortcut`

### Iteration 3 - Runner-Target Inspection UX

Purpose:

- make `[SH-RUNNER]` nodes inspectable and actionable in a read-only sense

Value:

- the operator can press `x` on a runner-target node and understand what SmokedMeat knows before any noisy action is taken

Scope:

- broaden `x` from "vuln only" to "act on selected actionable node"
- runner-target read-only details flow or wizard branch
- recommendation text when a better vuln-backed entry path already exists

Not in scope:

- GitHub admin enrichment
- probe PR creation
- callback PR creation

Review focus:

- whether the runner-target UX feels native to the current Counter layout
- whether `x` remains intuitive on both `[VULN]` and `[SH-RUNNER]`
- whether the recommendation language is honest and useful

Local acceptance:

- `x` on `[SH-RUNNER]` opens a dedicated runner-target details flow
- `x` on `[VULN]` still opens the current payload wizard
- runner-target details show labels, scope, existing usage, unknowns, and recommended entry path

Suggested branch:

- `stack/self-hosted/03-runner-target-inspection`

Suggested PR title:

- `self-hosted: add runner-target inspection flow in Counter`

### Iteration 4 - Elevated API Enrichment

Purpose:

- enrich runner targets with authoritative GitHub API evidence when the token permits it

Value:

- the operator can distinguish "unknown because we do not know" from "allowed or blocked because GitHub told us"

Scope:

- org and repo runner inventory lookups
- org runner policy lookup
- selected-repo allowlist lookup
- fork PR contributor approval policy lookup
- evidence attribution on runner-target nodes

Not in scope:

- PR creation
- workflow observation

Review focus:

- correct handling of `403` and `404`
- unknown versus blocked semantics
- evidence provenance

Local acceptance:

- mocked admin-grade responses enrich labels, visibility, fork PR execution, and ephemerality
- mocked `403` and `404` cases preserve `unknown` where appropriate
- the operator can tell which fields are authoritative and which remain unknown

Suggested branch:

- `stack/self-hosted/04-elevated-api-enrichment`

Suggested PR title:

- `self-hosted: enrich runner targets with admin API evidence`

### Iteration 5 - Benign Probe PR Creation

Purpose:

- let the operator launch a low-noise validation workflow against a selected runner target

Value:

- SmokedMeat can create a draft probe PR from the runner-target flow instead of forcing the operator to handcraft one

Scope:

- runner-target wizard branch for `Benign probe PR`
- single selected label set only
- draft PR creation only
- generated workflow template for validation
- PR URL and callback metadata persistence

Not in scope:

- multi-target fanout
- automated probe-result ingestion
- callback-bearing PR

Review focus:

- safety and honesty of the generated workflow
- metadata tagging for later correlation
- clear operator messaging about what the probe can and cannot answer yet

Local acceptance:

- the operator can create a draft probe PR from a selected runner target
- the returned PR URL is shown and persisted
- the workflow template is clearly probe-only and does not claim to gain execution
- only single-target mode is supported

Suggested branch:

- `stack/self-hosted/05-probe-pr-creation`

Suggested PR title:

- `self-hosted: add benign probe PR creation for runner targets`

### Iteration 6 - Probe Result Observation And Status Ingestion

Purpose:

- turn probe PRs from "created" into "usefully interpreted"

Value:

- the operator can learn whether the target was blocked, approval-gated, queued, or actually ran without leaving SmokedMeat

Scope:

- workflow observation for probe PRs
- result ingestion into runner-target evidence and status
- mapping observed outcomes to `validated`, `dead_end`, `approval_required`, or still `unknown`

Not in scope:

- callback-bearing PR
- persistence

Review focus:

- outcome mapping
- timeout behavior
- avoiding false negatives when observation is incomplete

Local acceptance:

- observed blocked, approval-gated, queued, and ran outcomes update the runner-target node correctly
- lack of evidence remains `unknown`, not `blocked`
- the latest probe result appears in the runner-target details flow

Suggested branch:

- `stack/self-hosted/06-probe-result-ingestion`

Suggested PR title:

- `self-hosted: ingest probe outcomes into runner-target status`

### Iteration 7 - Callback PR Flow For Runner Targets

Purpose:

- let the operator attempt code execution on a selected runner target without requiring an existing vuln

Value:

- the runner-target flow becomes more than read-only reconnaissance

Scope:

- runner-target wizard branch for `Callback PR`
- single selected label set only
- draft PR creation
- callback metadata that ties the resulting implant or callback back to the runner target
- reuse of the existing Waiting and Post-Exploit flows for first callback handling

Not in scope:

- persistence attempt from the runner-target wizard
- multi-target fanout

Review focus:

- workflow generation correctness
- callback correlation
- reuse of existing waiting and callback surfaces without UI drift

Local acceptance:

- the operator can create a draft callback PR from a selected runner target
- the first callback enters the existing Waiting or Post-Exploit flow correctly
- the implants inventory shows enough runner-target metadata to understand what the callback belongs to

Suggested branch:

- `stack/self-hosted/07-callback-pr-flow`

Suggested PR title:

- `self-hosted: add callback PR flow for runner targets`

### Iteration 8 - VULN-Backed Self-Hosted Persistence

Purpose:

- extend the existing vuln flow so self-hosted workflow exploitation can attempt persistence without inventing a second exploit model

Value:

- the strongest and quietest path gains the most important missing feature: post-job survival tracking

Scope:

- detect self-hosted context for the selected vuln
- show runner context in the existing wizard
- add `Persistence: Off / Attempt [p]` to Step 3 when relevant
- arm persistence attempt in Brisket without exposing low-level primitive names in the UI
- track `survival_pending`, `survived_post_job`, or `gave_up`
- show persistence status in Post-Exploit and the implants inventory
- bounded retry, backoff, and self-exit when the callback path is dead

Not in scope:

- multi-target fanout
- exposing internal persistence primitive names

Review focus:

- dwell versus persistence semantics
- first callback versus later survival signal handling
- bounded lifecycle behavior when the Kitchen endpoint disappears

Local acceptance:

- the persistence toggle appears only when the selected vuln is tied to a self-hosted runner context
- a first callback still transitions the operator normally
- if persistence was armed, Counter enters `survival_pending` and waits for a second survival signal
- a second survival signal promotes the runner target to confirmed reusable foothold
- Brisket gives up cleanly after bounded retry behavior when the callback path stays dead

Suggested branch:

- `stack/self-hosted/08-vuln-backed-persistence`

Suggested PR title:

- `self-hosted: add persistence tracking to self-hosted vuln flows`

### Final Stack Integration And Main Merge Gate

After the stacked PRs have been reviewed individually:

1. combine the full stack on an integration branch
2. run the full acceptance criteria from this task document on the combined stack
3. fix integration issues in the stack until the feature feels coherent end to end
4. merge to `main` only after the full combined feature is accepted

The final decision point is not "were the individual slices reviewable". It is "does the full stack behave like one coherent feature".

Suggested integration branch:

- `stack/self-hosted/integration`

Suggested final combined PR title:

- `self-hosted: ship runner-target recon, probe, callback, and persistence flows`

### Shared Convergence Rules

Every iteration above must converge on the same shared model:

- one runner-target asset type
- one callback correlation scheme
- one implants inventory
- one definition of confirmed reusable foothold

### Explicitly Deferred

These should not block the first useful full-stack acceptance:

- multi-target fanout in one generated workflow
- exposing low-level persistence primitives in the UI
- long-term stealth framework work beyond bounded survival attempts

## Acceptance Criteria

### Core Recon And UX

- a repo with observed self-hosted usage can show a weak `[SH-RUNNER]` node even before explicit enumeration
- explicit enumeration on a repo creates or enriches durable `[SH-RUNNER]` nodes in Pantry
- `E` on a repo node launches explicit enumeration
- `x` on `[SH-RUNNER]` opens a dedicated runner-target wizard
- `x` on `[VULN]` still opens the existing payload wizard
- The Menu can recommend self-hosted runner actions when appropriate

### Existing VULN Path

- a vuln tied to a self-hosted runner shows a persistence toggle in Step 3
- a vuln not tied to a self-hosted runner does not show the persistence toggle
- the persistence toggle does not require inventing a synthetic runner-target node just to use the current wizard

### Probe And Callback PR Flow

- the operator can choose a single runner target and launch a benign probe PR
- the operator can choose a single runner target and launch a callback PR
- the product does not claim it can automate maintainer approval or merge steps it cannot actually automate

### Post-Exploit And Persistence

- a first callback transitions the operator the same way Counter already does
- if persistence was armed, Counter continues tracking a secondary post-job survival signal
- a second survival signal promotes the runner target to confirmed reusable foothold
- the implants inventory surfaces `survival_pending`, `survived_post_job`, or equivalent statuses
- Brisket does not run forever if the callback path is dead

### Evidence And Policy Modeling

- repo eligibility is modeled explicitly
- fork PR execution is modeled explicitly, including approval-gated cases
- ephemerality can remain unknown
- the product can combine passive evidence, elevated API evidence, active probe results, and post-foothold confirmation on the same runner target

## Remaining Non-Blocking Questions

- should the runner-target wizard implement `Passive details` as a true wizard branch, or as a read-only modal opened from the selected node
- what exact workflow filename and branch naming scheme should Kitchen use for generated probe and callback PRs
- does multi-target fanout land in the first callback PR slice, or only after single-target correlation and UX are solid

## Appendix A - GitHub Evidence Notes

### GitHub Web-Only Signal

GitHub's Actions usage metrics expose a `runner type` dimension, including self-hosted usage.

In practice, authenticated browser access on some public repos can expose a useful web-only signal even without collaborator access, for example:

- `/actions/metrics/usage?...&tab=jobs&filters=runner_type:self-hosted`

This can provide strong confirmation that a repository used self-hosted runners during the selected time window. It is not a documented REST API surface and should be modeled separately from API-based evidence.

### Relevant Elevated REST Endpoints

When Kitchen has sufficiently strong permissions, useful GitHub REST surfaces include:

- `GET /repos/{owner}/{repo}/actions/runners`
- `GET /orgs/{org}/actions/runners`
- `GET /orgs/{org}/actions/permissions/self-hosted-runners`
- `GET /orgs/{org}/actions/permissions/self-hosted-runners/repositories`
- `GET /orgs/{org}/actions/permissions/fork-pr-contributor-approval`
- `GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`

### Observed Permission Reality

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

Practical conclusion:

- these endpoints should be treated as authoritative only when SmokedMeat holds a truly admin-grade principal token
- a recovered Classic PAT from an org owner or real admin remains a high-value lucky path and should be tried opportunistically
