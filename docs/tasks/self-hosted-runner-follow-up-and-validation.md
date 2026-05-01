# Self-Hosted Runner Follow-Up And Validation

## Why This Exists

The current self-hosted runner slice is now useful:

- observed self-hosted runner targets show up in Recon
- the operator can push or copy a callback workflow
- a resident foothold can survive and later be re-attached

That is enough for the NorthSec path, but it is not the full self-hosted runner feature.

The remaining gap is not "make the callback work better." The remaining gap is "help the operator answer the real pre-exploit question with stronger evidence and cleaner next steps."

That real question is still:

- can this repo actually reach a useful self-hosted runner
- will an attacker-controlled PR be allowed to run there
- is the runner reusable enough that persistence matters
- if the answer is still uncertain, what is the least noisy validation path

## Current Product Facts

After phase 1:

- SmokedMeat can surface observed self-hosted usage as a repo target
- the operator can open a dedicated runner-target flow from Counter
- the operator can push a workflow directly or copy one for manual use
- resident runner footholds can now persist, survive Counter restarts, and survive Kitchen refresh

What is still missing:

- explicit self-hosted enumeration entry points at repo scope
- richer evidence than "a workflow once used self-hosted"
- active validation for ambiguous repos and runner labels
- clearer persistence and validation lifecycle states in Counter
- a stronger separation between "observed target," "validated target," and "confirmed reusable foothold"

## Product Goal

Turn the current operator-usable phase 1 slice into a more authoritative self-hosted runner feature.

The operator should be able to:

- ask the repo-scoped self-hosted question directly
- see what evidence supports or weakens the target
- distinguish passive evidence from active validation
- understand whether a target is likely blocked, likely allowed, or still unknown
- move from weak signal to validation without losing history or context

## Non-Goals

This follow-up is not:

- a rewrite of the shipped resident foothold path
- a promise that low-privilege tokens can always enumerate runner policy
- a requirement that every repo be probed automatically
- a stealth-first covert validation system
- the interactive shell or richer Brisket post-exploit work

## Product Direction

### 1. Explicit repo-scoped enumeration entry points

Self-hosted runner enumeration should become a first-class operator action, not just a side effect of general analysis.

Initial entry points should be:

- REPL command: `enumerate-self-hosted-runners repo:org/repo`
- repo-node shortcut: `E`
- rerun or refresh action from an existing self-hosted runner target

This flow should write results into Pantry as self-hosted target evidence, not as a fake vulnerability.

### 2. Stronger evidence tiers

The product should keep evidence sources separate instead of flattening them into one boolean answer.

Useful evidence buckets:

- static workflow evidence
- historical usage evidence
- elevated API evidence
- active probe evidence

Static workflow evidence includes:

- `runs-on` references to `self-hosted`
- label combinations
- repeated workflow or job usage patterns

Historical usage evidence includes:

- prior analysis observations
- any persisted target history already known to Kitchen

Elevated API evidence includes:

- repo runner inventory when available
- org runner inventory and labels when available
- org-level selected-repo policy when available
- fork PR approval policy when available
- ephemeral versus reusable status when exposed

Evidence should preserve source and certainty. Unknown should remain a first-class result.

### 3. Active validation as an operator escalation path

When passive evidence is not enough, SmokedMeat should support an explicit validation step.

The likely shape is still:

- create a draft PR
- add a benign workflow referencing one candidate label set
- observe whether the workflow is blocked, awaiting approval, queued, or scheduled

The important design rule is that this should be framed as a deliberate escalation, not as background analysis.

The operator should see:

- what will be changed
- why the probe is needed
- what outcomes will be interpreted
- how the result will update the target state

### 4. Richer target and foothold lifecycle states

The current model is usable, but it is still too coarse for the whole self-hosted runner story.

The target model should distinguish states such as:

- observed
- enumerated
- eligible
- blocked
- approval-required
- queued
- validated
- express-hit
- resident-pending
- resident-live
- resident-lost
- unknown

This does not need to become a sprawling state machine in the first follow-up slice. It does need to stop collapsing different situations into one vague target row.

### 5. Cleaner operator presentation

Counter should make the evidence and next action obvious.

The target details view should answer:

- what labels were observed
- whether the target appears repo-scoped or org-scoped
- whether policy is known or inferred
- which evidence came from passive analysis
- which evidence came from elevated APIs
- whether an active probe has already been attempted
- what the recommended next action is

### 6. Persist evidence separately from exploit outcomes

Enumeration evidence should survive independently of callbacks and agents.

This helps avoid losing the higher-level conclusion when:

- the first validation run fails
- a resident foothold goes offline
- the operator restarts Counter
- different repos reuse the same runner labels

## Open Design Questions

- how much weight should historical observed usage carry compared to current policy reads
- whether GitHub web-only usage signals should be stored as a distinct evidence class
- how far to go on enterprise-level runners before the rest of the repo model is ready
- whether the first active probe should be workflow-push, draft PR, or both depending on permissions
- how to summarize selected-repo org policy without over-claiming certainty

## Acceptance Checks

- The operator can trigger repo-scoped self-hosted enumeration explicitly.
- Counter shows evidence source and certainty instead of a flat yes or no.
- Unknown remains a valid visible outcome.
- An operator-driven validation step exists for ambiguous cases.
- Validation outcomes feed back into the target state and survive restarts.
- The operator can distinguish observed targets from validated and resident ones.

## Done Criteria

This follow-up is in good shape when:

- self-hosted runner targeting feels like a real Recon workflow, not a demo-only side path
- the operator can understand why a target is interesting or uncertain
- the product has an explicit bridge from passive evidence to active validation
- the state model is clear enough that later QoL features can build on it cleanly
