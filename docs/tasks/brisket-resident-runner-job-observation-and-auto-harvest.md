# Brisket Resident Runner Job Observation And Auto-Harvest

## Why This Exists

The current resident self-hosted runner foothold is useful, but still too passive.

Today, once Brisket is resident on a reusable runner, the operator can:

- re-attach later
- run `order exec ...`
- run `gump`
- inspect the box manually

What is still missing is the next obvious post-exploit QoL step:

- notice when a later workflow job lands on the same runner
- run an express-like harvest automatically for that new job
- attach the resulting loot to the correct workflow or job context when possible

This matters because the real value of a reusable runner foothold often arrives after the initial attacker-controlled run. The later trusted job is the moment that may bring better credentials, better repository access, or more valuable local residue.

## Current Product Facts

Today:

- Brisket can survive as a resident foothold on a reusable self-hosted runner
- Brisket already has useful one-shot post-exploit primitives such as `order exec` and `gump`
- the original express path already knows how to collect rich runner and job-adjacent data during the seeded job
- Loot and callback metadata are built around the job that originally launched the foothold, not around later jobs seen from the side

Upstream GitHub runner behavior also gives useful clues:

- the self-hosted runner application is a long-lived listener that creates a session and waits for jobs, then prints `Listening for Jobs` when ready
- when a job is dispatched, the listener logs `Running job: {JobDisplayName}`
- the listener hands work to `Runner.Worker`
- GitHub documents that runner application logs live in `_diag` as `Runner_*` files and per-job execution logs live there as `Worker_*` files
- GitHub documents that customized services must still invoke the runner through `runsvc.sh`
- the stock `run.sh` wrapper keeps the listener alive across retryable exits by relaunching the helper loop

Implication:

- new job arrival should be locally observable from a resident foothold
- the harder problem is not detecting "a job started"
- the harder problem is extracting enough stable metadata to attach loot to the right repo, workflow, and job without over-claiming certainty

## Product Goal

Add an optional resident observation mode for self-hosted runner footholds.

When enabled, Brisket should:

- detect that a new workflow job has started on the same runner
- gather a bounded express-like harvest for that job
- send the results back through Kitchen
- preserve the best available job metadata and confidence level with the loot

The operator should not need to sit on `order exec ps` waiting for the next trusted job.

## Non-Goals

This follow-up is not:

- a replacement for the existing express path
- a stealth-perfect implant research project
- a guarantee of exact repo or workflow attribution for every job on day one
- a requirement to auto-harvest on every resident foothold by default
- the interactive PTY shell work

## Hard Constraints

- do not destabilize the runner or visibly break the job
- keep host-side overhead bounded while idle
- avoid duplicate harvest of the same job
- tolerate listener restarts and normal runner service behavior
- prefer Linux-first implementation if the first slice needs to narrow platform scope

## Product Direction

### 1. Detect job boundaries locally

The first implementation question is which local signal is stable enough to treat as "new job started."

Candidate signal families:

- `Runner.Worker` process creation under the runner listener
- new `Worker_*` files in the runner `_diag` directory
- `Runner_*` log lines such as `Running job: {JobDisplayName}`
- workspace and temp-directory changes under the runner work root

The first slice should explicitly rank these by reliability after real VM study, not by aesthetic preference.

### 2. Separate job detection from job attribution

These are different problems and should not be collapsed.

Problem one:

- did a new job start

Problem two:

- which repo, workflow, job, run, or attempt does it belong to

The feature should preserve confidence levels such as:

- strong attribution
- partial attribution
- weak attribution
- unknown attribution

Weak but honest metadata is better than incorrectly attaching secrets to the wrong repo or workflow.

### 3. Define a bounded harvest profile

The auto-harvest should be smaller and safer than "do everything express does every time."

Good first-slice candidates:

- capture high-value GitHub and runner environment variables
- collect runner identity and workspace deltas
- run `gump` or a narrowed secret scan at job start or shortly after
- optionally inspect job-adjacent files that are known to exist locally

Possible higher-cost actions such as broad memdump should remain opt-in or delayed until the detection and attribution model is proven.

### 4. Record later-job loot as a new event type

This should not masquerade as the original callback firing again.

Kitchen should preserve a separate event shape for:

- resident job observed
- resident job harvested
- resident job harvest failed

Loot should carry:

- resident foothold identity
- observed time
- best available repo or workflow metadata
- attribution confidence
- harvest profile used

### 5. Make the operator-facing state visible

Counter should surface whether a resident foothold is merely live or is also watching for later jobs.

Useful UI elements:

- watch mode enabled or disabled
- last observed job time
- last successful harvest time
- attribution confidence for the last harvest
- warnings when the foothold is alive but no stable runner signal source is available

### 6. Research track before implementation

This feature needs a short static-plus-dynamic study before code lands.

Static questions:

- what stable artifacts does `actions/runner` create when a job starts
- where are the least noisy metadata handoff points between `Runner.Listener` and `Runner.Worker`
- which Linux service and wrapper behaviors are part of the supported runner path

Dynamic questions:

- what changes can Brisket observe reliably on a real reusable runner VM
- which environment variables, files, or process arguments reveal repo and workflow identity
- how do retry, rerun, matrix, container, and service-container jobs differ
- how much latency is acceptable before harvest loses value

## Upstream Notes

Useful upstream references for this work:

- GitHub docs on self-hosted runner communication, ephemerality, and routing: <https://docs.github.com/actions/reference/runners/self-hosted-runners>
- GitHub docs on runner log locations and `_diag` `Runner_*` / `Worker_*` files: <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/monitoring-and-troubleshooting-self-hosted-runners>
- GitHub docs on service invocation through `runsvc.sh`: <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/configuring-the-self-hosted-runner-application-as-a-service?platform=linux>
- `actions/runner` listener startup and `Listening for Jobs`: <https://github.com/actions/runner/blob/main/src/Runner.Listener/Runner.cs>
- `actions/runner` job dispatch and `Running job: {JobDisplayName}` plus `Runner.Worker`: <https://github.com/actions/runner/blob/main/src/Runner.Listener/JobDispatcher.cs>
- `actions/runner` helper-loop restart behavior in `run.sh` and `run-helper.sh.template`: <https://github.com/actions/runner/blob/main/src/Misc/layoutroot/run.sh> and <https://github.com/actions/runner/blob/main/src/Misc/layoutroot/run-helper.sh.template>

## Open Design Questions

- what is the best stable local source for repo and workflow attribution on Linux runners
- whether `Worker_*` logs arrive early enough to drive useful harvest timing
- whether auto-harvest should trigger once at job start, once near completion, or both
- how to avoid duplicate harvest on reruns and retry storms
- how much of this should be Linux-first before macOS and Windows get real support

## Acceptance Checks

- A resident foothold can optionally watch for later jobs on the same runner.
- Brisket detects a later job without operator polling.
- A bounded harvest is performed automatically when that job starts.
- Kitchen stores the resulting event and loot as a distinct resident-job harvest record.
- Counter shows that a later job was observed and how strong the attribution is.
- The feature remains honest when metadata is partial or unknown.

## Done Criteria

This task is in good shape when:

- a reusable self-hosted runner foothold can capitalize on later jobs without manual timing
- the harvest path is useful without being noisy or fragile
- later-job loot is attached to honest metadata instead of guessed labels
- the resulting model is strong enough to support future operator UX and richer post-exploit automation
