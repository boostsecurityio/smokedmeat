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

## Dynamic Study Notes

Study date: 2026-05-01.

Environment:

- stock GitHub self-hosted runner `2.334.0`
- Linux x64 VM provisioned from the official GitHub runner flow
- repo: private test repository with a simple `workflow_dispatch` workflow
- workflow: `.github/workflows/dispatch.yml`
- default branch: non-`main`
- job: `test`

Observed baseline:

- runner root: `/home/<runner-user>/actions-runner`
- listener process: `/home/<runner-user>/actions-runner/bin/Runner.Listener run`
- listener cwd: `/home/<runner-user>/actions-runner`
- `_diag` exists under the runner root
- listener log prints `Listening for Jobs` when idle

Run timing:

- GitHub run creation and listener job-request logging were separated by only a few seconds
- listener logged `Running job: test` immediately after receiving the job request
- listener launched `/home/<runner-user>/actions-runner/bin/Runner.Worker`
- real worker process detection requires matching the executable path, not broad command-line search
- worker command followed the expected `Runner.Worker spawnclient ...` shape
- worker cwd was `/home/<runner-user>/actions-runner/bin`
- the worker process was observable only for a few seconds for this short workflow
- the fresh `Worker_*` log appeared and grew before the job finished

Signal ranking from this study:

1. Strong start signal: real `Runner.Worker` process creation, matched by executable path, not by broad `pgrep -f Runner.Worker`.
2. Strong attribution source: the fresh `Worker_*` log. It contains the job message, workflow file, repo, run ID, run number, run attempt, workflow ref, workflow SHA, check run ID, GitHub token permissions, runner environment, and `system.github.job`.
3. Useful listener source: `Runner_*` lines provide `Job request ... received`, job GUID, orchestration ID, worker PID, and `Running job: test`, but do not by themselves provide full repo or workflow attribution.
4. Weak source: `/proc/<Runner.Worker pid>/environ` exposed only `GITHUB_ACTIONS=true` in this stock run. It is not sufficient for attribution.
5. Workspace artifacts are useful after initialization but are too late and too indirect for first start detection.

Implementation implication:

- trigger auto-harvest on real worker process creation
- parse the newest `Worker_*` log for attribution as soon as it exists
- scan the worker process memory while it is alive, because the process environment alone is not enough
- fall back honestly if a worker process disappears before memory scan completes or if the worker log is missing

## Live Troubleshooting Notes

Additional live testing on 2026-05-01 exposed several practical edge cases that should shape the implementation.

Privilege behavior:

- resident Brisket may start as the runner service user, not root
- reading another process through `/proc/<pid>/mem` can fail with `permission denied` when Brisket is not privileged
- the stager should try passwordless `sudo -n -E` when installing a resident Linux foothold and the current user is not root
- if passwordless sudo is unavailable, Brisket should still run as the current user and report harvest failure honestly instead of blocking deployment
- once running as root, a diagnostic watcher could open the worker process `maps` and `mem` files during the short job window, so the remaining harvest failure was not caused by Linux permissions

Persistence behavior:

- a resident Brisket process can survive `Ctrl+C` of `./run.sh` because it is detached from the runner listener process
- after `./run.sh` is started again, the same resident watcher can observe new `Runner.Worker` processes
- this does not imply VM reboot persistence, which remains outside the first requirement
- validation must purge stale resident Brisket processes before testing a new build, otherwise old behavior can be mistaken for a fresh regression

Worker detection behavior:

- the resident watcher should seed its `seen` set with workers already present when it starts
- this prevents the watcher from treating the bootstrap job that installed the resident foothold as a new later job
- the watcher should keep polling while a harvest waits for log attribution or memory scan results
- each new worker harvest should run independently so one slow or incomplete `Worker_*` log does not block detection of another worker

Attribution behavior:

- `Worker_*` logs can exist before they contain enough repo and workflow metadata for strong attribution
- parsing the first fresh worker log too early can produce partial metadata
- Kitchen must not backfill missing resident job repo or workflow from the original stager origin
- backfilling from the stager origin incorrectly labels later jobs as the bootstrap workflow when attribution is incomplete
- Brisket should wait briefly for `Worker_*` attribution to include at least repository and workflow before sending the resident job event
- if attribution never becomes strong in the bounded window, the event should stay partial or unknown rather than using guessed labels

Memory harvest timing behavior:

- a trivial workflow can keep `Runner.Worker` alive for only a few seconds
- the worker process may be visible before the job token and step environment are present in memory
- early memory scans around process creation can return a clean but empty result even though the process is readable
- later workflow logs showed token permission output and step environment output more than one second after the worker was first visible
- resident harvest should attempt several bounded scans across the first few seconds of the worker lifetime, not just one immediate scan
- a later `no such process` error after one or more clean empty scans should not hide the useful fact that Brisket did read the worker and found no secrets
- when no scan finds data, prefer reporting `runner memory scan found no secrets` with scan counters over a misleading final `no such process` error
- the first immediate worker scan can consume most of the useful window and miss short-lived child processes
- early attempts should look for descendants first, then perform one bounded worker scan after the job has had time to hydrate its runtime state
- a very short `echo`-only job can still be too fast to harvest reliably, even with strong attribution
- a dispatchable self-hosted validation workflow with a short sleep produced a successful resident harvest after the descendant-first timing change

Operational logging:

- Kitchen should log resident job beacons with event, confidence, and memdump counters
- logs should avoid repo, workflow, host, or operator-specific identifiers unless those are already part of explicit operator-facing history
- useful memdump counters include attempted, pid, count, regions, bytes, read errors, scan attempts, process targets, and error string
- these counters made it clear whether the failure was permission, process lifetime, or timing

Validation workflow:

- manual validation was too tedious when it required rebuilding Kitchen, purging stale residents, deploying a new resident, triggering dispatch, then collecting logs by hand
- a temporary local driver now performs that loop end to end against the live test VM and repository
- the driver intentionally stays outside the repo and must not be committed
- the driver must register callbacks against the same quickstart Kitchen that the public tunnel reaches
- using the e2e Kitchen URL with the quickstart tunnel produced a valid local callback registration but a public `401` when the runner fetched the stager
- the driver should trigger workflow dispatch using the workflow file name that Kitchen expects, not a full `.github/workflows/...` path
- Docker build cache can hide embedded Brisket changes during this debugging flow, so the validation driver forces a no-cache Kitchen build
- the validation workflow should include `workflow_dispatch` plus a bounded sleep step so the resident harvester can be evaluated without racing a near-instant command

## Current Implementation Decisions

The first implementation should use the following simple model:

- resident Linux footholds start a lightweight watcher only in resident mode
- the watcher polls for real `Runner.Worker` executables at a short interval
- workers already present at watcher startup are ignored
- each newly observed worker starts an independent bounded harvest
- early memory scan attempts prefer worker descendants and defer the worker scan briefly
- the worker scan runs once inside the retry window so it does not starve descendant snapshots
- worker-log attribution waits briefly for repository and workflow data
- Kitchen records resident job observed, harvested, and failed events as distinct history and loot events
- Kitchen does not repair missing resident attribution with the stager origin
- Counter surfaces the last observed job, harvest status, attribution confidence, and resident watch state

## Related Dispatch Credential Note

This came up during manual validation but should remain separate from the resident auto-harvest feature branch:

- classic PATs with the `ghp_` prefix can be scope-preflighted reliably enough to warn about missing `repo` or `workflow` style capabilities
- fine-grained PAT permission discovery is less reliable from local token shape alone
- when Brisket cannot reliably prove a fine-grained PAT has `actions:write`, it should let the operator try the workflow dispatch and surface the GitHub API failure
- this is a dispatch credential UX fix, not part of the resident watcher or harvester logic

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
