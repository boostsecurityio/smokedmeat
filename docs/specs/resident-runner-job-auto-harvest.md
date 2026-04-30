# Resident Runner Later-Job Auto-Harvest

## Summary

Resident self-hosted runner footholds should automatically notice later trusted jobs on the same Linux runner and harvest useful job-adjacent material without operator polling.

This feature is Linux-only for the first slice. It is automatic for resident footholds. There is no Counter toggle and no extra wizard option.

The stage goal is simple: after the operator seeds a resident foothold on a reusable self-hosted runner, a later trusted workflow job should produce a distinct resident harvest event and update Loot Stash live.

## Current Facts

The current resident foothold can survive on a reusable runner, reattach later, and accept normal orders such as `order exec`, `recon`, and `gump`.

The missing piece is automatic later-job observation. The resident Brisket should capitalize on later trusted jobs because those jobs may bring better repository access, better cloud credentials, or higher-value local residue.

GitHub runner behavior gives useful local signals:

- the listener process starts jobs through `Runner.Worker`
- runner application logs live under `_diag` as `Runner_*`
- worker execution logs live under `_diag` as `Worker_*`
- listener logs include job-dispatch state such as `Running job: ...`
- hosted workflow logs expose useful but incomplete context such as runner name, job display name, repository paths, action inputs, and exported environment variables

The sample workflow log is enough for runner identity, repository hints, job display name, checkout path, and cloud credential paths. It is not enough by itself for strong workflow/run attribution because it does not include workflow path or run ID in the pasted lines.

## Non-Goals

- macOS or Windows support in the first slice
- a new operator toggle
- a new full-screen UI surface
- pretending partial metadata is strong attribution
- broad repeated memory dumping while idle
- destabilizing or visibly breaking the trusted job
- replacing the existing express path
- implementing the interactive PTY shell work

## Brisket Behavior

Brisket enters resident watch mode automatically when all of these are true:

- `callback_mode` is `resident`
- runtime OS is Linux
- the process is in the long-running resident mode, not one-shot express mode

The resident relaunch payload should try to keep the resident Brisket elevated:

1. try `sudo -n -E` for the resident background relaunch
2. fall back to the runner user if sudo is unavailable
3. continue unsetting `RUNNER_TRACKING_ID`
4. preserve the existing bounded offline window

The watcher must run alongside the normal beacon and order loop. It must not block operator command handling.

## Job Detection Strategy

Detection is event-first, with fallbacks.

Primary trigger:

- use Linux process event netlink through `github.com/mdlayher/netlink`
- detect new process activity and confirm `Runner.Worker` through `/proc/<pid>/cmdline`

Secondary signal:

- use fanotify through `golang.org/x/sys/unix` when available
- watch runner `_diag` and worker log activity as confirmation and metadata

Fallback:

- low-latency `/proc` polling for `Runner.Worker`
- this fallback is acceptable because `gump` already depends on the same process shape

`_diag` files must not be the primary trigger. They are useful supporting evidence, but they may appear or flush too late for the harvest window.

## Job Identity And Dedupe

One workflow job should produce at most one resident harvest.

The dedupe key should use the best available stable tuple:

- worker PID
- worker process start time
- worker log path, when known
- GitHub run ID, run attempt, and job ID, when discovered

If only PID is available, include process start time so PID reuse does not suppress a later job.

The observer should retain a bounded in-memory recent-job cache. It does not need durable dedupe across Brisket restarts for the first slice.

## Harvest Profile

On `Runner.Worker` detection, Brisket performs one bounded early harvest.

The first harvest profile:

- scan `Runner.Worker` memory with existing gump logic
- sample descendant process environments for about 15 seconds
- collect GitHub runtime vars, token permissions, OIDC endpoints, cache endpoints, and results endpoints
- collect runner identity, hostname, OS, arch, workspace, and temp path hints
- read small credential files referenced by env paths such as `GOOGLE_GHA_CREDS_PATH`, `GOOGLE_APPLICATION_CREDENTIALS`, and `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`
- record errors and unavailable signal sources without failing the whole resident loop

Size and safety limits:

- do not read arbitrary files
- only read env-referenced credential paths from known allowlisted env vars
- cap individual credential file reads at a small fixed size
- cap total descendant env sampling duration
- cap total harvest runtime
- do not retry broad memdump loops after the harvest window closes

The first slice should harvest at job start only. Near-cleanup harvesting can be a later enhancement if start-only misses too much material.

## Attribution Model

Harvested data carries explicit attribution confidence.

Confidence values:

- `strong`: GitHub env or worker memory provides repository, workflow ref or workflow path, job, and run metadata
- `partial`: repository or job is known, but workflow or run identity is missing
- `weak`: only runner identity, workspace path, checkout path, or `_diag` hints are available
- `unknown`: no reliable job metadata is available

Strong attribution can use:

- `GITHUB_REPOSITORY`
- `GITHUB_WORKFLOW_REF`
- `GITHUB_WORKFLOW`
- `GITHUB_JOB`
- `GITHUB_RUN_ID`
- `GITHUB_RUN_ATTEMPT`
- `GITHUB_SHA`
- `GITHUB_REF`

Partial attribution can use:

- `actions/checkout` repository input
- checkout working directory
- `remote.origin.url`
- job display name from logs
- runner name and machine name

Do not guess workflow path or run ID from the public workflow log. If the workflow path is not discovered from env, worker memory, local metadata, or a reliable log source, leave it empty and mark confidence below `strong`.

## Kitchen Contract

Kitchen receives resident harvests on the existing authenticated agent beacon endpoint.

The request must be distinct from normal express data. Use:

- `event_type`: `resident_job_harvest`
- `origin`: `resident_job_harvest`

Payload fields should include:

- agent ID
- session ID
- callback ID
- callback mode
- observed time
- runner name
- hostname
- OS and arch
- worker PID
- worker start time
- repository, workflow, job, run ID, run attempt, SHA, and ref when known
- attribution confidence
- harvest profile name
- harvest stats
- extracted secrets
- extracted vars
- extracted endpoints
- token permissions
- warnings and errors

Kitchen must not parse resident job harvests as ordinary express beacons.

Kitchen persists loot with a new origin:

- `resident_job_harvest`

If persisted row shape changes to carry attribution confidence or resident job metadata, bump the Kitchen DB schema minor. Do not bump schema major unless existing rows become unsafe to read.

## Counter Behavior

Counter handles resident harvest WebSocket messages regardless of current phase.

Required behavior:

- Loot Stash updates live in Recon, Waiting, Post-Exploit, and modal states
- harvested loot is labeled as later resident job loot, not original seed callback loot
- `Shift+I` shows watch state for resident callbacks
- resident callback details show last observed job time
- resident callback details show last successful harvest time
- resident callback details show attribution confidence
- warnings are visible when the resident foothold is alive but no stable signal source is available

Counter should reuse the existing callback and implants inventory. Do not add a separate resident-job inventory.

## Dependency Changes

Add one direct dependency:

- `github.com/mdlayher/netlink`

`golang.org/x/sys` is already available and should be used for fanotify where practical.

Do not add large process-inspection libraries for this slice.

## Testing

Brisket tests:

- process netlink event produces a `Runner.Worker` observation
- fanotify event on `_diag` contributes evidence but is not required
- `/proc` polling fallback detects `Runner.Worker`
- one worker produces one harvest
- PID reuse with different start time produces a new harvest
- descendant environment sampling is bounded
- allowlisted credential file reads respect size limits
- missing privilege records warnings and keeps the resident loop alive

Kitchen tests:

- `resident_job_harvest` is routed separately from express data
- resident harvest loot persists with origin `resident_job_harvest`
- attribution confidence is preserved
- stored loot sync restores resident harvest loot
- invalid or partial payloads do not crash the beacon handler

Counter tests:

- Loot Stash updates from resident harvest messages in multiple phases
- `Shift+I` displays resident watch state and last harvest status
- resident harvest loot is rendered with distinct origin
- partial attribution displays known repo or job while leaving unknown workflow and run fields empty

Manual NorthSec rehearsal:

1. seed a resident foothold on a reusable Linux self-hosted runner
2. let the resident beacon reattach
3. trigger a later trusted workflow on the same runner
4. observe resident job detection without operator polling
5. observe Loot Stash update dynamically
6. confirm `Shift+I` shows watch and confidence state
7. confirm cloud or GitHub material is attached with honest attribution

## References

- GitHub self-hosted runner docs: <https://docs.github.com/actions/reference/runners/self-hosted-runners>
- GitHub runner troubleshooting and `_diag` docs: <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/monitoring-and-troubleshooting-self-hosted-runners>
- GitHub runner service docs: <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/configuring-the-self-hosted-runner-application-as-a-service?platform=linux>
- GitHub Actions runner listener source: <https://github.com/actions/runner/blob/main/src/Runner.Listener/Runner.cs>
- GitHub Actions runner job dispatcher source: <https://github.com/actions/runner/blob/main/src/Runner.Listener/JobDispatcher.cs>
