# Embedded Shell And Native Go E2E

## Why This Exists

SmokedMeat already has the operator feature we actually care about:

- analyze
- exploit
- wait for dwell
- pivot
- enter `cloud shell` or `ssh shell`
- continue the operator flow from a local sandboxed shell

What is still weaker than it should be is the test and demo story around that shell boundary.

Today the main `.claude/e2e` harness is tmux-driven:

- `.claude/e2e/helpers.go` shells out to `tmux send-keys` and `tmux capture-pane`
- `make e2e-counter` starts Counter inside tmux
- tests poll pane text rather than driving the app directly

That was a pragmatic bootstrap, but it has real drawbacks:

- extra process hops and timing sensitivity
- terminal automation is coupled to tmux rather than to Counter itself
- the cloud and SSH shells currently suspend Bubble Tea through `ExecProcess`, so they are outside the app's control surface
- the walkthrough path has already shown automation-path fragility, including token corruption during tmux-driven entry

This task exists to close that gap by moving the terminal boundary inside Counter instead of around Counter.

## Product Goal

Replace the raw subprocess handoff for `cloud shell` and `ssh shell` with an embedded shell mode that remains visually and operationally inside SmokedMeat.

The intended end state is:

- `cloud shell` opens a near-full-screen shell panel inside Counter
- the content area is a real PTY-backed shell rendered through a terminal emulator
- SmokedMeat still owns the outer frame, status, and escape chord
- tab completion, shell editing, resize, paste, and shell exit/re-entry work as real shell behaviors
- the primary E2E harness becomes native Go and no longer depends on tmux

## Non-Goals

This task is not trying to build a full terminal OS inside SmokedMeat.

Specifically out of scope for the first slice:

- multiple shell windows
- workspaces
- tiling
- copy mode as a large subsystem
- a general-purpose terminal manager
- replacing Docker isolation for the shell itself
- making walkthrough recording a release blocker for the shell and E2E work

The goal is one excellent embedded shell mode, not a full terminal environment.

## Current State

Relevant code paths today:

- `.claude/e2e/helpers.go` drives Counter through tmux
- `Makefile` target `e2e-counter` launches Counter in tmux
- `internal/counter/tui/cloud_shell.go` and `internal/counter/tui/ssh_shell.go` use `ExecProcess`
- `deployments/cloud-shell-entrypoint.sh` builds the sandboxed shell home and rcfile
- `deployments/Dockerfile.cloud-base` installs the shell tooling image

Important current properties worth preserving:

- shell state is sandboxed to a session-local home
- provider config is redirected into the session home
- the shell can outlive the active dwell agent
- Docker remains the isolation boundary for the operator shell

Important current gaps worth fixing:

- the app loses control of the screen during `ExecProcess`
- the current harness cannot drive shell interactions natively from Go
- tab completion is only as good as the shell bootstrap inside the image
- the image currently attempts to source bash completion, but does not explicitly pin installation of a `bash-completion` package

## Why The Embedded Approach Is Better

### 1. More robust E2E

Driving Counter directly from Go is fundamentally stronger than driving tmux around Counter.

Benefits:

- fewer external moving parts
- fewer shell quoting and timing problems
- easier waits and assertions against app state and terminal state
- easier debugging when failures occur

### 2. Better shell UX

An embedded shell mode lets SmokedMeat keep visual ownership while still presenting a real shell.

Benefits:

- operator always knows they are still inside SmokedMeat
- a stable global escape path can return to Counter
- shell state and Counter state can coexist naturally
- future features such as markers, session status, and recording become straightforward

### 3. Better future demo workflow

Once the full flow stays inside the app, it becomes possible to add recording later as an app-level artifact rather than a terminal hack.

Benefits:

- record organically while operating the tool normally
- export to a replayable tape
- generate GIF or video artifacts through VHS
- keep demos aligned with the real product flow

This is a useful follow-on, but not required for the core shell and E2E milestone.

## Prior Art And Direction

Two external references are directly relevant:

- TUIOS proves that Bubble Tea can host a rich PTY/terminal UX
- VHS is a possible later export target for terminal-demo rendering and GIF export

This task should treat those as prior art, not as a requirement to vendor either project wholesale.

## Proposed Architecture

### Shell Session Backend

Introduce a shell-session abstraction with two real implementations:

- local/embedded backend for direct entrypoint execution when appropriate
- Docker backend for the normal sandboxed operator shell

The backend must own:

- start
- write input
- read output
- resize
- close
- wait for exit
- session metadata such as sandbox root and mode

The backend must not write to the operator's real `HOME`.

### Terminal Rendering

The shell content should be rendered through a VT emulator inside Counter.

Counter should continue rendering the outer screen:

- dimmed or frozen background
- large shell panel
- shell status header
- footer with exit hint and optional recording state

This must not be a tiny dialog. It should look like a large modal shell panel that uses roughly 90-95% of the terminal.

### Focus And Key Routing

When the shell mode is active:

- printable keys go to the shell
- `Tab` goes to the shell for completion
- arrows, ctrl keys, paste, and resize go to the shell
- Counter shortcuts should not steal input

One explicit app-level escape chord should remain reserved to close the shell mode and return to Counter.

### Completion And Shell Bootstrap

Completion must be treated as a product requirement, not an accidental side effect.

Requirements:

- the shell must be explicitly interactive
- the rcfile must explicitly load completion support
- provider tool completion should be registered intentionally rather than left to package auto-discovery
- the shell session home must contain all writable config and cache state

This matters for both nested and non-nested runs.

If Counter ever runs from a container while launching a Dockerized shell, the session root must be daemon-visible. A process-local temp dir is not enough in that mode. The shell mount source must be a host-visible bind mount or named volume.

### Optional Recording Follow-On

If recording is added later, it should sit at the Counter boundary, not at the tmux boundary.

The recorder should capture:

- key events
- pasted text
- waits
- resize events
- shell entry and shell exit
- optional chapter markers
- optional screenshot markers

The recorder should export:

- a raw SmokedMeat recording artifact for debugging and editing
- a compiled VHS `.tape` for playback and GIF/video generation, if that export target is still the best fit at implementation time

## Possible Follow-On UX For Recording

Keep this simple and global.

Suggested first-pass bindings:

- `F8` toggle recording
- `F9` insert chapter marker
- `F10` insert screenshot marker

These are simpler than multi-key prefix systems and can remain available even while the shell mode owns normal typing.

## Task Breakdown

### 1. Lock The Architecture

Write a short ADR that says:

- tmux is no longer the primary E2E driver
- `ExecProcess` shell handoff is replaced by embedded shell mode
- Docker remains the shell isolation boundary

Done when:

- the architecture decision is written down and linked from the roadmap

### 2. Introduce A Shell Backend Interface

Create a narrow abstraction for shell sessions.

Done when:

- both local and Docker-backed shell sessions can be created behind the same interface
- a fake backend exists for deterministic tests

### 3. Replace Raw Shell Handoff With Embedded Takeover

Move `cloud shell` and `ssh shell` from subprocess suspension to an in-app terminal shell mode.

Done when:

- Counter stays on screen while the shell is active
- exiting the shell returns to Counter cleanly
- re-entry works without losing the sandboxed session home

### 4. Make Completion A Hard Requirement

Harden the image and rc bootstrap for real completion support.

Done when:

- `Tab` completion works in the embedded shell
- completion works in the normal Docker-backed operator flow
- completion support is explicitly installed and bootstrapped

### 5. Optional Recording Follow-On

Once the embedded shell mode and native E2E path are stable, add recording only if it still pulls its weight.

Done when:

- recording no longer depends on tmux
- the exported artifact format is simple and maintainable
- recording remains a bonus layer, not a blocker for shell or E2E completion
