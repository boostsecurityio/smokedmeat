# Interactive Agent Terminal Via Kitchen

## Why This Exists

`order exec ...` is a useful primitive, but it is still a one-shot remote command.

Once an operator has a live agent, there is obvious value in a richer post-exploit terminal flow:

- inspect the target interactively
- run sequences of commands without retyping `order exec`
- use shell completion, history, and full-screen tools when needed
- stay inside SmokedMeat instead of pivoting to an external session-sharing product

This task exists to add an interactive remote terminal capability that feels closer to `tmate` or `ttyd`, but runs through Kitchen and stays aligned with SmokedMeat's control plane and deployment model.

## Product Goal

Add an interactive PTY-backed remote terminal for Brisket sessions.

The intended operator experience is:

- select a live agent
- enter a terminal mode from Counter
- type into a real remote shell instead of sending one-shot commands
- resize the terminal cleanly
- exit back to Counter without losing broader operator context

The transport path should be:

- Counter <-> Kitchen
- Kitchen <-> Brisket

There should be no requirement for a direct operator-to-agent tunnel.

## Hard Constraints

- native Go only
- no CGO
- no dependency on external hosted relay services
- Kitchen remains the relay point and trust boundary
- `order exec` remains available for non-interactive one-shot execution

## Non-Goals

This task is not:

- a replacement for `order exec`
- a browser-first shell product
- a full multi-tab terminal manager
- a shared collaboration terminal like `tmate`
- a requirement to vendor `ttyd`, `tmate`, or any non-Go daemon

The first slice is one interactive terminal session per selected agent in Counter.

## Current Product Facts

Today:

- Counter can send remote orders through Kitchen to Brisket
- `order exec` already gives a simple remote command primitive
- Kitchen already brokers post-exploit traffic between Counter and Brisket
- Counter already has large modal and panel rendering patterns that could host a terminal view

What is missing:

- a streaming byte channel for terminal I/O
- PTY lifecycle management on the agent
- terminal resize signaling
- a terminal renderer inside Counter for remote shell output
- operator UX for entering and exiting remote terminal mode

## Why This Should Be Separate From Embedded Operator Shell Work

This is not the same task as the embedded `cloud shell` / `ssh shell` work.

That task is about keeping the operator's own local sandboxed shell inside Counter.

This task is about opening an interactive shell on the remote target through the agent and tunneling it through Kitchen.

The two tasks may share some UI ideas, but the backend and threat model are different enough that they should be tracked separately.

## Proposed Direction

### 1. Add A Shell Session Primitive To Brisket

Brisket should be able to:

- start a PTY-backed shell process
- read output bytes
- accept input bytes
- handle terminal resize events
- close the shell cleanly

The implementation must stay native Go and avoid CGO.

### 2. Add A Multiplexed Relay In Kitchen

Kitchen should relay shell session traffic without interpreting the shell stream.

Kitchen responsibilities:

- authenticate the operator session
- authorize shell access to the selected agent
- relay input, output, resize, start, and close messages
- record shell session lifecycle events in history
- enforce idle timeout and cleanup on disconnect

Kitchen should not become a terminal emulator.

### 3. Add A Terminal Mode In Counter

Counter should expose a clear terminal entry point for the selected session.

Requirements:

- large dedicated terminal panel or modal
- terminal output rendered in-app
- shell input goes to the remote PTY, not to normal Counter commands
- one explicit escape chord returns to Counter
- session metadata remains visible enough that the operator knows which agent they are in

### 4. Keep The Transport Reusable

The transport and session model should not be TUI-specific.

If a browser operator UI is added later, it should be able to reuse the same Kitchen-side shell session contract instead of inventing a second terminal protocol.

## Prior Art

Useful reference points:

- `tmate` for the operator experience of a durable remote terminal
- `ttyd` for the general idea of serving terminal traffic through a relay

These should be treated as product references, not implementation dependencies.

## Open Design Questions

- should terminal mode require Dwell sessions only, or any active agent session
- should Kitchen allow only one attached operator terminal per agent at a time
- how much shell session history, if any, should be retained in audit logs
- whether terminal mode should start from the agent's default shell or from a constrained wrapper
- whether file upload and download should stay separate commands even after interactive terminal lands

## Acceptance Checks

- operator can start an interactive remote terminal from a selected live agent
- typed input is streamed through Kitchen to the remote PTY
- remote output streams back into Counter without freezing the UI
- terminal resize works
- disconnects and agent exit are handled cleanly
- no CGO dependency is introduced
- `order exec` remains intact for simple one-shot usage

## Done Criteria

This task is in good shape when:

- SmokedMeat has a real interactive remote terminal path for agents
- Kitchen is the only relay point needed between operator and agent
- the implementation remains native Go
- the feature is clearly separate from the local embedded operator shell work
