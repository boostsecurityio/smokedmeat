# Interactive Agent Terminal Via Kitchen

## Why This Exists

`order exec ...` is a useful primitive, but it is still a one-shot remote command.

Once an operator has a live agent, there is obvious value in a richer post-exploit terminal flow:

- inspect the target interactively
- run sequences of commands without retyping `order exec`
- use shell completion, history, and full-screen tools when needed
- stay inside SmokedMeat instead of pivoting to an external session-sharing product

This task exists to add an interactive remote terminal capability that feels closer to `sshx` than to buffered one-shot exec, but runs through Kitchen and stays aligned with SmokedMeat's control plane and deployment model.

## Why `sshx` Is The Right Product Reference

`sshx` is not just a terminal over WebSocket.

From the official site, README, and protocol files, the interesting parts are:

- a real streamed session instead of request/response terminal RPC
- explicit message types for terminal input, terminal output, resize, shell create, shell close, sync, and ping/pong
- reconnect and synchronization semantics instead of assuming a perfect always-on path
- low-latency UX goals such as latency measurement and predictive echo
- a clear separation between terminal session state and the web UI protocol
- later collaboration features such as read-only viewers and presence

That is a better reference for this task than `tmate` or `ttyd`, because the real gap in SmokedMeat is not "can we spawn a PTY", it is "can we hold and relay a durable interactive session that still feels good inside the TUI".

SmokedMeat should copy the session model and low-latency UX goals, not the public sharing model. Kitchen is the intended trust boundary, so end-to-end encrypted share links are explicitly out of scope for this task.

## Product Goal

Add an interactive PTY-backed remote terminal for Brisket sessions that feels sshx-like for a single operator inside Counter.

The intended operator experience is:

- select a live agent
- enter a terminal mode from Counter
- type into a real remote shell instead of sending one-shot commands
- keep the shell alive while detaching back to Counter
- re-attach without losing context if Counter reconnects
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
- the first usable slice should not depend on public link sharing or browser UI

## Non-Goals

This task is not:

- a replacement for `order exec`
- a browser-first shell product
- public link sharing like `sshx.io`
- end-to-end encrypted URL fragments
- mesh networking across regions
- infinite-canvas terminal layout
- chat, cursors, or multi-user presence in the first slice
- a requirement to vendor `sshx`, `ttyd`, `tmate`, or any non-Go daemon

The first slice is one interactive terminal session per selected agent in Counter, with one active writer.

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
- reconnect-safe shell session state
- a transport with lower latency than periodic command polling

## Why This Should Be Separate From Embedded Operator Shell Work

This is not the same task as the embedded `cloud shell` / `ssh shell` work.

That task is about keeping the operator's own local sandboxed shell inside Counter.

This task is about opening an interactive shell on the remote target through the agent and tunneling it through Kitchen.

The two tasks may share some UI ideas, but the backend and threat model are different enough that they should be tracked separately.

## `sshx` Research Notes And SmokedMeat Implications

| `sshx` signal | What it means there | SmokedMeat implication |
|---------------|---------------------|------------------------|
| `sshx` advertises automatic reconnection, latency estimates, and predictive echo. | The product is tuned for interactive feel, not just correctness. | This feature should not be framed as "exec but prettier". Latency and reconnect behavior are core requirements. |
| The core protocol defines `Open`, bidirectional `Channel`, and `Close`. | Session lifecycle is explicit. | SmokedMeat needs a real shell-session primitive, not ad hoc `order exec` reuse. |
| The stream protocol has typed messages for terminal data, input, resize, create shell, close shell, sync, and ping/pong. | Terminal traffic is a first-class protocol. | Define a dedicated shell message contract instead of overloading `Order` and `Coleslaw`. |
| The protocol carries sequence numbers and sync state for active shells. | Reattach and replay are part of the design. | Kitchen needs session IDs, output sequence tracking, and bounded replay for reconnect. |
| The repo has a separate web real-time protocol for browser concerns. | Transport and UI protocol are decoupled. | Keep Kitchen shell semantics reusable so a future web operator UI can attach without inventing a second shell backend. |
| `sshx` later added read-only links. | Collaboration roles grow over time. | Start with one writer, but do not paint Kitchen into a corner that forbids read-only observers later. |

## Proposed Direction

### 1. Add A Real Shell Session Primitive To Brisket

Brisket should be able to:

- start a PTY-backed shell process
- assign it a stable shell session ID
- read output bytes incrementally
- accept raw input bytes
- handle terminal resize events
- report exit and close cleanly
- keep a bounded output backlog for re-attach if Kitchen requests replay

The implementation must stay native Go and avoid CGO.

The first supported scope should likely be Linux only. Windows support is desirable, but it should be tracked as a separate follow-up until a native Go ConPTY path is proven acceptable under the no-CGO rule.

### 2. Add A Persistent Relay In Kitchen

Kitchen should relay shell session traffic without interpreting terminal bytes.

Kitchen responsibilities:

- authenticate the operator session
- authorize shell access to the selected agent
- open, attach, detach, resize, input, output, and close shell sessions
- assign and track shell session IDs
- buffer a bounded amount of recent output for reconnect
- record shell session lifecycle events in history
- enforce idle timeout and cleanup on disconnect
- apply backpressure and size limits so the shell path cannot starve the rest of the control plane

Kitchen should not become a terminal emulator.

### 3. Add A Streaming Transport Instead Of Reusing Polling

The current periodic Brisket beacon and one-order polling loop is the wrong transport for a real TTY.

Adaptive polling would make `order exec` feel better, but it is still a stopgap. If the goal is sshx-like UX, Brisket needs a persistent bidirectional transport to Kitchen for shell traffic.

Recommended shape:

- Counter <-> Kitchen continues using the existing operator WebSocket, with new typed shell frames
- Brisket <-> Kitchen gains a persistent shell transport, most likely WebSocket, scoped to interactive sessions
- shell messages stay separate from normal beacon, recon, loot, and one-shot order traffic
- shell sessions survive transient Counter disconnects for a grace window

The first shell protocol should include at least:

- `shell_open`
- `shell_opened`
- `shell_attach`
- `shell_detach`
- `shell_input`
- `shell_output`
- `shell_resize`
- `shell_exit`
- `shell_close`
- `shell_ping`
- `shell_pong`
- `shell_error`

Each output frame should carry sequence metadata so Kitchen can resume from an offset instead of forcing a brand new shell every time a link blips.

### 4. Add A Terminal Mode In Counter

Counter should expose a clear terminal entry point for the selected session.

Requirements:

- large dedicated terminal panel or modal
- terminal output rendered in-app
- shell input goes to the remote PTY, not to normal Counter commands
- one explicit escape chord returns to Counter
- session metadata remains visible enough that the operator knows which agent they are in
- detach should return to Counter without killing the remote shell
- re-attach should reopen the same shell session when possible
- full-screen terminal programs such as `vim`, `less`, and `top` should work within reason on supported platforms

### 5. Keep The Session Contract Reusable

The transport and session model should not be TUI-specific.

If a browser operator UI is added later, it should be able to reuse the same Kitchen-side shell session contract instead of inventing a second terminal protocol.

## Draft Session Model

Each remote shell session should have:

- `shell_session_id`
- `agent_id`
- `callback_id`
- `operator_id` or attachment owner
- `state` such as opening, active, detached, closing, closed
- current terminal size
- created and last-activity timestamps
- output sequence state
- bounded replay buffer or ring buffer
- exit status when known

The model should support one active writer in the first slice. It should not assume that there can only ever be one viewer.

## Suggested Milestones

### Milestone 1 - MVP Interactive Shell

Goal:

- one shell per selected agent
- one active writer
- Counter-only UX
- Linux support first
- persistent streamed transport
- open, input, output, resize, detach, re-attach, close

Not required yet:

- browser UI
- multiple shells per agent
- read-only observers
- predictive echo
- Windows support

### Milestone 2 - Durable Reconnect

Goal:

- Counter can reconnect and re-attach to the same shell session
- Kitchen can replay recent output from a sequence offset
- shell cleanup and idle timeout are deterministic
- history records shell open, attach, detach, and close events

### Milestone 3 - UX Polish

Goal:

- visible latency or status indicator
- paste handling and large-output backpressure tuning
- reliable alternate-screen behavior for full-screen tools
- keyboard routing polished enough that the shell feels native inside Counter

Predictive echo can be revisited here if transport latency remains the main complaint after the protocol is solid.

### Milestone 4 - Collaboration Follow-Ons

Goal:

- read-only observers
- optional second operator attach semantics
- future browser operator UI reuse
- optional multiple named shells per agent

## Open Design Questions

- should the first shell path be available for any active agent, or only for Dwell and resident sessions
- how much transcript, if any, should Kitchen persist beyond bounded replay
- should the first attach auto-start the user's login shell, or a controlled wrapper with a predictable prompt
- what is the minimum acceptable replay buffer for reconnect without creating too much memory pressure
- what exact escape chord should stay reserved by Counter
- whether Windows support should wait for a separate design pass

## Acceptance Checks

- operator can start an interactive remote terminal from a selected live agent
- typed input is streamed through Kitchen to the remote PTY
- remote output streams back into Counter incrementally without freezing the UI
- terminal resize works
- detach returns to Counter without killing the shell
- re-attach returns to the same shell session during the grace window
- transient Counter reconnects do not force immediate shell loss
- no CGO dependency is introduced
- `order exec` remains intact for simple one-shot usage

## Done Criteria

This task is in good shape when:

- SmokedMeat has a real interactive remote terminal path for agents
- Kitchen is the only relay point needed between operator and agent
- the implementation remains native Go
- the shell path behaves like a durable streamed session, not buffered one-shot exec
- the feature is clearly separate from the local embedded operator shell work

## References

- `sshx` site: <https://sshx.io/>
- `sshx` README: <https://github.com/ekzhang/sshx>
- `sshx` release with read-only mode: <https://github.com/ekzhang/sshx/releases/tag/v0.3.0>
- `sshx` core stream protocol: <https://raw.githubusercontent.com/ekzhang/sshx/main/crates/sshx-core/proto/sshx.proto>
- `sshx` web real-time protocol: <https://raw.githubusercontent.com/ekzhang/sshx/main/crates/sshx-server/src/web/protocol.rs>
- `sshx` encryption implementation: <https://raw.githubusercontent.com/ekzhang/sshx/main/crates/sshx/src/encrypt.rs>
