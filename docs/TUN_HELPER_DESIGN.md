# TUN Helper Design

## Goal

Reduce the privilege footprint of desktop TUN operation by moving the host-local
TUN and route control boundary into a small privileged helper, while keeping the
main ObstacleBridge runtime unprivileged.

This document describes a Linux-first design because Linux offers the simplest
deployment path for a narrow helper. The same Python helper split should also
support macOS by adding a Darwin backend that owns `utun` and runs the existing
macOS TUN hook scripts, while the packaging and privilege mechanism remain
platform-specific.

## Why

Today the Python desktop runtime is a single process:

- overlay transport sessions
- SecureLink
- ChannelMux
- Admin Web
- proxy provider
- lifecycle/config orchestration
- local TUN device open/read/write
- route and hook execution

When local TUN startup needs elevation, the current entrypoint relaunches the
entire Python runtime with elevated privilege. That works, but it means the
whole process owns more privilege than it really needs.

The desired end state is:

- unprivileged main process owns overlay, mux, admin, proxy, and policy
- privileged helper owns only local TUN and host-network operations

## Scope

### In scope for the Linux/macOS Python helper

- create or open a configured local TUN device
- configure link state and MTU
- optionally apply configured tunnel addresses
- optionally apply route/DNS/firewall lifecycle actions
- read packets from the TUN device
- write packets to the TUN device
- expose small diagnostics about helper state and failures

Linux and macOS differ only at the host-network backend:

- Linux opens `/dev/net/tun` and applies host state through `ip`,
  `resolvectl`, and firewall tooling
- macOS opens Darwin `utun`, writes/reads the four-byte utun address-family
  header around raw IP packets, and applies host state through
  `ifconfig`/`route`/`networksetup` or the existing
  `scripts/client-tun-hook-macos.sh` and `scripts/server-tun-hook-macos.sh`

### Explicitly out of scope

- overlay transport ownership
- SecureLink or compression logic
- ChannelMux policy decisions
- Admin Web HTTP serving
- proxy-provider serving
- peer authentication state
- general config editing

The helper should be a narrow device-and-routing servant, not a second runtime.

## Current Repo State

This document now tracks the helper work as it exists in the repository rather
than as a purely forward-looking plan.

### Delivered in the current branch

- `tun_execution` is a real config section with CLI/config parsing in
  `src/obstacle_bridge/bridge_tun_helper_settings.py`
- helper framing exists in
  `src/obstacle_bridge/bridge_tun_helper_protocol.py`
- local helper client/server scaffolding exists in
  `src/obstacle_bridge/bridge_tun_helper_client.py` and
  `src/obstacle_bridge/bridge_tun_helper_server.py`
- the current Linux helper backends exist in
  `src/obstacle_bridge/bridge_tun_helper_linux.py`
- helper backend selection now supports both the existing in-memory scaffold
  path and a selectable native Linux TUN backend that can open `/dev/net/tun`,
  set MTU/link-up state, and move packets through a real fd
- `Runner` can start helper mode, create a session token, launch the helper
  module as a separate subprocess, connect the helper client, expose helper
  state through status snapshots, skip the legacy whole-process Linux `sudo`
  relaunch when helper mode is selected, and elevate only the helper
  subprocess when the native Linux backend needs privilege
- `ChannelMux` can switch its local TUN open/read/write path to the helper
  backend when `tun_execution.mode=helper`, including a client-only path when
  the backend lives in the spawned helper process
- `helper_apply_network` now reaches a real helper control path in the current
  scaffold: helper-managed TUN open/close can trigger helper-side
  apply/remove calls, and helper snapshots expose the resulting counters/state
- the native Linux helper backend now uses that helper control path to apply
  and remove the configured interface IPv4 and IPv6 tunnel addresses,
  helper-merged excluded routes, non-default included routes, and Linux
  policy-table full-tunnel default-route rules on the real TUN device, plus
  helper-owned DNS apply/remove through `resolvectl` when that manager is
  available on the Linux host
- elevated Linux integration now proves that helper-owned firewall
  forwarding/NAT/TCPMSS apply and remove run on the real privileged path for a
  peer-instantiated helper-managed server TUN, including teardown cleanup
- elevated Linux integration now also proves that a helper-managed native
  `apply_network` failure after partial route/address programming rolls back
  the real host mutations and preserves structured helper failure diagnostics
  through runtime/Admin status
- helper runtime snapshots now also expose structured last-failure diagnostics
  for helper-owned network operations, and the native backend rolls back
  partial apply state when `apply_network` fails mid-flight
- helper-mode `ChannelMux` now refreshes the helper runtime snapshot after an
  asynchronous helper apply/remove failure so Admin Web and runtime status can
  surface helper-side `last_failure` details instead of keeping a stale
  pre-failure snapshot
- runtime helper status now treats post-start helper socket loss as a real
  disconnect signal: the status payload flips helper `connected` /
  `server_started` appropriately, preserves the last known helper runtime
  snapshot for diagnostics, and exposes the helper connection error plus
  helper-process return code when available
- runtime helper status and the TUN admin view now also emit a recovery
  warning when a dead helper's last cached runtime snapshot suggests that
  helper-owned firewall or other host-network state may still need manual
  cleanup before restart
- the runtime now also offers a first automatic repair slice for that stale
  helper-owned state: when the helper is already dead, the Linux-native path
  can replay cleanup for cached helper-owned routes, firewall rules, DNS, and
  tunnel addresses from the last helper runtime snapshot, and Admin Web can
  trigger that repair flow directly from the TUN page
- elevated Linux integration now also proves that this repair flow can clean
  up real helper-owned firewall state and surviving underlay-route mutations
  after post-start helper loss on the privileged path
- helper status now also preserves a post-repair result snapshot so Admin Web
  can distinguish a repair that cleared stale helper-owned state from a repair
  attempt that still leaves possible stale state behind, and the Linux-native
  path now performs a best-effort post-repair verification pass over helper-
  owned addresses, routes, policy rules, firewall rules, and DNS state so that
  distinction is based on checked host state rather than cleanup return codes
- the helper server module now has a runnable entrypoint and async serve
  contract in `src/obstacle_bridge/bridge_tun_helper_server.py`
- the TUN / Routing admin payload now carries helper status so the TUN page can
  show helper mode, backend, socket, and runtime packet counters
- Python/macOS already has inline host TUN support in
  `src/obstacle_bridge/bridge_tun_macos.py`, including real Darwin `utun`
  creation, utun frame adaptation, packet read/write, and MTU/link-up handling
  when the process has sufficient privilege
- the repository already carries Darwin host-network hook scripts in
  `scripts/client-tun-hook-macos.sh` and `scripts/server-tun-hook-macos.sh`;
  the Python/macOS helper backend now invokes those scripts for helper-owned
  network apply/remove rather than introducing a second hook contract
- `src/obstacle_bridge/bridge_tun_helper_macos.py` now provides the
  `darwin-native` helper backend: it owns the real `utun` fd from the elevated
  helper subprocess, reuses the inline macOS packet frame adaptation, emits raw
  IP packets over helper IPC, wraps runtime packets with the utun family header,
  and runs the Darwin hook scripts from helper-side apply/remove operations
- helper backend selection and runner launch now accept `darwin-native`; on
  macOS helper mode skips whole-runtime `sudo` reexec and elevates only the
  helper subprocess when the native backend needs privilege
- focused unit coverage exists for settings, protocol framing, client/server
  scaffolding, runner wiring, helper-backed ChannelMux TUN I/O, the selectable
  native Linux helper backend, and the selectable Darwin helper backend

### Important current limitation

The current delivered helper split is still not yet a real privileged helper
deployment that proves the full least-privilege goal end to end.

Today the branch proves two different things:

- the explicit `linux-python` helper flow remains the Linux-first
  memory-backed scaffold used to prove config, control protocol, runner
  ownership split, ChannelMux backend swapping, and admin/status visibility
- a selectable native Linux backend now proves that the helper-side backend API
  can own a real TUN fd and exchange packets through it
- a selectable `darwin-native` backend now moves Python/macOS `utun` ownership,
  utun/raw-IP packet adaptation, and Darwin hook execution behind the same
  helper IPC boundary

What is still not delivered is the broader hardening around that native helper
deployment rather than the basic Linux host-network ownership itself. The
Linux helper now owns interface address apply/remove, helper-merged excluded
routes, non-default included routes, Linux policy-table full-tunnel
default-route handling, helper-owned DNS through `resolvectl` when available,
and Linux server-side forwarding/NAT/TCPMSS firewall lifecycle when
helper-managed TUN services carry the same listener-side `WAN_IF` intent that
previously drove `scripts/server-tun-hook.sh`. Elevated integration now covers
packet carry, route-policy ownership, real helper-owned firewall apply/remove
with teardown cleanup, and rollback after partial helper apply failure. The
more meaningful remaining Linux work is now stronger proof of helper-death
cleanup handling and deployment hardening. The macOS Python helper backend is
now present and has unit coverage plus elevated/live helper proof for privileged
`darwin-native` launch, real `utun` creation, Darwin hook apply/remove, Admin
Web helper runtime reporting, packet carry through the real overlay, direct
Darwin route/DNS hook effects on a live helper-owned `utun`, helper-death
disconnect reporting, kernel cleanup of the helper-owned interface, and route
teardown after helper loss.

### Not delivered yet

- peer credential enforcement such as `SO_PEERCRED`
- file-capability or equivalent hardening beyond the current helper-subprocess
  `sudo` launch
- broader elevated Linux integration coverage for helper-death cleanup cases
  beyond packet carry, helper-managed route/DNS/firewall behavior, rollback
  after partial apply failure, post-start helper-loss observability, and
  operator-triggered stale-state repair after helper death
- Swift/macOS parity for the helper split

### Recent Linux learnings from live helper rollout

The recent Linux-native helper rollout surfaced a few behaviors that are easy to
miss in unit-only design work and should now shape the cross-platform helper
contract.

- `ip rule show` output is not canonical. Existing-rule detection must tolerate
  host routes rendered without `/32` and default rules rendered without an
  explicit `to 0.0.0.0/0` or `to ::/0` clause.
- The failure mode for missed policy-rule reuse is severe but misleading: the
  helper may open the TUN device successfully, then fail during route-policy
  apply, roll back addresses, and leave the operator seeing an `UP` helper path
  with missing tunnel addresses.
- Admin Web helper snapshots need to stay cheap. Active verification probes
  such as `ping` checks for local peer reachability or global connectivity must
  run outside the timeout-sensitive snapshot builder so a healthy runtime is not
  mislabeled as stale. The latest Linux fix now makes that contract explicit:
  when the TUN payload is being built on the Admin server thread, peer/global
  `ping` verification returns either a short-lived cached result or a `pending`
  placeholder while a background refresh thread performs the blocking probe.
  That keeps the TUN page responsive, avoids self-inflicted snapshot timeout
  noise, and still gives operators a concrete freshness signal via
  `cached`/`stale`/`refresh_in_flight` status fields.
- Helper lifecycle must cover abnormal parent loss, not only normal stop.
  Authenticated-client watchdog shutdown inside the helper and startup-time
  stale-helper reaping in the runner are both required to prevent orphaned
  helper processes from keeping a stale TUN device alive after bridge exit.
- Operator-facing status is materially better when the TUN page distinguishes
  configuration verification, peer-side tunnel connectivity verification, and
  global connectivity verification, and when the global target remains a normal
  configuration parameter rather than hard-coded policy.

The current live Linux state after these fixes is the expected steady-state:
helper connected, `obtun0` carrying both configured tunnel addresses, and the
Admin Web verification payload reporting successful config, peer, and global
connectivity checks.

## Linux-first architecture

### Process split

1. `python -m obstacle_bridge` starts as the normal unprivileged runtime.
2. `Runner` detects that a local desktop TUN service is configured and that the
   selected mode is `helper` rather than `inline`.
3. `Runner` starts or connects to a privileged local helper.
4. `ChannelMux` uses a `PacketIO`-style adapter backed by local IPC instead of
   opening `/dev/net/tun` directly.
5. The helper owns the real Linux TUN fd and any host-side route or hook work.

### IPC boundary

Use a local Unix domain socket.

Reasons:

- available on Linux without extra dependencies
- easy permission control on the socket path
- no packet-size translation surprises for TUN payloads
- simple to replicate later with different backends on other platforms

Suggested socket location:

- runtime default: `/run/user/<uid>/obstaclebridge/tun-helper.sock`
- fallback when that directory is unavailable: a user-private path under
  `$XDG_RUNTIME_DIR` or a temporary directory created with `0700`

### Helper launch mode

Linux-first minimum viable approach:

- keep the helper as a Python module in the same repo
- start it through `sudo` only when needed
- keep it short-lived and tied to the parent runtime session

Possible later hardening:

- dedicated executable
- systemd user/service integration
- file capabilities such as `CAP_NET_ADMIN` where feasible

The first version should optimize for correctness and observability, not for
packaging sophistication.

## macOS Python architecture

The macOS Python path should use the same high-level helper topology as Linux:

1. `python -m obstacle_bridge` starts as the normal unprivileged runtime.
2. `Runner` detects a local desktop TUN service with
   `tun_execution.mode=helper`.
3. `Runner` starts an elevated helper subprocess instead of relaunching the
   whole Python runtime through `sudo`.
4. `ChannelMux` uses the same helper-backed packet adapter it uses on Linux.
5. The helper selects a Darwin backend that owns `utun`, MTU/link setup, packet
   framing, and helper-owned network apply/remove.

The Darwin backend should reuse the existing Python `utun` code from
`src/obstacle_bridge/bridge_tun_macos.py` rather than inventing a second packet
adapter. macOS `utun` packets carry a four-byte address-family header on the fd
while ChannelMux expects raw IP packets, so the helper backend must preserve the
same packet wrapping/unwrapping behavior as the inline macOS adapter.

For network apply/remove, the first Python helper implementation should call the
existing Darwin hook scripts:

- client/local TUN: `scripts/client-tun-hook-macos.sh`
- listener/server TUN: `scripts/server-tun-hook-macos.sh`

Those scripts already encode macOS route, DNS, underlay-preservation, and
interface-address behavior. Keeping them as the helper-side script boundary
lets helper mode reduce the runtime privilege footprint without creating a
third macOS routing implementation.

### macOS helper launch mode

The near-term Python/macOS launch model can mirror the current Linux helper
subprocess approach:

- keep the helper as a Python module in the same repo
- start only the helper through `sudo` when `darwin-native` needs privilege
- keep the unprivileged parent runtime alive as the owner of overlay, mux,
  Admin Web, and policy state
- pass the same session token and helper socket path used by Linux helper mode

Longer-term app packaging can still use the Swift/macOS direction from
`docs/MACOSAPP_DESIGN.md`: a dedicated privileged helper managed through
`SMAppService` with XPC. That is a packaging and app-lifecycle concern; the
Python helper protocol and backend API should remain useful underneath it.

## Control protocol

The helper protocol should stay very small and versioned.

### Session setup

Client sends:

- protocol version
- requested interface name
- requested MTU
- TUN routing settings relevant to helper-owned work
- helper auth nonce or token

Helper replies:

- accepted/rejected
- effective interface name
- effective MTU
- helper pid
- helper capability flags
- structured error when rejected

### Commands

Minimal commands:

- `OPEN_TUN`
- `READ_START`
- `WRITE_PACKET`
- `APPLY_NETWORK`
- `REMOVE_NETWORK`
- `SNAPSHOT`
- `STOP`

### Data path

Packet traffic should not be wrapped in heavyweight JSON.

Use a small binary frame:

- `u8 kind`
- `u32 length`
- payload bytes

Frame kinds:

- control request
- control response
- packet from helper to runtime
- packet from runtime to helper
- event/log/diagnostic

## Ownership split

### Main runtime keeps ownership of

- overlay connection lifecycle
- ChannelMux service catalog
- TUN channel allocation and peer routing logic
- shared-TUN ownership decisions
- SecureLink counters and policy
- Admin Web snapshots and operator UX

### Helper owns

- real TUN fd
- `ip`/`ifconfig`/route-like host actions for the local device
- optional lifecycle-hook execution if those hooks must stay privileged

Important rule:

The helper should not decide where packets go in overlay terms. It only moves
bytes between the real host TUN interface and the unprivileged runtime.

## Routing and hook strategy

There are two viable options.

### Option A: helper owns all privileged host networking

Helper performs:

- interface up/down
- address assignment
- route changes
- DNS handoff
- firewall/NAT changes

Pros:

- cleaner privilege boundary
- fewer partial-failure states

Cons:

- helper protocol needs to carry more config
- helper must own more Linux-specific behavior

### Option B: helper owns only TUN fd, runtime still launches hooks

Pros:

- smaller initial helper
- fewer changes to existing hook model

Cons:

- does not reduce privilege as much
- runtime may still need elevation for hook actions

Recommendation:

Start with Option A for Linux if the goal is genuine privilege reduction rather
than only abstracting the TUN fd open path.

## Authentication and safety

The local IPC link must be treated as privileged control traffic.

Minimum protections:

- create the socket in a user-private directory
- validate peer credentials with `SO_PEERCRED` on Linux or the platform
  equivalent on macOS
- require the connecting uid to match the launching uid
- require a session token generated by the parent runtime
- reject helper reuse from unrelated processes unless explicitly allowed later

The helper should never expose a network listener.

## Failure model

Key failure cases:

- helper launch denied by sudo or policy
- helper cannot create/open TUN
- helper applies partial route state then fails
- helper dies while overlay remains connected
- parent dies and helper becomes orphaned

Required behavior:

- fail closed and surface structured reason to Admin Web and logs
- helper should tear down owned network state on normal stop
- helper should self-expire if the parent IPC session disappears
- runtime should mark TUN unavailable without taking down unrelated TCP/UDP
  services when possible

## Admin and diagnostics

Expose helper state through existing Admin Web runtime snapshots instead of
inventing a second operator surface.

Suggested snapshot fields:

- helper enabled
- helper connected
- helper pid
- helper mode: `inline` or `external`
- helper backend: default `linux-native` on Linux, selectable
  `darwin-native` on macOS, optional scaffold fallback `linux-python`
- last helper error
- helper reconnect attempts
- packets read from helper TUN
- packets written to helper TUN
- helper-owned route apply/remove status

This keeps the operator model aligned with the existing mux and TUN pages.

## Proposed configuration shape

Add a narrow TUN execution section rather than overloading unrelated settings.

Example:

```json
{
  "tun_execution": {
    "mode": "inline",
    "helper_backend": "linux-native",
    "helper_socket": "",
    "helper_apply_network": true
  }
}
```

Meaning:

- `inline`: current behavior, local process owns TUN directly
- `helper`: use a local helper when supported
- `helper_backend`: platform-specific helper selector; current choices are
  `linux-native`, `linux-python`, and `darwin-native`
- `helper_socket`: optional explicit IPC path
- `helper_apply_network`: whether the helper owns route/address/hook work

Recommendation:

Keep `inline` as the default initially so the helper path can mature behind an
explicit opt-in.

## Status Summary

The helper effort has moved beyond the original protocol experiment on Linux
and macOS: the native Linux backend owns real privileged TUN and host-network
work for the covered paths, and the native Darwin backend now owns the Python
macOS helper API surface with mocked unit coverage.

### Completed milestones

1. helper settings and config parsing
2. protocol encode/decode module and unit tests
3. helper client/server using a fake local packet transport
4. Linux helper backend stub capable of open/read/write semantics
5. helper mode wiring into `Runner`
6. helper-backed local TUN adapter wiring into `ChannelMux`
7. helper diagnostics exposed through runtime snapshots and the TUN-facing
   Admin Web payload
8. helper-network apply/remove control path exists in the Linux-first scaffold
   and is wired into helper-managed TUN open/close
9. real Linux elevated integration now covers helper-backed packet carry,
   helper-owned route-policy mutations, and helper-owned firewall apply/remove
   cleanup on the real privileged path
10. the selectable native backend is now a real helper-owned Linux TUN backend
    rather than only an in-process memory scaffold
11. the selectable `darwin-native` backend now owns Python/macOS helper-side
    `utun` open/read/write, utun frame adaptation, Darwin hook apply/remove,
    server backend selection, and helper-subprocess-only macOS sudo launch
    wiring under focused unit coverage

### Remaining milestones

12. decide how much of the existing whole-process `sudo` relaunch remains as
   the default inline fallback as helper mode matures
13. add broader adverse elevated coverage for post-start helper loss and
    partial cleanup failure paths
14. add elevated/live macOS tests or probes for `darwin-native` helper
    subprocess launch, real `utun` packet carry, helper-side Darwin hook
    route/DNS effects, status reporting, and teardown cleanup

## Open parity activities for macOS Python and macOS Swift

Recent Linux-native changes expanded the practical helper contract beyond basic
packet I/O and route apply/remove. To keep macOS Python and macOS Swift aligned
with that behavior, the following work remains open.

### Python/macOS parity backlog

1. Add elevated/live `darwin-native` coverage for parent-loss behavior so the
  helper proves the same abnormal-exit cleanup expectations as Linux: helper
  self-stop after authenticated client loss, kernel/interface teardown, and
  hook-driven route/DNS cleanup verification.
2. Mirror Linux helper observability in the Darwin runtime snapshot where it is
  meaningful: authenticated-client count, structured `last_failure`, last
  apply/remove payloads, and enough cleanup state to support post-failure
  diagnosis without attaching to the helper process.
3. Define whether Python/macOS needs the same startup stale-helper reaping flow
  as Linux for helper sockets and orphan processes, or whether launchd/macOS
  process semantics make a narrower cleanup path sufficient. The answer should
  be explicit and tested rather than implicit.
4. Prove that the Admin Web TUN verification model remains valid on macOS:
  observed-address verification, peer gateway verification, and configurable
  global-connectivity verification should all report consistently when the
  Darwin helper backend is active.
5. Review the Darwin hook scripts for idempotent cleanup behavior equivalent to
  the Linux-native backend's replay and repair expectations, especially for
  repeated apply/remove, partial failure rollback, and helper death after
  network state was already applied.

### Swift/macOS parity backlog

1. Keep the Swift privileged-helper design aligned with the now-proven Linux
  and Python/macOS responsibility split: unprivileged app/runtime owner,
  narrow privileged tunnel helper, and helper-owned host interface, route,
  DNS, and cleanup lifecycle.
2. Carry over the same abnormal-lifecycle requirements into the Swift helper
  design: authenticated session binding, parent/client-loss shutdown, orphan
  cleanup expectations, and operator-visible stale-state diagnostics.
3. Match the observable status model exposed by Python helper mode so the same
  Admin/TUN concepts exist across products: helper connected state, backend or
  packaging mode, packet counters, structured last failure, cleanup outcome,
  and verification results for config, peer connectivity, and global
  connectivity.
4. Preserve configurability rather than platform-specific hard-coding for the
  global connectivity target and any future verification probes so parity does
  not drift into separate platform policies.
5. Add Swift/macOS test and probe coverage for the same classes of regressions
  that recently appeared on Linux: non-canonical host route/state reporting,
  partial helper apply rollback, helper-loss cleanup, and operator-facing
  status freshness under verification load.

## Python/macOS and Swift parity note

This document started as a Linux-first experiment, but the helper boundary now
also applies to the Python/macOS runtime. The Python CLI can support macOS
helper mode with the same helper protocol and a Darwin-specific backend before
the Swift app adopts a final Apple-native helper package.

Current parity situation:

- Python desktop currently uses inline TUN ownership with whole-process
  privilege handoff when needed on Linux and macOS
- Python/macOS already proves real `utun` creation, packet carriage, and Darwin
  hook behavior when the whole process is elevated
- Python helper mode now moves that macOS `utun` and hook ownership into an
  elevated helper subprocess path, matching the Linux privilege split while
  keeping Darwin-specific host actions in a Darwin backend
- macOS Swift already has a related privileged-host-runner discussion and
  partial helper direction in `docs/MACOSAPP_DESIGN.md`
- iOS already has a platform-owned privileged packet boundary through
  `NEPacketTunnelProvider`

As helper mode becomes product behavior, Python/Linux, Python/macOS, and
Swift/macOS should share the same responsibility split:

- unprivileged UI/app/runtime owner
- privileged local tunnel helper
- narrow packet/control IPC boundary
- helper-owned host interface, route, DNS, and cleanup lifecycle

The packaging will differ. Python/Linux and Python/macOS can use the local
helper subprocess and Unix-domain-socket control plane. Swift/macOS should keep
moving toward `SMAppService` plus XPC. The protocol concepts and observable
state should stay aligned so Admin Web and runtime status mean the same thing
across products.

## Current working model

The current working model is:

1. Linux is the delivered helper implementation target today
2. Python/macOS now has a helper backend using Darwin `utun` and the existing
   macOS TUN hook scripts
3. explicit opt-in config through `tun_execution.mode=helper`
4. one helper-managed local TUN backend path at a time is the intended first
   practical target
5. main runtime still owns all mux and overlay semantics
6. helper visibility is exposed in runtime snapshots and on the TUN page
7. Linux native helper mode now proves actual privileged TUN and route
   lifecycle ownership; macOS helper mode now has unit-covered Darwin backend
   and helper-side hook execution, with elevated/live proof still remaining

This means the branch now answers "can the Linux product run with a reduced
helper-owned host-network boundary?" for the covered Linux paths, and "can
Python/macOS use the same helper boundary without relaunching the whole runtime
through sudo?" at the backend and runner wiring level. The next macOS question
is live elevated proof on a real host.

## Concrete Implementation State

This section maps the current code to the helper design and highlights the gap
between the current branch and the target architecture.

### Existing seams to reuse

The current Python codebase already has a few useful insertion points:

- `src/obstacle_bridge/packet_io.py`
  - defines a small packet-boundary abstraction that can be reused as the local
    helper seam
- `src/obstacle_bridge/bridge_runner.py`
  - already owns process startup, config loading, and current privilege handoff
- `src/obstacle_bridge/bridge_channelmux.py`
  - already centralizes local TUN open/read/write and TUN channel ownership
- `src/obstacle_bridge/bridge_tun_macos.py`
  - already centralizes Python/macOS `utun` open/read/write and utun
    frame/raw-packet adaptation that a Darwin helper backend should reuse
- `src/obstacle_bridge/bridge_tun_routing.py`
  - already defines the effective routing settings that the helper needs
- `src/obstacle_bridge/bridge_webadmin.py`
  - already publishes runtime snapshots and can surface helper state

That means the first implementation does not need a second configuration system
or a second admin surface.

### Current Python modules

#### `src/obstacle_bridge/bridge_tun_helper_protocol.py`

Purpose:

- protocol constants
- frame kinds
- version markers
- control request/response dataclasses
- encode/decode helpers

Why:

- keeps framing logic out of both runner and helper process code
- makes protocol tests straightforward

#### `src/obstacle_bridge/bridge_tun_helper_client.py`

Purpose:

- unprivileged runtime-side client for the helper
- socket connect/auth/session bootstrap
- packet send/receive bridge
- helper snapshot polling or event subscription

Expected owner:

- `Runner` creates and owns one client instance when helper mode is active

#### `src/obstacle_bridge/bridge_tun_helper_server.py`

Purpose:

- privileged helper main loop
- Unix socket listener
- peer credential validation
- command dispatch
- helper lifecycle and shutdown cleanup

Current owner:

- used by the spawned helper module entrypoint for Linux helper mode
- now selects both the Linux backends and the Darwin backend for Python/macOS
  helper mode

#### `src/obstacle_bridge/bridge_tun_helper_linux.py`

Current purpose:

- Linux-specific helper backends used by the current branch
- native Linux open/read/write semantics for real `/dev/net/tun`
- scaffold open/read/write semantics for the explicit `linux-python`
  memory-backed path
- native apply/remove control semantics for helper-owned Linux network
  lifecycle
- snapshot counters used by runtime and Admin Web diagnostics

Still missing:

- broader deployment hardening around native Linux helper cleanup and
  privilege configuration
- broader cross-platform hardening parity with the Darwin backend

Why separate it:

- keeps the generic server protocol clean
- provides a clear pattern for platform-specific Darwin and Windows backends to
  parallel

#### `src/obstacle_bridge/bridge_tun_helper_macos.py`

Purpose:

- Darwin-specific helper backend for Python/macOS
- opens and owns the real `utun` socket from the elevated helper process
- preserves the existing macOS packet adaptation between utun frames and raw IP
  packets
- applies/removes helper-owned host network state by invoking
  `scripts/client-tun-hook-macos.sh` or `scripts/server-tun-hook-macos.sh`
  with the same `TUN_routing`-derived environment used by inline Python today
- exposes structured runtime state for Admin Web, including actual utun ifname,
  hook apply/remove status, packet counters, and last failure diagnostics

Why separate it:

- Linux `/dev/net/tun` and Darwin `utun` have different fd semantics and
  packet framing
- macOS route and DNS state is already captured in the Darwin hook scripts
- keeping the backend separate lets the shared helper protocol stay stable

#### `src/obstacle_bridge/bridge_tun_helper_settings.py`

Purpose:

- config dataclass
- CLI registration
- config-section parsing
- normalization of helper mode and socket path

Why:

- avoids overloading `TunRoutingSettings` with process-topology choices

### Current runtime edits

#### `src/obstacle_bridge/bridge_runner.py`

Current state:

- helper settings registration and config-file mapping are implemented
- helper launch/connect orchestration is implemented for helper subprocesses
  and the explicit in-memory scaffold fallback
- `Runner` creates helper state before `ChannelMux.start()`
- `Runner` exposes helper snapshot data to Admin Web
- `Runner` stops helper client/server state during shutdown

Still missing:

- helper-subprocess-only elevation exists for `linux-native` and
  `darwin-native`

#### `src/obstacle_bridge/bridge_channelmux.py`

Current state:

- helper-aware local TUN backend selection is implemented
- helper mode swaps local TUN open/read/write over to the helper backend
- helper-managed TUN open/close can trigger helper apply/remove control calls
  when `helper_apply_network=true`
- ChannelMux still owns all TUN channel semantics and routing logic

Current limitation:

- the helper-backed path supports the native Linux helper-owned device, the
  native Darwin helper-owned device, and the explicit Linux memory scaffold

#### `src/obstacle_bridge/bridge_webadmin.py`

Current state:

- helper mode/status fields now exist in runtime status snapshots
- the TUN / Routing payload carries helper state for operator visibility

Still missing:

- helper pid once a separate helper process exists
- structured helper route apply/remove results
- helper reconnect-attempt counters if reconnect/restart logic becomes more
  complex

### Proposed config shape

Add a new top-level section:

```json
{
  "tun_execution": {
    "mode": "inline",
    "helper_backend": "linux-native",
    "helper_socket": "",
    "helper_apply_network": true,
    "helper_log_level": "INFO"
  }
}
```

Proposed meanings:

- `mode`
  - `inline`: current behavior
  - `helper`: route local desktop TUN through a helper
- `helper_backend`
  - Linux default: `linux-native`
  - supported today: `linux-native`, `linux-python`, `darwin-native`
- `helper_socket`
  - optional explicit Unix socket path
- `helper_apply_network`
  - helper owns address/route/DNS/firewall apply-remove
- `helper_log_level`
  - helper-side log verbosity

Recommendation for first implementation:

- keep `inline` as the default on every platform
- accept `helper` on Linux today
- accept `helper` on macOS with `darwin-native` when the host can elevate the
  helper subprocess
- reject unsupported platform/backend combinations with clear configuration
  errors

### Actual helper launch flow today

For Linux helper mode in the current branch:

1. `Runner` loads config
2. `Runner` generates a random session token
3. `Runner` chooses a socket path in a user-private runtime directory
4. `Runner` launches the helper module as a separate local subprocess
5. when the selected backend is `linux-native` and the desktop runtime is
   still unprivileged, `Runner` invokes `sudo` for the helper subprocess only
   rather than re-executing the whole runtime
6. `Runner` connects the local helper client to that process
7. runtime authenticates and can send `OPEN_TUN`
8. `ChannelMux` uses the helper-backed backend path for local TUN packet I/O

### Target helper launch flow for new native backend hardening

For any native backend hardening still to build:

1. unprivileged `Runner` loads config
2. `Runner` generates a random session token
3. `Runner` chooses a socket path in a user-private runtime directory
4. `Runner` launches a separate elevated helper process with compact effective
   helper config
5. helper starts under privilege and binds the Unix socket
6. runtime connects, authenticates, and sends `OPEN_TUN`
7. helper returns the effective interface and state
8. ChannelMux begins TUN packet exchange through helper IPC

On macOS, the helper's `OPEN_TUN` implementation opens Darwin `utun` and the
helper's `APPLY_NETWORK` / `REMOVE_NETWORK` implementations invoke the Darwin
hook scripts with the same `TUN_routing`-derived environment that inline Python
already uses. The remaining work is proving this flow under real elevated
macOS execution.

### Suggested CLI surface

Add CLI flags through `bridge_tun_helper_settings.py`:

- `--tun-execution-mode`
- `--tun-helper-backend`
- `--tun-helper-socket`
- `--tun-helper-apply-network`
- `--log-tun-helper`

These should be mirrored into WebAdmin config editing the same way other nested
sections are surfaced.

### Helper module entrypoint status

The helper server module now provides:

- `python -m obstacle_bridge.bridge_tun_helper_server`
- helper CLI parsing for socket path, session token, backend, and helper log
  level
- an async `run_helper_server(...)` contract that starts the helper and serves
  until a stop event is set

Current limitation:

- the default helper launch path now prefers the native Linux backend, while
  the `linux-python` memory backend remains available as an explicit scaffold
  fallback for focused tests and non-privileged protocol work
- the native Linux backend now uses helper-subprocess-only `sudo` launch when
  the desktop runtime itself is still unprivileged
- `Runner` now hands the helper a compact effective launch config through a
  short-lived private JSON file passed by `--config-path`, so the elevated
  helper no longer needs its session token and launch knobs expanded directly
  onto the process command line
- for the native Linux backend, `Runner` now also prefers a direct launch when
  the current Python executable or current process already carries
  `CAP_NET_ADMIN` or `CAP_SYS_ADMIN`; helper-subprocess `sudo` remains the
  fallback only when that capability path is unavailable
- when helper-managed TUN services use `helper_apply_network=true`, the runtime
  now also suppresses listener-side TUN `on_created` / `on_stopped` host-network
  hooks so the helper remains the sole owner of the privileged host-network
  lifecycle instead of double-running the old runtime hook path
- elevated proof is still narrower than the full helper-owned route/DNS/firewall
  lifecycle now implemented in the native backend

## Current Test Coverage

The branch already has both focused unit coverage and real elevated Linux
coverage for the shipped helper-owned TUN lifecycle.

### Unit tests

Current unit coverage includes:

- `tests/unit/test_tun_helper_settings.py`
- `tests/unit/test_tun_helper_protocol.py`
- `tests/unit/test_tun_helper_client_server.py`
- `tests/unit/test_tun_helper_server_entrypoint.py`
- `tests/unit/test_tun_helper_linux_backend.py`
- `tests/unit/test_tun_helper_macos_backend.py`
- `tests/unit/test_runner_tun_helper.py`
- `tests/unit/test_channel_mux_tun_helper.py`
- companion parser coverage in `tests/unit/test_embeddable_core.py`

Current admin coverage includes:

- helper state in runtime snapshots
- helper fields in the TUN / Routing payload
- TUN-page frontend bindings for helper diagnostics

Current helper-network control coverage includes:

- client/server round trips for `APPLY_NETWORK` and `REMOVE_NETWORK`
- ChannelMux helper-mode tests that verify automatic apply on open and remove on
  close for helper-managed TUN devices
- runner tests that verify helper mode can launch the helper module as a real
  subprocess, still exchange helper control messages, suppress the old
  whole-process Linux `sudo` relaunch in helper mode, and invoke `sudo` only
  for the native Linux or macOS helper subprocess when privilege is needed
- native-backend tests that verify Linux-only gating, `OPEN_TUN`, packet read
  delivery, packet write accounting, runtime snapshots, and backend shutdown
  against mocked Linux TUN syscalls
- native Darwin backend tests that verify macOS-only gating, `OPEN_TUN`, utun
  frame unwrap/wrap behavior, packet accounting, hook payload construction for
  client/server Darwin scripts, and backend shutdown against mocked Darwin
  syscalls

### Integration tests

Current elevated integration coverage now includes a first real helper-backed
Linux lane in `tests/integration/test_linux_elevated.py`:

- helper mode with `tun_execution.mode=helper`
- native helper backend selection
- real `/dev/net/tun` ownership inside the helper subprocess
- helper-owned IPv4 and IPv6 tunnel-address programming plus non-default
  included-route programming on that real TUN interface
- end-to-end packet carriage over the overlay while Admin Web reports active
  helper runtime state
- a second helper-managed route-policy lane that proves excluded-route install,
  Linux full-tunnel policy-rule installation, and teardown cleanup for the
  helper-owned network mutations under elevated Linux execution
- a third helper-managed firewall lane that proves Linux server-side
  forwarding/NAT/TCPMSS apply/remove on the real privileged helper path for a
  peer-instantiated TUN listener, including cleanup after shutdown
- a fourth helper-loss lane that proves post-start native helper subprocess
  death is surfaced through runtime/Admin status while preserving the last
  known helper runtime snapshot for diagnostics
- a fifth helper-failure lane that proves a native helper-side
  `apply_network` failure after partial route/address programming rolls back
  those real host mutations and reports structured helper `last_failure`
  cleanup diagnostics while the helper subprocess itself remains alive
- a sixth helper-cleanup lane that proves native helper death during
  `remove_network` after earlier cleanup steps have already run, proving on
  the real privileged helper path that route cleanup may already be gone while
  helper-owned firewall state is still left behind until an explicit
  host-side cleanup

### Current integration-coverage boundary

The elevated helper lanes now cover the main Linux-first adverse lifecycle
claims that were previously still open:

- post-start helper death while the runtime stays alive and reports the loss
- rollback after partial helper apply failure on the real privileged path
- helper death during partial cleanup after earlier remove steps have already
  run and before helper-owned firewall teardown completes

Current elevated integration coverage also includes a first real helper-backed
macOS lane in `tests/integration/test_macos_elevated.py`:

- helper mode with `tun_execution.mode=helper`
- `darwin-native` helper backend selection
- helper subprocess elevation through the same Python helper entrypoint used by
  normal macOS helper mode
- real Darwin `utun` creation inside the helper subprocess
- helper-owned invocation of `scripts/client-tun-hook-macos.sh` and
  `scripts/server-tun-hook-macos.sh` for apply/remove lifecycle ownership
- Admin Web helper runtime status reporting for the created `utun` interfaces
- live packet-carry proof across the helper-backed overlay path
- live route and DNS apply/remove proof on a real elevated Darwin path
- post-start helper-death proof that preserves the last helper runtime snapshot
  and raises the manual-cleanup warning when helper-owned route or DNS state
  may still remain
- teardown cleanup that verifies the helper-owned `utun` interfaces disappear

Remaining work is now broader hardening rather than an uncovered first-lane
elevated helper scenario on either Linux or macOS. The main uncovered areas
have narrowed to richer operator recovery and repair behavior, especially if a
future Darwin helper starts owning persistent host state beyond what today's
hook-driven route and DNS path can clean up during normal shutdown.

The first elevated case should stay:

- Linux only
- single peer
- single helper-backed TUN interface

The first elevated/live Python/macOS helper proof now mirrors that narrow
shape with a single-peer helper-backed `utun` lane and helper-side invocation
of the Darwin hook scripts.

## Open TODOs

These are the actionable next steps for the helper effort.

### Next practical follow-ups

- decide whether helper mode remains single-TUN initially or whether multiple
  local TUN services are worth supporting immediately
- harden operator recovery paths further after helper-death cleanup failures,
  for example partial-repair persistence, narrower per-resource repair actions,
  or richer live repair orchestration beyond the current post-repair
  verification/reporting pass
- broaden macOS helper-death recovery beyond kernel interface/route cleanup
  into explicit repair UX if Darwin later grows persistent helper-owned state
  that can survive helper process death

### Deliberately deferred

- Swift/macOS packaging parity for the helper split through the Apple-native
  helper direction in `docs/MACOSAPP_DESIGN.md`
- Windows helper/service design
- richer helper logging transport and reconnect counters
- any helper awareness of shared-TUN peer ownership beyond pure host-local
  packet I/O
