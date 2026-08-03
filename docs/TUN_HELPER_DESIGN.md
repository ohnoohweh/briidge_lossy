# TUN Helper Design

## Goal

Keep desktop TUN privilege boundaries narrow and behaviorally aligned across
the supported implementations. Linux/Python, macOS/Python, and macOS/Swift now
all have a helper-owned TUN and host-network boundary for the covered paths,
while the main ObstacleBridge runtime remains responsible for overlay
transport, mux policy, SecureLink, Admin Web, proxy serving, and configuration.

This document now records the implemented cross-platform helper contract rather
than a Linux-first proposal. Linux owns `/dev/net/tun` and host-network state
through its native helper backend; macOS/Python owns Darwin `utun` and
route/DNS lifecycle through the `darwin-native` helper plus existing hook
scripts; macOS/Swift owns the same boundary through its Apple-native package,
`SMAppService`, and XPC helper transport. iOS intentionally stays outside this
desktop helper split because Network Extension is already the platform-owned
privileged packet boundary there.

## Why

The helper split is now the desktop model for reducing privilege while keeping
operator behavior consistent across implementations. The runtime still owns the
large, fast-changing application surface:

- overlay transport sessions
- SecureLink and compression
- ChannelMux policy decisions
- Admin Web and live status APIs
- proxy provider
- lifecycle/config orchestration
- peer authentication state

The privileged side is intentionally small and host-local:

- local TUN device open/read/write
- interface address and MTU configuration
- route/DNS/firewall or hook execution
- helper runtime diagnostics and cleanup state

This split matters even after the first working helper paths have landed. It
keeps network privilege away from the overlay and Admin runtime, gives Linux,
macOS Python, and macOS Swift the same operator-visible status concepts, and
makes abnormal lifecycle cases explicit: helper disconnect, helper death,
partial apply failure, cleanup attempted/ok state, and stale-state repair
guidance. Platform mechanisms differ, but the reason for the split is the same:
the broad runtime should stay unprivileged, while the narrow helper owns only
the host packet and network-control boundary.

The legacy whole-process `sudo` path remains useful as an inline fallback while
helper mode matures, but it is no longer the target architecture for covered
desktop TUN paths.

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
work for the covered paths, the native Darwin backend owns Python/macOS `utun`
and hook lifecycle on a live elevated path, and Swift/macOS now exposes the same
helper boundary through an Apple-native package/XPC shape with a loopback
fallback for unapproved or unreachable helper packages.

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
12. Swift/macOS helper packaging parity is implemented through the
    Apple-native app package, launch-daemon plist, `SMAppService` lifecycle
    controls, XPC command transport, packaged-helper packet carry, helper-loss
    reporting, and stale-package repair coverage; iOS stays on its existing
    Network Extension packet boundary rather than adding a separate helper
    process

### Remaining milestones

1. decide how much of the existing whole-process `sudo` relaunch remains as
   the default inline fallback as helper mode matures
2. continue hardening operator recovery after post-start helper loss and
   partial cleanup failure paths

## Parity activities for macOS Python and macOS Swift

Recent Linux-native changes expanded the practical helper contract beyond basic
packet I/O and route apply/remove. To keep macOS Python and macOS Swift aligned
with that behavior, both macOS implementations need the same operator-visible
semantics even when the cleanup mechanism differs.

### Python/macOS parity status

Python/macOS now has live elevated `darwin-native` coverage for real `utun`
creation, packet carriage, route/DNS apply/remove, helper-death reporting, and
hook-driven cleanup verification. Its runtime snapshot mirrors the Linux helper
fields that are meaningful on Darwin: structured `last_failure`, last
apply/remove payloads, packet counters, cleanup attempted/ok state, and
operator-facing recovery warnings when helper-owned route or DNS state may
still need manual inspection.

The remaining Python/macOS parity work is narrower than the Linux backend
because Darwin cleanup is hook-driven rather than Linux snapshot-replay driven:
keep the Darwin hook scripts idempotent across repeated apply/remove and
partial failure, and only add automated repair UX if Darwin later grows
persistent helper-owned state that survives helper death in a way the current
normal shutdown hooks cannot clean up.

### Swift/macOS parity status

Swift/macOS follows the same responsibility split: the app/runtime owns overlay,
ChannelMux, SecureLink, config, Admin UI, and policy; the helper boundary owns
the host interface, route/DNS hook execution, packet I/O, and cleanup lifecycle.
The Admin/runtime status model uses the same concepts as Python helper mode:
helper connected state, backend/package transport, packet counters, structured
last failure, cleanup outcome, selected IPC transport, and stale-state recovery
warnings.

Swift/macOS now also mirrors the Linux recovery contract at the UI/API boundary:
if a packaged XPC helper is lost after network state was applied, the
`tun_helper.recovery` object reports `needs_manual_cleanup`,
`stale_network_possible`, `helper_owned_network_state_may_remain`, and a Darwin
route/DNS repair hint. Automated stale-state repair remains intentionally
Linux-native only because the Linux backend can replay cleanup from a runtime
snapshot; Swift/macOS exposes `/api/tun-helper/repair` with the same
`repair_supported_only_for_linux_native_helper` reason and the WebAdmin repair
button is gated to `linux-native`.

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
  `NEPacketTunnelProvider`; because the whole iOS packet-tunnel stack already
  runs inside that privileged extension boundary, the desktop helper split does
  not reduce iOS privilege or add useful isolation

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

For iOS, parity should stay behavioral rather than structural: the iOS app and
Network Extension should continue to match routing, packet-carry, cleanup, and
Admin/status semantics where applicable, but should not grow a second local TUN
helper process merely to mirror the desktop implementation shape. The iOS
`/api/tun-routing/status` payload therefore mirrors the desktop verification
fields, and the Swift implementation follows the same packet-level verification
contract used by the desktop runtimes:

- Python/Linux and Python/macOS verify peer/global connectivity with an
  internally generated ICMP/ICMPv6 echo probe injected through the active TUN
  path and matched against a corresponding echo reply
- macOS/Swift host-runner verifies peer/global connectivity with the
  same internally generated ICMP/ICMPv6 echo probe contract instead of
  shelling out to the operating system `ping` command
- iOS/Swift `NEPacketTunnelProvider` uses the same internal ICMP/ICMPv6
  echo probe contract through the active tunnel path rather than
  `Network.framework` endpoint-readiness checks or an external `ping` binary

The harmonized design target is therefore a shared verification contract with
platform-specific transport mechanisms. For connectivity monitoring, that
contract is shared across all covered runtimes:

- Python/Linux
- Python/macOS
- Swift/macOS
- Swift/iOS

Those runtimes all use the same operator-visible connectivity-monitoring
approach: an internally generated ICMP/ICMPv6 echo probe is injected through
the active TUN path, and verification succeeds only when a matching echo reply
is observed.

The remaining differences are around runtime lifecycle, packaging, helper
ownership, cache freshness strategy, and UI/reporting polish, not around the
core connectivity-monitoring method itself.

The shared verification contract is:

- config verification: confirm that the expected tunnel addresses are present
- peer connectivity verification: inject a real probe packet through the TUN
  path and require a corresponding response packet from the peer side
- global connectivity verification: inject a real probe packet through the TUN
  path toward a configured Internet target and require a corresponding response

Python, macOS/Swift host-runner, and iOS/Swift packet-tunnel provider all use
the injected-packet contract. The remaining Apple-side work is around
performance, caching, and UI presentation rather than semantic probe parity.

### Intended injected ping frame contract

Across Python/Linux, Python/macOS, Swift/macOS, and Swift/iOS, the probe
contract is a real ICMP echo packet written into the active tunnel path and
matched against a corresponding echo reply read back from that same path.

#### IPv4 echo request

- IPv4 header:
  - version `4`, IHL `5`
  - DSCP/ECN `0`
  - total length `20 + 8 + payload_length`
  - identification: probe-local monotonic or random value
  - flags/fragment offset `0`
  - TTL `64`
  - protocol `1` (`ICMP`)
  - source address: active tunnel IPv4 address
  - destination address: selected probe target IPv4 address
  - header checksum: computed after all fields are filled
- ICMP payload:
  - type `8` (`echo request`)
  - code `0`
  - checksum: computed over ICMP header plus payload
  - identifier: stable ObstacleBridge probe identifier for this runtime
  - sequence: monotonic per outstanding probe
  - payload bytes: fixed signature plus nonce/timestamp, for example:
    - magic: `OBTP`
    - probe kind: `peer` or `global`
    - send timestamp / nonce

#### Expected IPv4 echo reply

- IPv4 header:
  - source/destination reversed from the request
  - protocol still `1`
- ICMP payload:
  - type `0` (`echo reply`)
  - code `0`
  - same identifier as the request
  - same sequence as the request
  - payload bytes echoed unchanged

The verification should only succeed when the reply matches the outstanding
request's identifier, sequence, and payload signature. Any unrelated ICMP,
other packet types, or a timeout without a matching reply should report failure
or `no response`.

#### Linux shared-TUN server local-probe injection

For Linux `server_shared` TUN services with exactly one active peer binding, the
server-side Python probe path now uses a kernel-visible IPv4 injection path for
IPv4 targets instead of the older direct ChannelMux-local injection:

- the probe still reuses the ObstacleBridge raw ICMP packet builder
- the request source stays the server-local tunnel address, for example
  `192.168.106.1`, unless `global_connectivity_source_ipv4` overrides the IPv4
  source for the Admin Web global probe
- the packet is emitted through a raw socket bound to the active TUN ifname,
  for example `obtun0`
- this makes the request visible on `obtun0` packet captures before the helper
  forwards it into the shared-TUN / ChannelMux path
- the matching reply to the server-local tunnel address is consumed by the
  outstanding probe waiter and dropped locally instead of being forwarded back
  into shared-TUN peer routing

This Linux shared-TUN server path intentionally covers more of the local stack
than the generic internal-injection path:

`kernel-visible probe emission -> obtun0 -> TUN helper -> shared TUN -> ChannelMux -> peer -> Internet`

Other runtimes, non-shared TUN services, and non-IPv4 targets continue to use
the existing internal injected-probe contract until they gain an equivalent
kernel-visible path.

When operators need the server-side global probe to use a different IPv4 source
inside the tunnel fabric, `TUN_routing.global_connectivity_source_ipv4` may
provide that explicit source address, for example `192.168.108.31`.

#### IPv6 echo request/reply

If the selected target is IPv6, the same contract should use ICMPv6 instead:

- request type `128`, code `0`
- reply type `129`, code `0`
- source address: active tunnel IPv6 address
- destination address: selected probe target IPv6 address
- ICMPv6 checksum: computed with the IPv6 pseudo-header
- identifier / sequence / payload echo rules: same as IPv4

### Current harmonization state

The main implementation impact is not in the Admin payload shape; that is
already close across Python and Swift. The key requirement was to make each
platform mean the same thing by "verified".

- Python means "an internally generated ICMP echo request was injected
  through the active TUN path and a matching echo reply was observed"
- macOS/Swift host-runner means "an internally generated ICMP echo request
  was injected through the active TUN path and a matching echo reply was
  observed"
- iOS/Swift means "an internally generated ICMP echo request was
  injected through the active TUN path and a matching echo reply was observed"

The following repo surfaces need to stay aligned:

- Admin payload field names and state values:
  - `tun_config`
  - `tun_connectivity`
  - `tun_global_connectivity`
  - `ok`, `state`, `summary`, `detail`, `target`
- target selection rules:
  - peer probe should use the tunnel peer/gateway address, not merely the
    overlay transport endpoint host/port
  - global probe should resolve `global_connectivity_host` and probe the chosen
    IP, while keeping that host configurable rather than hard-coded policy
- timeout and freshness semantics:
  - desktop Python currently uses background refresh plus cached/pending states
  - iOS should keep the same observable freshness/reporting contract even if the
    packet-generation mechanism is in-process
- packet-flow plumbing:
  - iOS must correlate outbound injected probes with inbound replies at the
  `NEPacketTunnelFlow` boundary
  - replies must be identified before normal tunnel data handling consumes or
    obscures the probe outcome

For iOS, config verification should follow observed effective Network
Extension tunnel addresses rather than a separate packet-pump bookkeeping flag.
If the expected tunnel addresses are already installed, config verification
should report success even while packet forwarding is still transitioning.

### TODO: shared probe lifecycle and remaining UI cleanup

Python uses an internal packet-level TUN probe implementation, and both
macOS/Swift host-runner and iOS/Swift use the same internal injected-ICMP
probe path. Python/Linux, Python/macOS, Swift/macOS, and Swift/iOS therefore
share the same core connectivity-monitoring approach. The remaining parity work
is to keep the Admin payload/UI semantics identical across runtimes and to
harden probe lifecycle behavior.

#### Implementation TODO

1. Keep the probe contract identical across Python and Swift:
   - same packet formats
   - same identifier and sequence matching rules
   - same payload signature / nonce handling
   - same timeout and retry policy
   - same success criteria: matching echo reply observed before timeout
2. Keep macOS/Swift host-runner and iOS/Swift on the same internal
   injected-ICMP probe path, rather than regressing to any
   external `ping`-based
   verification path.
3. Add an explicit probe manager abstraction rather than embedding packet-build
   and reply-correlation logic directly into Admin snapshot code.
4. Ensure probe generation runs off the timeout-sensitive Admin snapshot path;
   the snapshot should consume cached/latest probe results rather than blocking
   on packet injection and reply wait.
5. Add explicit packet-flow interception/correlation points so injected probe
   replies are recognized before normal tunnel traffic handling loses the
   ability to match them to the outstanding verification request.
6. Support both IPv4 and IPv6 probe generation and matching.
7. Keep the global-connectivity target configurable through
   `global_connectivity_host`; do not hard-code platform-specific probe policy.
8. Add unit coverage for:
    - IPv4 request encoding
    - IPv6 request encoding
    - checksum generation
    - reply matching
    - timeout/no-response state
    - stale-reply rejection
    - concurrent probe bookkeeping
9. Add integration coverage that proves a successful reply path and a real
   no-response path on Python and Swift runtimes.

#### Python status in this branch

Python now has the first internal probe slice:

- `ChannelMux` builds ICMP/ICMPv6 echo requests, injects them through the same
  TUN path used by inline and helper mode, and intercepts matching echo replies
  before normal local-TUN delivery.
- `Runner` exposes that probe path to Admin Web as an async runtime call.
- Admin Web keeps the existing cached/pending refresh contract, but the
  background refresh now uses the internal probe instead of shelling out to
  `ping`.
- The payload now carries `value_ms`, `last_success_ago_s`, and
  `last_success_rtt_ms` so the UI can show measured RTT or `n/a` plus freshness.

#### UI / Admin payload TODO

The current Admin payload is too implementation-shaped. The user-facing TUN
page should emphasize the measured value and freshness, not the probe
mechanism.

1. Change the connectivity display so the primary user-visible value is the
   actual measured round-trip result for the latest successful probe:
   - example: `12 ms`
2. If the latest probe failed or timed out, display `n/a` as the value.
3. When the displayed value is `n/a`, also display how long it has been since
   the last successful probe:
   - example: `n/a, last success 37 s ago`
4. Store and expose per-check timestamps needed for that UI:
   - `last_checked_at`
   - `last_success_at`
   - `last_success_rtt_ms`
5. Keep `detail` as a secondary diagnostic field for operator drill-down, not
   the primary value shown in the table/card.
6. Keep the same three verification rows:
   - TUN config
   - peer connectivity
   - global connectivity
7. Keep the UI semantics identical across Python and Swift so the same TUN page
   language means the same thing regardless of runtime.
8. Prefer one normalized Admin payload shape for both implementations, for
   example:
   - `value_ms`: latest successful round-trip measurement or `null`
   - `last_success_ago_s`: elapsed seconds since the last successful probe or
     `null`
   - `state`: `verified`, `failed`, `pending`, or `skipped`
   - `target`
   - `detail`

Until the Swift/iOS side lands, Python and Apple runtimes should still be
treated as having different probe implementations with different evidentiary
strength even if the Admin payload field names look similar.

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
   lifecycle ownership; macOS helper mode now has a unit-covered Darwin backend
   plus elevated/live proof for privileged helper launch, real `utun`
   creation, packet carry, Darwin hook route/DNS effects, helper-death
   reporting, and cleanup

This means the branch now answers "can the Linux product run with a reduced
helper-owned host-network boundary?" for the covered Linux paths, and "can
Python/macOS use the same helper boundary without relaunching the whole runtime
through sudo?" on a real elevated host. The next macOS parity question is how
the Swift app should package and expose the same split through an Apple-native
privileged helper.

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

Current elevated integration coverage also includes real Python/macOS inline
and helper-backed lanes in `tests/integration/test_macos_elevated.py`:

- inline mode with `tun_execution.mode=inline`
- helper mode with `tun_execution.mode=helper`
- `darwin-native` helper backend selection
- real Darwin `utun` creation in the inline runtime and in the helper
  subprocess
- inline invocation of `scripts/client-tun-hook-macos.sh` and
  `scripts/server-tun-hook-macos.sh` through service lifecycle hooks
- helper subprocess elevation through the same Python helper entrypoint used by
  normal macOS helper mode
- helper-owned invocation of `scripts/client-tun-hook-macos.sh` and
  `scripts/server-tun-hook-macos.sh` for apply/remove lifecycle ownership
- Admin Web TUN config, peer connectivity, and global connectivity verification
  on the inline path
- Admin Web helper runtime status reporting for the created `utun` interfaces
- live packet-carry proof across the inline and helper-backed overlay paths
  while inline stats and helper packet counters advance
- live route and DNS apply/remove proof on a real elevated Darwin path
- post-start helper-death proof that preserves the last helper runtime snapshot
  and raises the manual-cleanup warning when helper-owned route or DNS state
  may still remain
- teardown cleanup that verifies helper-owned `utun` interfaces and helper-
  managed routes disappear

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
shape with single-peer helper-backed `utun` lanes, helper-side invocation of
the Darwin hook scripts, packet-carry proof, route/DNS verification, and
helper-loss cleanup reporting.

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

### Swift/macOS parity action items

This section tracks Swift/macOS parity separately from the Python/macOS helper.
The current Swift work now includes the contract, host-runner integration
slice, packaged helper skeleton, XPC command path, Admin activation surface,
and elevated packet-carry coverage that becomes a required packaged-XPC pass
once the test host has approved the bundled helper. Functional Swift/macOS
helper parity is now covered for local signed app activation, register,
unregister, stale-version repair guidance, packaged-XPC packet carry, route/DNS
effects, and helper-loss cleanup. Release notarization remains a distribution
pipeline concern rather than an uncovered helper behavior.

Done in this branch:

- `ObstacleBridgeTunHelperContract.swift` defines the Swift helper
  command/request model and Python-shaped runtime snapshot fields.
- The macOS host runner publishes a Python-shaped `tun_helper` status block
  with backend, lifecycle, realized interface, MTU, hook result, failure, and
  packet counters for the current privileged host-runner TUN path.
- The host runner no longer owns the `utun` adapter directly. It talks through
  `ObstacleBridgeTunHelperClienting`, an in-process macOS helper client
  wrapper, and a helper-client factory seam so the backend can later be swapped
  for a real XPC helper without reshaping overlay or ChannelMux code.
- The delivered helper boundary keeps app/runtime ownership of overlay,
  ChannelMux, SecureLink, config, Admin UI, and policy, while the helper-side
  client boundary owns `utun`, MTU/link setup, route/DNS apply/remove, packet
  I/O, and cleanup.
- A small in-process command server, command transport protocol, loopback
  transport, XPC-shaped envelope transport, packet/event envelope model, and
  loopback helper client exercise the same `OPEN_TUN`, `APPLY_NETWORK`,
  `REMOVE_NETWORK`, `WRITE_PACKET`, `SNAPSHOT`, and `STOP` shape that the
  future XPC connection should carry.
- Swift names the same frame kinds used by the Python helper protocol:
  `CONTROL_REQUEST`, `CONTROL_RESPONSE`, `PACKET_FROM_HELPER`,
  `PACKET_TO_HELPER`, and `EVENT`.
- Packets read from `utun` travel through a `PACKET_FROM_HELPER` envelope
  before they are handed back to the host runtime.
- Runtime packet writes travel through a `PACKET_TO_HELPER` transport path
  before reaching the backend write operation.
- Helper events travel through an `EVENT` envelope before the in-process path
  forwards them to the host-runner event sink.
- Runtime-originated XPC-shaped command and packet envelopes carry monotonic
  `seq` numbers, and the transport rejects command or packet responses that do
  not echo the expected sequence.
- The loopback helper client serializes helper operations and blocks network
  apply or runtime packet writes until `OPEN_TUN` has produced an actual helper
  interface name, leaving structured failure diagnostics when callers violate
  that ordering.
- Swift probes cover fake-helper open/apply/write/remove/stop ordering,
  packet-counter state, command/packet/event envelopes, sequence mismatch
  rejection, pre-open apply/write gating, and direct parity between the Swift
  helper runtime snapshot and Python `DarwinTunHelperBackend.local_snapshot()`
  for shared fields.
- Build wiring includes the shared helper contract in the macOS host-runner
  and app builds, with Xcode/source-list tests guarding that inclusion.
- The first helper package skeleton is present: the macOS app build compiles a
  standalone `ObstacleBridgeTunHelper` executable, bundles it under
  `Contents/Library/LaunchServices`, writes a LaunchDaemon plist skeleton under
  `Contents/Library/LaunchDaemons`, and exposes app-side package status plus
  register/start/stop lifecycle results. The app-side lifecycle now uses
  `SMAppService.daemon(plistName:)` for real register/unregister calls when
  the bundled helper and plist are present, reports the current
  `SMAppService` status, exposes approval-required state, and provides an
  app-callable action that opens System Settings Login Items when admin
  approval is needed.
- The first real XPC transport slice is present: the helper plist declares an
  XPC Mach service, the helper executable runs an `NSXPCListener` by default,
  the app side can ping the service after registration, package status reports
  XPC reachability, and a shared `ObstacleBridgeNSXPCTunHelperCommandTransport`
  maps the delivered command/packet envelope contract onto `NSXPCConnection`.
  The XPC service now delegates `OPEN_TUN`, `APPLY_NETWORK`,
  `REMOVE_NETWORK`, `PACKET_TO_HELPER`/`WRITE_PACKET`, `SNAPSHOT`, and `STOP`
  envelopes to the shared `ObstacleBridgeTunHelperCommandServer` and a
  helper-owned backend instead of returning a command stub. Focused Swift
  probes instantiate the service with a fake backend and prove XPC-shaped
  command dispatch, packet writes, sequence echoing, and error responses.
- The macOS host runner now selects the real
  `ObstacleBridgeNSXPCTunHelperCommandTransport` when package status reports
  the helper XPC service as reachable, while retaining the in-process loopback
  transport as the development fallback. Helper status includes the selected
  transport kind (`xpc`, `loopback`, or the last known value) so Admin/runtime
  snapshots show whether the packaged helper path or fallback path is in use.
- Helper-to-runtime callbacks are now part of the XPC contract. The host-side
  XPC connection exports `ObstacleBridgeTunHelperXPCClientCallbacks`, the
  helper-side connection declares that callback interface, and helper backend
  packet/event sinks forward `PACKET_FROM_HELPER` and `EVENT` envelopes back
  to the runtime packet and event sinks. The host runner advances the
  runtime-side `packets_to_runtime` counter when packets arrive through the
  XPC callback path, preserving the Python counter direction.
- Privileged `utun` open/write/snapshot/stop ownership now follows the XPC
  path when the packaged helper is reachable: the host runner selects
  `ObstacleBridgeNSXPCTunHelperCommandTransport` before the loopback fallback,
  sends `OPEN_TUN`, `PACKET_TO_HELPER`/`WRITE_PACKET`, `SNAPSHOT`, and `STOP`
  requests over XPC, and receives the helper backend's runtime payload,
  including the realized kernel interface name. The helper-side XPC service
  constructs the real macOS backend (`ObstacleBridgeInProcessMacOSTunHelperClient`)
  inside the helper process, so the production fd owner is the helper rather
  than the host runner whenever XPC helper mode is active. The loopback backend
  remains only as the development fallback for uninstalled or unreachable
  helper packages.
- Darwin route/DNS hook ownership now follows the helper boundary too. The
  host runner still renders the existing lifecycle hook argv and the filtered
  Python-parity environment, but no longer launches the hook process itself.
  Instead it sends `APPLY_NETWORK` / `REMOVE_NETWORK` to the helper client; the
  helper backend runs the bundled Darwin hook script, merges the helper-owned
  environment, emits a `macos_tun_hook_completed` event, and records hook
  success or structured failure diagnostics in the helper runtime snapshot.
  Focused Swift probes use harmless temporary hook scripts to prove helper-side
  hook execution, environment propagation, remove-state clearing, event
  emission, and nonzero-exit failure reporting.
- Swift/macOS helper status now carries the Python-shaped runtime and
  operational diagnostics needed for functional parity: apply/remove counters,
  last apply/remove payloads, actual interface name, runtime MTU, packet
  counters in both directions, hook action/argv/env, structured last failure,
  stopped state, and cleanup attempted/ok flags. The host-runner `tun_helper`
  status also lifts the most important fields to the top level, reports the
  selected transport, exposes XPC disconnect reason/detail when the packaged
  helper becomes unreachable, publishes a cleanup summary based on the last
  helper runtime snapshot, and emits the Python/Linux-shaped `recovery` warning
  object when helper-owned route or DNS state may still need manual cleanup.
  Because automated snapshot repair exists only for `linux-native`, the Swift
  Admin repair endpoint returns `repair_supported_only_for_linux_native_helper`
  and the shared WebAdmin repair button remains Linux-gated while still showing
  macOS recovery guidance.
- Helper approval and activation are now actionable through the macOS Admin API
  rather than only visible in raw status JSON. `GET /api/tun-helper/status`
  returns the host-runner `tun_helper` package/runtime view, and
  `POST /api/tun-helper/action` accepts `status`, `register`, `start`, `stop`,
  and `open_approval_settings`. Each action returns the SMAppService/package
  result plus a fresh `tun_helper` snapshot, so Admin/macOS callers can expose
  approval-required state, XPC reachability, registration failures, and
  System Settings approval handoff without taking ownership of the privileged
  TUN operations. The app/runtime side still owns overlay, ChannelMux,
  SecureLink, config, Admin UI, and policy; the helper package exposes only
  the narrow TUN and host-network surface.
- The macOS helper package now self-validates the bundled helper before
  registration. Package status runs the bundled `ObstacleBridgeTunHelper
  --status-json` path for an explicit app bundle, reports
  `bundled_helper_version`, `bundled_helper_status_ok`,
  `helper_version_matches_expected`, and `helper_package_valid`, and blocks
  install support when the helper's reported version does not match
  `expected_helper_version`. Stale or mismatched helper packages report
  `lifecycle_phase=helper_version_mismatch`, `repair_action=stop_then_register`,
  and operator guidance to unregister/stop the helper, replace or rebuild the
  bundle, and register again. Focused Swift/macOS tests cover both the real
  built app bundle's matching helper self-report and a synthetic stale-helper
  bundle.
- The first live/elevated Swift/macOS helper lane is now covered by
  `tests/integration/test_macos_swift_elevated.py` and
  `scripts/run_macos_swift_elevated_tests.sh`. That lane builds the macOS app
  bundle, launches `ObstacleBridgeHostRunner` from inside the bundle so the
  bundled Darwin hook scripts are used, pairs it with a Python
  `darwin-native` helper peer, creates a real Swift-owned `utun`, applies the
  client Darwin hook, verifies Admin helper runtime status including actual
  interface name and MTU, sends a packet through the Swift TUN path, observes
  Swift `packets_to_runtime` and Python peer `packets_from_runtime` movement,
  and verifies helper-owned interface teardown.
- The elevated Swift/macOS lane now also includes
  `test_macos_swift_elevated_packaged_xpc_helper_carries_packets_when_approved`.
  It drives the Admin helper registration action, waits for packaged XPC
  reachability, requires the runtime helper transport to be `xpc`, and then
  proves the same live packet-carry path through the packaged helper. If macOS
  reports `SMAppService` `requires_approval`, the test skips with an explicit
  System Settings approval reason instead of silently falling back to the
  loopback helper.
- Swift route/DNS apply/remove effects beyond the first narrow address lane are
  now covered by
  `test_macos_swift_elevated_helper_applies_routes_and_dns_live`. The test
  runs the built app bundle on a real elevated Darwin host, forces the
  non-packaged loopback helper transport so stale or approved XPC package state
  cannot change the lane being tested, verifies helper-propagated
  `INCLUDED_ROUTES`, `INCLUDED_ROUTES6`, `DNS1`, and `DNS2`, checks live IPv4
  and IPv6 routes through the created `utun`, checks DNS application through
  `networksetup`, asserts the Swift `/api/tun-routing/status` Admin
  verification payload for local config, peer TUN reachability, and global
  connectivity parity with the Linux/Python status payload, and then verifies
  route and DNS restoration after teardown.
- Swift packaged-helper death reporting plus interface/route cleanup is now
  covered by
  `test_macos_swift_elevated_packaged_xpc_helper_death_reports_and_cleans_routes`.
  The host runner now exposes the packaged helper's XPC PID and runtime state
  in the helper package snapshot, detects the `xpc_runtime_lost` condition when
  launchd restarts a helper with an empty runtime after the old helper was
  killed, and reports `helper_disconnect` plus cleanup-needed state. The live
  elevated test kills the real packaged helper process, verifies the helper-
  owned `utun` and included route disappear, and asserts the Admin helper
  snapshot reports the lost packaged-helper runtime.
- Live signed helper activation from an installed macOS app is now covered by
  `test_macos_swift_elevated_installed_signed_app_admin_helper_actions`. The
  test copies the built app bundle into
  `/Applications/ObstacleBridgeSMAppServiceActivationTest.app`, ad-hoc signs
  the installed bundle, launches `ObstacleBridgeHostRunner` from that installed
  app path, and exercises `/api/tun-helper/status` plus `stop`, `register`,
  `start`, and `unregister` Admin helper actions. It verifies the package
  snapshot points at the installed app, is accepted by `SMAppService`, reports
  a valid bundled helper and launch-daemon plist, and proves registered,
  running, and XPC-reachable state when the host has approved the helper. The
  same live lane then installs a locally signed stale helper package at the
  same `/Applications` path, verifies `helper_version_mismatch`,
  `repair_action=stop_then_register`, and the operator repair hint, runs the
  unregister step, replaces the bundle with the valid signed app, and proves
  register plus XPC reachability again. If a fresh host reports
  `requires_approval`, the same test asserts the approval-required fields and
  skips with the exact System Settings action instead of treating an unapproved
  helper as a runtime failure.

No functional Swift/macOS parity work packages remain open in this helper
design. Future release work can still add separate notarization/stapling proof
for the shipping artifact, but the helper behavior itself is now covered by
local signed live tests and focused Swift source/package probes.

iOS remains intentionally out of this desktop helper split. The iOS Network
Extension already runs as the platform-owned privileged packet boundary, so iOS
parity work should focus on matching packet, routing, cleanup, and status
behavior rather than adding a second local helper process.

### Deliberately deferred

- any helper awareness of shared-TUN peer ownership beyond pure host-local

### Windows support workpackages

- Requirements & gap analysis: produce a short spec listing Windows-specific
  API gaps, required permissions, and UX differences; acceptance = maintainer
  sign-off on the spec.
- Research Windows TUN backends: evaluate Wintun, TAP-Windows, and alternatives,
  document pros/cons, and confirm whether the existing Wintun path remains the
  only supported helper backend or whether a real fallback is justified;
  acceptance = backend decision and rationale recorded. Progress: repo review
  now shows only a real Wintun-backed implementation and test surface; no TAP-
  Windows or other Windows TUN backend is currently implemented.
- Privilege elevation & security model: define required privileges (driver
  install, helper launch, optional service), elevation UX (existing UAC
  relaunch vs helper-only elevation), and least-privilege checklist;
  acceptance = checklist and reviewer approval. Progress: current repo review
  confirms that inline Windows TUN already uses whole-runtime UAC relaunch in
  `bridge_runner.py`; helper work should narrow that to helper-only elevation.
  Additional progress: the helper settings/runtime surface now recognizes
  `windows-native` as the only Windows helper backend candidate and uses a
  Windows-specific default endpoint shape (`\\.\pipe\...`) plus a separate
  filesystem runtime directory for helper launch metadata.
- Windows TUN helper core (driver interfacing): adapt the existing inline
  `src/obstacle_bridge/bridge_tun_windows.py` Wintun implementation into a
  helper backend rather than re-implementing Windows TUN from scratch;
  acceptance = helper-backed packet round-trip tests plus parity with the
  current inline packet I/O behavior. Progress: `src/obstacle_bridge/
  bridge_tun_helper_windows.py` now exists and reuses the inline Wintun path
  for helper-side open/read/write/stop; helper-owned network apply/remove is
  still intentionally unsupported in that backend for now.
- Windows service & CLI wrappers: implement service install/uninstall/start/stop
  only if helper-subprocess launch proves insufficient; otherwise document the
  helper-only UAC launch flow and any later service hardening plan; acceptance
  = documented operator flow and a validated smoke test for the chosen launch
  model.
- Integrate Windows backend with existing API/CLI: provide adapter exposing the
  same helper control protocol and ensure existing helpers can select the
  Windows backend; acceptance = existing integration tests run against the
  Windows helper adapter without unnecessary protocol churn. Progress: current
  helper server only supports Unix-domain-socket Linux/macOS backends, so the
  Windows integration slice is concretely a new backend registration plus a
  Windows local IPC transport. Additional progress: the client/server code now
  has explicit local-transport wrapper seams instead of calling Unix-socket
  asyncio APIs directly, and those wrappers fail with a clear Windows
  "transport not implemented yet" error until a real Windows transport lands.
- Testing & CI for Windows: extend the existing Windows elevated lanes to cover
  helper mode, not just inline Wintun mode; acceptance = helper-mode Windows
  elevated coverage added alongside the already existing Windows CI/runtime
  paths.
- Docs & examples: update `docs/TUN_HELPER_DESIGN.md` and add Windows install
  and troubleshooting notes; acceptance = reviewer sign-off on documentation.
- Packaging & installer: produce an installer (MSI/NSIS) or packaging notes to
  install driver and service, including code-signing guidance; acceptance = a
  build artifact and an install verification step documented.
- Release validation & telemetry: create a Windows release checklist and
  optional non-PHI telemetry/error-reporting guidance; acceptance = checklist
  reviewed and a Windows test machine verification step completed.

Note: this project follows the `.codex/skills/obstaclebridge-project` SKILL.md
workflow; progress against each Windows workpackage will be appended to this
document as work progresses and after each tracked step completes.

## Windows — Requirements & Gap Analysis (completed)

Summary
- Goal: provide the same narrow privileged helper contract on Windows as on
  Linux/macOS: helper-owned TUN open/read/write, helper-owned network apply/
  remove, narrow IPC control, and aligned Admin snapshot visibility.
- The repository already ships a working inline Windows Wintun path plus
  Windows-specific elevated test coverage. The remaining Windows work is helper
  parity and operator convenience, not first-time Windows TUN enablement.

Key Windows-specific requirements
- TUN backend: a maintained, signed kernel driver (Wintun preferred) with a
  stable userspace API for open/read/write semantics equivalent to Linux/macOS
  TUN behavior.
- Reuse requirement: the helper design should reuse the delivered inline
  Windows Wintun loader/adapter behavior where practical, especially the
  current ctypes-based `wintun.dll` discovery and session I/O path.
- IPC: secure local IPC suitable for Windows (Named Pipes or AF_UNIX where
  available) with peer validation and session-token auth.
- Driver install and signing: an install-time admin flow (MSI/NSIS) to install
  the TUN driver and, if later required, a hardened helper package or service;
  code-signing and driver-signing guidance are required for production builds.
- Privilege model: least-privilege helper process that owns the driver-facing
  TUN session and any helper-owned host-network mutations; installer or UAC
  elevation performs privileged actions depending on the chosen launch model.
- Network apply primitives: native Windows APIs or PowerShell scripts to apply
  addresses, routes, DNS, and firewall rules in a robust, idempotent manner.
- Diagnostics and Admin parity: helper must export the same snapshot fields
  (connected, pid, last_failure, packet counters) and preserve rollback on
  partial apply failures.

Gaps vs current repo
- Inline Windows TUN implementation is present in `src/obstacle_bridge/bridge_tun_windows.py`.
  That module attempts to import an optional Python `wintun` or `pywintun` wrapper
  and falls back to a robust ctypes-based loader for `wintun.dll`. A runnable
  ctypes example exists at `scripts/wintun_example.py` and `README.md` documents
  runtime and `WINTUN_DIR` usage.
- Helper-backed IPC for Windows (Named Pipe server/client) is not yet
  implemented. The current helper IPC work uses Unix domain sockets on POSIX
  platforms; a Windows Named Pipe adapter is still a gap if we choose helper
  mode rather than inline runtime ownership.
- Installer/packaging and driver-signing workflows for Windows drivers/services
  remain to be defined for production releases (MSI/NSIS, code-signing,
  attestation). Development/test paths rely on manual Wintun driver install or
  the proposed convenience download for `wintun.dll`.
- Windows elevated integration tests are already present in the repo (see
  pytest marker `windows_elevated` and `pyproject.toml`), and CI exercises
  elevated Windows test paths in the project's pipelines; confirm CI job links
  when formalizing the Windows CI acceptance criteria.

Risks & constraints
- Driver signing: test/dev builds may need special handling; production builds
  require signed driver bundles and possibly Microsoft attestation.
- IPC semantics differ: rely on Named Pipe security (SDDL) or explicit PID
  checks; `SO_PEERCRED`-style checks are not available.
- Elevated operations already have an inline UAC-elevation story in the
  current Windows runtime; helper design should prefer helper-only elevation
  over introducing a mandatory Windows service unless testing shows that
  subprocess elevation is not sufficient.

Recommended minimal viable approach
1. Keep Wintun as the primary and already-delivered Windows TUN backend.
  Evaluate a fallback only if a concrete deployment need appears; do not add a
  second Windows backend merely for symmetry.
2. Introduce a Windows helper backend that reuses the existing
  `src/obstacle_bridge/bridge_tun_windows.py` Wintun loading and packet I/O
  semantics behind the helper control protocol.
3. Add a Windows local IPC transport for helper mode, with Named Pipes as the
  primary plan, and keep `ChannelMux`, `Runner`, and Admin helper status as
  close as possible to the existing Linux/macOS helper contracts.
4. Reuse the current Windows UAC/elevation model to elevate only the helper
  path first. Treat a Windows service or dedicated installer flow as a later
  hardening/packaging step rather than the first implementation requirement.
5. Extend existing Windows elevated tests to cover helper mode and preserve the
  current inline Wintun path as the baseline fallback while helper mode
  matures.

Acceptance criteria for this step (Requirements & gap analysis)
- A written spec (this section) recorded in `docs/TUN_HELPER_DESIGN.md`.
- Decision: existing inline Wintun backend remains the baseline Windows TUN
  implementation, and helper work should reuse that path rather than replacing
  it.
- Documented IPC plan: Named Pipes with SDDL + session-token auth.
- High-level implementation plan for a Windows helper backend, IPC transport,
  and elevation model recorded here.
- Maintainer review or explicit sign-off requested (next action: create PR
  with this document and request review).

Next steps
- Define the Windows helper elevation and IPC plan around the already shipped
  Wintun runtime path.  

## Windows — Backend research and decision (completed)

Summary
- The repository's actual Windows TUN implementation is Wintun-only today.
- The shipped Windows path already has runtime integration, elevation support,
  documentation, and elevated integration coverage around Wintun.
- There is no current code, test, packaging, or operator surface for
  TAP-Windows or any second Windows TUN backend.

Repo-grounded findings
- `src/obstacle_bridge/bridge_tun_windows.py` is the active Windows TUN module.
  It supports optional `wintun` / `pywintun` Python wrappers and a direct
  ctypes fallback to `wintun.dll`.
- `src/obstacle_bridge/bridge_runner.py` already carries Windows-specific UAC
  relaunch handling and preserves `WINTUN_DIR` into the elevated path.
- `README.md` documents the Wintun runtime path, DLL discovery, `WINTUN_DIR`
  usage, manual download/install instructions, and the `scripts/wintun_example.py`
  smoke path.
- `tests/integration/test_windows_elevated.py` already exercises elevated
  Windows TUN lanes, and the pytest marker set in `pyproject.toml` already
  reserves `windows_elevated` for this runtime path.
- The repo search surface for Windows TUN code currently exposes Wintun only;
  no implemented TAP-Windows backend, helper adapter, or alternate Windows TUN
  packet path was found.

Backend decision
- Keep Wintun as the only supported Windows TUN backend for the helper design
  until a concrete deployment blocker justifies a second backend.
- Do not add TAP-Windows merely as a speculative fallback. That would widen
  the test matrix, operator instructions, and failure surface without current
  repo evidence that Wintun is insufficient for the project's supported path.
- Future fallback consideration is acceptable only if it comes with a concrete
  failing host class, packaging constraint, or driver-policy restriction that
  the current Wintun path cannot satisfy.

Implications for helper work
- Windows helper mode should wrap and reuse the current Wintun path rather than
  abstracting over multiple Windows drivers.
- Helper IPC, elevation, and Admin/runtime parity are now the real Windows
  design gaps; backend multiplicity is not.
- The convenience download flow should target Wintun release layout directly,
  because that is already the runtime's documented and tested DLL shape.

## Windows — helper IPC and elevation plan

Summary
- Windows helper mode should reuse the existing Wintun inline runtime path,
  but move adapter ownership and optional helper-owned network mutations behind
  the same helper protocol shape already used on Linux/macOS.
- The current Windows privilege path elevates the whole runtime through UAC.
  The helper design should reduce that to helper-only elevation first, without
  introducing a mandatory Windows service in the first implementation slice.

Current repo anchors
- `src/obstacle_bridge/bridge_runner.py` already contains the Windows UAC
  relaunch path. It re-executes `python -m obstacle_bridge.bridge_runner` via
  `ShellExecuteW(..., "runas", ...)`, sets
  `OBSTACLEBRIDGE_WINDOWS_TUN_ELEVATED=1`, and preserves `WINTUN_DIR` into the
  elevated process.
- `src/obstacle_bridge/bridge_tun_helper_server.py` currently starts only a
  Unix-domain-socket helper server via `asyncio.start_unix_server(...)` and
  only registers Linux and Darwin backends in `_backend_from_name(...)`.
- `src/obstacle_bridge/bridge_tun_windows.py` already exposes the Wintun open,
  read, write, and close semantics that the future Windows helper backend
  should wrap rather than duplicate.

Proposed first Windows helper launch model
1. Keep the main `python -m obstacle_bridge` runtime unprivileged.
2. When `tun_execution.mode=helper` selects a Windows backend and privilege is
   needed, `Runner` launches only the helper entrypoint with UAC elevation.
3. The elevated helper process receives a compact launch config, just as the
   Linux/macOS helper path already does, including backend name, auth token,
   and any helper log level.
4. The helper process opens the Wintun adapter, serves helper protocol
   requests, and optionally owns helper-side network apply/remove work.
5. `ChannelMux` continues to treat the helper as a packet/control transport and
   does not gain Windows-specific routing or driver logic.

IPC plan
- Primary transport: Windows Named Pipes.
- Rationale: it is the Windows-native local privileged IPC mechanism, works
  well with service or elevated-subprocess models later, and fits the existing
  framed helper protocol without needing packet-shape changes.
- Security model: use a pipe ACL/SDDL that limits access to the launching user
  and elevated helper context, plus the existing helper session token.
- Protocol model: preserve the current helper frame kinds and command set
  (`HELLO`, `OPEN_TUN`, `APPLY_NETWORK`, `REMOVE_NETWORK`, `SNAPSHOT`,
  `STOP`, and packet frames) so Windows adds a transport/backend pair rather
  than forking helper semantics.

Backend plan
- Add a Windows helper backend class that reuses the logic in
  `src/obstacle_bridge/bridge_tun_windows.py` for:
  - Wintun DLL discovery
  - optional wrapper import fallback order
  - adapter/session creation
  - packet read/write loops
  - adapter/session shutdown
- The helper backend should expose the same snapshot/counter concepts as the
  Linux and Darwin helper backends so Admin/runtime status remains aligned.

Current progress
- `src/obstacle_bridge/bridge_tun_helper_windows.py` now implements the first
  Windows helper backend slice. That backend now owns Windows-side TUN network
  apply/remove for interface addresses, included routes, excluded underlay
  bypass routes, and DNS server assignment, with rollback + failure snapshots
  on partial apply errors.
- `src/obstacle_bridge/bridge_tun_helper_server.py` now recognizes
  `windows-native` in `_backend_from_name(...)` and no longer imports the
  Darwin backend eagerly at module import time, which keeps the helper server
  importable on Windows.
- `src/obstacle_bridge/bridge_tun_helper_client.py` and
  `src/obstacle_bridge/bridge_tun_helper_server.py` now route local transport
  startup through explicit wrapper functions instead of embedding direct
  `asyncio.open_unix_connection(...)` / `asyncio.start_unix_server(...)`
  calls at every use site. That seam is now used by a first Windows Named Pipe
  implementation built on stdlib `multiprocessing.connection` (`AF_PIPE`), so
  the existing framed helper protocol can now perform real Windows local
  client/server round-trips without changing helper message semantics.
- `src/obstacle_bridge/bridge_tun_helper_settings.py` now treats
  `windows-native` as the only Windows helper backend candidate, returns a
  Named-Pipe-style default helper endpoint on Windows, and separates helper
  launch metadata storage from the transport endpoint so the runner no longer
  assumes that every helper endpoint is also a filesystem path.
- `src/obstacle_bridge/bridge_runner.py` now derives helper launch-config and
  stale-reaping directories from that runtime-dir abstraction instead of from
  the helper endpoint string directly.
- `src/obstacle_bridge/bridge_runner.py` now also probes Windows Named Pipe
  endpoints for helper readiness instead of waiting for a filesystem socket
  path that never appears on Windows.
- `src/obstacle_bridge/bridge_runner.py` now launches the `windows-native`
  helper backend through the existing Windows PowerShell + `ShellExecuteW`
  elevation path instead of relaunching the whole runtime. The elevated helper
  launch preserves `WINTUN_DIR`, passes the compact helper launch config, and
  keeps the unprivileged runtime connected over the helper transport.
- `src/obstacle_bridge/bridge_runner.py` stale-helper reaping is now pipe-aware
  on Windows: `\\.\pipe\...` helper endpoints are treated as live candidates
  that should be probed through `TunHelperClient`, instead of being discarded
  immediately by filesystem existence checks.
- Focused unit coverage now exists in
  `tests/unit/test_tun_helper_windows_backend.py`, and backend-factory coverage
  includes `windows-native` in `tests/unit/test_tun_helper_server_entrypoint.py`.
  Windows backend tests now cover helper-owned address/route/DNS apply-remove,
  rollback on DNS failure, and interface-resolution failure recording.
- Focused transport-wrapper coverage now exists in
  `tests/unit/test_tun_helper_transport_windows.py`; that coverage now includes
  a real Windows Named Pipe round-trip using `TunHelperServer` and
  `TunHelperClient`, and the nearby helper tests now choose a Windows pipe
  endpoint on Windows instead of assuming Unix socket paths.
- Focused settings/runtime-dir coverage now also exists in
  `tests/unit/test_tun_helper_settings.py` and `tests/unit/test_runner_tun_helper.py`
  for the `windows-native` backend gate, Named Pipe endpoint naming, and the
  separate helper runtime directory used for launch metadata.
- Focused Windows helper-launch coverage now also exists in
  `tests/unit/test_runner_tun_helper.py` and `tests/unit/test_runner_events.py`
  for helper-only Windows UAC launch wiring, launch-config payload contents,
  and reuse of the existing PowerShell-encoded elevation path.
- Focused Windows stale-helper reaping coverage now also exists in
  `tests/unit/test_runner_tun_helper.py` for pipe-style helper endpoints and
  the runner's pipe-aware endpoint-candidate check.
- A first elevated Windows helper-mode integration lane now exists in
  `tests/integration/test_windows_elevated.py`. One lane brings up
  `tun_execution.mode=helper` with `--tun-helper-backend windows-native`,
  waits for helper runtime state through `/api/status`, verifies helper-owned
  IPv4 address + route application without out-of-band PowerShell route setup,
  and checks helper packet counters after a TUN-carried UDP datagram. A
  second lane kills the live helper process on the elevated path and verifies
  that runtime status preserves the cached helper snapshot, flips helper
  connectivity state, and raises the stale-network manual-cleanup warning when
  helper-owned Windows route/address state may remain after helper loss. A
  third elevated lane now posts `/api/tun-helper/repair` after helper death
  and proves that runner-driven Windows-native repair clears the warning, drops
  the cached helper-owned IPv4 address + included route + DNS servers from
  runtime status, and removes that route/address/DNS state from the real
  WinTun adapter on the host.
- Windows helper-owned network lifecycle now also includes a first firewall
  ownership slice keyed off `listener_hook_env.WAN_IF`: the
  `windows-native` backend creates per-family inbound/outbound Windows
  Defender Firewall rules scoped to the helper-owned tunnel subnet, tracks
  them in the runtime snapshot, removes them during normal teardown, and
  includes them in dead-helper repair plus post-repair verification. Focused
  unit coverage in `tests/unit/test_tun_helper_windows_backend.py` now proves
  apply/remove rule ownership and cached-snapshot firewall cleanup/verification
  alongside the existing route/address/DNS behavior.
- Windows warning-only recovery is no longer the whole story: the runner can
  now replay Windows helper-owned route/address/DNS/firewall cleanup from the cached
  dead-helper runtime snapshot through `request_tun_helper_repair()`, using
  `WindowsTunHelperBackend.repair_runtime_snapshot(...)` plus a focused
  PowerShell-backed verification pass to distinguish stale state that was
  cleared from state that may still remain. Focused unit coverage now exists in
  `tests/unit/test_tun_helper_windows_backend.py` and
  `tests/unit/test_runner_tun_helper.py` for that Windows-native repair path.
- Current limitation is narrower now: Windows helper transport exists, but
  first real elevated Windows execution still exposes one remaining live helper
  bring-up gap. The runtime now survives helper launch, helper-only UAC, Named
  Pipe readiness, `OPENv5` framing, and portable helper-path snapshotting on
  Windows, but the `windows-native` helper can still reach `OPEN_TUN` without
  consistently driving the subsequent live `APPLY_NETWORK` step on a real
  elevated WinTun adapter. Helper-owned route/address/DNS/firewall cleanup and
  repair logic remain unit-covered, while the live elevated helper lanes stay
  blocked on that post-open apply sequencing issue.
- Current limitation is otherwise narrower now: Windows helper transport exists, but
  the elevated helper subprocess is not observable through a native child
  handle yet, Windows stale-helper recovery still depends on launch-config
  probing rather than process enumeration, and higher-fidelity route policy
  parity is still missing.

Elevation plan
- First implementation target: helper-only elevated subprocess.
- Reuse the current Windows ShellExecute/UAC machinery conceptually, but scope
  it to the helper module launch rather than the whole runtime relaunch.
- Preserve `WINTUN_DIR` and any future local `.wintun` convenience-download
  path into the helper environment so the elevated helper resolves the same DLL
  selection as the unelevated parent intended.
- Defer a dedicated Windows service until a concrete operational reason exists
  such as persistence, service-manager recovery, or packaging policy.

Acceptance criteria for this design step
- The design explicitly chooses Named Pipes as the first Windows helper IPC
  transport.
- The design explicitly chooses helper-only UAC elevation as the first Windows
  privilege model.
- The design explicitly reuses `bridge_tun_windows.py` as the helper backend's
  Wintun implementation seam.
- The design records that the current Windows helper gaps are transport,
  backend registration, and helper launch wiring rather than missing Windows
  TUN packet I/O.

### Wintun convenience download (proposal)

Problem statement
- The repo currently documents a direct ctypes path to `wintun.dll` and
  supports a working inline Windows runtime, but still expects the user to
  obtain the Wintun package manually. That is workable for maintainers but
  burdensome for new users and testers.

Proposal
- When `WINTUN_DIR` is not set and a usable `wintun.dll` cannot be found via
  the normal autodetect paths, the runtime should offer to download a
  Wintun release archive from https://www.wintun.net/, extract the suitable
  `wintun.dll` for the running Python architecture, and place it under a
  project-local, git-ignored folder such as `.wintun/bin/<arch>/wintun.dll`.

Behavioral details
- Detection: on Windows startup only, attempt normal autodetect. If no DLL
  found and running in an interactive session, prompt the user to accept an
  automated download. The prompt should explain the need for driver install and
  that the runtime will not auto-install the driver (admin actions still
  required for driver install or device creation).
- Download source: identify the best-release archive URL from `https://www.wintun.net/`
  (or the official release mirror documented there). Prefer the latest stable
  release and download only the small binary archive containing `bin\<arch>\wintun.dll`.
- Extraction: create `.wintun/` under the project working directory (or
  another configurable but git-ignored path), extract `wintun.dll` into
  `.wintun/bin/amd64/wintun.dll` (or `x86` when running 32-bit Python).
- Security: show the remote URL to the user before download. If the release
  page lists checksums or signatures, attempt to verify; otherwise advise the
  user to verify manually. Provide an opt-out env var `OB_NO_WINTUN_AUTO
  = 1` to suppress automatic download attempts for air-gapped or security
  conscious environments.
- Ownership and gitignore: add `.wintun/` to the project's `.gitignore` (or
  document the recommended entry) so extracted binaries are not committed.
- CLI-only mode / non-interactive: when running non-interactively or when the
  env var opt-out is set, skip the download and surface a clear error that
  instructs how to obtain Wintun manually or enable the automatic download.

Implementation notes
- The download/verification code belongs in the Windows runtime startup path
  (near the existing Wintun autodetect code). Keep the extraction code simple
  and deterministic; avoid unpacking arbitrary archives into the repo root.
- Prefer the built-in `zipfile` module to extract the minimal files, or use
  `requests` and `shutil` to stream-and-extract safely.
- Record the extracted release version and source URL in a small
  `.wintun/README` or metadata file for auditability.

Acceptance criteria
- The runtime auto-downloads the appropriate `wintun.dll` when `WINTUN_DIR`
  is not set and the user accepts the prompt (or `OB_ENABLE_WINTUN_AUTO=1`
  is set non-interactively).
- The extracted DLL is placed under `.wintun/bin/<arch>/wintun.dll` and the
  folder is added to `.gitignore` (or documented if repo maintainers prefer
  not to edit `.gitignore` automatically).
- The code exposes the opt-out env var and documents the manual-install
  alternative in `README.md` and `docs/TUN_HELPER_DESIGN.md`.
- A short integration smoke test demonstrates `scripts/wintun_example.py`
  running successfully when the DLL was auto-downloaded.

Notes
- This convenience flow is intended to simplify developer and tester setup;
  it does not replace the need for an administrator to install or approve
  driver packages for production deployments. The helper/service design and
  installer tasks remain the authoritative production path for driver/service
  installation and signing.
