# macOS App Design

## Purpose

This document records the current macOS application design for ObstacleBridge,
with special attention to the gap between:

- the Python runtime, which can now establish a working macOS full-tunnel TUN
  session when started with sufficient privilege
- the Swift-based macOS app, which can start the overlay runtime and local
  services but does not yet own a privileged path for creating and configuring
  a real `utun` interface

The goal is to keep the macOS app aligned with the existing ObstacleBridge
architecture and with the working Linux and Python/macOS behavior, while being
honest about the macOS-specific privilege boundary.

## Current product status

The project now has three meaningfully different macOS runtime shapes:

1. Linux/Python-style ObstacleBridge, running on Linux:
   - already supports working full-tunnel TUN behavior
   - remains the main reference implementation for end-to-end TUN behavior
2. Python runtime on macOS:
   - now supports real `utun` creation
   - can configure addresses and default routes
   - can preserve an underlay host route to the overlay peer
   - can move real traffic through the tunnel when started with privilege
3. Swift-based macOS app:
   - can load config, start overlay transports, and expose admin state
   - can represent the TUN service logically
   - does not yet create and configure a real local `utun` interface during
     normal app startup

That means the Python/macOS path has crossed the "working full tunnel" line,
while the Swift app is still one layer short of that same outcome.

## What is already working on macOS

### Python runtime

The Python path now demonstrates the intended macOS TUN behavior:

- local `utun` creation succeeds when the process is started with sufficient
  privilege
- the Darwin-specific TUN hook scripts can configure the local interface
- IPv4 and IPv6 default routes can be redirected to the tunnel
- a host route to the overlay peer can be preserved on the physical underlay
- public traffic can exit through the remote peer as expected

This is important because it proves the ObstacleBridge protocol and control
model are suitable on macOS down to the OS-specific TUN boundary. The problem
is no longer "can macOS do it at all?" The problem is now "how should the
Swift app obtain and use the same privilege correctly?"

### Swift app runtime

The Swift app currently does several important things correctly:

- loads runtime config from the app support config path
- starts the overlay runtime
- supports the transport matrix used elsewhere in the project
- exposes admin APIs and connection state
- carries the logical TUN service definition into runtime state

However, the live state still shows the TUN path only as a logical listener,
not as an active local TUN channel with a real macOS interface behind it.

That is a design and privilege boundary issue, not a transport or ChannelMux
concept issue.

## Proven macOS-specific constraint

The project has now reproduced a concrete macOS platform boundary:

- raw Darwin `utun` creation from a normal process can fail with
  `Operation not permitted`
- the same Python runtime succeeds when relaunched through an elevated path
- the Swift app currently has no equivalent privilege-escalation or privileged
  helper path

This explains the current product split:

- Python on the command line can ask the user for admin permission and then
  continue
- a GUI app cannot rely on the same ad hoc terminal-style `sudo` interaction

So the missing piece in the Swift app is not merely "call the same code." It is
"obtain and hold the required privilege in a macOS-approved app architecture."

## Why Python can work without Network Extension

It is tempting to think "if Python can do it, the app should simply do the
same." The subtle difference is the execution model:

- the Python CLI can be relaunched with elevated privilege
- once elevated, it can open `utun`, configure routes, and run the TUN hooks
- this is acceptable as a developer or power-user flow

The Swift app, by contrast, is a normal macOS application process:

- it does not automatically become privileged
- it should not rely on deprecated one-off privilege APIs
- it needs a structured, system-approved privileged path if it wants to own the
  same `utun` and route-management responsibilities

So the fact that Python works without a real macOS Network Extension is useful
and encouraging, but it does not remove the need for a proper privilege design
for the app.

## Current helper implementation

The current first-step implementation now bundles the standalone
`ObstacleBridgeHostRunner` executable inside the macOS app and launches it with
administrator privileges when the runtime config contains a local TUN service.

That gives the app a practical bridge to the already-working host-runner TUN
path without waiting for a full `SMAppService` helper implementation first.

The current flow is:

1. the app loads its runtime config
2. if the config requires local TUN, it chooses the bundled host-runner helper
3. the app asks macOS for administrator authorization
4. the bundled helper starts as a privileged process and owns real local `utun`
   startup
5. the app continues to use WebAdmin and runtime status through the helper's
   localhost admin surface

This is intentionally a pragmatic first step. It is meant to make the Swift
app functionally converge with the working Python/macOS path, not to claim that
the final macOS privilege architecture is finished.

## Recommended near-term architecture

The recommended next macOS app step remains:

- keep the current Swift host-runner architecture
- keep the bundled privileged host-runner launch as the working bridge
- harden that bridge into a dedicated privileged helper for TUN and route
  operations
- have the app communicate with that helper over XPC

The current bundled-helper launch preserves the design investment already made
in:

- overlay transports
- secure-link
- ChannelMux
- admin observability
- config and invite handling

It also keeps the Python and Swift products conceptually aligned:

- same runtime model
- same tunnel plan
- same service model
- different OS-specific privilege packaging

## Why not jump straight to Network Extension

A real macOS `NetworkExtension` remains a valid long-term target, but it is not
the next required step.

Reasons:

- the Python/macOS runtime already proves the protocol and tunnel model can work
  on macOS without rearchitecting around Network Extension first
- the Swift app already has substantial transport, mux, and config work that
  should be reused
- introducing a macOS packet tunnel extension is a much larger packaging,
  entitlement, lifecycle, and observability step

So the current recommended sequence is:

1. make the Swift app functionally match the working Python/macOS TUN path
   through a privileged helper
2. only then decide whether a full Network Extension product is worth the added
   complexity and platform ceremony

## Apple platform guidance

Current Apple guidance points away from older privilege approaches:

- `AuthorizationExecuteWithPrivileges` is deprecated
- `SMJobBless` is also deprecated
- the modern direction is `SMAppService` for helper management

The long-term hardened version of the macOS app should therefore use:

- a privileged helper managed via `SMAppService`
- XPC communication between app and helper
- a clear helper API for TUN and route lifecycle operations

So the design posture is:

- current implementation: bundled privileged host-runner launched with an admin
  authorization prompt
- preferred future hardening: `SMAppService` + XPC

This keeps the product moving while still acknowledging the cleaner long-term
Apple-aligned direction.

## Responsibilities of the privileged helper

The helper should own the operations that require elevated system access:

- create and tear down the local `utun` interface
- report the realized interface name back to the app
- configure IPv4 and IPv6 point-to-point tunnel addressing
- apply and remove default routes for full-tunnel mode
- preserve an underlay host route to the overlay peer
- perform teardown cleanup on disconnect or app stop

The main Swift app should continue to own:

- overlay transport lifecycle
- ChannelMux and secure-link runtime logic
- config loading and validation
- admin UI and observability
- user-initiated connect and disconnect flow

This keeps the helper small and focused, which is good both for reliability and
for future review of the privileged boundary.

## Parity target with Python and Linux

The parity goal is not merely "a TUN row appears in WebAdmin." The parity goal
is:

- Swift app establishes a real local macOS `utun`
- the interface is configured using the same tunnel plan semantics as Linux and
  Python/macOS
- default routing moves to the tunnel
- the underlay route to the overlay peer is preserved
- live traffic really flows through the tunnel
- admin state reflects real TUN open/connected behavior instead of only a
  logical listener row

## Observed macOS IPv6 route behavior

Recent live tracing on macOS showed an important difference from the Linux and
Python-host-TUN path:

- IPv4 default-route takeover onto `utun` can succeed and verify cleanly
- direct IPv6 `default` replacement on macOS is much less reliable
- `route -n get -inet6 default` can fail or return unstable results even while
  the kernel still holds other scoped IPv6 defaults
- rolling back after that partial IPv6 failure can leave the machine in an
  awkward split state unless the script is careful

To keep the behavior config-driven while still matching what macOS will accept,
the client hook now interprets the configured IPv6 full-tunnel intent
(`included_routes6` containing `::/0`) as two explicit routes:

- `::/1`
- `8000::/1`

Those two routes together capture the global IPv6 space without requiring the
script to replace the system's own IPv6 `default` route directly. This is not
a separate product policy hard-coded outside config; it is the macOS-specific
realization of the same configured full-tunnel intent.

That gives the project a safer operating model:

- config remains the source of truth
- macOS-specific route programming happens in the hook
- IPv4 and IPv6 can now be debugged independently without needlessly tearing
  down the whole routing session

## Swift Packet Adapter Behavior Versus Python

One subtle but important difference has now been observed between the Python
TUN clients and the Swift packet-adapter path used by the macOS app.

Python on Linux and Python on macOS use host-style TUN adapters:

- the operating system routes packets onto the local TUN interface
- the packet source identity seen by ObstacleBridge already aligns with the
  tunnel-owned address space often enough that shared-TUN ownership checks do
  not require additional packet rewriting in the mux layer

The Swift macOS app uses a different path:

- a native packet adapter reads packets from the local `utun`
- those packets can still carry the machine's original local source identity
  when they first enter the shared Swift runtime
- shared-TUN ownership on the server is stricter and expects the peer to source
  packets from its assigned tunnel-owned address, such as `192.168.106.3` or
  `fd20:106::3`

That means the Swift path needs one explicit normalization step that Python did
not need in practice:

- before ChannelMux frames a local TUN packet for shared-TUN forwarding, the
  Swift runtime rewrites the packet source to the configured tunnel-owned IPv4
  or IPv6 address and updates the affected checksums

This is not treated as a protocol change. It is a parity fix that makes the
Swift packet-adapter path present the same effective tunnel identity that the
Python host-TUN path already provides implicitly.

Design consequence:

- shared-TUN server ownership rules stay strict
- Python behavior stays unchanged
- Swift packet adapters normalize local source identity before shared-TUN mux
  forwarding

The same shared Swift runtime is used by both the macOS app and the iOS packet
tunnel implementation, so this source-normalization behavior is intentionally
shared across both Apple-platform clients.

That is the standard the Swift app should meet before we call the macOS app TUN
path complete.

## Current known gap

At the time of writing, the Swift app can still end up in the following state:

- overlay connected
- local services running
- TUN service listed as listening
- no active local `utun` interface
- no active TUN channel counters

This should now be interpreted as:

- config is present
- ChannelMux/service wiring is present
- privilege-backed local TUN realization is missing

That diagnosis is much better than the earlier uncertainty, because it gives us
a narrow next step instead of a vague one.

## Further steps

1. Prove the bundled privileged host-runner path fully matches the working
   Python/macOS path:
   - real `utun` appears
   - routes are installed
   - underlay route is preserved
   - traffic exits through the remote peer
   - admin state shows a real TUN channel
2. Introduce a dedicated privileged helper managed through `SMAppService`.
3. Define an XPC contract for:
   - create local TUN
   - configure addressing and routes
   - preserve underlay route
   - teardown and cleanup
4. Wire the Swift host-runner TUN path to request that helper service instead
   of assuming unprivileged local TUN access.
5. Reevaluate whether a full macOS Network Extension remains necessary after
   the helper-backed design is working.

## Relationship to other design notes

This document should be read together with:

- [ARCHITECTURE.md](./ARCHITECTURE.md)
- [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md)
- [IOSAPP_DESIGN.md](./IOSAPP_DESIGN.md)
- [QUIC_DESIGN.md](./QUIC_DESIGN.md)

`CHANNELMUX_DESIGN.md` explains the shared TUN and service semantics.
`IOSAPP_DESIGN.md` describes the iOS packet-tunnel direction. This macOS design
note exists because macOS currently sits in between:

- more native-app freedom than iOS
- but still a real privilege boundary for raw TUN and route control

That middle ground is exactly why the privileged-helper step is the natural next
move.
