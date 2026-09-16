# Linux Swift Client Design

## Purpose

ObstacleBridgeLinux is a foreground Swift command-line client for Linux. It
reads the established runtime configuration, runs the overlay without Python at
runtime, serves the established local Admin vocabulary, and can own a Linux TUN
device when the operator supplies the required privilege.

Python is the functional reference. A Swift feature is accepted only when its
observable configuration, wire behavior, lifecycle, and redacted operator
state are compatible with the applicable Python feature and have executable
evidence. Requirements and traceability records, not this document, carry the
complete evidence matrix.

Build the product with:

```bash
./scripts/build_linux_app.sh
```

The build uses the host Swift toolchain and produces `ObstacleBridgeLinux` plus
a build-information sidecar under `build/linux/`. It requires neither Xcode
nor Python at runtime.

## Product boundary

The Linux product provides one foreground executable with the established
runtime-config, bind-host, status-port, and bounded diagnostic controls. It
supports non-TUN operation without elevation. TUN operation is explicit: a
missing privilege produces a specific failure and never invokes `sudo` or
persists credentials.

The first product surface is deliberately narrow. GUI, package management,
system service ownership, updater behavior, and a privileged daemon are not
part of it. QUIC and TLS WebSocket are capability-gated until maintained Linux
backends are selected and qualified; they are rejected before a partial session
is created.

## Shared architecture

```text
iOS extension    macOS app/runner    Linux CLI    future Windows host
      \                 |                /                  /
       +----------------+---------------+------------------+
                                |
                       ObstacleBridgeCore
                  protocol, state, policy, models
                                |
        +-----------------------+-----------------------+
        |                       |                       |
   Apple adapters          Linux adapters         Windows adapters
```

`ObstacleBridgeCore` is the canonical SwiftPM library for wire codecs, typed
models, SecureLink, ChannelMux, myudp reliability, compression policy, and
portable lifecycle decisions. It uses Foundation and the pinned `Crypto`
product, but does not import OS socket, packet-device, UI, key-store, or Apple
framework APIs. Common state receives clocks and entropy through contracts so
that transitions can be tested deterministically.

Platform adapters execute Core effects. They own descriptors and callbacks,
not protocol decisions, serializers, counters, or alternate retry policies.
Common APIs expose typed data rather than `NWConnection`, file descriptors,
`sockaddr`, Darwin structures, or Windows handles.

| Area | Core owns | Platform adapter owns |
| --- | --- | --- |
| Crypto and SecureLink | Handshake, protected records, rekey, replay/counter rules, redacted protocol snapshot | Key-store integration and transport-frame delivery |
| Overlay transports | Envelopes, liveness/retry decisions, epoch/readiness state | TCP, WebSocket, datagram, QUIC, TLS, trust, and socket I/O |
| ChannelMux and services | Frame/service models, catalog state, packet policy, queue/backpressure decisions | Local socket or packet-device execution |
| Compression | Zlib policy, eligible-frame rules, no-gain fallback | Configuration storage and platform status presentation |
| Configuration and Admin | Typed configuration, capability admission, routing, redaction | HTTP serving, DNS, persistence, secret acquisition, assets |
| Lifecycle | Ordered effects and cancellation semantics | Signals, scheduling, process/hooks, OS cleanup |

## Platform specialties

### Linux

`ObstacleBridgeLinuxAdapters` uses Foundation, Dispatch, Glibc, POSIX sockets,
and narrow C bindings. It owns connected TCP, cleartext WebSocket, and myudp
I/O; descriptor cancellation; signals; resolver calls; process execution; and
capability reporting. The live runtime serializes adapter execution around Core
state, publishes redacted status, and cancels a lower session before waiting
for a blocked reconnect handshake.

The Linux packet adapter uses `/dev/net/tun` with `IFF_TUN | IFF_NO_PI` and
exchanges raw IPv4/IPv6 packets. The checked-in `scripts/client-tun-hook.sh`
remains the owner of address, route, DNS, underlay-preservation, and cleanup
policy. Swift supplies the compatible lifecycle action and environment; it
does not duplicate host-network policy.

Linux support is intentionally capability-based. A missing TUN privilege,
QUIC provider, TLS WebSocket provider, or other optional mechanism is an
explicit admission result, never an implied protocol fallback.

### macOS and iOS

Apple products consume the Core contract while retaining Apple-only
mechanisms: `Network.framework` and URLSession transport integration, Darwin
`utun`, Network Extension packet flow/settings, XPC and service-management
paths, and Apple secret storage. Apple wrappers retain product configuration,
peer accounting, and status presentation, but delegate wire, SecureLink, and
ChannelMux compression policy to Core.

The macOS host runner and iOS extension are distinct product surfaces. Their
build and runtime qualification cannot be substituted with a Linux build or
source inspection.

### Future Windows

Windows is a portability sentinel rather than a Linux-parity prerequisite. A
future Windows product will provide WinSock, packet-device, routing, service,
and credential adapters through the same Core ports. It must not introduce a
second protocol or runtime-policy implementation.

## Current supported runtime shape

The Linux executable starts configured TCP, cleartext WebSocket, or myudp
client sessions with PSK SecureLink, ChannelMux, bounded reconnect, ordered
signal shutdown, and local redacted `/api/status` and `/api/peers` endpoints.
TCP and cleartext WebSocket listener mode are also admitted. Local TCP/UDP
services start only after an authenticated overlay epoch and are replaced or
withdrawn from received catalogs without a reconnect.

The core layer provides the shared binary/JSON codecs, SecureLink client and
server roles, ChannelMux service/catalog formats, myudp peer engine, and
bounded zlib policy. Linux and Apple code use those owners rather than
independent wire serializers or compression parsers.

The Linux peer projection is a deliberately small, redacted capability
contract. It reports lifecycle/readiness, SecureLink state, session and
protected-frame counters, bounded retry information, failure reason, and
transport ownership. It never reports PSKs, nonces, keys, plaintext, or
Python-only diagnostic/traffic fields that Linux has not qualified.

| Linux lifecycle | `state` / `app_ready` | SecureLink state | Snapshot rule |
| --- | --- | --- | --- |
| stopped | `stopped` / `false` | `disconnected` for PSK, otherwise `off` | no current session or retry |
| reconnecting | `reconnecting` / `false` | `disconnected` before SecureLink admission | bounded retry duration only |
| failed | `failed` / `false` | `disconnected` before SecureLink admission | failure reason, no current session |
| connected | `connected` / `true` after PSK admission | `authenticated` for PSK, otherwise `off` | current session and Core counters |

Each peer row also carries a redacted `compression_layer` object derived from
the Core compression policy and the Linux ChannelMux boundary. It publishes
the effective zlib policy plus attempted/applied/no-gain counts and bytes,
dedicated compressed TX/RX counts and bytes, uncompressed TX/RX counts and bytes, and
rejected compressed-frame counts and bytes. It records no payload bytes,
keys, or zlib state. Core classifies the compression decision and decoder
outcome; the Linux Admin adapter only serializes that snapshot.

Enabled compression is qualified end-to-end with an independent Python TCP
SecureLink peer: Swift emits a protected compressed ChannelMux request, Python
rejects any uncompressed request, independently decompresses and recompresses
the response, and Swift restores the original response frame. This is the
supported R005.5e-2a bidirectional contract; disabled/mismatched-policy
qualification is also explicit: disabled Swift emits and accepts uncompressed
protected frames, while an enabled Swift client interoperates with Python's
passive disabled-side decoder after it observes a compressed frame. This is
the Python-compatible mismatch outcome, not a connection failure. A malformed
or unsupported compressed frame fails deterministically at the Core decoder
boundary; the authenticated session remains usable for its next valid
protected exchange.

The iOS physical-device qualification uses the normal signed app and bundled
`IPServer` extension rather than the resource-constrained simulator lane. Its
authenticated overlay-published WebAdmin endpoint exposes redacted status and
peer data while the device-local WebAdmin listener remains on loopback. The
qualified device build reports its embedded source commit, dirty/diff identity,
and timestamp, and its containing app and extension share one numeric
`CFBundleVersion`. This device evidence covers the functional SecureLink and
status contract; signed release-archive distribution remains separate work.

The macOS Swift-backed CI lane builds the complete normal app bundle from a
clean checkout, verifies the nested executable signatures and both bundle
plists, packages that exact bundle, and reuses it for the host-side tests. Its
ZIP, SHA-256, and build-info JSON are retained together as one CI artifact.
The successful job is the macOS build evidence; the `macos-preview` release
workflow performs its ongoing convenience-preview publication after `main`
updates, rather than creating a separate development gate.

R005 is closed. Its applicable Linux, macOS, traceability, README, and
ownership gates pass; the macOS bundle artifact and the physical-iPhone
SecureLink/WebAdmin evidence qualify their platform-specific outcomes.
Privileged-TUN and device-only results remain explicitly reported as such,
rather than being mistaken for ordinary hosted CI coverage. TestFlight archive
recording is optional release housekeeping and is not an R005 development
gate.

### R006 overlay convergence status

Core owns a deterministic overlay coordinator and logical TCP/WebSocket
envelope decision. The Linux live runtime executes its typed effects: Core
allocates the admitted epoch, starts and cancels the one receive owner,
chooses bounded retry timing and candidate index, and rejects stale retry or
receive completion. Linux retains only Dispatch scheduling and native session,
socket, and worker operations. An already-authenticated inbound listener
session receives a Core epoch without opening an unintended outbound
connection.

The Apple shared runtime uses the same envelope decision and publishes
transport/authentication readiness to Core, but it does not yet execute the
coordinator's candidate, retry, receive-cancellation, or backpressure effects.
R006 remains open until both Apple consumers execute those effects and the
cross-platform traceability lane proves the following work packages.

| Work package | Remaining definition of done |
| --- | --- |
| `LSW-R006.1` | Core coordinator and envelope types are compiled by SwiftPM, macOS, and iOS build graphs; Linux and Apple consumers use them for their admitted decisions. |
| `LSW-R006.2` | TCP and WebSocket logical application, PING, and PONG policy has one Core owner with byte-level Python/SWift characterization. |
| `LSW-R006.3` | Every adapter reports epoch, transport, authentication, readiness, and stale completion through Core and executes the resulting lifecycle effects. |
| `LSW-R006.4` | Candidate rotation, retry bounds, and delayed-callback invalidation have no adapter-side policy owner. |
| `LSW-R006.5` | Exactly one receive owner per epoch is Core-admitted; replacement first cancels the old owner and stale completions cannot affect the next epoch. |
| `LSW-R006.6` | Core owns liveness and bounded overlay backpressure decisions; adapters expose native queue and timer mechanics only. |
| `LSW-R006.7` | Linux, macOS, and physical-iOS traceability records classify the same Python-reference behavior and make remaining platform exclusions explicit. |

## Engineering rules

- Move shared behavior in vertical slices. A slice changes both consumers to
  Core and removes the duplicate owner; a forwarding facade may not acquire
  protocol logic.
- Core transitions are deterministic and serialization-safe. Queues, locks,
  callbacks, polling, and OS timers remain adapter mechanics.
- Characterization compares bytes, effects, state, counters, errors, and
  redacted snapshots. Source guards enforce ownership boundaries but do not
  establish behavioral parity by themselves.
- Every change keeps Python and Swift evidence, requirement ownership, and
  product applicability aligned. A capability rejection remains a parity gap
  until its Linux mechanism is implemented or a requirement scopes it to a
  different product.
- SwiftPM package targets are the common-source authority. Apple build graphs
  consume package products rather than maintaining another common source list.

## Future TODO

Only unfinished work is listed here. Completed work packages are intentionally
absent; their durable behavior is described above and their detailed evidence
lives in the traceability records.

### Core convergence

| Item | Remaining outcome |
| --- | --- |
| `LSW-R006` | Move the overlay coordinator, stream/WebSocket logical framing, epoch/readiness, reconnect, receive ownership, cancellation, and backpressure decisions into Core; adapters execute transport effects only. |
| `LSW-R007` | Move ChannelMux TCP/UDP/TUN state, service/catalog lifecycle, packet policy, and portable IP handling into Core; retain platform socket and packet-device execution below it. |
| `LSW-R008` | Consolidate typed configuration, capability admission, Admin routing/redaction, onboarding, and secret transformation in Core while retaining platform storage and HTTP services. |
| `LSW-R009` | Finish package-product adoption, remove duplicate shared source ownership, and make Linux/macOS/Core/Windows-sentinel validation and traceability required CI behavior. |

### Linux product mechanisms

| Item | Remaining outcome |
| --- | --- |
| `LSW-005` | Qualify the Linux TUN adapter with privileged bidirectional packet, queue-bound, and cleanup evidence. |
| `LSW-005A` | Add authenticated multi-peer myudp listener admission around the Core peer registry. |
| `LSW-005B` | Select and qualify a maintained Linux QUIC backend, including mixed-runtime and privileged-TUN behavior. |
| `LSW-005C` | Select and qualify a maintained TLS WebSocket backend with fail-closed trust and certificate behavior. |
| `LSW-006` | Integrate hook, route, DNS, underlay-preservation, and teardown lifecycle evidence without duplicating hook policy. |
| `LSW-007` | Complete CLI, Admin, operational documentation, signal handling, diagnostics, and capability guidance for the admitted Linux feature set. |
| `LSW-008` | Run the final Linux product parity gate: clean build, common and mixed-runtime suites, privileged TUN/route/DNS/hook qualification, and a zero-gap applicable feature inventory. |

### Optional follow-on

`LSW-R010` adds Windows adapters after Linux parity closes. It is not a gate
for Linux delivery.

`R005.4c` is optional TestFlight release housekeeping: record the signed
archive identity and upload reference for a source revision already qualified
by R005.4b. It does not block R005 development work or repeat device
functional qualification.

## Open platform decisions

- supported Linux distributions and deployment model;
- DNS backend expectations for the existing hook;
- maintained Linux TLS WebSocket and QUIC providers; and
- Windows socket, packet-device, route/DNS, service, and secret providers.

The admitted TCP, cleartext WebSocket, and myudp clients remain the
interoperability baseline while these decisions are resolved. Privilege
elevation remains operator-controlled on every platform.
