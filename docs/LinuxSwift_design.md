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

### ChannelMux convergence status

Core owns ChannelMux frame, control-chunk, service-open, and service-catalog
codecs, compression eligibility, overlay admission, the bounded TCP/UDP
service-session lifecycle, and epoch-scoped catalog replacement decisions.
The session emits OPEN/DATA/CLOSE, local-I/O, and cancellation effects,
including bounded control-chunk emission and reassembly. Linux consumes the
session at its service data-plane boundary and consumes Core catalog decisions
through a POSIX listener facade. Apple TCP server and ordinary client
OPEN/DATA/CLOSE channels, plus ordinary non-fragmented UDP server channels,
consume the same session; UDP client paths and TUN runtimes still retain
channel tables, packet parsing, fragmentation,
ownership, and throttling. R007 moves those remaining portable decisions into
typed Core state machines while adapters retain local socket, packet-flow, and
device execution.

## R007 work packages

Packages close consecutively. Work may establish a later Core prerequisite,
but no later package is complete until its predecessor has completion evidence
in the traceability record and its adapter-side policy has been removed.

| Package | Scope | Definition of done |
| --- | --- | --- |
| `LSW-R007.1` | Core ChannelMux session | Core admits an epoch, allocates channels/counters, reassembles control records, and emits typed outbound, local-I/O, cancellation, and bounded-queue effects. Linux and Apple consume the same state-machine tests. |
| `LSW-R007.2` | Core service catalog and lifecycle | Core validates and replaces service catalogs, resolves service identity, and owns OPEN/DATA/CLOSE lifecycle decisions. Platform code only binds, accepts, connects, reads, writes, and closes local sockets. |
| `LSW-R007.3` | TCP and UDP adapter adoption | Linux and Apple TCP/UDP owners translate Core effects to native I/O and feed all completions back into Core. No channel allocation, counter, queue, or remote-service policy remains in an adapter. |
| `LSW-R007.4` | Portable packet model | Core parses IPv4/IPv6 endpoints, normalizes eligible source addresses, recomputes required checksums, fragments/reassembles bounded TUN payloads, and classifies malformed packets. Byte characterization covers Python, Core, Linux, and Apple consumers. |
| `LSW-R007.5` | Core TUN ownership and packet policy | Core owns local-TUN channel lifecycle, shared-TUN bindings, peer routing, anti-spoof admission, scoped throttling, drops, and epoch reset. Packet-device adapters only supply packets, apply accepted writes, and expose device status. |
| `LSW-R007.6` | Product qualification and traceability | Linux, signed macOS, and physical iOS run the common ChannelMux/TUN path appropriate to their capabilities. Traceability identifies the same Python-reference behavior and explicitly records any capability-limited platform evidence. |

### Current status

| Package | Status today | Remaining completion condition |
| --- | --- | --- |
| `LSW-R007.1` | In progress: Core session behavior is covered in SwiftPM; Linux, Apple TCP server and client frames including OPEN chunks, and ordinary UDP server paths translate its effects. | Move UDP client lifecycle to the same session, then add shared consumer characterization. |
| `LSW-R007.2` | Groundwork only: Core catalog validation and the Linux facade exist. | Adopt the catalog and lifecycle decisions in Apple after R007.1 closes. |
| `LSW-R007.3` | Not started as a completion package. | Remove the remaining Apple client allocation, counter, queue, and remote-service policy after R007.1/R007.2 close. |
| `LSW-R007.4` | Not started. | Deliver the portable packet model and byte characterization. |
| `LSW-R007.5` | Not started. | Move TUN ownership and packet policy into Core. |
| `LSW-R007.6` | Not started. | Qualify the completed common path on Linux, signed macOS, and physical iOS. |

### Known R007 gaps

- UDP client paths and TUN runtimes retain ChannelMux lifecycle state beyond
  the common service-session boundary. Reduced-budget UDP fragmentation
  remains native until the portable packet model exists.
- Apple does not yet consume Core catalog replacement decisions; local-service
  queue policy is not yet one Core state machine.
- Packet parsing, address normalization, checksum repair, fragmentation, and
  reassembly remain Apple-specific implementation details.
- Shared-TUN ownership, peer routing, packet admission, throttle state, and
  drop accounting do not yet have a portable Core owner.
- Linux has no qualified privileged-TUN data-plane evidence; Apple device
  evidence must be repeated after the common TUN state machine is adopted.

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

## Open platform decisions

- supported Linux distributions and deployment model;
- DNS backend expectations for the existing hook;
- maintained Linux TLS WebSocket and QUIC providers; and
- Windows socket, packet-device, route/DNS, service, and secret providers.

The admitted TCP, cleartext WebSocket, and myudp clients remain the
interoperability baseline while these decisions are resolved. Privilege
elevation remains operator-controlled on every platform.
