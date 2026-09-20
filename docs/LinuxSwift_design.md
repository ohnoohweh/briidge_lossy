# Linux Swift Client Design

## Runtime integration

`ObstacleBridgeLinux` is a foreground Linux client built from the SwiftPM
packages. It reads the established sectioned runtime configuration, owns its
overlay process and serves a local, redacted Admin projection. It has no
Python runtime dependency. The executable is built with:

```bash
./scripts/build_linux_app.sh
```

## Ownership boundaries

`ObstacleBridgeCore` is the portable owner of binary and service codecs,
SecureLink state, myudp reliability, compression decisions, ChannelMux
service-session transitions, and service-catalog replacement decisions. Core
APIs exchange typed records and effects; they do not expose sockets, packet
devices, platform handles, or platform callback types.

Linux adapters own POSIX sockets, descriptor lifetime, resolver and signal
integration, HTTP serving, and translation of Core effects to local I/O. An
adapter may bind, accept, connect, read, write, or close a local resource. It
must not allocate a portable service channel, advance a portable frame
counter, validate a service OPEN, decide remote-service catalog replacement,
or apply ChannelMux queue policy.

The Core service session accepts TCP and UDP local services, emits
OPEN/DATA/CLOSE and bounded OPEN-chunk records, validates inbound lifecycle
ordering and the configured epoch, and emits `connectLocal`, `writeLocal`, and
`closeLocal` effects. Its snapshot holds active/opened-channel, malformed,
service-failure, queue, and drop counters. The Linux service data-plane facade
only maps these effects to its wire and socket-owner representations.

`ObstacleBridgeServiceCatalogStore` accepts a complete peer catalog atomically.
It returns the listeners to withdraw before the replacement listeners to
activate, rejects equal-or-older sequences within the active transport epoch,
and clears that replay state when the epoch is withdrawn. Linux converts its
typed result to POSIX listener operations without duplicating its decision rules.
`ObstacleBridgeAppleServiceCatalog` compiles that same store into the direct
Apple source set and reassembles catalog chunks before overlay owners consume
its typed install result. The macOS host activates accepted TCP/UDP listener
replacements in separate catalog-owned listener maps and withdraws the prior
maps before starting the replacement.

`ObstacleBridgePacketModel` is the portable boundary for bounded IPv4/IPv6
header admission, address-byte projection, Internet checksum calculation, and
ChannelMux fragment header/reassembly state. Its reassembler is keyed by
channel and datagram ID, rejects overlap and inconsistent length records, and
has explicit datagram and packet-size limits. It also performs source
replacement with IPv4 header and safe ICMP/TCP/UDP checksum repair across
bounded IPv6 extension chains. `ObstacleBridgeChannelMuxSession` owns TUN
channel allocation, OPEN/DATA/CLOSE counter progression, bounded OPEN-chunk
admission, and transport-epoch reset. The packet model owns TUN binding,
ownership routing, inbound source admission, bounded drop accounting, and
ingress-shedding state. Apple adapters supply configured address bytes,
transport measurements, and packet-device I/O, then render typed results for
native diagnostics.

Server-owned shared TUN readers route a return packet through the peer-specific
binding established by that peer's authenticated TUN OPEN. A listener has no
single global overlay readiness state, so return admission is authorized only
when the process-shared registry resolves that binding to the same active TUN
device. Normal client and unbound/disconnected paths retain the ordinary
lifecycle gate. Apple owners retain their local channel across lower-layer
continuity and reannounce its OPEN at a bounded interval only while local TUN
traffic has no inbound delivery; successful inbound delivery stops replays.

## Linux operator projection

The local `/api/status` and `/api/peers` endpoints expose a redacted
Core/adapter projection: lifecycle and readiness, SecureLink state, session
diagnostics, retry state, protected-frame totals, transport ownership, and
compression telemetry. Secrets, key material, plaintext, nonces, and
unqualified traffic or failure-detail fields are absent. The compression
projection reports policy and aggregate decision/counter values only; decoding
and eligibility remain Core decisions.

## Cross-platform runtime health evidence

Swift Core defines the portable redacted record schema, bounded ring, and
atomic file representation. The Python Runner persists it beside its effective
configuration (or at an explicit environment-selected path); the Linux Swift
foreground owner persists it beside its runtime configuration; and the macOS
host runner persists it in its runtime-config directory. These owners record
startup, lifecycle, 15-second heartbeat, and controlled-stop observations and
project the prior-lifetime classification through Admin status. The iOS
packet-tunnel provider persists the same ring in the App Group at
provider-state cadence and reads it before starting a new provider lifetime.
No record adds data to SecureLink or ChannelMux.

A record contains the lifecycle sequence and clean-stop marker, process and
memory high-water measurements where the platform supplies them, heartbeat
age, packet-pump state, overlay and SecureLink epoch/state, and the existing
bounded packet-flow measurements: queued and inflight work, queue high-water,
drops, slow writes, and packet counters. It contains no packet payload,
credential, key, nonce, or peer traffic detail.

The iOS packet-flow bridge accounts separately for incoming queue shedding and
outgoing queue rejection. Both counts, together with outgoing queue depth,
inflight writes, and slow-write count, are copied into the retained provider
health record at each provider-state observation. This gives a post-loss record
of whether local packet admission was under pressure without retaining traffic.

The next runtime owner continues the retained bounded ring and reports whether
the preceding lifetime ended through a recorded controlled stop or ended
without one. Admin status provides the most recent redacted records as well as
the preceding-lifetime classification, allowing an authenticated remote
WebAdmin path to capture evidence before and after a restart. This distinguishes
a clean shutdown from an unclean termination even when the prior process could
not serve its live Admin API. Platform crash, watchdog, and memory-termination
reports remain external evidence correlated by timestamp; they are not inferred
as a specific cause from the health ring alone.

Load protection is expressed as bounded admission and backpressure before
resource exhaustion: adapters slow or discard packet work at configured queue,
write-latency, or memory thresholds while retaining the health evidence.
Runtime owners do not self-terminate to enforce these limits. Physical
qualification selects and records operating thresholds because available
memory, scheduler behavior, and termination policy differ by platform.

## Known open gaps

- Packet policy does not yet admit IPv6 jumbograms or encrypted payloads,
  classify all malformed transport payloads, or expose
  packet-device-independent effects for packet delivery and discard.
- Catalog-driven listener lifecycle still lacks connection-drain qualification
  across all Apple owners.
- Linux lacks privileged `/dev/net/tun` data-plane qualification. The
  foreground executable rejects TUN configuration until that adapter and its
  evidence exist.
- Linux does not provide TLS WebSocket, QUIC, proxy, package/service-manager,
  or multi-peer myudp-listener support.
- Physical-device threshold qualification remains open. Live Admin data alone
  cannot diagnose an abrupt runtime loss; retained health evidence must be
  correlated with platform crash, watchdog, and memory-termination reports.
- A supervised server restart can leave its bridge child alive after graceful
  termination, while the launcher and Admin endpoint have already exited.
  Shutdown must have a bounded completion path, report the blocking owner, and
  prevent orphaned packet or socket workers before a replacement instance is
  admitted.

## R007 delivery packages

The packages are consecutive. Each produces an evidence bundle that is the
entry condition for the next package. Only unfinished packages are listed.

| Package | Deliverable | Definition of done |
| --- | --- | --- |
| `LSW-R007.5a` | Qualification evidence procedure | A version-pinned procedure identifies the signed build, authenticated Admin endpoint, sampling interval, traffic source, evidence directory, and platform termination-report location. Its preflight rejects an unauthenticated overlay, missing health ring, or absent packet-direction counters. |
| `LSW-R007.5b` | iOS physical load evidence | A signed physical iPhone carries controlled sustained bidirectional tunnel traffic for the selected operating threshold. The evidence bundle contains the pre/post redacted Admin snapshots, retained health-ring tail, packet-flow queue/inflight high-water, drop and slow-write totals, and the correlated iOS termination, watchdog, or no-termination report. |
| `LSW-R007.5c` | Released-host load evidence | Each released host owner carries the same controlled sustained traffic for its selected threshold. Its evidence bundle contains the host health-ring tail, bounded-admission measurements, packet directions, and the matching platform process/termination evidence. |
| `LSW-R007.6` | Product lifecycle qualification | Linux privileged TUN, signed macOS, and physical iOS each execute the common service and packet paths their capability set admits. For every supervised restart, the evidence records the shutdown initiator, completion bound, child-process result, replacement readiness, and pre/post health classification; no replacement admits traffic while an owner from the preceding lifetime remains. The inventory links the executable evidence to Python-reference behavior and records each capability limit. |

## Follow-on Linux packages

| Package | Remaining outcome |
| --- | --- |
| `LSW-005` | Provide and qualify the Linux `/dev/net/tun` adapter, including bidirectional packets, bounded queues, cleanup, and operator-controlled privilege. |
| `LSW-005A` | Add authenticated multi-peer myudp listener admission around the Core peer registry. |
| `LSW-005B` | Select and qualify a maintained Linux QUIC backend. |
| `LSW-005C` | Select and qualify a maintained Linux TLS WebSocket backend with fail-closed trust handling. |
| `LSW-006` | Qualify hook, route, DNS, underlay-preservation, and teardown integration without reproducing hook policy in Swift. |
| `LSW-007` | Complete operator documentation, diagnostics, Admin, signal, and capability guidance for the admitted product surface. |
| `LSW-008` | Run the Linux product parity gate, including clean build, mixed-runtime suites, and privileged TUN/route/DNS/hook qualification. |

## Platform decisions still required

- Supported Linux distributions and deployment model.
- DNS backend expectations for the existing hook contract.
- Maintained Linux TLS WebSocket and QUIC providers.
- Windows socket, packet-device, route/DNS, service, and secret providers.
