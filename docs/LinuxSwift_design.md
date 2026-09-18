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

## R007 delivery packages

The packages are consecutive. A package may start only after all completion
conditions of its predecessor have evidence in the traceability inventory.
Only unfinished packages are listed here.

| Package | Deliverable | Definition of done |
| --- | --- | --- |
| `LSW-R007.5` | Physical runtime-load qualification | On a signed physical iPhone and each released host owner, controlled sustained traffic demonstrates bounded packet admission without self-termination. Retained health records and redacted Admin snapshots capture both packet directions, queue/inflight high-water, drops, slow writes, lifecycle classification, and the matching platform termination or watchdog evidence. The recorded operating threshold and authenticated remote-WebAdmin evidence location are reproducible without protocol changes. |
| `LSW-R007.6` | Product qualification | Linux privileged TUN, signed macOS, and physical iOS exercise the common service and packet paths that each capability admits. The inventory links Python-reference behavior to executable platform evidence and records every remaining capability limit. |

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
