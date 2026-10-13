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

The Linux myudp listener owns exactly one UDP descriptor and is its only
reader. It derives a stable numeric endpoint identity, maps that identity and
the selected transport epoch into the Core peer registry, and retains the
socket endpoint only for executing the registry's outbound effects. The
listener-side SecureLink PSK handshake is also driven from that reader. It
does not construct a usable child session until Core authentication succeeds;
thereafter each child receives records through its own handoff queue while the
shared descriptor remains exclusively under listener ownership. This prevents
one endpoint's reliability state, delayed datagrams, or authentication failure
from being interpreted as another peer's state.

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
- Linux does not provide TLS WebSocket, proxy, or package/service-manager
  support.
- The foreground myudp listener rejects `own_servers` and `remote_servers`.
  This is intentional parity with listener-mode service policy: a listener
  does not infer a target peer for a locally accepted connection, and binding
  a complete service map per child would race for the same local ports.
  Packet-path qualification remains dependent on the Linux TUN adapter.
- Physical-device threshold qualification remains open. Live Admin data alone
  cannot diagnose an abrupt runtime loss; retained health evidence must be
  correlated with platform crash, watchdog, and memory-termination reports.
- A supervised server restart can leave its bridge child alive after graceful
  termination, while the launcher and Admin endpoint have already exited.
  Shutdown must have a bounded completion path, report the blocking owner, and
  prevent orphaned packet or socket workers before a replacement instance is
  admitted.

## R007 delivery packages

The packages are consecutive. A package may start only after all completion
conditions of its predecessor have evidence in the traceability inventory.
Only unfinished packages are listed here.

| Package | Deliverable | Definition of done |
| --- | --- | --- |
| `LSW-R007.5` | Physical runtime-load qualification | On a signed physical iPhone and each released host owner, controlled sustained traffic demonstrates bounded packet admission without self-termination. Retained health records and redacted Admin snapshots capture both packet directions, queue/inflight high-water, drops, slow writes, lifecycle classification, and the matching platform termination or watchdog evidence. The recorded operating threshold and authenticated remote-WebAdmin evidence location are reproducible without protocol changes. |
| `LSW-R007.6` | Product lifecycle qualification | Linux privileged TUN, signed macOS, and physical iOS exercise the common service and packet paths that each capability admits. Each supervised restart reaches a bounded, observable shutdown without orphaned workers before its replacement admits traffic. The inventory links Python-reference behavior to executable platform evidence and records every remaining capability limit. |

## Follow-on Linux packages

| Package | Remaining outcome |
| --- | --- |
| `LSW-005` | Provide and qualify the Linux `/dev/net/tun` adapter, including bidirectional packets, bounded queues, cleanup, and operator-controlled privilege. |
| `LSW-005B.2` | Qualify Linux QUIC listener ownership, configured trust anchors, and full ChannelMux service traffic. |
| `LSW-005C` | Select and qualify a maintained Linux TLS WebSocket backend with fail-closed trust handling. |
| `LSW-006` | Qualify hook, route, DNS, underlay-preservation, and teardown integration without reproducing hook policy in Swift. |
| `LSW-007` | Complete operator documentation, diagnostics, Admin, signal, and capability guidance for the admitted product surface. |
| `LSW-008` | Run the Linux product parity gate, including clean build, mixed-runtime suites, and privileged TUN/route/DNS/hook qualification. |

## LSW-005A implementation state

The registry-backed listener and PSK admission adapter are present. Endpoint
identity is an adapter-local routing key rather than a portable peer identity,
and the Core registry remains the owner of epochs, ordered myudp records,
retransmission, control, and idle effects. Configuration recognizes a myudp
listener port without requiring an outbound peer address.

The foreground owner retains one inbound-only child runtime per authenticated
endpoint. A child cannot initiate an outbound reconnect: the shared listener
withdraws the endpoint and its Core transport state instead. The owner limits
both concurrent endpoint admission and records waiting for each child, calls
Core timer and idle-expiry effects on a bounded receive cadence, and publishes
aggregate status plus one redacted Admin peer row per child. Endpoint strings
are only local routing labels in that projection.

There are no remaining LSW-005A.2 implementation gaps. Service rejection is a
deliberate listener ownership rule rather than an unfinished duplicate service
implementation. Linux TUN work remains under `LSW-005`; protocol requirements
remain in the requirements inventory.

## LSW-005B backend decision

`swift-nio-quic` 0.4.1 is the selected Linux backend. The Linux adapter target
links its `NIOQUIC` product directly, and SwiftPM pins its transitive SwiftNIO,
Swift Network Evolution, Swift TLS, and beta `swift-crypto` graph. This avoids
an adapter-local C binding and keeps QUIC stream ownership at the same POSIX
and NIO boundary as the rest of the Linux runtime. The qualification build sets
`SWIFT_CERTIFICATES_ALLOW_SWIFT_CRYPTO_BETA=1`, as required by the backend's
certificate dependency graph.

The package has no stable API guarantee, so the exact release is pinned rather
than ranged. A change to that release is a deliberate compatibility review,
not a routine dependency update.

`LSW-005B` is complete as the pinned-backend selection package. Its remaining
runtime integration was delivered by `LSW-005B.1`; the remaining Linux QUIC
work is named explicitly below rather than leaving backend selection in the
pending list.

## LSW-005B.1 implementation state

The foreground client admits `transport = quic` and maps `quic_session` peer,
port, ALPN, and explicit insecure-test posture into one NIO QUIC connection
with one bidirectional reliable stream. The established TCP overlay envelope
is carried unchanged on that stream, so Core and SecureLink do not gain an NIO
dependency. The owner closes the stream and datagram channel before releasing
its event-loop group; cancellation of an in-flight setup closes the same
datagram owner.

Certificate verification is enabled by default using the platform trust store.
`quic_insecure=true` is the only trust bypass and is used solely by the
ephemeral Python/aioquic interoperation fixture. That fixture verifies the
`hq-29` ALPN path and reliable request/reply bytes with a P-256 certificate.

Known gaps after `LSW-005B.1`: Linux has no QUIC listener owner, no configured
custom trust-anchor input, no peer-family preference mapping, and no full
ChannelMux service-flow qualification over QUIC. Those are the explicit
`LSW-005B.2` follow-up; configuration rejects QUIC listener mode until that
owner exists. TLS WebSocket remains separate under `LSW-005C`.

## LSW-005B.2.1 trust-material boundary

The Linux configuration carries an optional PEM trust-root bundle for an
outbound QUIC client. The lower client passes that bundle directly to the
selected NIO QUIC verifier; when it is absent, verification remains rooted in
the platform trust store. The existing `quic_insecure` setting remains the
explicit test-only bypass.

Known gaps after `LSW-005B.2.1`: Linux QUIC listener configuration remains
fail-closed. An NIO 0.4.1 listener reached TLS handshake but aborted inside its
upstream inbound-stream ownership before a stream could be admitted, so this
package does not expose certificate/key configuration or a crash-prone server
mode. Peer-family preference and mixed-runtime ChannelMux service-flow
qualification remain in the following `LSW-005B.2` packages.

## LSW-005B.2.2 reliable-stream qualification result

The single reliable-stream request/reply probe remains the admitted Linux
QUIC boundary. It proves TLS setup, ALPN negotiation, framing, and one
application reply against an aioquic peer, but it does not imply that a
long-lived protected session is qualified.

Known gaps after `LSW-005B.2.2`: on the pinned `swift-nio-quic` 0.4.1 graph,
the listener aborts when its first inbound stream is created, and a client
aborts after TLS when a SecureLink multi-exchange stream is exercised. Neither
failure is safe to expose as an admitted runtime mode. Linux QUIC listener
ownership, custom-trust-root runtime interoperability, and ChannelMux service
traffic therefore remain blocked on a released upstream backend correction;
the current source still rejects listener mode and retains only the bounded
single-exchange client probe. Peer-family preference is also not mapped.

## Platform decisions still required

- Supported Linux distributions and deployment model.
- DNS backend expectations for the existing hook contract.
- Maintained Linux TLS WebSocket provider.
- Windows socket, packet-device, route/DNS, service, and secret providers.
