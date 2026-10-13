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

## Apple shared-source cleanup

`ios/native/ObstacleBridgeShared` is an Apple-adapter source set, not a
second portable Core. Its end state contains only implementation that is
shared by iOS and macOS *because it requires an Apple-only API or ABI*:
`Network`, `NetworkExtension`, `Security`, `ServiceManagement`, XPC, Darwin
TUN plumbing, or the Objective-C host bridge. Platform-neutral data models,
wire codecs, state machines, configuration parsing, planning, Admin request
semantics, and policy belong in `swift/Sources/ObstacleBridgeCore`, which must
compile for Linux and Windows Swift consumers without importing Apple
frameworks.

The baseline review covered all 47 files currently in the directory. The
machine-readable source inventory remains authoritative for the file set and
is checked with:

```bash
./.venv/bin/python scripts/check_linux_swift_r001_inventory.py
```

The following work packages are consecutive. They intentionally move behavior
rather than mechanically relocating source: public Core records/effects and
explicit ports replace dependencies on `NWConnection`, `SecIdentity`, TUN
descriptors, XPC objects, Objective-C selectors, and HTTP listeners. A package
may start only after its predecessor's definition of done has evidence.

| Package | Scope | Definition of done |
| --- | --- | --- |
| `LSW-SC.1` | Extract the 17 directly portable files below into `ObstacleBridgeCore`. | Every named implementation is removed from `ios/native/ObstacleBridgeShared`; its replacement is compiled by the Core target on macOS and Linux; Apple callers import/use the Core replacement rather than a compatibility copy; direct Python/Swift vectors cover each affected protocol or policy; and the iOS/macOS source-compilation probes still pass. |
| `LSW-SC.2` | Split the remaining mixed files below at explicit Core ports. | The Core side contains all portable types, state transitions, parsing, validation, and policy; its public API contains no Apple framework or ABI type; each remaining Apple adapter is limited to translating Core effects to platform I/O or credentials; and contract tests exercise each injected port and failure path. Linux production adoption and Linux-host evidence are separately required by `LSW-SC.2L-A` and `LSW-SC.2L-B`. |
| `LSW-SC.3` | Reduce the 13 retained Apple files to adapters and enforce the boundary. | Each retained file has a documented Apple-only dependency and imports `ObstacleBridgeCore` for shared behavior; no retained file recreates a protocol codec, state machine, configuration parser, or Admin policy; a repository guard rejects a portable implementation or an Apple-framework-free new `.swift` file under `ObstacleBridgeShared`; Core has no Apple imports; and macOS/iOS build and parity probes pass. |
| `LSW-SC.4` | Retire transitional shims and make the ownership map current. | Obsolete duplicate files and Xcode flat-source references are removed; `LinuxSwift_r001_inventory.json`, `LinuxSwift_source_map.md`, Xcode patch tests, traceability, and this design describe only the delivered owner; Linux, macOS, and iOS compile from that owner; and the clean-up leaves no pending file in this section. |

### Remaining Linux adoption packages

Extraction is not Linux delivery. The following packages make each Core
extraction an exercised Linux dependency without duplicating protocol or
product requirements: they prove that the Linux owner uses the one Core
implementation already governed by the requirements inventory.

| Package | Scope | Definition of done |
| --- | --- | --- |
| `LSW-SC.1L-A` | Adopt the direct `LSW-SC.1` extractions already in Core in Linux. | The relevant Linux adapter/runtime imports `ObstacleBridgeCore` and calls each applicable API in production code, without recreating its codec, snapshot shaping, planner, or lifecycle state machine. Focused Linux adapter tests execute the Core path for UDP frame/batch/control handling, Admin snapshot selection, overlay planning, and each admitted transport lifecycle. Python/Swift vectors remain byte- and state-equivalent where an existing parity fixture covers that behavior. `swift test --filter ObstacleBridgeLinuxAdapterTests` and the applicable mixed-runtime probes pass on Linux. |
| `LSW-SC.1L-B` | Adopt every later `LSW-SC.1` extraction as it lands. | Each extraction adds or updates the corresponding Linux caller and focused Linux adapter evidence in the same change. The caller uses the moved Core API rather than a Linux-local equivalent; its failure/backpressure/lifecycle edge is exercised; and the source inventory names the Core owner. No `LSW-SC.1` file is counted complete solely because Apple callers compile. |
| `LSW-SC.1L-C` | Qualify the complete `LSW-SC.1` Core surface in the Linux product. | Every one of the 17 source rows has a linked Linux production caller or an explicit product-scoped non-admission reason in the source inventory. The Linux runtime executes all admitted callers in its clean build and focused adapter suite, and mixed-runtime evidence covers the protocol-bearing rows. No Apple flat-source compile result is used as Linux execution evidence. |
| `LSW-SC.1L-F.1` | Expose platform-neutral public effect records from the moved ChannelMux TCP and UDP runtimes. | Linux can construct each Core runtime and submit typed local-accept, inbound OPEN/DATA/CLOSE, local-data, local-close, connection-result, and epoch-reset inputs. Effects contain only wire frames, local I/O requests, and bounded backpressure decisions; no POSIX/NIO type crosses Core. Focused Core vectors cover TCP and UDP success, malformed/stale rejection, and reset. |
| `LSW-SC.1L-F.2` | Replace Linux-local ChannelMux TCP and UDP lifecycle state with the public Core effects. | Linux socket/listener owners translate the F.1 effects into POSIX/NIO reads, writes, dial, close, and backpressure operations. A focused suite proves local accept, remote OPEN, data, close, reconnect/epoch reset, and rejected malformed or stale frames for both protocols. No Linux reconnect owner duplicates channel allocation, counters, pending-buffer, or close state. |
| `LSW-SC.1L-G` | Adopt SecureLink transport and overlay-layer effects at Linux transport boundaries. | Each Linux lower transport drives `ObstacleBridgeSecureLinkPskTransportAdapter` and `ObstacleBridgeOverlayLayerTransportAdapter` for connect, disconnect, inbound/outbound frames, retry, readiness, and liveness samples; Linux executes only the resulting I/O effects. Tests cover queued pre-auth payloads, authentication failure/retry, rekey, compression failure, readiness gating, and transport-delay rotation without Linux-local copies of these decisions. |
| `LSW-SC.1L-I` | Finish listener ownership and backpressure execution for the moved TCP, QUIC, and WebSocket overlay runtimes. | The Linux listener owners translate Core peer-add/remove and backpressure effects to POSIX/NIO/TLS operations. Focused tests exercise listener peer add/remove and backpressure for each available transport. Mixed-runtime probes cover TCP and WebSocket; QUIC listener coverage remains limited until its documented platform blocker is resolved. |
| `LSW-SC.2L-A` | Admit each SC.2 Core contract to Linux only after its Apple extraction is stable. | For every SC.2 Core contract, Linux either calls the contract through an injected Linux port in production code or records a product-scoped non-admission reason in the inventory. Linux does not copy policy, parsing, state transitions, or validation from the Apple adapter. Focused Linux-host tests exercise each admitted port's success and failure effects. |
| `LSW-SC.2L-B` | Qualify the SC.2 Linux contract surface. | The source inventory links every admitted SC.2 contract to Linux callers and Linux-host evidence; every non-admission has a product-scoped reason. Mixed-runtime tests cover protocol-bearing contracts, while Apple-only credential/device bindings remain below the Core port. |

### `LSW-SC.1` — direct Core extraction

| Source file | Core destination/responsibility |
| --- | --- |
| `ObstacleBridgeAdminAPI.swift` | Portable Admin request/response routing vocabulary and state-provider contract. |
| `ObstacleBridgeAdminConfigSupport.swift` | Admin JSON validation and configuration/onboarding request policy. |
| `ObstacleBridgeAdminSnapshotSupport.swift` | Redacted Admin snapshot shaping. |
| `ObstacleBridgeAdminWebSupport.swift` | Static-path admission, content-type mapping, and Admin UI/security-advisor payload policy. |
| `ObstacleBridgeChannelMuxCodec.swift` | Remaining ChannelMux compatibility codec facade; merge with Core codecs without changing wire bytes. |
| `ObstacleBridgeChannelMuxTcpRuntime.swift` | TCP ChannelMux lifecycle/state transitions and effects. |
| `ObstacleBridgeChannelMuxUdpRuntime.swift` | UDP ChannelMux lifecycle, fragmentation, and effects. |
| `ObstacleBridgeNativeServiceSpec.swift` | Platform-neutral service-spec model and validation. |
| `ObstacleBridgeOnboarding.swift` | Invite/onboarding configuration projection and validation. |
| `ObstacleBridgeOverlayLayerTransportAdapter.swift` | Portable overlay lifecycle adaptation and effect sequencing. |
| `ObstacleBridgeOverlayStackPlanner.swift` | Overlay selection/planning policy. |
| `ObstacleBridgeQuicOverlayRuntime.swift` | QUIC-independent overlay lifecycle state machine. |
| `ObstacleBridgeSecureLinkPskTransportAdapter.swift` | SecureLink transport-independent effect adapter. |
| `ObstacleBridgeTcpOverlayRuntime.swift` | TCP-independent overlay lifecycle state machine. |
| `ObstacleBridgeUdpOverlayCodec.swift` | UDP overlay record codec. |
| `ObstacleBridgeUdpOverlayPeerRuntime.swift` | UDP peer state machine and effects. |
| `ObstacleBridgeWebSocketOverlayRuntime.swift` | WebSocket-independent overlay lifecycle state machine. |

### `LSW-SC.1` implementation state

`ObstacleBridgeUdpOverlayCodec.swift`,
`ObstacleBridgeAdminSnapshotSupport.swift`,
`ObstacleBridgeAdminAPI.swift`,
`ObstacleBridgeChannelMuxCodec.swift`,
`ObstacleBridgeChannelMuxTcpRuntime.swift`,
`ObstacleBridgeChannelMuxUdpRuntime.swift`,
`ObstacleBridgeOverlayStackPlanner.swift`,
`ObstacleBridgeQuicOverlayRuntime.swift`,
`ObstacleBridgeTcpOverlayRuntime.swift`, and
`ObstacleBridgeUdpOverlayPeerRuntime.swift`, and
`ObstacleBridgeWebSocketOverlayRuntime.swift` are in `ObstacleBridgeCore` and
are built from those sources by the Apple flat-source projects. The UDP codec
remains a compatibility facade over the Core myUDP codec; its stream, batch,
control, and wire-frame vectors continue to exercise the same Core-owned
layout constants. The snapshot helper retains the redacted Admin envelope and
selection policy without an Apple-framework dependency. The overlay planner
and transport-independent runtime state machines depend only on Foundation and
existing Core framing/payload codecs.

`ObstacleBridgeAdminAPI` retains the platform-neutral request/response and
state-provider vocabulary; platform HTTP listeners remain outside this package.
The ChannelMux compatibility facade is an extension of Core's public codec,
so the Apple flat builds retain their source-compatible helpers without
creating a second Core type. Its TCP/UDP lifecycle and myUDP peer runtimes now
use that one Core codec and the existing portable session/effect types.
The SecureLink PSK compatibility codec, runtime, and transport adapter are
also Core-owned, so their handshake and protected-payload lifecycle has no
Apple framework dependency.
The compression configuration, accounting, and policy wrapper is also
Core-owned; Apple owners only supply transport measurements and render its
snapshot.

`ObstacleBridgeNativeServiceSpec.swift` is Core-owned. Its active construction
path converts the portable ChannelMux service record and returns that same
record for adapter use; the unused initializer that accepted the mixed
runtime-configuration record was removed rather than retaining a Core-to-Apple
type dependency.

`ObstacleBridgeAdminWebSupport.swift` is Core-owned. Static-path admission,
content-type selection, Admin UI state, and security-advisor policy now read
only portable Foundation values and the configuration dictionary; Apple hosts
remain responsible for HTTP serving the returned response.

`ObstacleBridgeOnboarding.swift` is Core-owned. Invite profile projection,
service and proxy sanitization, token encoding/decoding, and suggested-update
construction use its portable configuration view; that view accepts the same
flat and grouped invite inputs without depending on runtime socket or file
configuration code.

`ObstacleBridgeAdminConfigSupport.swift` is Core-owned. Its request parsing,
invite generation/preview, challenge response, value validation, and response
policy are portable. The mixed runtime-configuration adapter supplies the
single schema/normalization policy through `ConfigurationPolicy`; Core does
not recreate that schema.

`ObstacleBridgePeerAddressProtocolRuntime.swift` now performs bounded
IPv4/IPv6 parsing and canonical formatting in Core without Darwin or Glibc
socket conversion. `ObstacleBridgeOverlayLayerTransportAdapter.swift` is
therefore Core-owned as well, preserving the mapped-IPv4 and malformed-frame
admission rules while composing the portable compression and SecureLink
effects.

All 17 direct `LSW-SC.1` source rows are now Core-owned, with no forwarding
copy under `ObstacleBridgeShared`. The source-boundary portion still does not
close the work package: Linux must execute each admitted moved API under the
Linux adoption packages before the `LSW-SC.1` definition of done is met.

`LSW-SC.1L-A` is open: Linux does not yet execute the moved APIs as a complete
group. The existing Linux runtime uses Core codecs and selected
transport policy, but this package must replace any overlapping Linux-local
planner, lifecycle, snapshot, or myUDP facade with the moved Core type and add
direct Linux adapter evidence before those extractions count as Linux-adopted.

Current Linux adoption sends only `ObstacleBridgeUdpOverlayCodec`-validated
datagrams at the POSIX boundary, shapes the Admin transport projection through
`ObstacleBridgeAdminSnapshotSupport`, and obtains Admin JSON response bodies
from `ObstacleBridgeAdminAPI`. Linux configuration admission calls the portable
overlay-stack planner before any POSIX transport is opened. The POSIX owners
retain descriptor I/O and HTTP serialization; Core owns record acceptance,
selected runtime envelopes, and the admitted framing/effect paths.

Known gaps after this `LSW-SC.1L-A` slice: the Linux production callers cover
`ObstacleBridgeAdminAPI`, `ObstacleBridgeAdminSnapshotSupport`,
`ObstacleBridgeUdpOverlayCodec`, `ObstacleBridgeOverlayStackPlanner`, and
`ObstacleBridgeTcpOverlayRuntime` and `ObstacleBridgeQuicOverlayRuntime` for
client connection, buffered-flush, inbound-frame, and reconnect effects, plus
`ObstacleBridgeWebSocketOverlayRuntime` for client payload, ping/pong,
connection, disconnect, and proxy CONNECT effects. Linux service configuration maps admitted scalar rows through
`ObstacleBridgeNativeServiceSpec` before Linux protocol/socket admission.
Linux myUDP delegates record batching, inbound delivery, control acknowledgement,
retransmit timers, and counter rollover to `ObstacleBridgeUdpOverlayPeerRuntime`;
the adapter retains descriptor send/receive and its small delivered-record queue.
Linux-host probes against the Python peer exercise dropped data recovery,
duplicated out-of-order delivery, malformed-datagram rejection, and rollover.
POSIX/NIO retains only the connection and byte I/O below those Core effects.
Linux status readiness also uses the overlay-layer adapter's Core conjunction;
the adapter's full lifecycle/effect executor is not yet adopted.
The current macOS host can compile the portable Core target but does not expose
SwiftPM's Linux adapter target; the focused Linux adapter suite remains
required Linux-host evidence for this admission.
`LinuxSwift_r001_inventory.json` now records one machine-checked admission row
per direct `LSW-SC.1` source, including linked Linux callers, product-scoped
non-admission reasons, and the remaining deferred/partial gaps.
The Linux Admin product deliberately remains read-only and has no Apple Admin
UI/security-advisor or invite/onboarding route; the inventory records those
product-scope exclusions. Linux has no legacy compatibility-control format.
The remaining gaps are ChannelMux TCP/UDP runtime, overlay-layer lifecycle,
and QUIC listener plus backpressure owners. TCP and WebSocket listener peer
add/remove and client effect execution are Core-owned; the remaining listener
and backpressure paths still need explicit Core-effect to POSIX translations.
Linux client sessions now drive `ObstacleBridgeSecureLinkPskTransportAdapter`
for handshake, protected send/receive, and explicit rekey, using injected
session-ID and nonce material to preserve deterministic tests. Listener-side
server sessions still use their existing server owner, and Linux-host duplex,
rekey, and retry evidence remains required before this adapter is counted as
fully qualified.

The Admin-component runner now compiles the full Core ChannelMux dependency
closure. Its focused Admin UI and security-advisor vectors pass. Its separate
status/tunnel snapshot assertions currently have response-shape drift outside
the moved Admin Web policy, so those assertions are not used as `LSW-SC.1`
completion evidence until their fixture expectations are reconciled.

### `LSW-SC.2` — Core contracts with Apple implementations below them

The first SC.2 split is `ObstacleBridgeAdminConfigChallenge`. Core now owns
the challenge record, expiry, canonical JSON update comparison, and proof
decision in `ObstacleBridgeAdminConfigChallengePolicy`; its inputs are an
adapter-supplied identifier, seed, clock value, and digest function. The Apple
adapter retains only serialized challenge storage, UUID/time acquisition, and
the CryptoKit SHA-256 binding. `LSW-SC.2L-A` remains open for this contract:
Linux has not admitted a configuration-mutation surface and must either use
this policy through a Linux digest/clock port or record its product-scoped
non-admission in the source inventory.

`ObstacleBridgeAdminAuth` now follows the same boundary: Core owns challenge
and session state, expiry, cookie parsing, cookie-header formatting, and proof
decisions. The Apple adapter retains its serialized queue, UUID/time sources,
CryptoKit digest binding, and HTTP response conversion. Linux has no Admin
authentication route today, so its separate `LSW-SC.2L-A` admission is open.

`ObstacleBridgeTunPing` is now Core-owned: ICMP probe payload, IPv4/IPv6 echo
packet construction, checksum, address parsing, and reply decoding are
portable. Packet-device reads/writes remain in the Apple TUN adapter. Its
Linux admission is deliberately deferred to `LSW-SC.2L-A`, where a Linux TUN
owner can provide the packet I/O port and execute the same packet vectors.

`ObstacleBridgeConfigSecretPolicy` now owns recursive selection of sensitive
configuration fields and the versioned URL-safe envelope representation. The
Apple codec remains responsible for hostname-derived key material, CryptoKit
ChaChaPoly, and the native HKDF binding. `LSW-SC.2L-A` remains the separate
Linux admission point for a Linux key-material and cryptographic provider.

`ObstacleBridgeProxyProtocolCodec` is Core-owned for HTTP/SOCKS request
parsing, authority normalization, proxy-header rewriting, and credential
validation. The Apple adapter retains Network.framework listener/connection
ownership. Linux admission remains separately scoped to `LSW-SC.2L-A`, where
its listener owner must execute the Core decisions rather than reproduce them.

| Source file | Required Core extraction; Apple remainder |
| --- | --- |
| `ObstacleBridgeAdminAuth.swift` | Challenge/session state and proof policy; inject clock, random source, and cryptographic digest provider. |
| `ObstacleBridgeAdminConfigChallenge.swift` | Configuration-change challenge state and canonical digest/proof policy; inject clock/random/digest. |
| `ObstacleBridgeChannelMuxTunRuntime.swift` | ChannelMux TUN session, packet policy, and effects; retain only packet-device calls. |
| `ObstacleBridgeConfigSecretCodec.swift` | Secret envelope policy and serialization; inject key-storage/crypto provider. |
| `ObstacleBridgeOverlayChannelCore.swift` | Overlay channel policy and effect model; retain only `Network` connection binding. |
| `ObstacleBridgeOverlayConnectionSupport.swift` | Connection state and send/receive policy; retain only Apple connection-driver implementation. |
| `ObstacleBridgePeerAddressResolver.swift` | Address selection and normalization policy; inject resolver. |
| `ObstacleBridgeProxyServer.swift` | Proxy protocol parsing/session policy; retain only listener/connection I/O. |
| `ObstacleBridgeRuntimeConfig.swift` | Configuration schema, parsing, defaults, and derived portable settings; inject filesystem/environment access. |
| `ObstacleBridgeTunHelperContract.swift` | Helper commands, envelopes, and validation; retain only macOS helper execution and transport binding. |
| `ObstacleBridgeTunPing.swift` | Ping packet construction/parsing and diagnostics policy; inject packet I/O. |
| `ObstacleBridgeTunProbeDiagnosticsSupport.swift` | Probe correlation/history/timeout policy; inject clock and packet I/O. |
| `ObstacleBridgeWebAdminServer.swift` | HTTP request interpretation and Admin policy; retain only `NWListener`/HTTP transport. |

### `LSW-SC.3` — retained Apple adapters

These files may remain in `ios/native/ObstacleBridgeShared` only as the thin
Apple bindings described here. Their portable decisions are owned by the
packages above.

| Source file | Apple-only reason and allowed responsibility |
| --- | --- |
| `ObstacleBridgeAppleServiceCatalog.swift` | Applies Core catalog installs to Apple listener owners. |
| `ObstacleBridgeChannelMuxTCPTransportOwner.swift` | Owns `Network.framework` TCP resources. |
| `ObstacleBridgeMacOSTunAdapter.swift` | macOS `utun`/Darwin TUN device integration. |
| `ObstacleBridgeMacOSTunHelperService.swift` | macOS ServiceManagement helper lifecycle. |
| `ObstacleBridgeNativeCrypto.swift` | Objective-C selector facade for Core crypto; it must add no cryptographic behavior. |
| `ObstacleBridgeNativeProxyConnections.swift` | Apple `Network.framework` proxy connection ownership. |
| `ObstacleBridgePacketTunnelConfiguration.swift` | `NetworkExtension` settings projection; portable route/default derivation moves to Core. |
| `ObstacleBridgeQuicOverlayTransportOwner.swift` | Apple QUIC `Network.framework` resource ownership. |
| `ObstacleBridgeTcpOverlayTransportOwner.swift` | Apple TCP `Network.framework` resource ownership. |
| `ObstacleBridgeTelemetryMTLSUploader.swift` | Apple `Security` identity and URL-session mTLS binding; Core retains upload policy/spool. |
| `ObstacleBridgeTunHelperXPCTransport.swift` | macOS NSXPC helper transport. |
| `ObstacleBridgeUdpOverlayTransportOwner.swift` | Apple UDP `Network.framework`/Darwin resource ownership. |
| `ObstacleBridgeWebSocketOverlayTransportOwner.swift` | Apple URLSession/Security WebSocket resource ownership. |

The review classifies no other file in this directory as Apple-only. In
particular, Foundation-only source is not a reason to retain portable behavior
there; Core may use Foundation and the package's cross-platform dependencies.

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
- Linux does not provide the separate local `proxy_provider` capability. This
  is distinct from the admitted outbound WebSocket HTTP proxy client, which
  resolves policy and owns its CONNECT tunnel below SecureLink.
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
 owner exists. TLS WebSocket listener ownership is separate under `LSW-005C.1`.

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
aborts after TLS when a SecureLink multi-exchange stream is exercised. A
two-client listener reproduction retained the UDP channel, multiplexer,
connections, and streams using the upstream example's ownership pattern and
still reached that abort, so the fault is not an adapter lifetime inference.
The separately current Swift Network Evolution crypto rewrite cannot be pinned
with current NIO QUIC: its protocol-stack API no longer compiles against NIO
QUIC main. There is consequently no compatible released correction to select.
Neither failure is safe to expose as an admitted runtime mode. Linux QUIC
listener ownership, custom-trust-root runtime interoperability, and ChannelMux
service traffic therefore remain blocked on a released compatible backend
correction; the current source still rejects listener mode and retains only
the bounded single-exchange client probe. Peer-family preference is also not
mapped.

## LSW-005C TLS WebSocket client boundary

Outbound WSS uses the pinned `swift-nio-ssl` 2.37.5 provider and its NIO TLS
event. The TLS channel completes a verified handshake before the existing HTTP
upgrade and WebSocket framing receive plaintext bytes. That framing remains
above a small common byte-stream boundary, so cleartext WS and WSS retain the
same overlay, SecureLink, and ChannelMux ownership.

Verification is always full: there is no WSS insecure switch. With no
`ws_ca_cert`, NIO SSL uses the platform trust store. When configured, the PEM
bundle is added to that store rather than replacing it. The configured peer
name is supplied to NIO SSL for SNI and certificate-name verification; a
numeric endpoint is rejected by that backend rather than silently weakening
host verification.

The focused Linux qualification creates a P-256 certificate with localhost
and loopback identities, proves an upgrade and binary overlay round trip using
its configured PEM root, and proves that the same peer is rejected without
that root. This is intentionally an outbound client boundary; it does not
make a Linux WSS listener or proxy an admitted mode.

WSS listener ownership, proxy negotiation, and deployment integration are
separate adapter concerns; the client boundary does not add a trust bypass or a
second WebSocket protocol implementation.

## LSW-005C.1 WSS listener ownership

The Linux listener binds loopback TCP through NIO, terminates TLS before
admitting a WebSocket HTTP upgrade, and transfers only upgraded binary frames
to the existing SecureLink PSK session boundary. Certificate and private-key
paths are required for `runner.listener_mode=true`, `overlay_transport=ws`, and
`ws_tls=true`; an outbound `ws_ca_cert` is never repurposed as listener
identity material. The foreground owner selects this listener only for WSS,
leaving TCP and cleartext WS ownership unchanged.

The listener has no proxy role: outbound proxy selection and CONNECT ownership
remain in the C.2 client adapter. Listener certificates are operator-provided
PEM files; automated issuance, client-certificate policy, and public-interface
exposure are not admitted by this loopback boundary.

## LSW-005C.2.1 clear-WebSocket proxy bootstrap

Linux clear-WebSocket clients resolve proxy policy at the transport boundary:
`off` forces a direct socket, `env` selects the POSIX HTTP proxy environment,
and `manual` selects the configured endpoint. `NO_PROXY` returns to the direct
path. When a proxy is selected, the owner completes HTTP `CONNECT` before it
sends the WebSocket upgrade, so the WebSocket framing and SecureLink layers do
not observe proxy bytes.

## LSW-005C.2.2 WSS tunnel promotion

The WSS owner connects to the selected proxy without TLS, consumes the complete
successful `CONNECT` header, then inserts its verified NIO TLS handler ahead
of the established byte sink. TLS handshake completion remains mandatory before
the WebSocket upgrade, so a proxy cannot alter certificate verification or
inject HTTP bytes into the upgrade stream.

The transport snapshot preserves a proxy-specific CONNECT failure reason until
a later successful epoch replaces it. The mixed-runtime fixture proves an
operator-configured WSS client completes CONNECT, full certificate validation,
WebSocket upgrade, and one application exchange through an HTTP proxy.

Proxy endpoint strings may carry percent-encoded user-info. Both Linux Swift
and Python split that user-info from the dial endpoint and emit it only as a
Basic `Proxy-Authorization` header on CONNECT; endpoint selection, logs, and
status retain only the proxy host and port. This applies equally to
`HTTP_PROXY`/`HTTPS_PROXY` and the manual WebSocket proxy host setting.

Known gaps after `LSW-005C.2`: challenge-based proxy authentication, chained
proxies, and HTTP/2 proxy transports remain outside this owner. They would require a
separate credential and connection-pool policy, rather than extending the
single-epoch WebSocket bootstrap.

### Apple-equivalent ownership seam

The Linux TLS listener and outbound connection own only the transport epoch:
TCP/TLS channel lifetime, HTTP upgrade, WebSocket frame I/O, and close. They
hand an authenticated byte stream to SecureLink and the configured runtime in
the same way that Apple
`ObstacleBridgeWebSocketOverlayTransportOwner` owns its URLSession/Security
WebSocket task and hands overlay records upward. Neither owner embeds
ChannelMux, TUN, service catalog, or reconnect policy in the TLS/WebSocket
adapter. This keeps a future Apple listener or proxy implementation a platform
resource-owner substitution rather than a second application protocol path.

The shared cross-platform contract is: verified TLS precedes upgrade; failed
TLS, upgrade, or proxy setup creates no adopted SecureLink epoch; the owner
closes all transport resources before it reports a terminal epoch; and custom
trust roots extend rather than replace platform trust. Apple continues to use
URLSession/Security policy, while Linux uses NIO/OpenSSL policy behind that
contract.

## Linux package and service-manager integration

The distributable Linux archive includes the executable, the systemd unit
template, and an explicit installer. `install_linux_service.sh` renders an
operator-selected binary, configuration, account, state directory, and Admin
port, then reloads systemd; `--dry-run` renders without changing the host.
`package_linux_app.sh` constructs the archive from a supplied executable. A
service-manager marker in runtime JSON no longer rejects foreground startup:
systemd remains the process supervisor rather than a runtime protocol mode.

Known gaps after package/service-manager integration: RPM/DEB repository
metadata, automatic upgrades, and privilege provisioning are deliberately not
performed by the archive or installer. Operators explicitly choose service
enablement and any required network capability.

## Platform decisions still required

- Supported Linux distributions and deployment model.
- DNS backend expectations for the existing hook contract.
- Windows socket, packet-device, route/DNS, service, and secret providers.
