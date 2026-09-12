# Linux Swift Client Design

## Purpose

This document defines the target Linux-native Swift client for ObstacleBridge
and the work needed to deliver it. The product is a foreground command-line
client that reads an existing ObstacleBridge runtime configuration, starts the
overlay entirely in Swift, exposes the existing Admin Web/API vocabulary, and
can own a Linux TUN interface when started with the required privileges.

The supported build entry point shall be:

```bash
./scripts/build_linux_app.sh
```

The target host has Swift installed. The build must use that local toolchain;
the resulting client must not need Xcode, a macOS SDK, or Python at runtime.
The Linux Python runtime is the normative functional reference, the most
complete and stable implementation, and a development/test peer. Swift source
may be reused from Apple targets, but observable behavior is accepted only
against the Python requirement, implementation, and test evidence.

## Current starting point

The repository has a substantial Swift runtime in
`ios/native/ObstacleBridgeShared/` and a runnable macOS host runner in
`ios/native/ObstacleBridgeApp/`. It already implements much of the overlay,
SecureLink, ChannelMux, Admin API, config, and service behavior in Swift. The
macOS build is currently an explicit `swiftc` source list in
`ios/scripts/build_macos_app.sh`.

The Apple targets remain the source material for later portability work:

- the host runner owns a Darwin `utun` adapter and macOS helper/XPC paths;
- some Swift files import Apple-only frameworks, including `CommonCrypto`,
  `CryptoKit`, `Network`, and Darwin APIs;
- the Linux Swift package and foreground executable are separate from the
  Apple build graph, while the Linux TUN adapter and elevated integration lane
  remain pending; and
- Linux routing and DNS lifecycle are currently expressed by
  `scripts/client-tun-hook.sh` and proven through Python.

Linux must be a deliberate portability effort, not a renamed macOS build.
Implemented observable behavior must remain interoperable with Python, macOS
Swift, and iOS Swift. Platform-specific code belongs below a narrow native OS
adapter boundary.

## Product contract

The first distributable Linux Swift client shall provide:

- one executable, `ObstacleBridgeLinux`;
- `--runtime-config <path>` and the established runner controls for bind host,
  status port, and bounded test holds;
- parsing of supported existing configuration shapes without using Python as a
  runtime bridge;
- Swift-owned overlay, SecureLink, compression, ChannelMux, service catalog,
  config/onboarding, and Admin behavior for supported features;
- `tun -> tun` client operation through `/dev/net/tun`, exchanging raw IPv4 and
  IPv6 packets through the Swift ChannelMux runtime;
- lifecycle-hook compatibility with `scripts/client-tun-hook.sh` for addresses,
  routes, DNS, underlay preservation, and cleanup;
- unprivileged operation for non-TUN configurations and a specific privilege
  failure for TUN configurations; and
- deterministic build output plus a revision, dirty-state, and build-time
  sidecar.

The first release is a foreground CLI. A GUI, package, systemd service,
privileged daemon, updater, and automatic Linux QUIC support are out of scope
for that first increment. This is not a parity waiver: the roadmap may be
reported complete only after every Linux-Python feature applicable to the
Linux Swift product is implemented and verified, including transport features
planned in the remaining work. A feature may be marked not applicable only
when its requirement explicitly belongs to a different product surface; an
unsupported, planned, skipped, or partially implemented Linux feature remains
a parity gap.

## Architecture

```text
iOS extension    macOS app/runner    Linux CLI    future Windows host
      \                 |                /                  /
       +----------------+---------------+------------------+
                                |
                       composition roots
                  +-------------+-------------+
                  |                           |
                  v                           v
         ObstacleBridgeCore            platform adapters
      bytes, state, policy, models   Apple / Linux / future Windows
                                      | implements core ports
                                      | sockets, TUN, DNS, timers, hooks
                                      v
                               operating-system APIs
```

The canonical common boundary is the SwiftPM library named `ObstacleBridgeCore`.
It replaces the prior narrow portable target and the portable parts of
`ios/native/ObstacleBridgeShared/`. Linux must not depend directly on a source
directory named for iOS, and Apple products must consume the same core module
rather than compile their own copy of the algorithms.

`ios/native/ObstacleBridgeShared/` is therefore a migration source, not the
final common boundary. Portable sources move under `swift/Sources/`, while its
remaining Apple mechanisms move to explicit Apple adapter targets. The flat
`ObstacleBridgeShared` source bucket is retired after all consumers use the
package products.

### Target and source ownership

| Target/source area | Owns | Must not own |
| --- | --- | --- |
| `ObstacleBridgeCore` | Wire codecs, typed configuration/service models, myudp/SecureLink/ChannelMux state machines, overlay lifecycle decisions, Admin routing and projections | Sockets, OS handles, `DispatchSource`, process execution, TUN creation, DNS calls, key stores, or UI |
| `ObstacleBridgeZlib` | The narrow zlib implementation of the core compression-engine contract | Compression policy, ChannelMux parsing, or runtime counters |
| Apple network adapters | `Network.framework`/URLSession stream, datagram, listener, WebSocket, QUIC, and trust integration | ObstacleBridge protocol framing or reconnect policy |
| macOS/iOS adapters | Darwin `utun`, XPC/ServiceManagement, Network Extension packet flow/settings, Apple secret storage | Cross-platform packet, routing, config, or Admin semantics |
| `ObstacleBridgeLinuxAdapters` | Glibc/POSIX I/O, `/dev/net/tun`, signals, process/hooks, Linux resolver and capability reporting | Wire constants, reliability windows, service catalogs, or Admin payload construction |
| future Windows adapters | WinSDK/WinSock, a selected packet-device backend, Windows routing/service/credential integration | A second implementation of any common protocol or runtime policy |

Common APIs use `Data`, typed endpoint/IP values, and core-owned events. They
must not expose `NWConnection`, `NWEndpoint`, file descriptors, `sockaddr`,
Darwin structs, or Windows handles. Required platform services are injected
through small contracts for monotonic/wall clocks, scheduling, entropy,
byte-stream/datagram/listener I/O, DNS, packet devices, compression, config and
secret storage, lifecycle hooks, and Admin HTTP/assets. Prefer deterministic
state transitions that accept an event plus time and return effects; adapters
serialize those transitions and execute the effects.

`ObstacleBridgeCore` may depend on Foundation and the already pinned
`apple/swift-crypto` `Crypto` product. It must not import Darwin, Glibc,
WinSDK, `Network`, Network Extension, XPC, `Security`, ServiceManagement,
`CommonCrypto`, `CryptoKit`, zlib, or Apple UI frameworks. It also receives
time and randomness instead of reading `Date`, `DispatchTime`, or system random
generators inside protocol state. If a current shared file cannot meet that
boundary, split its contract from its implementation rather than adding broad
conditional compilation around unrelated runtime logic.

Linux code may use Foundation, Dispatch, Glibc, POSIX descriptors, and narrowly
scoped C bindings. The macOS `utun`, Linux `/dev/net/tun`, and iOS packet-flow
implementations must conform to one packet-adapter contract and must not be
compiled into each other's product.

Swift Package Manager manifests and library targets become the source of truth
for common Swift code. `scripts/build_linux_app.sh` continues to invoke
`swift build` and install the requested executable and build-info sidecar in
the ignored `build/linux/` directory. Generated Xcode projects and the macOS
script consume the same local package products; they do not maintain another
handwritten inventory of core source files.

### TUN and privilege boundary

The Linux adapter opens `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`, drains and
writes packets without blocking the overlay event loop, and reports actual
interface name, MTU, and counters through existing snapshot vocabulary. It
exchanges raw IP packets: it must not add the four-byte Darwin `utun` header.

The client runs the checked-in Linux hook for `on_created`,
`on_channel_connected`, and `on_stopped`. The hook stays the owner of host
route and DNS mutation during the initial delivery. Swift supplies compatible
environment such as `TUN_ADDR`, `TUN_GW`, route lists, DNS servers, and resolved
overlay-peer route data; it must not independently duplicate part of that
policy.

The client must never silently invoke `sudo` or persist credentials. It may be
run as root or with an operator-selected, narrowly scoped capability/deployment
method. A privileged service is a future, separately reviewed design.

### Crypto and transports

Wire formats and security invariants are shared requirements. Linux needs a
maintained available crypto backend proven byte-compatible for the required
SHA-256/HMAC/HKDF/PBKDF2, AES-GCM, ChaCha20-Poly1305, Ed25519, and X25519 paths.
No key material may appear in logs or errors.

Transport implementations are admitted one at a time. `myudp`, TCP, and
WebSocket form the first qualification set only when their POSIX dependencies
and mixed-runtime tests pass. The current Network.framework QUIC owner is not
Linux portable. QUIC remains rejected during configuration validation until a
selected Linux-capable backend passes equivalent wire and end-to-end tests.

## Compatibility and observability

For supported features, the Linux client preserves configuration/service
definitions, SecureLink and ChannelMux bytes, readiness state, Admin paths and
payload vocabulary, lifecycle-hook arguments, cleanup behavior, and bounded
failure reporting. Python is the parity oracle. Tests compare concrete codec
vectors, configuration results, Admin payloads, transitions, and packets—not
only source-text similarity.

“Supported features are in parity” is an interim, feature-scoped statement.
“Linux Swift is in parity” is a final product statement and requires the
closed-world feature inventory and per-product traceability gate defined below
to have no applicable missing, partial, unsupported, unknown, or skipped row.

## Current implementation state

The checked-in [Linux Swift source map](./LinuxSwift_source_map.md) inventories every Swift
source selected by the macOS build, assigns its Linux portability action, and
defines the Linux v1 support and rejection matrix. It also identifies the
parity evidence required before portable code or Linux adapters may be admitted.

[Package.swift](../Package.swift) defines separate
portable-runtime, Linux-adapter, and executable targets. The executable is
currently a foreground diagnostic/runtime baseline: it reports `--help`,
`--version`, transport/config validation, runtime status, and bounded runtime
probes.

Build it from the repository root:

```bash
./scripts/build_linux_app.sh
```

The script selects a release build by default, writes
`build/linux/ObstacleBridgeLinux` and its build-info JSON sidecar, and supports
`--debug`, `--output-dir <directory>`, and the documented
`OBSTACLEBRIDGE_LINUX_*` environment overrides. Both `/build/` and SwiftPM
scratch output are ignored. The build graph contains no macOS SDK or Xcode
dependency.

The portable target has an explicit `ObstacleBridgeCrypto` contract backed by
the pinned `apple/swift-crypto` 4.5.1
`Crypto` product. It requires caller-supplied 256-bit keys and 96-bit AEAD
nonces, returns generic authentication failures rather than plaintext, and
does not log secret data. Its tests cover known-answer vectors for SHA-256,
HMAC-SHA-256, HKDF-SHA-256, PBKDF2-HMAC-SHA-256, AES-256-GCM,
ChaCha20-Poly1305, Ed25519, and X25519, plus a Python-derived SecureLink PSK
transcript vector. Existing Apple runtime sources are unchanged; platform
adoption remains a later parity-preserving refactor.

Run the focused portable crypto qualification on Linux with:

```bash
swift test --filter ObstacleBridgeCryptoTests
```

The Linux adapter target has POSIX TCP framing and cleartext
WebSocket upgrade/binary-frame clients, bounded read/write timeouts, connection
attempt snapshots, and a `--transport-probe` executable diagnostic. Mixed
Swift/Python fixture tests cover authenticated SecureLink PSK handshake and
protected application-data exchanges over both admitted lower transports. The
overlay E2E suite also runs the built Linux executable against a Python
reference peer over TCP, cleartext WebSocket, and myudp.
The executable also validates the existing sectioned JSON runtime-config shape
for those endpoints and PSK mode without exposing secrets. Its bounded
`--runtime-probe` transaction opens the configured transport and performs the
same PSK handshake/protected-data exchange when configured; the adapter also
owns an explicit multi-message configured session with deterministic close.
`--runtime-config <path> --run` starts a foreground live-runtime owner that
serializes the admitted transport, SecureLink, ChannelMux binding, bounded
reconnect timer, and shutdown. It exposes redacted `/api/status` and
`/api/peers` on its local Admin listener and handles SIGINT/SIGTERM with an
ordered stop. Process E2E coverage starts that built executable with a Python
peer over TCP, cleartext WebSocket, and myudp, verifies application readiness,
and verifies clean signal-driven shutdown.
The portable crypto target also owns the reciprocal PSK server handshake and
protected-data state machine, pinned by a deterministic Swift client/server
exchange. The foreground TCP and cleartext WebSocket listeners accept Python
clients into that server state and hand authenticated epochs to the live
ChannelMux, service-owner, receive-worker, and Admin lifecycle.
`runner.listener_mode` currently admits TCP and cleartext WebSocket PSK listeners without an outbound
peer configuration and starts its local Admin endpoint before accepting the
first peer. Myudp listener mode remains unadmitted.
For TCP and cleartext WebSocket it rotates through comma-separated configured
peer candidates on connection failure and provides an explicit fresh-epoch
reconnect operation plus a bounded fresh-epoch retry for a failed one-shot
transaction. A serialized reconnect supervisor adds bounded exponential delay,
fresh SecureLink material per epoch, observable reconnect state, retry
exhaustion, and timer cancellation on stop. A redacted runtime-status payload
and `--status` diagnostic expose
transport state, attempts, configured candidates, active endpoint, failure
reason, SecureLink mode/state, and application readiness without exposing the
PSK. QUIC and TLS WebSocket are rejected specifically before a partial session
is created; they are not advertised as Linux runtime features.
The portable ChannelMux header codec and Linux mux binding admit only
`app_ready` sessions, bound one synchronous frame in flight, replay supplied
startup/catalog frames on each fresh binding, and reject stale reconnect epochs.
The Linux configuration reader represents supported structured TCP and UDP
`own_servers` and `remote_servers` entries directly. Its service layer has
Python-compatible RS3 catalog encoding plus deterministic epoch replacement
and withdrawal state, and POSIX TCP/UDP listener owners that create local
ChannelMux OPEN/DATA/CLOSE frames with bounded queues. The foreground runtime
starts configured local listeners only after its authenticated overlay epoch is
ready and exposes aggregate service channel, queue, malformed-frame, drop, and
failure counters on the redacted Admin status response. Received RS3 catalogs
atomically replace or withdraw remote listener owners and the public
authenticated-frame handoff routes matching OPEN/DATA/CLOSE frames into them.
Each cleartext lower transport session exposes independent send and receive
operations. The live runtime attaches one epoch-tagged receive worker, with a
bounded handoff queue, to TCP, cleartext WebSocket, and myudp sessions; stop
and reconnect cancel that worker before a replacement epoch becomes visible.
Redacted Admin status exposes its state, epoch, frame/drop totals, queue depth,
and final receive failure. SecureLink PSK keeps independent serialized transmit
and receive counter/key ownership; the same receive worker authenticates each
inbound protected record once before ChannelMux dispatch. ChannelMux routes
peer-initiated control frames without a local request, and a protected receive
failure withdraws its epoch before the bounded reconnect owner exposes a
replacement. Process-level mixed-runtime service qualification establishes the
current service-owning endpoint boundary. The Linux process E2E lane proves local TCP
and UDP listener round trips through the built foreground executable over TCP,
cleartext WebSocket, and myudp against the Python SecureLink/ChannelMux
reference endpoint. A full Python runtime qualifies SecureLink authentication,
bidirectional TCP/UDP service traffic, opt-in reverse-direction catalog
delivery, and recovery after a Python peer-process restart on all three
admitted lower transports. TCP consumes Python RTT PING/PONG lower-transport
control; cleartext WebSocket consumes the Python APP/PING/PONG subframe
envelope; myudp consumes DATA_BATCH stream records and ignores transport-only
CONTROL/IDLE frames while acknowledging ordered inbound chunks. The Linux
myudp owner exchanges v2 DATA batches over connected POSIX UDP, preserves
ordered stream-record reassembly across chunk boundaries, advances candidates
after a failed live epoch, recovers after a silent-peer timeout, and carries
SecureLink PSK plus ChannelMux frames against Python peers. The authenticated
Python Admin catalog operation publishes a newer RS3 catalog, including an
empty withdrawal, and Swift replaces or stops its remote listener owners
without a reconnect. The Linux Admin HTTP server serves redacted `/api/status` and `/api/peers`
payloads from that runtime state on a listener isolated from transport and
reconnect execution. TUN service routing remains in the remaining work.

## Common Swift convergence analysis

The remaining separation follows product boundaries rather than the desired
responsibility. The root package builds `ObstacleBridgeCore` and the Linux
targets, while Apple compiles roughly the same
`ObstacleBridgeShared` files directly into each executable or Xcode target.
`ObstacleBridgeShared` has no module API: its declarations are internal and
flat compilation hides dependencies and cycles that a reusable library will
make explicit.

The generated iOS project currently uses Swift 5 language mode while the root
package uses Swift 6 tooling. Module extraction must select the language mode
deliberately and expose concurrency/`Sendable` issues as their own migration
work, not hide them inside protocol changes. CI also has a blind spot: a change
only under `swift/` selects the macOS Swift jobs but does not select the Ubuntu
integration job, and no required job directly runs `swift test`.

Conversely, much of `ObstacleBridgeLinuxAdapters` is not a Linux adapter. Nine
of its fourteen files do not import Glibc. Configuration, ChannelMux binding,
catalog state, service state, reconnect policy, receive ownership, and live
runtime orchestration are common behavior coupled to Linux concrete classes.
Only socket/file-descriptor ownership, OS scheduling integration, TUN, signals,
resolver calls, hooks, and capability discovery belong in that target.

The duplicated areas and their required disposition are:

| Area | Current evidence | Target disposition |
| --- | --- | --- |
| myudp v2 | `ObstacleBridgeCore/ObstacleBridgeMyUDPCodec.swift` and `ObstacleBridgeLinuxMyUDPTransport.swift` duplicate framing, counters, reordering, record assembly, and ACK logic from `ObstacleBridgeUdpOverlayCodec.swift`, `ObstacleBridgeUdpOverlaySessionCodec.swift`, and `ObstacleBridgeUdpOverlayPeerRuntime.swift`. The Linux path currently ignores inbound CONTROL/IDLE and has no retained retransmit window or batch coalescing. | Use the richer Apple Swift codec/session/peer engine as extraction material, close every gap against Python, and make the resulting core engine the sole Swift owner. Apple `Network` and Linux POSIX owners execute its datagram/timer effects; a future WinSock owner does the same. |
| ChannelMux and services | The portable target implements only the eight-byte mux header. Linux separately encodes O5 OPEN and RS3 catalogs, while the Apple codec also owns O4/O5, RS2/RS3, metadata, control chunks, and reassembly. | One core frame/service model and codec owns all wire formats. Core service/TCP/UDP/TUN state emits socket or packet effects; adapters never serialize ChannelMux themselves. |
| SecureLink | `ObstacleBridgeCore.swift` contains a reduced PSK client/server implementation. Apple has a separate codec and a fuller runtime with rekey, timeout, retry, readiness, replay, and diagnostic state. | Move the full role-neutral state machine to core and use the pinned `Crypto` implementation. Keep the Objective-C Apple crypto class only as a compatibility facade. |
| Stream and WebSocket overlays | Linux implements ObstacleBridge APP/PING/PONG framing in its POSIX owner. Apple TCP and QUIC logical runtime files are effectively identical, while the nominally logical WebSocket runtime exposes `URLSessionWebSocketTask.Message`. | Core owns ObstacleBridge stream/WebSocket envelopes, buffering, liveness, and lifecycle decisions. Adapters own TCP, RFC 6455/backend integration, TLS/trust, and QUIC I/O. |
| Lifecycle and readiness | Linux configured/live runtimes, receive worker, and reconnect supervisor duplicate epoch and retry decisions also repeated across four large Apple transport owners. | A serialized core coordinator owns epochs, candidate rotation policy, layered readiness, startup replay, reconnect, backpressure state, and cancellation effects. |
| Configuration and Admin | Linux reparses a supported subset of configuration and hard-codes two Admin payloads. Apple has the fuller schema, onboarding, Admin router, auth, snapshots, and redaction, but mixes them with resolver, crypto, file, and `NWListener` services. | Core parses one typed configuration and shapes one Admin API. A platform capability set controls feature admission; OS adapters supply DNS, storage, secrets, HTTP, and assets. |
| Compression, TUN, and diagnostics | Apple compression directly imports zlib and reparses mux bytes. TUN runtimes mix packet/state logic with libc IP conversion, Network Extension, Darwin `utun`, XPC, or process behavior. | Core owns compression policy, packet parsing, ChannelMux TUN state, helper DTOs, and diagnostics state. Backend targets own zlib and each OS packet device/helper. |
| Build and enforcement | Apple build scripts and tests carry raw source lists. Existing Swift parity guards watch `ios/native` but not canonical code under `swift/Sources`; no required CI job directly runs `swift test` on Linux. | Apple products import local package libraries, tests exercise modules, and guards/CI cover core plus every adapter target on its supported host. |

The Apple implementation is often the richer Swift source candidate, but it is
not the functional reference and is not copied wholesale. The Linux Python
runtime, its requirements, and executable Python behavior decide every
observable result. Differences already needing an explicit decision include
trailing bytes after declared frames, myudp CONTROL missing-list capacity, the
exact half-ring comparison, and canonical JSON key ordering. These choices
must be frozen from Python evidence before either Swift implementation is
deleted; where Apple Swift is also incomplete, core must add the missing Python
behavior rather than preserve the Swift subset.

This extraction is not a Linux rewrite: the Apple myudp codec, session codec,
and peer runtime already compile and execute with the Linux Swift toolchain
when their currently hidden endian helpers are included. The module work makes
that accidental dependency explicit and replaces its platform-facing API.

### Executable parity and traceability contract

The current traceability view cannot prove Swift completeness. The requirements
manifest maps a requirement to tests but not to the implementation that
satisfies it. Its product classifier recognizes `python`, `macos`, and `ios`,
but not `linux-swift`, and does not count `swift/Tests` as a product suite.
Consequently the aggregate report can show every requirement as test-covered
when the covering test exercises Python only. The drift report counts selected
parity-oriented tests and correctly warns that the count is evidence, not proof
of full equivalence. Neither output may be used to claim Linux Swift parity.

The target is an executable, requirement-centered matrix generated from
checked-in metadata. The existing `.github/requirements_traceability.yaml`
remains the compatibility requirement-to-test manifest while its flat parser is
in service. The versioned
[`LinuxSwift_r001_inventory.json`](./LinuxSwift_r001_inventory.json) inventory
and validator provide the per-product model that later reporting and CI
interfaces consume. Each active requirement has one row per product and the
following links:

| Matrix field | Required meaning |
| --- | --- |
| Requirement | One active `REQ-*` identifier and its observable contract |
| Applicability | `required` or a reviewed `not-applicable` with a requirement-level product-scope reason; `planned` and `unsupported` are gaps |
| Implementation | Existing source paths and symbols for Python reference, shared Swift core, and any Linux Swift adapter/composition code needed by the requirement |
| Unit/contract tests | Executable tests of the product implementation, including error and boundary behavior; source-text checks do not qualify |
| Integration/E2E tests | Built-product evidence at the same layer used by the Python requirement, including real Linux mechanisms where the behavior depends on them |
| Direct parity tests | The same fixtures, event traces, packets, configuration, or requests executed against Python and Swift with compared results |
| Status | Computed from the links and test results as `verified`, `partial`, `missing`, `failing`, or `not-applicable`; it is never a manually asserted parity flag |

The target manifest shape is equivalent to:

```yaml
REQ-EXAMPLE-001:
  products:
    python:
      applicability: required
      implementations: [src/example.py::ExampleRuntime]
      unit_tests: [tests/unit/test_example.py::test_example]
      integration_tests: [tests/integration/test_example_e2e.py::test_example]
    linux-swift:
      applicability: required
      implementations:
        - swift/Sources/ObstacleBridgeCore/ExampleRuntime.swift::ExampleRuntime
        - swift/Sources/ObstacleBridgeLinuxAdapters/ExampleIO.swift::ExampleIO
      unit_tests: [swift/Tests/ObstacleBridgeCoreTests/ExampleTests.swift::example]
      integration_tests:
        - tests/integration/test_example_e2e.py::test_example_linux_swift
  parity_tests: [tests/parity/test_example_parity.py::test_python_swift_example]
```

The matrix must distinguish `python`, `swift-core`, `linux-swift`,
`macos-swift`, and `ios-swift`. A shared core implementation may satisfy the
implementation link for several Swift products, but it does not replace each
platform's adapter or built-product evidence. A mixed-runtime smoke test proves
interoperability for its scenario only; it does not make other requirements or
the whole product green. Evidence ownership is explicit in the manifest rather
than inferred only from a test file's directory. Architecture-component
traceability uses the same per-product implementation-and-test structure.

Requirements alone are not a closed-world feature list. Before measuring
coverage, an automated inventory must enumerate the Linux Python runtime's
user-visible and protocol surfaces: CLI options and exit behavior, accepted
configuration fields, transport/client/listener roles, overlay layers,
ChannelMux service kinds, SecureLink modes, Admin routes/actions/fields,
onboarding and secret handling, TUN/routing/DNS/hooks, lifecycle/reconnect and
backpressure behavior, diagnostics/counters, and persistence/reload behavior.
Every inventory entry must link to an existing requirement or create a missing
requirement. Deleting or adding a Python feature, Swift implementation symbol,
or test must make an orphan or coverage change visible in CI.

Validation is bidirectional: each required product row must resolve from
requirement to implementation and tests, and every inventoried behavior-bearing
Python or Swift implementation entry must resolve back to its requirement and
defending tests. Pure internal helpers may be covered through their owning
component, but no transport, parser, state machine, Admin action, configuration
field, lifecycle policy, or platform mechanism may remain unmapped.

The final parity gate requires all of the following:

- every inventoried Linux Python feature has an active requirement and an
  explicit Linux Swift applicability decision;
- every Linux-applicable row links to working Python and Swift implementation
  symbols, Swift unit/contract evidence, and the same integration evidence
  class required for Python; higher-risk TUN, route, DNS, privilege, crypto,
  reconnect, listener, and multi-peer behavior has built-process or real-host
  coverage rather than a mock-only substitution;
- deterministic behavior has direct differential tests driven by shared
  fixtures, and nondeterministic/platform behavior has matched assertions over
  normalized events, state, errors, counters, and side effects;
- all required test references exist, are collected, run in their required CI
  lane, and pass without an unconditional platform/toolchain skip;
- the generated per-product report shows zero `partial`, `missing`, `failing`,
  `unsupported`, `planned`, `unknown`, or unjustified `not-applicable` Linux
  Swift rows; and
- the full Python regression suite, Swift core/adapter suites, differential
  parity suite, both mixed-runtime directions, and qualified Linux mechanism
  suites pass in the same revision.

Test quantity, aggregate requirement coverage, source similarity, compilation,
and one successful mixed-runtime path are never sufficient parity criteria.
Any discovered usage difference first becomes a failing requirement/matrix row
and a reproducing Python-versus-Swift test; parity cannot be restored merely by
changing a dashboard label or adding a waiver.

### Migration rules

- Refactor in vertical behavior slices. A slice is not complete until Apple and
  Linux both use the core implementation and the duplicate implementation has
  been removed.
- Temporary facades may forward or typealias during one slice; they may not
  contain protocol decisions, counters, parsers, or fallback implementations.
- Implement the Linux Python reference behavior when either Swift
  implementation is a reduced subset. Platform capability validation may
  reject an unavailable feature during an interim milestone, but that row
  remains incomplete until the required Linux mechanism is delivered.
- Core state machines have an explicit serialization contract and deterministic
  clock/entropy inputs. Locks, Dispatch queues, `NWConnection` callbacks, fd
  polling, and future Windows completion callbacks remain adapter concerns.
- Characterization tests compare bytes, effects, state transitions, counters,
  errors, and redacted snapshots. Source-text checks enforce dependency
  boundaries only; they are not parity evidence.
- Every vertical slice updates its requirement-to-implementation-to-test rows
  in the same revision. A slice with an unclassified Python feature or a Swift
  row lacking executable evidence is not complete.
- No new common behavior may be added under an adapter target while convergence
  is in progress. If two platforms need it, introduce it in core first.

## Remaining common-runtime work

These work areas precede or gate the remaining Linux feature work. A package
is complete only when every Definition of Done item is met; compiling alone is
not completion.

### LSW-R002 — Canonical package graph and ports

`ObstacleBridgeCore` is the importable library product for the shared Swift
surface. Its Swift 6 package target contains the former portable codecs and
crypto primitives plus OS-neutral endpoint, IP, event, clock, scheduler,
entropy, stream, datagram, listener, resolver, packet-device, compression,
persistence, and hook contracts. The contracts expose values and effects, never
Darwin, Glibc, WinSDK, `Network`, Network Extension, XPC, Security, zlib, or UI
handles.

The Linux executable and adapters import that product directly; there is no
behavior-bearing `ObstacleBridgePortable` compatibility target. The package
declares macOS and iOS support, and `ObstacleBridgeApplePackageProbe` imports
the same library product for Apple consumers. The macOS Swift workflow builds
both the core target and that probe. `check_obstaclebridge_core_imports.py` is
called by the requirements guard and rejects OS, crypto-framework, compression,
and UI imports from core.

The common port definitions establish the dependency direction only. R003
moves concrete event DTOs and wire utilities below adapters; R004 through R008
move protocol and runtime policy behind these contracts. An unsigned iOS
simulator destination build remains a CI qualification item in R009, rather
than evidence manufactured from a Linux compiler.

### LSW-R003 — Consolidate binary utilities, codecs, and service models

Move wire ownership before moving state machines. Start with a bounded binary
reader/writer so codecs do not depend on the global `Data.appendUInt*` helpers
currently hidden in the Apple ChannelMux file.

Definition of Done:

- core owns one endian-safe binary cursor/writer and one typed JSON value used
  by every codec;
- the full ChannelMux codec and service model preserve O4/O5 OPEN, RS2/RS3
  catalogs, `name`/`lifecycle_hooks`/`options`, control chunks, and strict
  bounded reassembly;
- myudp envelope/batch/stream-record, SecureLink envelope, TCP APP/PING/PONG,
  and ObstacleBridge WebSocket payload-mode codecs have one core owner;
- Apple and Linux consumers import those types, and the portable header codec,
  Linux RS3 catalog codec, Linux O5 encoder/parser, and duplicate endian helpers
  are removed;
- exact-byte vectors and a shared malformed/truncated/trailing-byte corpus pass
  on Linux and macOS; and
- adapter directories contain no allowlisted ObstacleBridge wire magic or
  alternate serializer, enforced by a source-ownership guard.

Depends on LSW-R002.

### LSW-R004 — Consolidate the full myudp runtime

Use `ObstacleBridgeUdpOverlaySessionCodec` and
`ObstacleBridgeUdpOverlayPeerRuntime` as the initial material for a role-neutral
core engine, then add any behavior required by the Python reference. Its API
accepts stream data, received datagrams, timer ticks, and transport-epoch
resets, then returns delivered records, outbound datagrams, scheduling needs,
and status changes.

Definition of Done:

- the engine owns batching/coalescing, send-window bounds, chunk counters,
  ordered reassembly, ACK/missing policy, fresh-envelope retransmission,
  CONTROL/IDLE, RTT/transmit-delay estimation, liveness, reset, and metrics;
- the Linux myudp type owns only UDP socket/address/cancel I/O and execution of
  timer effects, while the Apple owner similarly delegates protocol state;
- no myudp counter arithmetic, ACK construction, stream buffer, retransmit
  decision, or protocol constant remains in either adapter;
- deterministic tests cover loss, duplication, reordering, coalescing,
  backpressure, counter rollover, maximum missing lists, malformed input,
  idle/liveness expiry, and reconnect reset;
- Python-to-Swift and Swift-to-Python tests qualify Apple and Linux clients, and
  an in-memory multi-peer test qualifies the common listener state; and
- the reduced portable myudp codec and Linux reliability implementation are
  deleted in the same slice.

Depends on LSW-R003. LSW-005A must use this engine rather than add listener
protocol state to `ObstacleBridgeLinuxAdapters`.

### LSW-R005 — Consolidate SecureLink and crypto

Replace the separate reduced Linux and full Apple PSK implementations with one
feature-complete core state machine and one cryptographic primitive surface.

Definition of Done:

- the pinned `Crypto` backend supplies the common SHA/HMAC/HKDF/PBKDF2, AEAD,
  Ed25519, and X25519 implementation after Apple size/platform qualification;
- SecureLink client and server roles share one codec/runtime covering handshake,
  authenticated data, replay defense, rekey, timeout, retry/backoff, readiness,
  counters, and redacted diagnostics;
- clocks and random bytes are injected, and the core serialization/concurrency
  contract prevents key/counter reuse across simultaneous send, receive, and
  reconnect events;
- `ObstacleBridgeNativeCrypto` remains only where its Objective-C bridge is
  required and delegates to the common implementation;
- known-answer, wrong-key, malformed-frame, replay, timeout, rekey, reconnect,
  and deterministic client/server tests pass on Linux and Apple, together with
  mixed Python interoperability; and
- direct `CryptoKit`/`CommonCrypto` SecureLink logic and the reduced portable
  client/server implementation are removed.

Depends on LSW-R003 and may proceed in parallel with LSW-R004.

### LSW-R006 — Consolidate overlay layers and lifecycle

Create a core overlay coordinator over injected transport sessions. Merge the
identical TCP/QUIC length-framing state and detach WebSocket logical frames from
`URLSessionWebSocketTask.Message`; keep each concrete transport mechanism in an
adapter.

Definition of Done:

- core owns APP/PING/PONG handling, early buffers, candidate/epoch decisions,
  layered readiness, startup-frame replay, receive ownership, bounded queues,
  backpressure state, reconnect/backoff, and cancellation ordering;
- the stack planner and capability admission select an available injected
  stream, datagram, WebSocket, or QUIC factory without importing it;
- the WebSocket core uses neutral `.binary(Data)`/`.text(String)` values, while
  RFC 6455, URLSession/Network.framework, POSIX, TLS, proxy, and trust mechanics
  remain below adapters;
- compression policy and counters use the canonical ChannelMux frame model and
  an injected engine; a narrow `ObstacleBridgeZlib` target contains the zlib C
  binding;
- fake-clock/fake-transport tests pin retry, stale epoch, app-readiness,
  send/receive concurrency, queue bounds, timeout, and ordered stop behavior;
- Apple and Linux TCP, cleartext WebSocket, and myudp integrations use the same
  coordinator without advertising unavailable QUIC or TLS support; and
- Linux configured/live runtime, receive-worker, and reconnect-policy logic is
  removed from the adapter target or reduced to composition-only wrappers.

Depends on LSW-R003 through LSW-R005.

### LSW-R007 — Consolidate ChannelMux, services, and TUN state

Move the ChannelMux TCP/UDP/TUN runtimes and service/catalog lifecycle into
core. Split pure controller state from Apple `NWConnection` owners and Linux
POSIX service owners.

Definition of Done:

- core owns channel allocation, OPEN/DATA/CLOSE/DATA_FRAG handling, catalog
  replacement/withdrawal, control-chunk reassembly, queue limits, startup
  replay, stale-epoch rejection, backpressure, counters, and TUN packet policy;
- one typed service model preserves hooks/options on configuration, OPEN, and
  catalog round trips, including the compatibility formats recorded in the
  inventory;
- common TCP/UDP/TUN controllers emit connect/listen/write/close/packet effects;
  Apple, Linux, and future Windows owners only execute those effects;
- portable IP parsing and packet inspection replace libc-specific address
  structs in the core TUN runtime and diagnostics;
- the existing shared-TUN ownership, anti-spoof, destination routing,
  fragmentation, reconnect, and diagnostics tests run against the core module;
- platform integration tests prove Apple Network/packet-flow and Linux POSIX
  service I/O without any wire encoder in their socket owners; and
- `ObstacleBridgeLinuxServiceCatalog` and common parts of the Linux service data
  plane are deleted after both consumers switch.

Depends on LSW-R003 and LSW-R006. LSW-005 supplies only the Linux packet-device
implementation against this core contract; LSW-006 supplies Linux hook and
host-network lifecycle integration.

### LSW-R008 — Consolidate configuration, Admin, onboarding, and secrets

Use the Linux Python schema and Admin behavior as the functional baseline,
reusing suitable Apple Swift code only after separating it from Apple I/O and
closing its Python gaps. Replace `[String: Any]` across concurrency boundaries
with typed `Sendable` models or the core JSON value.

Definition of Done:

- one parser normalizes supported flat and sectioned configuration, endpoints,
  peer candidates, services, overlay stacks, and onboarding payloads;
- a platform capability value performs explicit post-parse admission for QUIC,
  TLS WebSocket, TUN, helpers, secret storage, and other optional mechanisms;
- resolver policy and address-family preference are core behavior, while
  `getaddrinfo`, Darwin, Glibc, and future WinSock calls are adapter services;
- one Admin router owns request/response types, auth/challenge policy, redaction,
  status/peer/TUN projections, config operations, and WebAdmin bootstrap data;
- Apple `NWListener` and Linux POSIX HTTP servers only parse/serve HTTP and
  dispatch to that router; static assets, persistence, and restart/process
  behavior use injected services;
- recursive config-secret transformation is common, but machine-key acquisition
  and storage are explicit Apple/Linux/future Windows adapters; and
- cross-platform config acceptance/rejection and exact Admin/auth/redaction
  payload tests pass, after which the Linux subset parser and hard-coded Admin
  payload builders are removed.

Depends on LSW-R002 through LSW-R007.

### LSW-R009 — Migrate builds, enforce uniqueness, and add the Windows sentinel

Finish adoption after the vertical slices have moved behavior. This package
retires the flat Apple source bucket; it does not defer duplicate deletion that
belongs to an earlier slice.

Definition of Done:

- macOS builds and generated iOS projects link local package products instead
  of compiling raw common-source lists into every target;
- remaining Apple mechanisms live in explicit Apple network, packet-tunnel,
  and macOS adapter targets, and `ios/native/ObstacleBridgeShared/` is retired
  as a flat implementation bucket;
- raw `swiftc` component probes are converted to module-backed tests/runners,
  with source-text tests retained only for import and ownership boundaries;
- required Ubuntu CI verifies the Swift toolchain, runs `swift test`, builds the
  release Linux executable, and runs focused mixed-runtime Linux tests without
  toolchain-based skips;
- macOS runs core tests before its host/app suites, an iOS simulator compile
  consumes the package, and Windows CI builds/tests core and crypto without
  implying that a Windows runtime adapter is delivered;
- workflow path detection and requirements/testing/parity/traceability/drift
  tooling cover `Package.swift`, `Package.resolved`, `swift/Sources`,
  `swift/Tests`, and every Apple/Linux/future Windows adapter path;
- product classification and suite statistics include `swift-core` and
  `linux-swift`; the traceability report emits the requirement, implementation,
  unit, integration, direct-parity, applicability, and computed-status columns
  for each product instead of deriving parity from an aggregate test count;
- CI rejects missing implementation paths/symbols, behavior-bearing Python or
  Swift implementation entries without requirement/test ownership, stale or
  uncollected test references, orphaned Python inventory features, unjustified
  applicability exclusions, and any regression from `verified` to an
  incomplete state;
- import, dependency-direction, and uniqueness guards prove that each wire
  codec and runtime policy has one owner; and
- behavior-bearing compatibility facades, obsolete source lists, and all
  migrated duplicate implementations are removed.

Depends on LSW-R002 through LSW-R008 and gates the non-refactor LSW-008 release
qualification package below.

## Remaining Linux feature work

These packages add Linux mechanisms and product behavior on top of the common
runtime. They must not introduce a Linux-specific version of a core function.

### LSW-005 — Linux TUN packet adapter

Implement only the raw-packet Linux device adapter against the packet-device
contract delivered by LSW-R007. ChannelMux/TUN policy remains in core and
interface configuration stays outside the adapter.

Definition of Done:

- `/dev/net/tun` creation uses `IFF_TUN | IFF_NO_PI`, reads/writes raw IPv4/IPv6
  packets, and closes descriptors exactly once;
- bounded queues/backpressure prevent TUN I/O from blocking overlay processing
  or growing memory without bound;
- core TUN OPEN/DATA/DATA_FRAG, reconnect, stale-binding, counter, and drop
  effects are executed without reimplementing them in the adapter;
- a privileged Linux test with a Python peer proves bidirectional packet flow
  and counter updates; and
- malformed packets or creation failure leak no descriptor or running adapter.

Depends on LSW-R007.

### LSW-005A — Linux myudp listener admission

Add server-side Linux UDP ownership around the common myudp engine delivered by
LSW-R004. It is independent of the TUN milestone and must not add another
listener protocol implementation.

Definition of Done:

- one bound UDP socket demultiplexes peer epochs without handing the shared
  descriptor to a single session;
- all DATA/CONTROL/IDLE, reliability, timing, and reset behavior delegates to a
  peer-scoped core engine; the adapter owns only address/socket/timer execution;
- peer-scoped reliable-stream counters, CONTROL/IDLE handling, inactivity
  expiry, cancellation, and reconnect cleanup match the Python listener;
- SecureLink, ChannelMux, TCP/UDP services, Admin peer rows, and bounded queues
  remain isolated per accepted peer; and
- built-process Python-client/Linux-Swift-listener E2E tests cover service
  traffic, concurrency, withdrawal, and reconnect without socket leakage.

Depends on LSW-R004 and LSW-R006. It does not depend on LSW-005.

### LSW-005B — Linux QUIC transport admission

Select, isolate, and qualify a maintained Linux QUIC backend after the TUN and
common lifecycle paths are proven.

Definition of Done:

- the backend has an explicit dependency, license, distribution, and security
  update plan;
- QUIC configuration, certificate/PSK behavior, layered readiness, and
  reconnect semantics match the portable contract; and
- mixed-runtime SecureLink and privileged TUN packet tests pass, including
  deterministic failure when the qualified backend is unavailable.

Core/backend admission depends on LSW-R006. Final privileged packet
qualification also depends on LSW-005 and the hook package LSW-006.

### LSW-005C — TLS WebSocket transport admission

Add `wss` only after a maintained Linux TLS backend and certificate lifecycle
are available.

Definition of Done:

- hostname verification, trust configuration, certificate failures, and
  redacted diagnostics fail closed;
- WebSocket upgrade, binary framing, SecureLink, and reconnect behavior remain
  compatible with the cleartext WS contract where TLS is not relevant; and
- mixed-runtime tests cover trusted success and untrusted/expired/wrong-host
  rejection without leaking key or certificate secret material.

Depends on LSW-R006.

### LSW-006 — Hook, route, DNS, and teardown integration

Integrate the existing lifecycle-hook contract without reimplementing its
routing/DNS policy in Swift.

Definition of Done:

- Swift invokes `scripts/client-tun-hook.sh` with compatible actions,
  environment, working directory, timeout, and redacted captured diagnostics;
- creation, connected state, reconnect, stop, and startup failure invoke the
  compatible lifecycle contract;
- elevated tests prove IPv4/IPv6 route apply/remove, overlay-peer underlay
  preservation, supported DNS apply/remove, and idempotent cleanup;
- hook failure exposes a failed state, rolls back owned resources, and never
  claims the tunnel connected; and
- unprivileged TUN startup exits nonzero with guidance and no route mutation.

Depends on LSW-R007, LSW-R008, and LSW-005.

### LSW-007 — CLI, Admin, and operational documentation

Finish the user-facing foreground client surface and safe-operation guidance.

Definition of Done:

- `--help`, invalid configuration errors, logs, signals, and exit status are
  stable and automated-tested;
- supported Admin Web/API status, peers, TUN routing, build info, and
  diagnostics retain Python-compatible semantics;
- SIGINT/SIGTERM performs bounded ordered overlay stop, hook teardown, TUN
  close, and Admin shutdown;
- documentation covers build, config, privileges, recovery, artifacts, the
  current matrix status, and any interim capability gaps; and
- documentation does not claim a feature before its implementation and
  qualification rows are verified.

Depends on LSW-R008 and the Linux mechanism packages represented by the final
documented feature set.

### LSW-008 — Release qualification and parity gate

Make Linux Swift delivery continuously verifiable and define the only gate that
may declare the roadmap complete. Earlier releases may name a verified feature
subset, but they must not claim product parity.

Definition of Done:

- CI builds from a clean checkout and runs portable unit, codec, config, and
  mixed-runtime integration tests;
- a privileged/self-hosted Linux lane runs real `/dev/net/tun` and routing
  tests; restricted hosted CI reports a clear skip, not a false pass;
- requirements, architecture, testing traceability, and generated statistics
  are refreshed from the executable matrix rather than manually summarized;
- the generated Python and Linux Swift feature inventories have the same set of
  required runtime capabilities, with zero missing, partial, unsupported,
  planned, unknown, or unjustified not-applicable Linux Swift rows;
- every applicable requirement links to extant Python and Swift implementation
  symbols and passing product-owned unit plus risk-appropriate integration
  evidence; all deterministic common behavior additionally has a direct
  Python-versus-Swift comparison;
- Python/Swift drift, implementation ownership, test-reference collection, and
  shared-source parity guards pass for shared changes;
- a release candidate passes the full Python regression suite, Swift suites,
  direct differential tests, both mixed-runtime directions for every transport
  and role, and privileged TUN/route/DNS/hook paths in the same revision; and
- the report contains no broad platform waiver. A genuinely different product
  feature such as a GUI may be not-applicable only when its requirement says so;
  a Python Linux runtime capability such as QUIC or TLS WebSocket must be
  implemented by its admission package before this gate can pass.

Depends on LSW-R009 and every Linux-applicable feature package identified by
the Python inventory. A release selection cannot omit a Python Linux runtime
capability and still satisfy this parity gate.

## Suggested sequence and open decisions

LSW-R002 establishes the package boundary; LSW-R003 starts wire/source movement
while preserving the current qualified evidence. LSW-R004 myudp and LSW-R005 SecureLink can then proceed in
parallel before converging in the common overlay coordinator.
LSW-R007 gates the Linux TUN adapter; LSW-R004 plus LSW-R006 gate the Linux
myudp listener. LSW-R008 gates the final CLI/Admin surface, and LSW-R009 gates
release qualification. This order prevents LSW-005 and LSW-005A from creating
new state that would immediately need to be extracted.

The complete Python feature inventory records the present partial and missing
Linux Swift rows. Each remaining work area closes its rows by adding the Swift
implementation and equivalent tests; LSW-R009 makes those relationships
executable in required CI. LSW-008 may turn the product-level parity result
green only after all Linux-applicable rows close.

The admitted TCP, cleartext WebSocket, and myudp client transports remain the
Linux interoperability baseline throughout the migration. QUIC and TLS
WebSocket remain gated by LSW-005B and LSW-005C and by selection of maintained
backends during interim milestones, but they cannot remain missing at final
parity when the Linux Python reference supports them. The pinned `swift-crypto`
dependency is the current common crypto choice; it needs Apple product-size and
platform qualification, not a second Linux implementation.

Open product/platform decisions are the supported Linux distribution matrix,
DNS backend expectations for the existing hook, Linux TLS and QUIC providers,
and the eventual Windows socket, packet-device, route/DNS, service, and secret
providers. Windows core compilation is an early portability sentinel only.
Privilege elevation remains operator-controlled on every desktop platform.
