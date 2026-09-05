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
Python remains the reference implementation and a development/test peer.

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
privileged daemon, updater, and automatic Linux QUIC support are out of scope.

## Architecture

```text
runtime configuration / CLI
            |
            v
ObstacleBridgeLinux executable
            |
            +-- portable Swift runtime
            |     config, overlay, SecureLink, compression, ChannelMux,
            |     service catalog, Admin API/Web state
            |
            +-- Linux adapters
                  POSIX sockets and timers
                  Linux crypto implementation
                  /dev/net/tun packet adapter
                  process and hook runner
                  route/DNS lifecycle through existing hook
```

### Source ownership

Portable Swift targets must not import Darwin, `Network`, XPC, `CommonCrypto`,
`CryptoKit`, or Apple UI/Network Extension frameworks. If a current shared file
cannot meet that boundary, split its contract from its implementation rather
than adding broad conditional compilation around unrelated runtime logic.

Linux code may use Foundation, Dispatch, Glibc, POSIX descriptors, and narrowly
scoped C bindings. The macOS `utun`, Linux `/dev/net/tun`, and iOS packet-flow
implementations must conform to one packet-adapter contract and must not be
compiled into each other's product.

Swift Package Manager manifests and targets become the source-of-truth build
graph. `scripts/build_linux_app.sh` invokes `swift build` and installs the
requested executable and build-info sidecar in the ignored `build/linux/`
directory. The macOS script may migrate later; Linux delivery must not wait for
that migration.

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
The Linux myudp owner exchanges v2 DATA batches over connected POSIX UDP,
advances candidates after a failed live epoch, recovers after a silent-peer
timeout, and carries SecureLink PSK plus ChannelMux frames against Python
peers. The Linux Admin HTTP server serves redacted `/api/status` and `/api/peers`
payloads from that runtime state on a listener isolated from transport and
reconnect execution. TUN service routing is deferred to later work packages.

## Delivery work packages

Work packages are ordered by dependency. A package is complete only when every
Definition of Done item is met; compiling alone is not completion.

### LSW-005 — Linux TUN packet adapter

Implement the raw-packet Linux TUN adapter for the established ChannelMux
integration. Interface configuration stays outside the adapter.

Definition of Done:

- `/dev/net/tun` creation uses `IFF_TUN | IFF_NO_PI`, reads/writes raw IPv4/IPv6
  packets, and closes descriptors exactly once;
- bounded queues/backpressure prevent TUN I/O from blocking overlay processing
  or growing memory without bound;
- TUN OPEN/DATA/DATA_FRAG, reconnect epochs, stale binding removal, counters,
  and drop diagnostics match the ChannelMux contract;
- a privileged Linux test with a Python peer proves bidirectional packet flow
  and counter updates; and
- malformed packets or creation failure leak no descriptor or running adapter.

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

### LSW-007 — CLI, Admin, and operational documentation

Finish the user-facing foreground client surface and safe-operation guidance.

Definition of Done:

- `--help`, invalid configuration errors, logs, signals, and exit status are
  stable and automated-tested;
- supported Admin Web/API status, peers, TUN routing, build info, and
  diagnostics retain Python-compatible semantics;
- SIGINT/SIGTERM performs bounded ordered overlay stop, hook teardown, TUN
  close, and Admin shutdown;
- documentation covers build, config, privileges, recovery, artifacts, and
  unsupported features; and
- documentation does not imply service, GUI, package, or QUIC support.

### LSW-008 — Release qualification and parity gate

Make Linux Swift delivery continuously verifiable and define release acceptance.

Definition of Done:

- CI builds from a clean checkout and runs portable unit, codec, config, and
  mixed-runtime integration tests;
- a privileged/self-hosted Linux lane runs real `/dev/net/tun` and routing
  tests; restricted hosted CI reports a clear skip, not a false pass;
- requirements, architecture, testing traceability, and generated statistics
  are refreshed for delivered coverage;
- Python/Swift drift and shared-source parity guards pass for shared changes;
- a release candidate passes documented mixed-runtime smoke runs for each
  supported transport and a privileged full TUN path; and
- deferred Linux QUIC, packaged service/daemon, GUI, and elevated helper work
  are explicitly listed as unsupported.

## Suggested sequence and open decisions

The admitted TCP, cleartext WebSocket, and myudp transports supply the secure
ChannelMux baseline for the LSW-005 TUN milestone. QUIC and TLS WebSocket
remain gated by LSW-005B and LSW-005C.
LSW-006 through LSW-008 make the result supportable.

Before implementation, select and pin the Linux crypto dependency strategy;
define the supported Linux distribution matrix; confirm DNS backend expectations
against the existing hook; and keep privilege elevation operator-controlled.
