# Linux Swift Client Design

## Current runtime

`ObstacleBridgeLinux` is a foreground SwiftPM client. It reads the sectioned
runtime configuration, owns Linux resources and exposes a local redacted Admin
projection. It has no Python runtime dependency; the Linux product build is
`./scripts/build_linux_app.sh`.

`ObstacleBridgeCore` owns portable codecs, SecureLink and myudp state,
compression policy, ChannelMux service transitions, service-catalog replacement,
and packet-model validation. Core APIs exchange typed records and effects only;
they do not contain sockets, packet devices, framework callbacks, or platform
handles. Linux translates those effects to POSIX/NIO resources. Apple translates
the same contracts to its URLSession, Security, Network, and packet-tunnel
resources. This is the cross-platform seam: a resource owner may change, but
the protocol and lifecycle owner does not.

Linux calls each admitted SC.1 Core surface through a Linux adapter. The
ChannelMux TCP/UDP runtimes own service-channel admission and epoch withdrawal;
the Linux socket owner performs only descriptor, peer-address, and byte-I/O
work. Remaining product qualifications are recorded under their applicable
work packages below rather than as an unadopted Core surface.

## SC.2 Linux admission map

Linux consumes portable policy only through explicit Core ports. The resource
owner supplies POSIX/NIO mechanics and redacted snapshots; it does not recreate
portable selection or topic policy.

| Contract | Linux admission | Linux-host evidence |
| --- | --- | --- |
| Configured peer candidates | `ObstacleBridgePeerAddressPort` | `corePeerAddressPortNormalizesLinuxCandidateLists` |
| Admin snapshot envelopes | `ObstacleBridgeAdminSnapshotSupport` | `statusAndPeersAreRedactedAndDescribeLayeredState` |
| Admin live topics | `ObstacleBridgeAdminLiveTopicPort` | `statusAndPeersAreRedactedAndDescribeLayeredState` |
| Local proxy provider | Not admitted; configuration fails closed. | `rejectsUnsafeRuntimeChoicesBeforeNetworking` |
| TUN diagnostics | Not admitted; configuration fails closed under `LSW-005`. | `rejectsUnsafeRuntimeChoicesBeforeNetworking` |
| Persisted secret envelopes | Not admitted; the Linux foreground runtime has no configuration-write/key-material owner. | Read-only Admin routes and redaction coverage above. |

The non-admitted rows are product capabilities, not Linux-local substitutes:
their remaining delivery and qualification stay with `LSW-005`, `LSW-006`, and
the Admin/product packages that own those resources.

## Resource ownership decisions

- A Linux listener or dial owner exclusively owns its descriptor/channel and
  serializes its I/O. Core owns portable channel identifiers, counters, pending
  buffers, frame validation, and reconnect/epoch state.
- The service socket owner drives public Core TCP and UDP ChannelMux effects for
  both locally accepted services and admitted remote OPENs. The remote target is
  obtained from Core's admitted service specification; Linux does not parse or
  re-decide that target. Core epoch withdrawal invalidates channels and the
  Linux owner closes the matching descriptors.
- A shared myudp listener is the sole UDP reader. It keeps a Linux-local opaque
  endpoint key and address for routing outbound effects; Core receives the
  stable key and transport epoch, never a socket address as peer identity.
- The WebSocket resource owner owns TCP/TLS, HTTP upgrade, WebSocket frames,
  proxy CONNECT, and close. It hands authenticated bytes to SecureLink. This is
  deliberately equivalent to Apple
  `ObstacleBridgeWebSocketOverlayTransportOwner`, whose URLSession/Security task
  has the same bounded ownership.
- WSS verification is mandatory. A configured PEM root extends the platform
  trust store; it never replaces it. Proxy user-info is decoded only to create a
  CONNECT `Proxy-Authorization` header, and status/logging retain host and port
  only. This applies equally to manual proxy configuration and
  `HTTP_PROXY`/`HTTPS_PROXY`.
- Linux packaging treats systemd as an external supervisor, not a protocol
  mode. The archive, unit template, and explicit installer select binary,
  configuration, account, state location, and Admin port.

## Present boundaries

The local Admin projection contains redacted lifecycle, readiness, retry,
SecureLink, session, compression, and resource-ownership counters. It never
contains secrets, keys, plaintext, nonces, or packet traffic. Runtime health
uses the Core bounded record schema and is persisted by each platform owner;
an unclean prior lifetime is a classification, not an inferred crash cause.

The Linux WSS client supports direct, environment-selected, and manual HTTP
proxies. It completes CONNECT before TLS and HTTP upgrade, so proxy bytes are
not exposed to WebSocket, SecureLink, or ChannelMux. WSS listener certificates
are operator-provided PEM identity files and the listener is loopback-only;
it is not a proxy or automated certificate issuer.

The selected Linux QUIC backend is pinned `swift-nio-quic` 0.4.1. The admitted
surface is a verified outbound single reliable stream with `hq-29`; the overlay
envelope remains above the NIO boundary. Listener configuration stays
fail-closed because upstream stream ownership aborts on first inbound stream,
and a SecureLink multi-exchange client stream also aborts on this dependency
graph.

## Open work packages

Only incomplete packages appear below. The DoD column records the present
design/evidence boundary rather than restating product requirements; the
adjacent field is the known gap that keeps the package open.

| Package | DoD / current design | Known gap |
| --- | --- | --- |
| `LSW-SC.2` | Mixed Apple sources are split through typed Core ports, leaving Apple framework and ABI handling in adapters. The remote-service catalog facade plus native-service, listener-hook, CIDR, tunnel-routing, UDP-peer, overlay-planning, first-start, Admin authentication/configuration-change challenge orchestration, TUN-helper protocol/state/loopback semantics, ChannelMux TUN state/effect policy, overlay-channel coordination, and TUN-probe diagnostic state/reply accounting are Core-owned; Apple owners receive only accepted catalog effects and apply platform configuration, Darwin route normalization, POSIX resolution, packet-device I/O, or macOS helper-process effects. Linux Admin owns validated configuration persistence, redacted exports, Core onboarding admission, and live-topic subscriptions; secret-bearing onboarding is fail-closed without a Linux key owner. | Linux callers for the remaining extracted Core contracts are planned in `LSW-SC.2L-D` through `LSW-SC.2L-F` and `LSW-SC.2L-H` through `LSW-SC.2L-L`. |
| `LSW-SC.3` | `ObstacleBridgeShared` is constrained to Apple-resource adapters; portable behavior belongs in Core. | The retained Apple-file set still needs per-file dependency classification and an enforced repository boundary. |
| `LSW-SC.4` | The source inventory remains the ownership authority while transition work is active. | Transitional shims, flat Xcode references, and inventory/traceability cleanup depend on SC.2 and SC.3. |
| `LSW-SC.2L-E` | Implement Linux bindings for `ObstacleBridgeSecureLinkPskTransportAdapter`, `ObstacleBridgeUdpOverlayPeerRuntime`, and `ObstacleBridgeOverlayLayerTransportAdapter`. **DoD:** adapter events feed bytes, transport state, monotonic time, and bounded scheduler wakeups into Core; every Core outbound byte/effect is delivered once to the selected Linux resource owner; deterministic tests cover authentication, retransmit/deadline, epoch withdrawal, UDP peer replacement, and layer readiness without duplicating protocol decisions. | No Linux caller yet owns the moved SecureLink transport adapter, UDP peer runtime, or overlay-layer adapter. |
| `LSW-SC.2L-F` | Implement separate Linux TCP, QUIC, and WebSocket lifecycle owners for the Core runtime contracts. **DoD:** each owner translates its own Core connect/send/receive/close/timer effects into POSIX/NIO operations and reports completion, EOF, TLS/proxy/QUIC failure, and monotonic time back as typed inputs; each has independent cancellation and epoch fencing; tests prove no owner wraps or delegates lifecycle to `ObstacleBridgeLinuxReconnectSupervisor`, and Python-peer qualification covers reconnect plus stale-completion rejection for all three transports. | No Linux caller owns the TCP/QUIC/WebSocket runtime contracts; wrapping the existing Linux reconnect owner is explicitly out of scope. |
| `LSW-SC.2L-G` | Qualify the admitted Linux SC.2 composition after `LSW-SC.2L-C` through `LSW-SC.2L-F`. **DoD:** the Linux-host suite runs Admin, service-catalog, SecureLink, UDP, TCP, QUIC, and WebSocket caller evidence against a Python peer; the inventory maps every Core contract to caller and test; unsupported TUN, proxy-provider, and persisted-secret capabilities remain fail-closed with explicit diagnostics. | Depends on the caller packages above and Linux-host runtime availability. |
| `LSW-SC.2L-H` | Implement the Linux helper-control adapter against `ObstacleBridgeTunHelperContract`. **DoD:** a Linux IPC transport maps Core command/packet envelopes and sequence checks to the selected local helper endpoint; Core command validation, snapshots, loopback semantics, packet counters, and failure payloads remain the only protocol/state authority; the adapter owns only Unix-socket/child-process lifecycle and reports disconnect, timeout, malformed reply, and cleanup completion as typed Core inputs. Linux-host tests prove OPEN_TUN/APPLY_NETWORK/REMOVE_NETWORK/WRITE_PACKET/SNAPSHOT/STOP round trips, duplicate or mismatched sequence rejection, packet-boundary preservation, reconnect after helper loss, and fail-closed behavior when no privileged `/dev/net/tun` backend is admitted. No Darwin utun, macOS process-hook, or XPC class is linked. | No Linux caller yet consumes the moved Core TUN-helper contract; privileged TUN qualification remains under `LSW-005` and hook/route/DNS qualification under `LSW-006`. |
| `LSW-SC.2L-I` | Implement the Linux TUN-probe adapter against `ObstacleBridgeTunProbeDiagnosticsSupport`. **DoD:** the adapter maps POSIX `getaddrinfo` results, monotonic time, ICMP echo packet effects, matched replies, timeout wakeups, and packet-device errors to Core inputs; Core remains the sole authority for target-family selection, outstanding waiters, reply matching, counters, cache retention, and diagnostic projection. Linux-host tests cover literal and DNS targets for IPv4/IPv6, matched and unmatched replies, timeout/cache expiry, resolver and packet-device failure, and fail-closed behavior without an admitted `/dev/net/tun` device. No Darwin socket constant, utun API, or Apple semaphore/waiter implementation is linked. | No Linux caller yet consumes the moved Core TUN-probe runtime; privileged packet-device qualification remains under `LSW-005`. |
| `LSW-SC.2L-J` | Implement the Linux overlay-channel adapter against `ObstacleBridgeOverlayChannelCore` and `ObstacleBridgeChannelMuxTunRuntime`. **DoD:** the adapter supplies Linux packet-device reads, monotonic backpressure snapshots, service-catalog startup frames, and connection lifecycle inputs; it performs Core-produced TUN OPEN/DATA/CLOSE, relay, drop, and diagnostic effects exactly once on the selected Linux resource owner. Core remains the sole authority for TUN service defaults, overlay-ready admission, shared-route selection, counters, packet relay, delay-based post-mux dropping, and connection-row projection. Linux-host tests cover pre-ready drop, first-open ordering, shared-route fan-out and relay, stale-epoch rejection, delay drop, inbound counter discontinuity, packet-device write failure, and no-device fail-closed behavior. No `NWConnection`, Darwin dispatch source, or Apple TCP-owner type is linked. | No Linux packet-device/channel owner yet consumes the moved Core overlay-channel policy; privileged packet-device qualification remains under `LSW-005`. |
| `LSW-SC.2L-K` | Core owns scalar configuration parsing plus overlay payload/inflight limits through `ObstacleBridgeRuntimeConfigPolicy`; extract the remaining grouped-runtime configuration, schema, flattening, service-catalog planning, tunnel-routing record derivation, and onboarding/bootstrap policy from `ObstacleBridgeRuntimeConfig`, then implement a Linux configuration adapter against that policy. **DoD:** Core receives only typed values and deterministic dictionaries; the Apple adapter alone performs Darwin numeric-address/CIDR normalization and environment selection; the Linux adapter owns POSIX configuration input and Linux route representation. Linux-host tests prove Python-equivalent grouped/flat precedence, secret redaction, catalog-frame derivation, invalid route rejection, IPv4/IPv6 literal handling, and fail-closed unsupported TUN/proxy/secret configuration without importing Darwin, Network, or Apple runtime types. | No Linux caller owns the remaining RuntimeConfig policy; Core extraction is required before Linux configuration admission can claim parity. |
| `LSW-SC.2L-L` | Extract packet-tunnel route/address/DNS planning and diagnostic projection from `ObstacleBridgePacketTunnelConfiguration` into Core, then implement the Linux packet-device network-settings adapter. **DoD:** Core validates IPv4/IPv6 route records, merges configured and peer-excluded routes, derives MTU/DNS/enabled state, and projects route diagnostics without `NetworkExtension`; the Apple adapter alone creates `NEPacketTunnelNetworkSettings`, and the Linux adapter translates Core effects to the admitted helper or `ip`/DNS owner. Linux-host tests prove default and overridden route composition, full-tunnel exclusion, IPv4/IPv6 diagnostics, invalid CIDR rejection, disabled-start behavior, rollback after partial apply, and fail-closed absence of a privileged packet-device backend. | No Linux owner consumes packet-tunnel configuration planning; Linux route/DNS execution remains dependent on `LSW-005` and `LSW-006`. |
| `LSW-005` | The foreground runtime keeps packet-device work outside portable Core policy. | Privileged `/dev/net/tun` bidirectional data-plane qualification is unavailable. |
| `LSW-005B.2` | QUIC remains a bounded outbound reliable-stream client boundary. | No safe Linux listener, custom-trust-root interoperability, peer-family mapping, or ChannelMux service-flow qualification exists on the pinned backend. |
| `LSW-006` | Swift consumes the existing hook contract rather than recreating route or DNS policy. | Linux hook, route, DNS, underlay-preservation, and teardown integration is unqualified. |
| `LSW-007` | Admin and runtime health expose the admitted redacted state. | Operator diagnostics, signals, and capability guidance are not complete for the full Linux product surface. |
| `LSW-008` | Clean-build and focused adapter evidence qualify individual admitted boundaries. | The product parity gate lacks privileged TUN, route, DNS, and hook qualification. |
| `LSW-R007.5` | Bounded admission and retained redacted health records are implemented across runtime owners. | Signed physical iPhone and released-host sustained-load evidence, including external termination correlation, is unavailable. |
| `LSW-R007.6` | Runtime owners provide bounded controlled-stop and prior-lifetime state. | Linux privileged TUN, signed macOS, and physical iOS common-path restart qualification remains unavailable; server shutdown can still leave a bridge child alive. |

## Known product limitations

- Linux has no separate local `proxy_provider`; this is intentionally distinct
  from the delivered outbound WebSocket HTTP proxy client.
- Listener-mode myudp rejects `own_servers` and `remote_servers`: a listener
  does not infer a target peer or bind a competing service map per child.
- Packet policy does not admit IPv6 jumbograms or encrypted payloads, and its
  packet-device-independent delivery/discard effects are not yet exposed.
- Catalog listener connection-drain behavior has not been qualified across all
  Apple resource owners.
- Proxy challenges, chained proxies, and HTTP/2 proxy transports are outside
  the single CONNECT bootstrap owner.
- The archive and installer intentionally omit repository metadata, automatic
  upgrades, and privilege provisioning; operators choose enablement and
  capabilities explicitly.

## Evidence and inventory

`LinuxSwift_r001_inventory.json` and `LinuxSwift_source_map.md` remain the
machine-readable and reviewable source-ownership maps. The focused Linux
adapter suite exercises the admitted Core-to-resource-owner paths; the product
build and inventory guard are the routine structural checks:

```bash
./scripts/build_linux_app.sh
swift test --package-path swift --filter ObstacleBridgeLinuxAdapterTests
./.venv/bin/python scripts/check_linux_swift_r001_inventory.py
```
