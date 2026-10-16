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
| TUN diagnostics | Not admitted; no Linux probe-packet injection scheduler is selected. | `rejectsUnsafeRuntimeChoicesBeforeNetworking` |
| Persisted secret envelopes | Not admitted; the Linux foreground runtime has no configuration-write/key-material owner. | Read-only Admin routes and redaction coverage above. |

The non-admitted rows are product capabilities, not Linux-local substitutes:
their resource ownership remains with the authenticated helper and the
Admin/product packages that own those resources.

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
`/api/status` includes redacted Linux operator capability guidance for TUN,
effective `CAP_NET_ADMIN`, address/route, DNS, and firewall tooling. It also
correlates the packet-tunnel helper/device/policy and local/remote service
socket state with the bounded health tail; helper socket paths and session
tokens are never projected. Foreground `SIGINT` and `SIGTERM` are recorded as
fixed health origins before controlled shutdown.

The authenticated Swift TUN helper is the Linux owner of `/dev/net/tun` and
the complete packet-policy lifecycle. It applies and rolls back address,
route, underlay-preserving exclusion, `resolvectl` DNS, optional WAN-scoped
firewall, and explicitly configured absolute hook effects; it persists a
mode-600 redacted policy snapshot and cleans prior helper-owned state before
accepting new ownership. The foreground runtime either attaches to an explicit
endpoint or launches the configured Swift helper, and retains one authenticated
packet/event channel. The privileged Linux product qualification runs with
`OBSTACLEBRIDGE_PRIVILEGED_TUN=1` on an authorized host and verifies real
TUN address/route, `resolvectl` DNS, and absolute-hook apply/remove cleanup.

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
| `LSW-SC.2` | Mixed Apple sources are split through typed Core ports, leaving Apple framework and ABI handling in adapters. The remote-service catalog facade plus native-service, listener-hook, CIDR, tunnel-routing, UDP-peer, overlay-planning, first-start, Admin authentication/configuration-change challenge orchestration, TUN-helper protocol/state/loopback semantics, ChannelMux TUN state/effect policy, overlay-channel coordination, and TUN-probe diagnostic state/reply accounting are Core-owned; Apple owners receive only accepted catalog effects and apply platform configuration, Darwin route normalization, POSIX resolution, packet-device I/O, or macOS helper-process effects. Linux Admin owns validated configuration persistence, redacted exports, Core onboarding admission, and live-topic subscriptions; secret-bearing onboarding is fail-closed without a Linux key owner. | Linux callers for the remaining extracted Core contracts are planned in `LSW-SC.2L-D` through `LSW-SC.2L-F` and `LSW-SC.2L-K` through `LSW-SC.2L-L`. The completed H boundary admits a configured Unix helper-control socket without admitting privileged TUN startup; the completed I boundary maps POSIX TUN-probe inputs into its Core-owned runtime while packet-device access remains fail-closed under `LSW-005`; the completed J boundary retains its packet-device owner injection and therefore does not qualify privileged device setup. |
| `LSW-SC.3` | `ObstacleBridgeAppleShared` is constrained to Apple-resource adapters; portable behavior belongs in Core. | The retained Apple-file set still needs per-file dependency classification and an enforced repository boundary. |
| `LSW-SC.4` | The source inventory remains the ownership authority while transition work is active. | Transitional shims, flat Xcode references, and inventory/traceability cleanup depend on SC.2 and SC.3. |
| `LSW-SC.2L-F` | Implement separate Linux TCP, QUIC, and WebSocket lifecycle owners for the Core runtime contracts. **DoD:** each owner translates its own Core connect/send/receive/close/timer effects into POSIX/NIO operations and reports completion, EOF, TLS/proxy/QUIC failure, and monotonic time back as typed inputs; each has independent cancellation and epoch fencing; tests prove no owner wraps or delegates lifecycle to `ObstacleBridgeLinuxReconnectSupervisor`, and Python-peer qualification covers reconnect plus stale-completion rejection for all three transports. | The live runtime selects TCP/QUIC/WebSocket lifecycle owners that construct their lower POSIX/NIO sessions and retain independent candidate rotation, authenticated-session, cancellation, epoch admission, receive-worker, and retry-timer state; `ObstacleBridgeLinuxConfiguredRuntime` publishes only the active redacted projection. TCP connection-failure retry, WebSocket HTTP-upgrade rejection, and TCP/WebSocket immediate-EOF close handling are qualified, and the live-owner Python-peer test directly qualifies retired protected-frame rejection after reconnect for TCP and WebSocket. A Python `aioquic` peer proves the QUIC owner can reconnect. QUIC protected stale-frame qualification is explicitly deferred: the attempted SwiftNIO/aioquic SecureLink exchange fails in lower QUIC packet parsing before the SecureLink callback runs. |
| `LSW-SC.2L-G` | Qualify the admitted Linux SC.2 composition after `LSW-SC.2L-C` through `LSW-SC.2L-F`. **DoD:** the Linux-host suite runs Admin, service-catalog, SecureLink, UDP, TCP, QUIC, and WebSocket caller evidence against a Python peer; the inventory maps every Core contract to caller and test; unsupported TUN, proxy-provider, and persisted-secret capabilities remain fail-closed with explicit diagnostics. | The inventory maps each admitted lifecycle caller and current evidence. TCP/WebSocket direct protected stale-frame rejection and immediate-EOF close handling are qualified; TCP connection-failure retry and WebSocket HTTP-upgrade rejection are also qualified, with receive/retry effects owned by the selected lifecycle-owner instance. QUIC is deferred because its SwiftNIO/aioquic SecureLink test fails below the SecureLink callback during QUIC packet parsing. The full overlay matrix is workflow-dispatch-only; final G qualification cannot be claimed until the deferred QUIC lifecycle condition is complete. |
| `LSW-005B.2` | QUIC remains a bounded outbound reliable-stream client boundary. | No safe Linux listener, custom-trust-root interoperability, peer-family mapping, or ChannelMux service-flow qualification exists on the pinned backend. |
| `LSW-R007.5` | Bounded admission and retained redacted health records are implemented across runtime owners. | Signed physical iPhone and released-host sustained-load evidence, including external termination correlation, is unavailable. |
| `LSW-R007.6` | Runtime owners provide bounded controlled-stop and prior-lifetime state. | Linux privileged TUN, signed macOS, and physical iOS common-path restart qualification remains unavailable; server shutdown can still leave a bridge child alive. |
| `LSW-009` | Python helper mode can select `linux-swift`. Startup verifies the executable's embedded commit, dirty flag, and diff digest, builds when the executable is absent or does not match, and deliberately rebuilds a dirty checkout. Core owns the protocol-v1 framing and JSON control codec used by the Linux socket adapter/server. The packaged macOS helper also accepts the authenticated protocol-v1 Unix-socket server command and translates Python routing payloads into its bundled Darwin hook contract. | Python has not yet selected, verified, or launched the macOS Swift helper artifact. The macOS artifact also needs an embedded identity exposed through its command interface before startup can apply the same dirty/mismatch rebuild policy. |

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
