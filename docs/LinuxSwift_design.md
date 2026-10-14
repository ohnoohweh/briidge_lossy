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
| `LSW-SC.2` | Mixed Apple sources are split through typed Core ports, leaving Apple framework and ABI handling in adapters. | Remaining mixed contracts beyond the extracted peer-address policy still need Core ports. |
| `LSW-SC.3` | `ObstacleBridgeShared` is constrained to Apple-resource adapters; portable behavior belongs in Core. | The retained Apple-file set still needs per-file dependency classification and an enforced repository boundary. |
| `LSW-SC.4` | The source inventory remains the ownership authority while transition work is active. | Transitional shims, flat Xcode references, and inventory/traceability cleanup depend on SC.2 and SC.3. |
| `LSW-SC.2L-A` | Linux may consume an SC.2 contract only through its explicit Core port. | No complete admission map and Linux-host success/failure evidence exists for the unfinished SC.2 contracts. |
| `LSW-SC.2L-B` | The inventory is the qualification map for admitted SC.2 contracts. | Contract-to-caller links, Linux-host evidence, and non-admission reasons are incomplete. |
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
