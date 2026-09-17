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
bounded IPv6 extension chains; the Apple TUN adapter supplies only the
configured address bytes and renders parsed address bytes for native
diagnostic projections. Apple UDP and TUN frames use its fragmenter and
reassembler; their adapters supply local channel/socket state, MTU, and
accepted packet delivery.

## Linux operator projection

The local `/api/status` and `/api/peers` endpoints expose a redacted
Core/adapter projection: lifecycle and readiness, SecureLink state, session
diagnostics, retry state, protected-frame totals, transport ownership, and
compression telemetry. Secrets, key material, plaintext, nonces, and
unqualified traffic or failure-detail fields are absent. The compression
projection reports policy and aggregate decision/counter values only; decoding
and eligibility remain Core decisions.

## Known open gaps

- Packet policy does not yet admit IPv6 jumbograms or encrypted payloads,
  classify all malformed transport payloads, or expose
  packet-device-independent effects for packet delivery and discard.
- Catalog-driven listener lifecycle lacks iOS packet-tunnel runtime evidence
  and connection-drain qualification across all Apple owners.
- Core owns logical TUN channel binding, preference, close, epoch reset, and
  deterministic shared-peer binding/disconnect cleanup. Routing, anti-spoof
  admission, transport-delay shedding, and packet-drop accounting remain
  adapter-owned.
- Linux lacks privileged `/dev/net/tun` data-plane qualification. The
  foreground executable rejects TUN configuration until that adapter and its
  evidence exist.
- Linux does not provide TLS WebSocket, QUIC, proxy, package/service-manager,
  or multi-peer myudp-listener support.

## R007 delivery packages

The packages are consecutive. A package may start only after all completion
conditions of its predecessor have evidence in the traceability inventory.
Only unfinished packages are listed here.

| Package | Deliverable | Definition of done |
| --- | --- | --- |
| `LSW-R007.4` | Core TUN policy state | Core owns TUN-channel lifecycle, shared-TUN bindings, peer selection, anti-spoof decisions, delay shedding, drop counters, and epoch reset. Packet adapters only provide reads, accepted writes, and device state. |
| `LSW-R007.5` | Product qualification | Linux privileged TUN, signed macOS, and physical iOS exercise the common service and packet paths that each capability admits. The inventory links Python-reference behavior to executable platform evidence and records every remaining capability limit. |

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
