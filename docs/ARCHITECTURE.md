# Architecture

This document describes the main runtime components and how they contribute to the overall behavior of the project.

## Architectural layers

The current runtime can be understood in six layers:

1. transport/session layer
2. secure-link layer
3. reliability and framing layer
4. channel/service multiplexing layer
5. runner and process orchestration layer
6. admin web and observability layer

The secure-link layer now exists as a delivered runtime slice between the transport/session layer and the current reliability/framing layer. The delivered modes now include both the Phase 1 PSK slice and the Phase 2 certificate-based trust-anchor / certificate-validation slice, so the boundary itself is no longer only a reservation.

## Stable component IDs

The following component IDs are intended to stay stable so requirements, tests, and future design notes can point to architecture elements without depending on section wording.

| Component ID | Component | Primary scope |
|---|---|---|
| `ARC-CMP-001` | Transport and session layer | Transport-specific peer connectivity, listener/client state, and per-peer transport ownership |
| `ARC-CMP-002` | Reliability and framing layer | Reliable overlay framing, retransmission, RTT, inflight, and missed-frame tracking |
| `ARC-CMP-003` | Channel and service multiplexing layer | `own_servers`, `remote_servers`, channel routing, and peer-scoped service isolation |
| `ARC-CMP-004` | Runner and process orchestration layer | CLI/config composition, lifecycle wiring, restart/shutdown coordination, process startup, and entrypoint supervision |
| `ARC-CMP-005` | Admin web and observability layer | HTTP API/UI, auth/session control, runtime snapshots, logs, and operator visibility |
| `ARC-CMP-006` | Secure-link layer | Delivered PSK-based and certificate-based authentication, frame protection, replay defense, rekeying, and secure-link diagnostics between transport sessions and `ChannelMux` |

## 1. Transport and session layer

Primary responsibility:

- establish peer-to-peer connectivity over `myudp`, `tcp`, `ws`, or `quic`

Main contribution:

- creates the underlying transport session
- owns peer connectivity state
- provides send/receive hooks into the higher framing layer

Important behaviors:

- single-peer client mode
- listener mode
- multi-peer listener behavior for transports that support multiple concurrent peer clients
- transport-specific client bootstrap, such as proxy tunnel establishment and direct-path HTTP root preflight, before higher protocol handshakes
- endpoint-local auxiliary behavior, such as WebSocket pre-upgrade HTTP/static handling, must stay scoped to the originating socket/request and must not mutate unrelated peer sessions

The current WebSocket-specific listener split, including direct static HTTP handling and same-socket upgrade considerations, is documented in [WEBSOCKET_DESIGN.md](/home/ohnoohweh/quic_br/docs/WEBSOCKET_DESIGN.md).

Representative implementation area:

- [bridge.py](/home/ohnoohweh/quic_br/src/obstacle_bridge/bridge.py)

Important proxy expectation:

- default WebSocket peer-client proxy behavior should follow platform-native settings unless application configuration explicitly overrides that behavior

### Payload-size accounting across the lower layers

There is no single project-wide "maximum packet size". The runtime applies size limits at each envelope boundary, and the effective application-data budget shrinks as more framing layers are stacked.

The current accounting model is:

1. `ChannelMux` builds a mux frame with an 8-byte header (`>HBHBH`).
2. Optional `SecureLink` wrapping adds its own secure-link frame header plus authenticated-encryption overhead before the wrapped session sees the data.
3. The concrete session (`UdpSession`, `TcpStreamSession`, `QuicSession`, or `WebSocketSession`) applies its own framing and transport-specific size limit.

Current lower-layer budgets in the runtime:

| Layer / component | What the upper layer may pass in | Additional bytes added before the next lower boundary | Current implementation note |
|---|---|---|---|
| `ChannelMux` | TCP/UDP service payload chunk | 8-byte mux header | `ChannelMux` drops a mux frame if its packed size exceeds the wrapped session's advertised app-payload limit |
| `SecureLinkPskSession` / cert mode | plaintext mux frame | 20-byte secure-link header + 16-byte AEAD tag for protected DATA frames | `get_max_app_payload_size()` subtracts this overhead from the wrapped session limit before `ChannelMux` sees it |
| `UdpSession` | session app payload | lower UDP/reliability/IP overhead below the `send_app()` boundary | Currently advertises `65535` as a software cap |
| `TcpStreamSession` | session app payload | 4-byte length prefix + 1-byte kind marker on the stream | Currently advertises `65535` as a software cap |
| `QuicSession` | session app payload | 4-byte length prefix + 1-byte kind marker inside the QUIC stream payload | Advertises configurable `quic_max_size` (default `65535`) |
| `WebSocketSession` | session app payload | 1-byte kind marker, then payload-codec expansion into the WS frame | Advertises `ws_max_size - 1` to reserve the kind byte |

From the mux perspective, the effective per-frame application-data budget is therefore:

- without secure-link: `session_limit - 8`
- with secure-link protected DATA: `session_limit - 36 - 8`

where `36 = 20-byte secure-link header + 16-byte AEAD tag`.

This same budget is also used to derive `ChannelMux._SAFE_TCP_READ`, so TCP application streams are read in chunks that fit into one mux DATA frame after headers are added. In other words, TCP stream handling does not try to preserve one large application write as one giant overlay frame; it slices the byte stream into chunks that fit the current session budget.

#### UDP

At the API boundary, `UdpSession` currently reports `65535` as its maximum application payload size. That value is a project-local software budget, not a literal statement that a `65535`-byte UDP payload is always valid on the wire.

Important caveat:

- real UDP datagrams still pay for UDP, IP, and ObstacleBridge reliability/session overhead below the `send_app()` boundary
- path MTU, IP version, and kernel/socket behavior can therefore make the true wire-safe datagram size smaller than the abstract `65535` session budget

For a concrete MTU example, assume a path MTU of `1550` bytes:

- IPv4 leaves at most `1550 - 20 - 8 = 1522` bytes for the UDP payload
- IPv6 leaves at most `1550 - 40 - 8 = 1502` bytes for the UDP payload

That is before any ObstacleBridge-specific framing inside the UDP payload. The `myudp` protocol layer then consumes another 19 bytes for `ptype + len + tx_time_ns + echo_time_ns`, so the maximum protocol payload becomes:

- IPv4: `1522 - 19 = 1503` bytes
- IPv6: `1502 - 19 = 1483` bytes

So the raw received UDP payload is already 28 bytes smaller than MTU for IPv4 and 48 bytes smaller for IPv6, and the maximum overlay protocol payload is 47 bytes smaller than MTU for IPv4 and 67 bytes smaller for IPv6. ChannelMux application data is smaller again once mux and optional secure-link headers are included.

So for UDP the current runtime is internally consistent at the `ChannelMux`/session interface, but that interface is more generous than a strict end-to-end wire budget. This is the main remaining systematic caveat in the size model.

Safety-by-design improvement:

- the mux layer now provides UDP service datagram fragmentation when one local UDP datagram would not fit into one effective session payload budget
- peer-side mux reassembles those fragments before emitting one local UDP datagram on the destination side
- the mux layer also enforces an explicit maximum UDP service datagram size and logs the active wrapped transport stack together with that cap at startup

The current mux-level fragment header carries:

- `datagram_id`
- `total_len`
- `offset`

so the receiving side can rebuild one original UDP service datagram before passing it to `sendto(...)`.

The implementation details and boundary rationale for this behavior are documented in [CHANNELMUX_DESIGN.md](./CHANNELMUX_DESIGN.md).

#### Who splits and who reassembles?

This is the key behavioral distinction once the effective session budget becomes smaller than the original local payload source.

For local TCP services:

- `ChannelMux` reads from the local TCP socket in chunks of at most `ChannelMux._SAFE_TCP_READ`
- each chunk becomes one mux `DATA` message
- on the far side, mux writes each received chunk directly into the destination TCP stream

So TCP service traffic is split by `ChannelMux` and implicitly reassembled by the receiving TCP byte stream. There is no separate mux-level message reassembly step for TCP services because the local application already consumes a stream, not message boundaries.

For local UDP services:

- each received local UDP datagram is forwarded as one mux `DATA` message
- if that one mux frame would exceed the effective session budget after mux, secure-link, and session framing are considered, `ChannelMux` fragments the UDP service datagram into multiple mux fragment messages
- the peer-side mux reassembles those fragments before emitting one local UDP datagram

So UDP service traffic no longer has to fit into one effective mux/session payload budget to survive the overlay path. Unlike TCP, however, the receiving side must preserve datagram boundaries, so reassembly happens explicitly at mux level before local delivery.

For the `myudp` transport itself, there is an additional lower-layer fragmentation and reassembly mechanism, but it sits below the session API:

- after `ChannelMux` has already produced one session payload, `UdpSession` can hand that payload into the reliable `myudp` framing layer
- that lower layer can fragment the session payload into multiple `DataPacket` frames over UDP
- the peer-side `myudp` session reassembles those fragments back into the original session payload before passing it upward to `ChannelMux`

That means there are now two separate fragmentation layers for different purposes:

- mux-level UDP fragmentation protects UDP service datagrams when the effective session budget is smaller than the original datagram
- `myudp` transport fragmentation protects one already-accepted session payload while it is being carried over the unreliable UDP transport

The `myudp` transport layer still sits below the session API; it is not the mechanism that preserves UDP service datagrams across tight mux/session budgets.

#### TCP

TCP itself is a stream, not a datagram protocol, so there is no protocol-level single-message ceiling analogous to UDP's length field. In this runtime, `TcpStreamSession` imposes a project-local application-frame budget of `65535` bytes and then adds:

- 4 bytes of stream-frame length
- 1 byte of frame kind (`APP`, `PING`, `PONG`)

The important point is that large TCP application traffic is handled by chunking at the mux layer, not by assuming one overlay APP frame must carry an arbitrarily large contiguous stream write.

#### QUIC

The current QUIC session uses the same internal `LEN(4) + KIND(1) + BYTES...` stream framing model as `TcpStreamSession`, but exposes a configurable upper-layer cap through `quic_max_size`.

That means:

- the QUIC session budget is explicit and configurable
- `ChannelMux` and `SecureLink` both account against that configured budget before sending
- QUIC send-side code also rejects application payloads above `quic_max_size`

So QUIC is conceptually aligned with TCP stream processing, but with an explicit knob rather than a hard-coded `65535` software budget.

#### WebSocket

WebSocket has two distinct size concerns:

1. the raw session payload passed down from `ChannelMux` / `SecureLink`
2. the final WebSocket frame size after text encoding, when a text payload mode is enabled

The current runtime handles this by separating the two:

- `WebSocketSession.get_max_app_payload_size()` returns `ws_max_size - 1`, reserving one byte for the internal WS kind marker before payload encoding
- `_ws_frame_max_size` is then computed from the selected payload codec's `max_encoded_size(...)`
- inbound manual WS frame parsing rejects frames larger than `_ws_frame_max_size`

Current codec growth behavior:

- `binary`: no payload expansion beyond the 1-byte kind marker
- `base64`: expansion to `4 * ceil(n / 3)` bytes
- `json-base64`: base64 expansion plus the compact JSON wrapper `{"data":"..."}`
- `semi-text-shape`: expansion to `ceil((8 * n) / 6)` encoded symbols, plus one grouping space after each full group of 8 symbols, for a total of `symbols + floor((symbols - 1) / 8)` characters

Because `_ws_frame_max_size` is derived from the encoded size rather than the raw payload size, the text-oriented modes are explicitly accounted for. This is the code path that prevents healthy traffic from fitting the raw `ws_max_size` budget but then overflowing only after `base64`, `json-base64`, or `semi-text-shape` expansion.

For `semi-text-shape`, the spacing overhead is not data-dependent. The encoder first converts the entire byte stream into consecutive 6-bit symbols and then inserts a space between fixed groups of 8 emitted symbols. That means the worst case is already captured by the exact formula above; it does not depend on particular bit triples such as `000b` appearing in the payload.

### SecureLink encapsulation and growth

For protected application traffic, SecureLink does not change the mux payload semantics; it wraps the already-packed mux frame.

Protected DATA layout is conceptually:

- secure-link header (`version`, `type`, `flags/reserved`, `session_id`, `counter`)
- encrypted ciphertext carrying the plaintext mux frame
- AEAD authentication tag

This is why `SecureLinkPskSession.get_max_app_payload_size()` subtracts `20 + 16` bytes from the wrapped session limit before advertising its own limit upward.

Handshake and rekey control frames can be larger than protected DATA overhead alone:

- PSK mode carries nonces/proofs
- cert mode additionally carries canonical JSON plus base64-encoded certificate/signature/public-key material

Those control frames are still sent through the same wrapped session budget. The runtime does not currently provide a separate fragmentation layer just for SecureLink control frames, so unusually large control payloads still depend on the underlying session limit being large enough.

### Consistency conclusion

The current size-handling story is mostly consistent at the project-internal boundaries:

- `ChannelMux` enforces the wrapped session's advertised maximum application payload size
- `ChannelMux` now fragments oversized UDP service datagrams at mux level and reassembles them before local UDP delivery
- `SecureLink` subtracts its framing and AEAD overhead before advertising its own payload budget upward
- WebSocket text modes account for encoded-frame growth rather than only raw payload size
- TCP stream reads are chunked to fit the current mux/session budget instead of assuming one unbounded frame

The main systematic caveat is narrower and more specific:

- the generic `65535` budget exposed by `UdpSession` and `TcpStreamSession` is a software-layer application budget, not a rigorous proof that every lower-layer envelope or real network path can carry that amount unchanged on the wire

So the architecture is internally coherent now, and it avoids the earlier class of overflow bug where wrapped sessions under-reported their budgets. The remaining caution is that the abstract session budget should not be confused with a guaranteed path-safe wire budget, especially for UDP.

## 2. Secure-link layer

Primary responsibility:

- provide one transport-independent place for overlay authentication, protected carriage, and secure-link diagnostics

Current delivered boundary:

- the delivered secure-link runtime sits below `ChannelMux` and above the transport/session layer

Current contribution:

- PSK-based and certificate-based peer authentication
- session-key establishment
- ciphertext/plaintext transition for mux payloads
- replay protection and rekey hooks
- bounded client-side retry/backoff after repeated auth failures
- secure-link status and failure diagnostics for admin/API consumers
- certificate-root, detached-signature, role, validity-window, deployment-scope, and revoked-serial enforcement in cert mode

Current boundary contract:

- input from transport/session layer:
  - connected byte or datagram path
  - transport lifecycle events such as connect, disconnect, and reconnect
- output to transport/session layer:
  - ciphertext frames or datagrams ready for transport send
- input from `ChannelMux` / framing side:
  - plaintext overlay frames after future integration
- output upward:
  - authenticated plaintext overlay frames only

Current ownership decisions:

- websocket proxy behavior stays in `ARC-CMP-001`; secure-link must not reimplement transport bootstrap
- retransmission policy and RTT/inflight metrics stay in `ARC-CMP-002` until an implementation phase deliberately reworks that boundary
- service publication, channel IDs, and remote catalog state stay in `ARC-CMP-003`
- secure-link config loading and lifecycle wiring belong to `ARC-CMP-004`
- transport bootstrap or websocket-open failures stay owned by the transport/session layer, but their user-visible failed-state reporting belongs to `ARC-CMP-005`
- peer identity visibility in admin APIs belongs to `ARC-CMP-005`
- passive listener rows may stay zeroed in admin snapshots, but live per-peer listener metrics such as RTT on accepted peers must come from peer-local runtime state rather than listener-global defaults
- encryption-layer status visibility in WebAdmin/API is a joint function:
  - `ARC-CMP-006` owns the underlying secure-link state machine and failure categories
  - `ARC-CMP-004` contributes snapshot aggregation and process-level wiring
  - `ARC-CMP-005` contributes HTTP payloads, live admin messages, and webpage rendering

Important non-responsibilities:

- transport-specific socket management remains in the transport/session layer
- service publication and channel semantics remain in `ChannelMux`
- admin rendering remains in the admin web layer
- transport/session implementations remain unaware of certificate policy, identity validation, and traffic ciphers
- `ChannelMux` remains unaware of certificate contents, peer-authentication policy, and traffic ciphers

Current status:

- the PSK-based Phase 1 runtime slice and the certificate-based Phase 2 slice are implemented and defended by unit and integration tests
- delivered runtime behavior currently includes:
  - `secure_link_mode=psk` on `myudp`, `tcp`, `ws`, and `quic`
  - `secure_link_mode=cert` on `myudp`, `tcp`, `ws`, and `quic`
  - authenticated protected carriage below `ChannelMux`
  - live rekey support
  - fail-closed malformed-input handling
  - bounded reconnect/failure throttling after repeated client-side auth failures
  - admin/API visibility of secure-link state and stronger operational diagnostics
- certificate-mode trust-anchor validation, detached signature verification, richer peer identity semantics, and trust-failure visibility are now delivered
- the design baseline and remaining planned work for this component are documented in [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md)

### Functional decomposition for secure-link status visibility

This decomposition applies to the delivered `REQ-AUT-004`, `REQ-AUT-008`, and `REQ-AUT-009` items in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md), and remains relevant for the planned certificate-mode follow-up.

| Component ID | Contribution to secure-link status visibility |
|---|---|
| `ARC-CMP-006` | Determines whether secure-link is disabled, handshaking, authenticated, failed, or listening; determines mode, failure reason, lifecycle event, retry window, and rekey/auth counters |
| `ARC-CMP-004` | Pulls secure-link state from the wrapped session and places it into process-level status and peer snapshots |
| `ARC-CMP-005` | Exposes the secure-link state through `/api/status`, `/api/peers`, live admin updates, and the WebAdmin page |

The webpage is therefore an explicit contributor to the overall function, not only the API payloads behind it.

The supporting architecture traceability manifest is maintained in [.github/architecture_traceability.yaml](/home/ohnoohweh/quic_br/.github/architecture_traceability.yaml).

## 3. Reliability and framing layer

Primary responsibility:

- turn raw transport datagrams or frames into reliable overlay behavior

Main contribution:

- DATA and CONTROL framing
- retransmission
- missed-frame tracking
- RTT and inflight tracking

Important behaviors:

- cope with delay and loss on `myudp`
- keep counters and state needed for admin visibility
- preserve message integrity for large payloads

This layer is especially important for the `myudp` requirements in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md).

## 4. Channel and service multiplexing layer

Primary responsibility:

- map overlay traffic to exposed TCP/UDP services

Main contribution:

- `own_servers` handling
- `remote_servers` handling
- per-channel open/data/close behavior
- per-peer service scoping

Important behaviors:

- multiple concurrent TCP channels on one peer
- mixed UDP and TCP services on one peer
- per-peer isolation in listener mode
- cleanup on disconnect
- peer-scoped mutation only: routing, remote catalog changes, and disconnect cleanup must always act on the owning peer rather than on listener-global shortcuts inherited from earlier single-peer designs

This is the main realization layer for listener and mixed-service requirements.

## 5. Runner and process orchestration layer

Primary responsibility:

- compose the configured transports, mux, and admin systems into one runnable process
- supervise process restarts at the runtime entrypoint boundary

Main contribution:

- launcher entrypoint (`python -m obstacle_bridge`) handles restart supervision and runner-only options
- bridge runtime (`bridge.py`) owns the full transport/mux/admin CLI and in-process runtime behavior
- forwards non-launcher options from the launcher to `bridge.py` unchanged
- keeps restart policy outside `bridge.py` so the core runtime stays focused on one process lifecycle

Important behaviors:

- reconnect support
- restart handling
- process-safe event binding
- configuration persistence

### Entrypoint split (`bridge.py` vs module launcher)

The runtime restart design is intentionally split:

- `src/obstacle_bridge/bridge.py`:
  - parses the full bridge/runtime CLI surface (`--config`, transport, mux, admin, secure-link, logging)
  - builds sessions and runs the in-process runtime (`Runner`)
  - can be called directly as `python -m obstacle_bridge.bridge`
- `python -m obstacle_bridge` (implemented by `src/obstacle_bridge/__main__.py` + `src/obstacle_bridge/launcher.py`):
  - provides restart supervision behavior
  - understands launcher-only options (`--interval`, `--no-redirect`, optional `--command`)
  - forwards unknown options to `bridge.py`, so bridge CLI flags remain first-class on the default entrypoint

## 6. Admin web and observability layer

Primary responsibility:

- make runtime state observable and manageable

Main contribution:

- health/status/peers/connections APIs
- configuration API and UI
- debug logs and log retrieval
- authentication and session control

Important behaviors:

- show connected peers and listener state
- show per-connection and aggregate transfer state
- isolate authenticated sessions per client
- support troubleshooting and regression validation

## Component responsibilities

### Transport runtimes

Expected to own:

- transport-specific sockets/connections
- connect/listen behavior
- per-peer transport state where required
- transport-specific client bootstrap steps such as proxy discovery, tunnel setup, or transport preflight when those are needed before the overlay session can start

Expected not to own:

- service publication logic
- application protocol semantics

### Reliability/session logic

Expected to own:

- frame numbering
- missed-frame tracking
- retransmission decisions
- RTT and inflight metrics

Expected not to own:

- UI concerns
- service binding policy

### ChannelMux and related service machinery

Expected to own:

- mapping between overlay channels and local TCP/UDP services
- peer-scoped remote service state
- listener lifecycle for published services

Expected not to own:

- transport-specific socket semantics beyond the abstraction it consumes

### Runner

Expected to own:

- composition
- startup/shutdown lifecycle
- config and argument integration
- platform-gated enablement of optional transport features such as Windows `Negotiate` proxy authentication, while preserving platform-default proxy discovery semantics

Expected not to own:

- detailed transport framing policy
- detailed admin rendering logic

### Admin web

Expected to own:

- HTTP API
- auth session control
- presentation of runtime state

Expected not to own:

- transport behavior itself

## WebSocket proxy tunneling

Scope:

- WebSocket peer client only
- HTTP proxy traversal with `CONNECT`
- default proxy discovery from platform-native settings
- proxy authentication via `Negotiate` / NTLM-style Windows credentials where supported

Intended layering:

1. the runner/configuration layer decides whether platform-default proxy behavior is used or consciously overridden for the websocket client
2. the transport/session layer performs proxy discovery from system settings or uses explicitly configured proxy settings
3. the transport/session layer establishes a TCP tunnel to the proxy target
4. after the tunnel is established, the existing websocket handshake continues over the tunneled socket
5. the higher reliability, mux, and admin layers remain unchanged

Architectural consequence:

- proxy support belongs in the websocket client bootstrap path, not in the overlay framing or channel mux logic
- this capability should be isolated so it does not accidentally appear as a cross-transport or listener-side feature before those variants are explicitly designed
- platform-specific details should stay below the shared websocket client contract: Windows may use system proxy APIs and `Negotiate`, while Linux/POSIX may use `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`

Functional decomposition:

- project-owned responsibilities:
  - decide the effective proxy mode for the websocket peer client: platform default, explicit manual proxy, or explicit direct-connect override
  - discover the proxy endpoint from Windows system settings or Linux/POSIX `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
  - keep proxy behavior scoped to websocket peer-client mode so listener mode and non-websocket transports do not silently inherit it
  - establish the HTTP `CONNECT` tunnel before starting the websocket handshake
  - handle proxy failure as an observable connection failure without corrupting the overlay state machine
  - neutralize library-level proxy autodiscovery when application configuration says to connect directly, so one clear proxy policy is enforced by the application
- library-owned responsibilities:
  - perform the websocket HTTP upgrade and websocket frame processing once the application has provided either a direct TCP path or a proxied tunnel
  - preserve normal websocket reconnect and I/O behavior above the socket path selected by the application
- ownership boundary:
  - proxy policy is an application contract, not a library default
  - the `websockets` dependency is used as the websocket protocol engine after proxy selection and tunnel bootstrap are complete
  - if the library offers independent proxy features, they must not compete with the application-owned proxy decision path

Concrete mapping in the current implementation:

- runner and CLI configuration select the effective proxy mode for each `WebSocketSession`
- runner and CLI configuration also select the client-advertised websocket payload form, while each accepted listener-side peer binds its own effective payload codec from the upgrade request metadata
- `WebSocketSession._get_ws_proxy_endpoint(...)` resolves the proxy endpoint from manual settings, platform defaults, or environment variables
- `WebSocketSession._open_ws_proxy_socket_blocking(...)` owns HTTP `CONNECT` setup and proxy authentication preconditions
- `WebSocketSession._suspend_library_proxy_env()` keeps the dependency from silently re-introducing proxy behavior that bypasses the application contract
- `websockets.connect(...)` owns the websocket handshake and framed transport after the direct socket or proxy tunnel already exists

## Test implications

This architecture implies a testing split:

- integration tests primarily defend requirements at the transport, listener, reconnect, and admin behavior level
- unit tests primarily defend component contracts such as ChannelMux scoping, snapshot formatting, runner event wiring, and websocket-specific behavior

The first traceability mappings for integration and unit coverage are maintained in [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md), and should refer to the stable component IDs above where architecture-level traceability is needed.
