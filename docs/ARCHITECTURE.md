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
| `ARC-CMP-004` | Runner and process orchestration layer | CLI/config composition, lifecycle wiring, restart/shutdown coordination, and process startup |
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

## 2. Reliability and framing layer

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

## 3. Channel and service multiplexing layer

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

## 4. Runner and process orchestration layer

Primary responsibility:

- compose the configured transports, mux, and admin systems into one runnable process

Main contribution:

- reads configuration and CLI arguments
- starts the right transport sessions
- wires callbacks and lifecycle events
- coordinates shutdown and restart behavior

Important behaviors:

- reconnect support
- restart handling
- process-safe event binding
- configuration persistence

## 5. Admin web and observability layer

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
