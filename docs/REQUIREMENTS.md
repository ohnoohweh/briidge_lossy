# Requirements

This document captures black-box requirements for the project. These are intentionally phrased as observable behavior, not implementation detail.

These statements are limited to project-owned behavior. They are not a catalog of end-user goals, deployment recipes, infrastructure prerequisites, operating-system capabilities, browser guarantees, or third-party library contracts. Those boundaries are described in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md).

## Scope

ObstacleBridge is expected to:

- establish overlay connectivity between peers over supported transports
- carry UDP and TCP application traffic across that overlay
- support listener and peer-client deployment modes
- expose runtime state and configuration through the admin web interface
- remain testable under reconnect, restart, concurrency, and lossy-path scenarios

The motivating user use-cases and the external assumptions around them are documented separately in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md) and the user-facing sections of [README.md](/home/ohnoohweh/quic_br/README.md). The requirement IDs below describe what the project itself is expected to do inside that broader system context.

Planned secure-link authentication and encryption work now has a reserved future requirement set in this document. The detailed realization concept remains in [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md), and the component ownership boundary remains in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md). Until runtime behavior and black-box tests exist, the secure-link items below reserve future black-box requirement IDs rather than claiming already-defended shipped behavior.

## Overlay and transport requirements

- `REQ-OVL-001`: A peer client shall be able to establish a native UDP (`myudp`) overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-002`: A peer client shall be able to establish a native UDP (`myudp`) overlay session to a listener and carry TCP application traffic across it.
- `REQ-OVL-003`: A peer client shall be able to establish a TCP overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-004`: A peer client shall be able to establish a WebSocket overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-005`: A peer client shall be able to establish a QUIC overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-006`: Supported overlay transports shall work on both IPv4 and IPv6 where the specific transport mode is configured for that address family.
- `REQ-OVL-007`: Localhost-based peer resolution shall behave deterministically for reconnect scenarios on both IPv4 and IPv6.

## WebSocket proxy requirements

- Functional decomposition note: the requirements in this section are implemented jointly by project-owned websocket bootstrap logic and dependency-owned websocket protocol handling. The ownership boundary is documented in `docs/ARCHITECTURE.md` under `WebSocket proxy tunneling`.

- `REQ-WSP-001`: A WebSocket peer client shall be able to establish its outbound websocket transport through an HTTP proxy when proxy routing is required for the target environment.
- `REQ-WSP-002`: The WebSocket proxy capability shall be scoped to peer-client mode only; it shall not imply listener-side proxy support.
- `REQ-WSP-003`: The WebSocket proxy capability shall be scoped to the WebSocket transport only; it shall not imply equivalent support for `myudp`, `tcp`, or `quic`.
- `REQ-WSP-004`: When proxy tunneling is enabled for the WebSocket peer client, the transport bootstrap shall establish the proxy tunnel before the websocket handshake begins.
- `REQ-WSP-005`: When proxy discovery, proxy connection, or proxy authentication fails, the WebSocket peer client shall report a connection failure without corrupting the overlay state machine.
- `REQ-WSP-006`: On Windows, the default WebSocket peer-client behavior shall honor the effective system proxy configuration unless the application configuration explicitly overrides it.
- `REQ-WSP-007`: On Linux and other POSIX-style environments, the default WebSocket peer-client behavior shall honor the effective `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment settings unless the application configuration explicitly overrides it.
- `REQ-WSP-008`: Application configuration shall be able to consciously override the platform-default proxy behavior, including forcing direct connection or using an explicitly configured proxy endpoint.
- `REQ-WSP-009`: A WebSocket peer client running on Windows shall be able to establish its outbound websocket transport through an HTTP proxy that requires `Negotiate` / NTLM-style authentication.

## Planned authentication and encryption requirement IDs

This section reserves the future black-box requirement IDs for the transport-independent secure-link capability.

Functional decomposition note:

- `PLAN-AUT-001` through `PLAN-AUT-006` are realized primarily by the planned secure-link layer in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md) (`ARC-CMP-006`), with lifecycle and config wiring contributed by the runner/process orchestration layer (`ARC-CMP-004`).
- `PLAN-AUT-007` is realized jointly by:
  - the planned secure-link layer (`ARC-CMP-006`), which owns the underlying authentication/encryption state and failure categories
  - the runner/process orchestration layer (`ARC-CMP-004`), which gathers and shapes snapshot data
  - the admin web and observability layer (`ARC-CMP-005`), which exposes that state through `/api/status`, `/api/peers`, the live admin feed, and the WebAdmin page

The component ownership boundary for these planned secure-link requirements is documented in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

These IDs intentionally do not use the active `REQ-*` namespace yet, because:

- no secure-link runtime behavior has been delivered
- no defending integration or unit tests exist yet
- the current requirement-coverage guard treats `REQ-*` items as active delivered requirements that must already trace to real tests

The certificate/profile details that ObstacleBridge expects as input are documented in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md), because they describe requirements on supplied key material and crypto support rather than black-box delivery of the current runtime.

Current implementation note:

- a narrow Phase 1 prototype exists for `secure_link_mode=psk` on `overlay_transport=myudp`, `tcp`, `ws`, and `quic`
- that prototype currently proves the first protected happy-path slice across those transports
- broader multi-peer listener validation now exists on `ws`, `myudp`, `tcp`, and `quic`, with the deepest concurrent channel-routing slice still exercised on the TCP transport
- the prototype now exposes first admin/API observability for secure-link state through `/api/status` and `/api/peers`
- the current user-facing prototype configuration surface is `secure_link`, `secure_link_mode=psk`, `secure_link_psk`, and `secure_link_require`; certificate-mode startup remains intentionally unsupported in the current runtime slice
- that prototype is intended for development and testing of the layer boundary
- it does not yet promote these planned IDs into the active delivered `REQ-*` requirement namespace

- `PLAN-AUT-001`: The project should provide one transport-independent secure-link capability for overlay authentication and encryption rather than separate authorization models per transport.
- `PLAN-AUT-002`: A peer client and peer server should authenticate each other before protected overlay traffic is accepted.
- `PLAN-AUT-003`: Protected secure-link overlay traffic should provide confidentiality, integrity protection, and replay rejection.
- `PLAN-AUT-004`: The deployment trust anchor should be an admin-controlled root public key configured on peer clients and peer servers.
- `PLAN-AUT-005`: Peer certificates should be issued by that deployment-local admin root and be constrained by machine-enforced roles.
- `PLAN-AUT-006`: Certificate role checks, validity checks, deployment-scope checks, and serial-based revocation checks should be enforced before the protected secure-link data phase is entered.
- `PLAN-AUT-007`: The admin web interface should expose the secure-link / encryption-layer status for the local session and reported peers so an operator can distinguish disabled, handshaking, authenticated, and failed protected-overlay states and understand the reported authentication failure category.

## Reconnect and restart requirements

- `REQ-LIFE-001`: When one side disconnects or is restarted, the remaining side shall eventually report the overlay as not connected.
- `REQ-LIFE-002`: When the disconnected side returns, the overlay shall reconnect automatically when the configured topology supports reconnection.
- `REQ-LIFE-003`: After reconnection, traffic forwarding shall resume and probes shall again succeed.
- `REQ-LIFE-004`: Restart-specific regressions for concurrent channel cases shall remain covered so existing functionality does not silently erode.

## Listener and multi-peer requirements

- `REQ-LST-001`: A WebSocket listener shall support two independent peer clients concurrently.
- `REQ-LST-002`: A myudp listener shall support two independent peer clients concurrently.
- `REQ-LST-003`: A TCP listener shall support two independent peer clients concurrently.
- `REQ-LST-004`: A QUIC listener shall support two independent peer clients concurrently.
- `REQ-LST-005`: When a listener has multiple connected peers, the admin peer API shall report distinct peer endpoints for the connected peers.
- `REQ-LST-006`: Listener-side peer reporting shall distinguish passive listening state from active connected peers.

## Mixed traffic and channel requirements

- `REQ-MUX-001`: A connected peer shall be able to carry multiple simultaneous TCP channels over one overlay connection.
- `REQ-MUX-002`: A connected peer shall be able to carry mixed UDP and TCP services at the same time.
- `REQ-MUX-003`: Multi-client listener scenarios shall preserve peer isolation so one peer’s channels and services do not conflict with another peer’s.
- `REQ-MUX-004`: Remote service publication shall remain scoped to the intended peer.

## Loss and delay requirements

- `REQ-MYU-001`: The myudp transport shall continue to function under added propagation delay.
- `REQ-MYU-002`: The myudp transport shall recover from selected DATA frame loss through retransmission.
- `REQ-MYU-003`: The myudp transport shall recover from selected CONTROL frame loss.
- `REQ-MYU-004`: The myudp transport shall correctly transfer large payloads under delayed and lossy conditions.
- `REQ-MYU-005`: Bidirectional myudp traffic shall remain functional when both directions are active concurrently.
- `REQ-MYU-006`: The myudp transport shall tolerate heavy early loss patterns without silently corrupting delivered payloads.

## Admin web requirements

- `REQ-ADM-001`: The admin web interface shall expose health, status, peer, connection, log, and configuration-related APIs needed for operational visibility.
- `REQ-ADM-002`: When admin authentication is disabled, the admin API shall remain available without login.
- `REQ-ADM-003`: When admin authentication is enabled, protected admin APIs shall remain unavailable until correct authentication completes.
- `REQ-ADM-004`: After correct authentication, the admin API shall become available to that authenticated client.
- `REQ-ADM-005`: Authentication state shall remain isolated per HTTP client session.
- `REQ-ADM-006`: Peer and connection APIs shall reflect connected peers, channel state, and transfer metrics accurately enough for troubleshooting and regression validation.

Development-process measures such as test-execution discipline, regression-writing policy, and CI split strategy are documented in [DEVELOPMENT_PROCESS.md](/home/ohnoohweh/quic_br/docs/DEVELOPMENT_PROCESS.md). They intentionally do not appear here because they govern how the project is built and validated, not what the delivered project promises to an operator.

The supporting product-requirement traceability manifest is maintained in [.github/requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml). It is stored with the repository's CI/support metadata rather than in `docs/`, but it continues to trace these product requirements to their defending tests.
