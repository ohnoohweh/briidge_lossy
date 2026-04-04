# Requirements

This document captures black-box requirements for the project. These are intentionally phrased as observable behavior, not implementation detail.

## Scope

ObstacleBridge is expected to:

- establish overlay connectivity between peers over supported transports
- carry UDP and TCP application traffic across that overlay
- support listener and peer-client deployment modes
- expose runtime state and configuration through the admin web interface
- remain testable under reconnect, restart, concurrency, and lossy-path scenarios

## Overlay and transport requirements

- `REQ-OVL-001`: A peer client shall be able to establish a native UDP (`myudp`) overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-002`: A peer client shall be able to establish a native UDP (`myudp`) overlay session to a listener and carry TCP application traffic across it.
- `REQ-OVL-003`: A peer client shall be able to establish a TCP overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-004`: A peer client shall be able to establish a WebSocket overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-005`: A peer client shall be able to establish a QUIC overlay session to a listener and carry UDP application traffic across it.
- `REQ-OVL-006`: Supported overlay transports shall work on both IPv4 and IPv6 where the specific transport mode is configured for that address family.
- `REQ-OVL-007`: Localhost-based peer resolution shall behave deterministically for reconnect scenarios on both IPv4 and IPv6.

## WebSocket proxy requirements

- `REQ-WSP-001`: A WebSocket peer client shall be able to establish its outbound websocket transport through an HTTP proxy when proxy routing is required for the target environment.
- `REQ-WSP-002`: The WebSocket proxy capability shall be scoped to peer-client mode only; it shall not imply listener-side proxy support.
- `REQ-WSP-003`: The WebSocket proxy capability shall be scoped to the WebSocket transport only; it shall not imply equivalent support for `myudp`, `tcp`, or `quic`.
- `REQ-WSP-004`: When proxy tunneling is enabled for the WebSocket peer client, the transport bootstrap shall establish the proxy tunnel before the websocket handshake begins.
- `REQ-WSP-005`: When proxy discovery, proxy connection, or proxy authentication fails, the WebSocket peer client shall report a connection failure without corrupting the overlay state machine.
- `REQ-WSP-006`: On Windows, the default WebSocket peer-client behavior shall honor the effective system proxy configuration unless the application configuration explicitly overrides it.
- `REQ-WSP-007`: On Linux and other POSIX-style environments, the default WebSocket peer-client behavior shall honor the effective `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment settings unless the application configuration explicitly overrides it.
- `REQ-WSP-008`: Application configuration shall be able to consciously override the platform-default proxy behavior, including forcing direct connection or using an explicitly configured proxy endpoint.
- `REQ-WSP-009`: A WebSocket peer client running on Windows shall be able to establish its outbound websocket transport through an HTTP proxy that requires `Negotiate` / NTLM-style authentication.

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

## Testing requirements

- `REQ-TST-001`: User-visible transport behavior shall be protected by integration tests.
- `REQ-TST-002`: Important local invariants and component contracts shall be protected by unit tests.
- `REQ-TST-003`: Known bugs and regressions shall be turned into regression tests whenever practical.
- `REQ-TST-004`: The integration harness shall support regular parallel execution on a local development machine.
