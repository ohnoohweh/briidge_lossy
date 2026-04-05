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

Secure-link authentication and encryption work now has three delivered requirement slices in this document:

- active `REQ-AUT-*` items for the delivered and defended PSK-based Phase 1 runtime slice
- active `REQ-AUT-*` items for the delivered certificate-based Phase 2 trust model and validation slice
- active `REQ-AUT-*` items for the delivered Phase 3 operational-control slice around live certificate/revocation reload and enforcement

The detailed realization concept remains in [SECURE_LINK_DESIGN.md](/home/ohnoohweh/quic_br/docs/SECURE_LINK_DESIGN.md), and the component ownership boundary remains in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

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

## Authentication and encryption requirements

This section covers the delivered PSK-based Phase 1 secure-link slice and the delivered Phase 2 certificate-based follow-up.

Functional decomposition note:

- `REQ-AUT-001` through `REQ-AUT-003`, `REQ-AUT-005`, `REQ-AUT-006`, and `REQ-AUT-007` are realized jointly by the secure-link runtime slice in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md) (`ARC-CMP-006`), with lifecycle/config/snapshot wiring contributed by the runner/process orchestration layer (`ARC-CMP-004`).
- `REQ-AUT-004`, `REQ-AUT-008`, `REQ-AUT-009`, and `REQ-AUT-010` are realized jointly by:
  - the secure-link runtime slice (`ARC-CMP-006`), which owns the underlying authentication/encryption state and failure categories
  - the runner/process orchestration layer (`ARC-CMP-004`), which gathers and shapes snapshot data
  - the admin web and observability layer (`ARC-CMP-005`), which exposes aggregate runtime summary through `/api/status`, peer-scoped secure-link state through `/api/peers`, the live admin feed, and the WebAdmin page
- `REQ-AUT-011` through `REQ-AUT-019` are realized jointly by:
  - the secure-link layer (`ARC-CMP-006`), which owns the underlying authentication/encryption state and failure categories
  - the runner/process orchestration layer (`ARC-CMP-004`), which gathers and shapes snapshot data
  - the admin web and observability layer (`ARC-CMP-005`), which exposes aggregate runtime summary through `/api/status`, peer-scoped secure-link state through `/api/peers`, the live admin feed, and the WebAdmin page

The component ownership boundary for these secure-link requirements is documented in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

The certificate/profile details that ObstacleBridge expects as input are documented in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md), because they describe requirements on supplied key material and crypto support rather than black-box delivery of the current runtime.

Current implementation note:

- delivered secure-link modes now include `secure_link_mode=psk` and `secure_link_mode=cert`
- both delivered modes run on `overlay_transport=myudp`, `tcp`, `ws`, and `quic`
- broader multi-peer listener validation now exists on `ws`, `myudp`, `tcp`, and `quic`, with the deepest concurrent channel-routing slice still exercised on the TCP transport
- the runtime now exposes aggregate runtime summary through `/api/status` and peer-scoped secure-link observability through `/api/peers`
- in `secure_link_mode=cert`, operators can now trigger live `revocation`, `local_identity`, or `all` reload/apply actions through `POST /api/secure-link/reload` and the WebAdmin controls without restarting the process
- some secure-link subprocess integration tests use a test-only failure-injection seam that is enabled explicitly by the harness and is not reachable in the normal runtime by default; this seam exists only to defend reconnect/replay/fail-closed requirements where pure black-box stimulation would otherwise add disproportionate harness complexity
- the current user-facing runtime configuration surface also includes `secure_link_root_pub`, `secure_link_cert_body`, `secure_link_cert_sig`, `secure_link_private_key`, `secure_link_revoked_serials`, and `secure_link_cert_reload_on_restart` for `secure_link_mode=cert`
- the Phase 1 PSK mode remains useful for development/testing/lab bring-up, while the certificate-based Phase 2/3 slices provide deployment-rooted mutual authentication, trust validation, and operator-driven live trust-material application

- `REQ-AUT-001`: The project shall provide one transport-independent PSK secure-link capability for overlay authentication and protected data carriage across `myudp`, `tcp`, `ws`, and `quic`.
- `REQ-AUT-002`: When both peers are configured with the same PSK, the secure-link protected data phase shall authenticate successfully before overlay traffic is accepted and forwarded.
- `REQ-AUT-003`: When peers are configured with different PSKs, the protected data phase shall not start, overlay traffic shall not be forwarded, and the session shall remain observable as an authentication failure rather than a false connected state.
- `REQ-AUT-004`: The admin web interface and admin API shall expose secure-link state in an operator-usable way: peer-scoped secure-link state shall be reported with the corresponding peer rows and peer views so an operator can distinguish disabled, handshaking, authenticated, and failed protected-overlay states, including the reported authentication failure category, while the peer box preserves connection uptime and transport-appropriate protocol statistics. On secure-link-wrapped `myudp` listener and peer rows, `/api/peers` shall continue to report the underlying `myudp` frame/transmit counters for the corresponding active peer after protected traffic has flowed; the wrapper must not collapse those counters to zero.
- `REQ-AUT-005`: Multi-peer listener scenarios using secure-link PSK shall preserve peer isolation and distinct authenticated-peer visibility across the supported listener transports, with the deepest concurrent routing slice defended on the TCP listener path.
- `REQ-AUT-006`: The PSK secure-link runtime shall preserve a deterministic session and counter lifecycle: protected data counters start at `1`, remain strictly monotonic per direction, reject stale or reserved counters, and when `secure_link_rekey_after_frames` is configured to a positive value the runtime shall rotate to a fresh secure-link session under live traffic without losing healthy overlay functionality.
- `REQ-AUT-007`: Malformed, unexpected, or out-of-order secure-link control/data frames shall fail closed: the affected secure-link peer state shall stop forwarding overlay traffic, remain observable as a secure-link failure, and drop any server-side peer-channel routing state that belonged to the failed peer.
- `REQ-AUT-008`: Repeated client-side PSK authentication failures shall be retried with bounded backoff rather than an immediate tight loop, and the peer-scoped admin/API surface shall expose the current consecutive failure count and next retry window so operators can diagnose persistent secret mismatch or similar auth failures.
- `REQ-AUT-009`: The peer-scoped admin/API surface shall expose stronger operational diagnostics for the PSK secure-link runtime, including the most recent secure-link event, handshake-attempt count, authenticated-session count, completed-rekey count, last authenticated timestamp, most recent failed session id, and connection uptime so operators can distinguish repeated auth failures from healthy recovery and live-session rotation.
- `REQ-AUT-010`: The PSK secure-link runtime shall support time-based rekey on authenticated client-side sessions and operator-forced rekey through the admin API and WebAdmin controls; both paths shall rotate to a fresh secure-link session without breaking healthy overlay traffic and shall remain observable through peer-scoped admin/API fields that identify the last rekey trigger and any scheduled rekey deadline. Time-based rekey shall arm from the authenticated client-side session itself, shall not require a later protected application frame before the timer starts, and shall not be postponed indefinitely merely because protected traffic continues to flow. Operator-triggered rekey requests shall target a specific peer row rather than acting as an implicit runtime-wide broadcast, and the commit-to-done cutover window shall preserve healthy overlay traffic rather than dropping same-channel application payloads solely because the server has already switched to the new session before the client receives `REKEY_DONE`.

- `REQ-AUT-011`: The deployment trust anchor shall be an admin-controlled root public key configured on peer clients and peer servers, and `secure_link_mode=cert` shall authenticate successfully only when both peers trust the same deployment root.
- `REQ-AUT-012`: Peer certificates used by `secure_link_mode=cert` shall be issued by that deployment-local admin root and constrained by machine-enforced roles so that client/server direction mismatches fail closed before protected traffic starts.
- `REQ-AUT-013`: Certificate role checks, validity checks, deployment-scope checks, and serial-based revocation checks shall be enforced before the protected secure-link data phase is entered, and the failure shall remain observable as a secure-link authentication/trust failure rather than a false connected state.
- `REQ-AUT-014`: The certificate-based secure-link mode shall preserve the same peer-scoped admin/API visibility model as the current PSK slice while adding peer identity and trust-validation details such as subject id/name, roles, deployment id, serial, issuer, trust-anchor id, trust-validation state, and trust-failure diagnostics.
- `REQ-AUT-015`: The certificate-based secure-link runtime shall support operator-triggered live reload of revocation material from the configured revoked-serial source without requiring a process restart.
- `REQ-AUT-016`: After a successful live revocation reload, peers whose certificates are now revoked shall be disconnected immediately and shall remain observable as peer-scoped secure-link trust failures rather than silently continuing on superseded trust state.
- `REQ-AUT-017`: The certificate-based secure-link runtime shall support operator-triggered live reload of local root/certificate/private-key material from the configured files, and it shall validate the full replacement bundle atomically before activation so that a broken bundle does not partially replace the active material.
- `REQ-AUT-018`: After a successful live local-identity reload, already-authenticated certificate-mode peers shall not continue indefinitely on the superseded local identity; they shall be disconnected and required to re-authenticate under the new material generation.
- `REQ-AUT-019`: The admin API and WebAdmin shall expose aggregate reload/apply results at the runtime level and peer-scoped enforcement/disconnect diagnostics at the peer level so operators can tell what changed, when it changed, and why a peer was dropped or re-authenticated.

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
