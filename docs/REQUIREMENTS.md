# Requirements

This document captures black-box requirements for the project. These are intentionally phrased as observable behavior, not implementation detail.

These statements are limited to project-owned behavior. They are not a catalog of end-user goals, deployment recipes, infrastructure prerequisites, operating-system capabilities, browser guarantees, or third-party library contracts. Those boundaries are described in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md).

## Scope

ObstacleBridge is expected to:

- establish overlay connectivity between peers over supported transports
- carry UDP and TCP application traffic, plus Linux and Windows TUN packet traffic, across that overlay where the required OS capability is available
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

## WebSocket proxy and payload requirements

- Functional decomposition note: the requirements in this section are implemented jointly by project-owned websocket bootstrap logic and dependency-owned websocket protocol handling. The ownership boundary is documented in `docs/ARCHITECTURE.md` under `WebSocket proxy tunneling`.

- `REQ-WSP-001`: A WebSocket peer client shall be able to establish its outbound websocket transport through an HTTP proxy when proxy routing is required for the target environment.
- `REQ-WSP-002`: The WebSocket proxy capability shall be scoped to peer-client mode only; it shall not imply listener-side proxy support.
- `REQ-WSP-003`: The WebSocket proxy capability shall be scoped to the WebSocket transport only; it shall not imply equivalent support for `myudp`, `tcp`, or `quic`.
- `REQ-WSP-004`: When proxy tunneling is enabled for the WebSocket peer client, the transport bootstrap shall establish the proxy tunnel before the websocket handshake begins.
- `REQ-WSP-005`: When proxy discovery, proxy connection, or proxy authentication fails, the WebSocket peer client shall report a connection failure without corrupting the overlay state machine.
- `REQ-WSP-006`: On Windows, the default WebSocket peer-client behavior shall honor the effective system proxy configuration unless the application configuration explicitly overrides it. When system proxy discovery returns no proxy endpoint for the target, that result shall be treated as a direct-connect path rather than as a fatal bootstrap error.
- `REQ-WSP-007`: On Linux and other POSIX-style environments, the default WebSocket peer-client behavior shall honor the effective `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment settings unless the application configuration explicitly overrides it.
- `REQ-WSP-008`: Application configuration shall be able to consciously override the platform-default proxy behavior, including forcing direct connection or using an explicitly configured proxy endpoint.
- `REQ-WSP-009`: A WebSocket peer client running on Windows shall be able to establish its outbound websocket transport through an HTTP proxy that requires `Negotiate` / NTLM-style authentication.
- `REQ-WSP-010`: The WebSocket overlay transport shall support selectable payload transfer forms through `ws_payload_mode`: raw binary websocket frames (`binary`), plain base64 text websocket frames (`base64`), compact JSON text websocket frames carrying the base64 payload in the `data` field (`json-base64`), and a grouped semi-text form (`semi-text-shape`) using the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+`. Receivers configured for the text-oriented modes shall continue to accept raw binary websocket frames so mixed peers can fail soft during migration or debugging. A peer client shall advertise its configured payload transfer form during the WebSocket upgrade request, and the listener shall adopt that transfer form for the accepted peer automatically so compatible client/listener pairs do not require manually mirrored `ws_payload_mode` settings. For all text-oriented payload modes, the runtime shall budget WebSocket receive/open limits against the encoded frame size rather than the raw overlay payload size so text-mode expansion does not make healthy forwarded-service traffic fail solely because the websocket frame exceeds the raw payload budget.
- `REQ-WSP-011`: On the direct non-proxied WebSocket peer-client path, transport bootstrap shall complete a separate `GET /` HTTP preflight against the target listener before the later websocket upgrade attempt, shall consume the full HTTP response body for that preflight, and shall refuse the websocket upgrade attempt when the preflight status is not `200 OK`.
- `REQ-WSP-012`: When a WebSocket peer-client connection attempt fails during transport bootstrap or websocket opening, including failures such as DNS resolution, proxy negotiation, opening the HTTP preflight channel, unsuccessful `GET /` preflight, incomplete preflight body download, or websocket-open failure after bootstrap, the admin status shall report the connection as `FAILED` and expose a transport-level failure reason/detail until a later successful connection clears that failure state.

Current payload-form note:

- `binary`: the overlay wire bytes are sent directly as websocket binary frames with no text envelope.
- `base64`: the same overlay wire bytes are base64-encoded into one websocket text frame.
- `json-base64`: the overlay wire bytes are base64-encoded and emitted as compact JSON text of the form `{"data":"..."}`.
- `semi-text-shape`: the overlay wire bytes are split into 6-bit symbols using the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+`, the final symbol is padded with `0` bits if needed, and the resulting text is grouped into whitespace-separated runs of 1 to 8 symbols to keep a text-shaped appearance while remaining exactly reversible back to the original byte stream.

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
- `REQ-AUT-020` is realized jointly by:
  - the compression layer (`ARC-CMP-007`), which applies per-frame compress-or-bypass and decode semantics
  - the runner/process orchestration layer (`ARC-CMP-004`), which wires peer-session wrappers and per-peer compression parameters
  - the admin web and observability layer (`ARC-CMP-005`), which exposes peer-scoped compression telemetry in `/api/peers`

The component ownership boundary for these secure-link requirements is documented in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md).

The certificate/profile details that ObstacleBridge expects as input are documented in [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md), because they describe requirements on supplied key material and crypto support rather than black-box delivery of the current runtime.

Current implementation note:

- delivered secure-link modes now include `secure_link_mode=psk` and `secure_link_mode=cert`
- both delivered modes run on `overlay_transport=myudp`, `tcp`, `ws`, and `quic`
- the current runtime keeps mux payload budgeting aligned with the wrapped transport session budget for `myudp`, `tcp`, and `quic`, so SecureLink wrapping does not reduce healthy forwarded application traffic to the mux-header size alone
- when a protected client observes a transport-epoch change during reconnect or restart recovery, it now restarts the secure-link client handshake against that fresh transport epoch instead of continuing on stale client-side handshake state
- broader multi-peer listener validation now exists on `ws`, `myudp`, `tcp`, and `quic`, with the deepest concurrent channel-routing slice still exercised on the TCP transport
- the runtime now exposes aggregate runtime metadata and secure-link reload/apply summaries through `/api/status`, while peer-scoped traffic, connection, compression, and secure-link observability live in `/api/peers` and `/api/connections`
- in `secure_link_mode=cert`, operators can now trigger live `revocation`, `local_identity`, or `all` reload/apply actions through `POST /api/secure-link/reload` and the WebAdmin `Reload Revocation`, `Reload Local Identity`, and `Reload All` controls without restarting the process
- some secure-link subprocess integration tests use a test-only failure-injection seam that is enabled explicitly by the harness and is not reachable in the normal runtime by default; this seam exists only to defend reconnect/replay/fail-closed requirements where pure black-box stimulation would otherwise add disproportionate harness complexity
- the current user-facing runtime configuration surface also includes `secure_link_root_pub`, `secure_link_cert_body`, `secure_link_cert_sig`, `secure_link_private_key`, `secure_link_revoked_serials`, and `secure_link_cert_reload_on_restart` for `secure_link_mode=cert`
- the Phase 1 PSK mode remains useful for development/testing/lab bring-up, while the certificate-based Phase 2/3 slices provide deployment-rooted mutual authentication, trust validation, and operator-driven live trust-material application

- Implementation note (instrumentation): The runtime now includes additional `secure_link`-scoped DEBUG logging that surfaces incoming secure-link frames and handshake events to aid troubleshooting WebSocket-secure-link handshakes. Operators may enable `secure_link` DEBUG logging temporarily when diagnosing handshake/transport interactions. (see PR #178)
- Implementation note (testability): The delivered integration harness now generates localhost TLS fixture material at runtime and allocates loopback port blocks by probing host availability before selecting a case slot. This keeps localhost private keys out of version control and preserves stable Linux shared integration coverage even when unrelated host daemons already bind uncommon local ports.

- `REQ-AUT-001`: The project shall provide one transport-independent PSK secure-link capability for overlay authentication and protected data carriage across `myudp`, `tcp`, `ws`, and `quic`.
- `REQ-AUT-002`: When both peers are configured with the same PSK, the secure-link protected data phase shall authenticate successfully before overlay traffic is accepted and forwarded. On the listener/server side, authentication shall complete as soon as the client proof-of-key-possession frame is decrypted; it shall not wait for a first real application payload before reporting the session as authenticated.
- `REQ-AUT-003`: When peers are configured with different PSKs, the protected data phase shall not start, overlay traffic shall not be forwarded, and the session shall remain observable as an authentication failure rather than a false connected state.
- `REQ-AUT-004`: The admin web interface and admin API shall expose secure-link state in an operator-usable way: peer-scoped secure-link state shall be reported with the corresponding peer rows and peer views so an operator can distinguish disabled, handshaking, authenticated, and failed protected-overlay states, including the reported authentication failure category, while the peer box preserves connection uptime and transport-appropriate protocol statistics. On secure-link-wrapped `myudp` listener and peer rows, `/api/peers` shall continue to report the underlying `myudp` frame/transmit counters for the corresponding active peer after protected traffic has flowed; the wrapper must not collapse those counters to zero.
- `REQ-AUT-005`: Multi-peer listener scenarios using secure-link PSK shall preserve peer isolation and distinct authenticated-peer visibility across the supported listener transports, with the deepest concurrent routing slice defended on the TCP listener path. On mixed-listener processes that expose both WebSocket and non-WebSocket overlay transports, repeated plain HTTP handling on the WebSocket front end shall remain isolated from healthy secure-link peers on either transport.
- `REQ-AUT-006`: The PSK secure-link runtime shall preserve a deterministic session and counter lifecycle: protected data counters start at `1`, remain strictly monotonic per direction, reject stale or reserved counters, and when `secure_link_rekey_after_frames` is configured to a positive value the runtime shall rotate to a fresh secure-link session under live traffic without losing healthy overlay functionality.
- `REQ-AUT-007`: Malformed, unexpected, or out-of-order secure-link control/data frames shall fail closed: the affected secure-link peer state shall stop forwarding overlay traffic, remain observable as a secure-link failure, and drop any server-side peer-channel routing state that belonged to the failed peer.
- `REQ-AUT-008`: Repeated client-side PSK authentication failures shall be retried with bounded backoff rather than an immediate tight loop, and the peer-scoped admin/API surface shall expose the current consecutive failure count and next retry window so operators can diagnose persistent secret mismatch or similar auth failures.
- `REQ-AUT-009`: The peer-scoped admin/API surface shall expose stronger operational diagnostics for the PSK secure-link runtime, including the most recent secure-link event, handshake-attempt count, authenticated-session count, completed-rekey count, last authenticated timestamp, most recent failed session id, and connection uptime so operators can distinguish repeated auth failures from healthy recovery and live-session rotation.
- `REQ-AUT-010`: The PSK secure-link runtime shall support time-based rekey on authenticated client-side sessions and operator-forced rekey through the admin API and WebAdmin controls; both paths shall rotate to a fresh secure-link session without breaking healthy overlay traffic and shall remain observable through peer-scoped admin/API fields that identify the last rekey trigger and any scheduled rekey deadline. Time-based rekey shall arm from the authenticated client-side session itself, shall not require a later protected application frame before the timer starts, and shall not be postponed indefinitely merely because protected traffic continues to flow. After a time-based rekey completes, the authenticated session shall remain stably observable as rekey-complete rather than immediately re-entering a fresh time-triggered rekey cycle without a newly established authenticated session, and that freshly authenticated post-rekey session shall arm a later time-threshold rekey again so long-lived healthy sessions continue rotating instead of stopping after one time-based rekey. Operator-triggered rekey requests shall target a specific peer row rather than acting as an implicit runtime-wide broadcast, and the commit-to-done cutover window shall preserve healthy overlay traffic rather than dropping same-channel application payloads solely because the server has already switched to the new session before the client receives `REKEY_DONE`.

- `REQ-AUT-011`: The deployment trust anchor shall be an admin-controlled root public key configured on peer clients and peer servers, and `secure_link_mode=cert` shall authenticate successfully only when both peers trust the same deployment root.
- `REQ-AUT-012`: Peer certificates used by `secure_link_mode=cert` shall be issued by that deployment-local admin root and constrained by machine-enforced roles so that client/server direction mismatches fail closed before protected traffic starts.
- `REQ-AUT-013`: Certificate role checks, validity checks, deployment-scope checks, and serial-based revocation checks shall be enforced before the protected secure-link data phase is entered, and the failure shall remain observable as a secure-link authentication/trust failure rather than a false connected state.
- `REQ-AUT-014`: The certificate-based secure-link mode shall preserve the same peer-scoped admin/API visibility model as the current PSK slice while adding peer identity and trust-validation details such as subject id/name, roles, deployment id, serial, issuer, trust-anchor id, trust-validation state, and trust-failure diagnostics.
- `REQ-AUT-015`: The certificate-based secure-link runtime shall support operator-triggered live reload of revocation material from the configured revoked-serial source without requiring a process restart.
- `REQ-AUT-016`: After a successful live revocation reload, peers whose certificates are now revoked shall be disconnected immediately and shall remain observable as peer-scoped secure-link trust failures rather than silently continuing on superseded trust state.
- `REQ-AUT-017`: The certificate-based secure-link runtime shall support operator-triggered live reload of local root/certificate/private-key material from the configured files, and it shall validate the full replacement bundle atomically before activation so that a broken bundle does not partially replace the active material.
- `REQ-AUT-018`: After a successful live local-identity reload, already-authenticated certificate-mode peers shall not continue indefinitely on the superseded local identity; they shall be disconnected and required to re-authenticate under the new material generation.
- `REQ-AUT-019`: The admin API and WebAdmin shall expose aggregate reload/apply results at the runtime level and peer-scoped enforcement/disconnect diagnostics at the peer level so operators can tell what changed, when it changed, and why a peer was dropped or re-authenticated.
- `REQ-AUT-020`: Compression-enabled secure-link peers shall interoperate even when client and server use different local compression settings (for example different `compress_layer_min_bytes`, `compress_layer_level`, and allowed `compress_layer_types`). The peer-client setting shall control whether a peer connection actively uses compression, and client-side peer rows shall report that configured compression state even before counters are nonzero. The peer server shall keep a passive decoder, detect valid client-compressed frames from the wire-level compression signal, and expose compression only for those activated peer rows. After such activation, the peer server shall compress replies for that peer without requiring mirrored local thresholds or levels, as long as both peers support the same compression framing and decode guardrails. Compression telemetry shall be peer-scoped, and emitted output-byte totals shall account for both compressed output and uncompressed emitted payload bytes when a compression attempt is skipped because it does not reduce size.

## Reconnect and restart requirements

- `REQ-LIFE-001`: When one side disconnects or is restarted, the remaining side shall eventually report the overlay as not connected.
- `REQ-LIFE-002`: When the disconnected side returns, the overlay shall reconnect automatically when the configured topology supports reconnection.
- `REQ-LIFE-003`: After reconnection, traffic forwarding shall resume and probes shall again succeed.
- `REQ-LIFE-004`: Restart-specific regressions for concurrent channel cases shall remain covered so existing functionality does not silently erode.
- `REQ-LIFE-005`: Repeated failed reconnect attempts shall be throttled by a configurable minimum retry delay so client overlays do not hammer connection setup continuously while a peer remains unavailable.
- `REQ-LIFE-006`: Operator-triggered reconnect requests exposed by the admin API and WebAdmin shall be scoped to the selected established peer connection rather than being process-global across unrelated peer sessions.
- `REQ-LIFE-007`: Startup through the default runtime entrypoint shall tolerate a missing or empty default config file by continuing with built-in defaults, while malformed JSON config input shall fail fast with a clear error.
- `REQ-LIFE-008`: When startup uses the default runtime entrypoint and Admin Web is enabled, the launcher shall print a clickable Admin Web entrypoint URL derived from the effective Admin Web bind/port/path configuration before handing control to the supervised bridge process. For wildcard/global Admin Web binds, the launcher may additionally print clearly labeled network-reachability hints derived from the local host and best-effort public address discovery, but those extra lines shall remain advisory rather than a guarantee of external reachability and may be emitted after the supervised bridge process has already started so slow public-address discovery does not delay local operator access.

## Listener and multi-peer requirements

- `REQ-LST-001`: A WebSocket listener shall support two independent peer clients concurrently.
- `REQ-LST-002`: A myudp listener shall support two independent peer clients concurrently.
- `REQ-LST-003`: A TCP listener shall support two independent peer clients concurrently.
- `REQ-LST-004`: A QUIC listener shall support two independent peer clients concurrently.
- `REQ-LST-005`: When a listener has multiple connected peers, the admin peer API shall report distinct peer endpoints for the connected peers.
- `REQ-LST-006`: Listener-side peer reporting shall distinguish passive listening state from active connected peers, keep the passive listener row zeroed, and expose live per-peer connection metrics such as RTT on the active accepted peer rows. Peer-scoped traffic totals shall remain attributable to the owning peer after individual UDP/TCP/TUN mux channels close, so short-lived service channels do not disappear from the peer-level accounting immediately after teardown.
- `REQ-LST-007`: Listener behavior shall remain peer-independent: auxiliary listener activity on a shared endpoint, including non-upgrade HTTP handling on a WebSocket listener, repeated plain HTTP requests on the same TCP connection before any later upgrade, per-peer handshake/failure handling, and disconnect cleanup, shall stay scoped to the originating request or peer and shall not degrade healthy traffic forwarding, published-service reachability, or authenticated session state that belongs to another peer, including a healthy peer that is using a different active transport on the same listener process.

## Mixed traffic and channel requirements

- `REQ-MUX-001`: A connected peer shall be able to carry multiple simultaneous TCP channels over one overlay connection.
- `REQ-MUX-002`: A connected peer shall be able to carry mixed UDP and TCP services at the same time.
- `REQ-MUX-003`: Multi-client listener scenarios shall preserve peer isolation so one peer’s channels and services do not conflict with another peer’s.
- `REQ-MUX-004`: Remote service publication shall remain scoped to the intended peer.
- `REQ-MUX-005`: Listener-side service, catalog, and cleanup decisions shall be keyed to the owning peer or request scope rather than to process-global singleton state, so legacy single-peer assumptions cannot make unrelated peers inherit disconnects, catalog replacement, or auxiliary-endpoint side effects.
- `REQ-MUX-006`: On hosts where a supported TUN backend is available and the process has permission to create/configure TUN devices, including Linux hosts with `/dev/net/tun` and Windows hosts with a usable WinTun installation, a connected peer shall be able to carry packet traffic between local TUN interfaces over one overlay connection. Symmetric TUN opens for the same interface shall remain routable as channel aliases for one underlying TUN device rather than evicting each other. Peer-scoped traffic accounting shall include TUN payload bytes alongside UDP and TCP payload bytes, and connection snapshots shall distinguish passive/listening TUN interfaces from active TUN packet channels.
- `REQ-MUX-007`: TUN service publication shall use the same peer-scoped catalog and channel-isolation rules as TCP and UDP services, so one peer's TUN interfaces and packet channels do not conflict with another peer's channels or published services. Peer-installed TUN listener startup shall win races with incoming TUN opens for the same target interface so listener hooks still configure the intended service-owned TUN device.
- `REQ-MUX-008`: When a UDP service datagram or TUN packet does not fit into one effective wrapped-session payload budget, the mux layer shall preserve the logical message boundary by fragmenting it across multiple mux messages and reassembling it before local delivery.
- `REQ-MUX-009`: The service-definition runtime surface shall accept structured JSON entries for both `own_servers` and `remote_servers`, and a structured service entry may include lifecycle hook commands that execute on listener-side service events (`on_created`, `on_channel_connected`, `on_channel_closed`, `on_stopped`) with placeholder-driven argument/environment rendering. Hook context shall include the configured overlay transport plus the configured and resolved overlay peer endpoint so route-preserving scripts do not need a duplicate peer IP in hook-specific config. The `on_stopped` listener hook shall run before the listener service is closed during overlay disconnect, peer disconnect, catalog replacement, or process shutdown so operator routing/firewall teardown can run while the local service resources still exist. Hook executable paths that include a path separator may be relative to the loaded configuration file directory, while bare command names remain resolved through the process `PATH`.

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
- `REQ-ADM-006`: Peer and connection APIs shall reflect connected peers, channel state, and transfer metrics accurately enough for troubleshooting and regression validation, including peer-local listener metrics such as RTT on active accepted peer rows, peer-scoped RX/TX byte totals and byte-per-second rates across UDP/TCP/TUN payloads, archived closed-channel payload totals for the owning peer, configured service names on UDP/TCP/TUN connection rows, TUN interface state for passive/listening interfaces and active packet channels, logical TUN connection rows that collapse multiple internal channel aliases for the same underlying TUN device, and observable time-since-last-received-frame diagnostics such as `last_incoming_age_seconds` on non-listening peer rows when inbound traffic has been observed. `/api/status` shall remain limited to runtime metadata, aggregate UDP/TCP/TUN open-connection counts, and aggregate secure-link reload/apply summaries rather than duplicating peer-scoped connection, traffic, compression, or decode-error fields.

- `REQ-ADM-007`: Secret configuration keys exposed by the runtime (for example `secure_link_psk` and `admin_web_password`) shall be writable through the admin configuration update API but must never be returned in cleartext by read-only snapshots. The admin UI shall render these keys as password-style inputs (empty on read) and must not display the stored secret value.

- `REQ-ADM-008`: When admin authentication is enabled, configuration updates submitted through WebAdmin shall require a fresh challenge-response confirmation bound to the exact update block before the runtime applies the change. The confirmation proof shall be derived from a server-issued seed, the current admin password, and the canonicalized update payload so the proof cannot be reused for a different configuration block. The guarded write flow shall cover both secret and non-secret configuration changes rather than protecting only password-like fields.

- `REQ-ADM-009`: Saved configuration files shall not expose `admin_web_password` or `secure_link_psk` in plaintext. When the runtime loads an encrypted configuration file, it shall restore those values back into memory so the application can continue to start, save, and operate with the configured secrets. The encryption/decryption key derivation for those saved secrets shall come from machine-derived identity only; runtime environment-variable overrides shall not be accepted for cross-machine secret portability.
- `REQ-ADM-010`: The admin web onboarding surface shall expose APIs to derive connection profiles from current runtime/config state, generate invite tokens, and preview invite tokens before apply. Invite preview output shall not expose the secure-link PSK in plaintext while the apply/update payload keeps the effective secure-link setting values usable for runtime configuration updates.
- `REQ-ADM-011`: The WebAdmin configuration editor shall make structured `own_servers` and `remote_servers` service catalogs editable without requiring operators to hand-edit the raw JSON for routine changes. The service editor shall preserve the same JSON config shape on save, show the current JSON value as the row preview, and provide a focused per-service popup flow for adding, removing, and navigating service entries.

- Implementation note: the admin web challenge-response login shall remain usable over plain HTTP as well as HTTPS. When the page is not in a secure context, the browser-side proof generation shall fall back to an equivalent client-side SHA-256 implementation so the login flow still works without requiring `window.crypto.subtle`.

Development-process measures such as test-execution discipline, regression-writing policy, and CI split strategy are documented in [DEVELOPMENT_PROCESS.md](/home/ohnoohweh/quic_br/docs/DEVELOPMENT_PROCESS.md). They intentionally do not appear here because they govern how the project is built and validated, not what the delivered project promises to an operator.

Repository governance update (process change): the project now documents and requires a consistent PR style and a repository PR template to improve review quality and traceability. See [DEVELOPMENT_PROCESS.md](/home/ohnoohweh/quic_br/docs/DEVELOPMENT_PROCESS.md) and `.github/PULL_REQUEST_TEMPLATE.md` for the required PR structure and checklist. This administrative change is intended to improve reviewer efficiency and traceability when implementation, tests, or architecture documents are modified. The top-level [README.md](/home/ohnoohweh/quic_br/README.md) is intentionally treated as a compact entrypoint and coverage snapshot; detailed requirement, design, system-boundary, and test-catalog narrative belongs in the dedicated docs rather than being duplicated in that snapshot. When behavior, tests, or architecture/process guidance changes, the snapshot is expected to stay current while the durable explanation remains in [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md), [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md), [SYSTEM_BOUNDARY.md](/home/ohnoohweh/quic_br/docs/SYSTEM_BOUNDARY.md), and [README_TESTING.md](/home/ohnoohweh/quic_br/docs/README_TESTING.md).

The supporting product-requirement traceability manifest is maintained in [.github/requirements_traceability.yaml](/home/ohnoohweh/quic_br/.github/requirements_traceability.yaml). It is stored with the repository's CI/support metadata rather than in `docs/`, but it continues to trace these product requirements to their defending tests.
