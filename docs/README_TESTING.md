# Clean Test Suite — NAT + 300ms delay + 5-frame guarantee

**What this suite guarantees**
- On-wire ptypes: **DATA=0x01**, **CONTROL=0x02** (original).
- NAT overlay: **PC1:40001 ↔ PC2:443** (single logical path in both directions).
- **300 ms one way** overlay delay between PCs.
- Overlay frames are **RX-logged before delivery** — so PCAP shows overlay immediately *before* the local deliver on the receiver.
- **Exactly 5 frames** per message: local send → overlay DATA → local receive → CONTROL (rx→tx) → CONTROL (tx→rx).

**Files**
- `src/obstacle_bridge/transfer.py` – deterministic CONTROL emission: receiver sends CONTROL on DATA; sender replies with CONTROL on CONTROL.
- `virtual_net.py` – NAT mapping, 300ms overlay delay, overlay RX-first PCAP logging, local app logging with global IPs.
- `scripts/run_udp_bidir_tests.py` – five scenarios, including two large and one concurrent case.

## Overlay integration suites

The repository also ships two end-to-end overlay harnesses in `tests/integration/`:

- `test_overlay_e2e.py`: unified smoke/reconnect/listener harness. `--mode` is optional; if omitted, the runner infers the path from selected cases.

The harness supports **two execution modes**:

- **CLI mode** (direct script entrypoint) for `--cases` control with optional `--mode` override.
- **pytest mode** for marker/k-expression filtering and standard pytest workflows.

Both paths start a local bounce-back server, launch one or more `ObstacleBridge.py` processes, wait for tunnel readiness, then probe through the overlay and fail with process/log dumps if a step breaks.

---


## Pytest interface

Run the unified harness through pytest (environment gate required):

```bash
RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -k basic
RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -k reconnect
RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -k listener_two_clients
```

### Markers and filtering

The overlay end-to-end coverage uses pytest markers:

- `integration`: integration/subprocess tests (typically slower than unit scope).
- `slow`: long-running scenarios (restart/reconnect and listener multi-client flows).

Common marker filters:

```bash
# run integration tests that are not marked slow
RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -m "integration and not slow"

# run only slow integration coverage
RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py -m "integration and slow"
```

## Unified harness: `test_overlay_e2e.py`

### Start the suite

Canonical/common command (no mode flag required):

```bash
python tests/integration/test_overlay_e2e.py
```

List available case names:

```bash
python tests/integration/test_overlay_e2e.py --list-cases
```

Run only selected cases:

```bash
python tests/integration/test_overlay_e2e.py \
  --cases case01_udp_over_own_udp_ipv4 case08_overlay_ws_ipv4
```

Preserve logs in a chosen folder:

```bash
python tests/integration/test_overlay_e2e.py --log-dir /tmp/overlay-e2e-logs
```

### Options

- `--cases <case...>`: run only the selected named cases (default: all).
- `--list-cases`: print supported case names and exit.
- `--log-dir <dir>`: keep process and bounce logs in a fixed directory (otherwise temp dir).
- `--settle-seconds <float>`: override default startup wait before probing.
- `--require-aioquic`: fail immediately if `aioquic` is missing (instead of silently skipping QUIC coverage).
- `--mode <basic|reconnect|listener-two-clients|concurrent-tcp-channels>`: optional override for execution path in the unified harness.
- `--reconnect-timeout <float>`: timeout used for connected/disconnected admin-state waits (applies to reconnect mode; ignored by basic mode).

Mode inference when `--mode` is omitted:

- if only concurrent TCP case(s) are selected (currently `case13_*`, `case14_*`, or `case15_*`), the concurrent runner is used,
- if selected cases are reconnect-only localhost variants, reconnect runner is used,
- otherwise the basic suite path is used.

## Overlay E2E catalog

The overlay harness currently covers 16 documented test targets:

- 15 named transport/topology cases in `CASES`
- 1 additional restart-behavior regression test that reuses `case13`

The pytest entry points are:

- `test_overlay_e2e_basic`: runs `BASIC_CASES`
- `test_overlay_e2e_reconnect`: runs `RECONNECT_CASES`
- `test_overlay_e2e_listener_two_clients`: runs `LISTENER_CASES`
- `test_overlay_e2e_concurrent_tcp_channels`: runs `CONCURRENT_TCP_CHANNEL_CASES`
- `test_overlay_e2e_server_restart_closes_tcp_preserves_udp`: extra restart-behavior regression for `case13`

### Common pass criteria

Unless a case says otherwise, every overlay case validates this baseline:

- the required bounce-back service starts
- the bridge server and bridge client process stay alive
- admin API becomes reachable
- both sides reach `CONNECTED` when the scenario expects an active overlay session
- a probe sent through the advertised local port reaches the bounce-back target and returns the expected transformed payload

### Case 1: `case01_udp_over_own_udp_ipv4`

- Scope: plain UDP payload forwarding over the native UDP overlay on IPv4.
- What is under test: `--udp-bind`, `--udp-peer`, `--udp-own-port`, and a single `own-servers` UDP mapping.
- Pass criteria:
- the UDP overlay comes up over IPv4
- a UDP probe to the peer client service port returns the expected bounced payload

### Case 2: `case02_udp_over_own_udp_overlay_ipv6_clients_ipv4`

- Scope: UDP overlay on IPv6 while the exposed application-side service remains IPv4.
- What is under test: mixed address-family handling between overlay transport and local forwarded service.
- Pass criteria:
- the IPv6 UDP overlay connects successfully
- the IPv4-side UDP service is reachable through the overlay and returns the expected payload

### Case 3: `case03_udp_over_own_udp_overlay_ipv6_clients_ipv6`

- Scope: end-to-end UDP over UDP using IPv6 on both overlay and application-facing side.
- What is under test: all-IPv6 bind, peer, and forwarded UDP service behavior.
- Pass criteria:
- overlay reaches `CONNECTED`
- UDP probe over IPv6 succeeds end-to-end

### Case 4: `case04_tcp_over_own_udp_clients_ipv4`

- Scope: TCP application traffic tunneled through the native UDP overlay on IPv4.
- What is under test: TCP channel creation on top of UDP overlay transport.
- Pass criteria:
- the peer client TCP listen port becomes reachable
- a TCP client can connect, exchange data, and receive the expected bounced reply

### Case 5: `case05_tcp_over_own_udp_clients_ipv6`

- Scope: same as case 4, but with IPv6 application-side TCP clients.
- What is under test: IPv6 TCP service exposure while the overlay transport remains UDP.
- Pass criteria:
- the TCP listener is reachable over IPv6
- TCP payload exchange succeeds through the overlay

### Case 6: `case06_overlay_tcp_ipv4`

- Scope: UDP application traffic carried over the dedicated TCP overlay transport on IPv4.
- What is under test: `--overlay-transport tcp` listener/client setup and UDP forwarding over a TCP overlay session.
- Pass criteria:
- TCP overlay reaches `CONNECTED`
- UDP probe through the overlay returns the expected response

### Case 7: `case07_overlay_tcp_ipv6`

- Scope: same transport model as case 6, but with IPv6 TCP overlay endpoints.
- What is under test: IPv6 TCP overlay establishment and UDP forwarding through it.
- Pass criteria:
- TCP overlay over IPv6 connects
- UDP probe succeeds

### Case 8: `case08_overlay_ws_ipv4`

- Scope: UDP application traffic over a WebSocket overlay on IPv4.
- What is under test: websocket overlay listener/client setup, NO_PROXY handling, and UDP forwarding through WS framing.
- Pass criteria:
- WS overlay reaches `CONNECTED`
- UDP probe through the WS tunnel succeeds

### Case 9: `case09_overlay_ws_ipv6`

- Scope: UDP application traffic over a WebSocket overlay on IPv6.
- What is under test: IPv6 websocket overlay setup and forwarding.
- Pass criteria:
- WS overlay over IPv6 connects
- UDP probe succeeds end-to-end

### Case 10: `case10_overlay_quic_ipv4`

- Scope: UDP application traffic over a QUIC overlay on IPv4.
- What is under test: QUIC listener/client startup, insecure client mode, and UDP forwarding through QUIC.
- Pass criteria:
- QUIC overlay reaches `CONNECTED`
- UDP probe succeeds through the tunnel

### Case 11: `case11_overlay_quic_ipv6`

- Scope: same as case 10, but with IPv6 QUIC endpoints.
- What is under test: IPv6 QUIC transport bring-up and forwarding.
- Pass criteria:
- QUIC overlay over IPv6 connects
- UDP probe succeeds

### Case 12: `case12_overlay_ws_ipv4_listener_two_clients`

- Scope: one WS listener with two independent peer clients behind it.
- What is under test: multi-client listener behavior and admin reporting for peer sessions.
- Pass criteria:
- both clients can connect to the same listener
- both exposed UDP service ports respond correctly
- listener `/api/status` keeps `overlay.peer` as `n/a`
- listener `/api/peers` reports at least two peer sessions

### Case 13: `case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels`

- Scope: one WS peer carrying several concurrent TCP channels plus additional UDP mappings.
- What is under test: concurrent channel multiplexing for mixed TCP and UDP traffic on a single peer.
- Pass criteria:
- five concurrent TCP channels can stay open long enough to be observed in `/api/connections`
- each TCP channel returns the correct payload
- both extra UDP mappings answer correctly
- aggregate traffic counters in `/api/status` and `/api/connections` reflect the transfer volume

### Case 14: `case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp`

- Scope: listener mode with two different peer clients, one on WS and one on myudp, both carrying mixed UDP and TCP services.
- What is under test: multi-transport listener behavior, concurrent TCP channels, multiple own/remote service publications, and dual-client coexistence.
- Pass criteria:
- both peer clients connect to the same listener
- all configured TCP probes across both clients return the correct responses
- all configured UDP probes across both clients return the correct responses
- server `/api/connections` exposes the expected active TCP rows during the held-open phase

### Case 15: `case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp`

- Scope: listener mode with two peer clients, both on myudp, both carrying mixed UDP and TCP services.
- What is under test: multi-client myudp listener behavior, concurrent TCP channels, multiple own/remote service publications, and dual-client coexistence on one UDP listener socket.
- Pass criteria:
- both peer clients connect to the same listener
- all configured TCP probes across both clients return the correct responses
- all configured UDP probes across both clients return the correct responses
- server `/api/connections` exposes the expected active TCP rows during the held-open phase
- listener `/api/peers` reports both myudp peers with distinct peer endpoints

### Localhost resolve-family reconnect variants

The reconnect suite adds these localhost-specific transport variants:

- `case01_udp_over_own_udp_localhost_ipv4`
- `case01_udp_over_own_udp_localhost_ipv6`
- `case06_overlay_tcp_localhost_ipv4`
- `case06_overlay_tcp_localhost_ipv6`
- `case08_overlay_ws_localhost_ipv4`
- `case08_overlay_ws_localhost_ipv6`
- `case10_overlay_quic_localhost_ipv4`
- `case10_overlay_quic_localhost_ipv6`

- Scope: verify that `localhost` plus explicit `--peer-resolve-family` keeps reconnect behavior deterministic.
- What is under test: name resolution family selection during reconnect and restart transitions.
- Pass criteria:
- the same reconnect criteria described below continue to pass when the peer host is `localhost`
- the selected IPv4 or IPv6 family remains valid after restart cycles

### Restart regression 15: `test_overlay_e2e_server_restart_closes_tcp_preserves_udp`

- Scope: a targeted regression test built on `case13`.
- What is under test:
- an active TCP application connection must not survive a peer server restart
- UDP mappings may resume after reconnect, but the peer client must keep using the same UDP source port for the resumed flow
- Pass criteria:
- one TCP socket and one UDP mapping are opened from the test harness through the peer client
- after the peer server is stopped, the peer client leaves `CONNECTED`
- the active TCP connection row disappears from the peer client `/api/connections`
- the held TCP socket closes and does not silently resume
- after the peer server restarts and both sides reconnect, the same UDP socket can exchange data again
- the resumed UDP connection row on the peer client still shows the same UDP source port as before the restart
- a brand-new TCP client socket opened by the test harness after reconnect succeeds as a fresh connection

Use `--list-cases` to print the exact active case names from the harness.

---

## Reconnect mode (same file)

### Start the suite

Run reconnect regression mode explicitly (backward-compatible with existing CI/script invocations):

```bash
python tests/integration/test_overlay_e2e.py --mode reconnect
```

Run only one case with custom transition timeout:

```bash
python tests/integration/test_overlay_e2e.py --mode reconnect \
  --cases case08_overlay_ws_ipv4 \
  --reconnect-timeout 45
```

List cases:

```bash
python tests/integration/test_overlay_e2e.py --mode reconnect --list-cases
```

### Options

- `--cases <case...>`: run only selected case names (default: all).
- `--list-cases`: print supported names and exit.
- `--log-dir <dir>`: output directory for child-process logs.
- `--settle-seconds <float>`: override case startup delay.
- `--require-aioquic`: fail fast if `aioquic` is unavailable.
- `--reconnect-timeout <float>`: timeout used for connected/disconnected admin-state waits.

### Reconnect pass criteria

For every case in `RECONNECT_CASES`, the reconnect runner validates this sequence:

1. initial overlay connectivity is established
2. a probe succeeds before any restart
3. stopping the outgoing bridge client forces the server side to leave `CONNECTED`
4. probes fail while the client is down
5. restarting the outgoing bridge client restores `CONNECTED` on both sides
6. a probe succeeds again after client restart
7. stopping the incoming bridge server forces the client side to leave `CONNECTED`
8. probes fail while the server is down
9. restarting the incoming bridge server restores `CONNECTED` on both sides
10. a final probe succeeds again
11. connection metrics or aggregate traffic counters update accordingly

This is the suite that validates restart resilience and admin-plane state transitions, distinct from the dedicated TCP-close/UDP-resume regression above.

---

## Consolidated test catalog

This repository currently collects **91 pytest tests**.

Observed execution modes:

- Default run: `pytest -q` -> **52 passed, 39 skipped**
- Gated overlay integration run: `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py` -> **43 passed**

Interpretation:

- the default run executes all unit tests plus the lightweight CLI-routing integration tests
- the remaining 39 overlay subprocess/socket tests are intentionally gated behind `RUN_OVERLAY_E2E=1`

### Unit tests

#### `tests/unit/test_channel_mux_listener_mode.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Client mode keeps `own_servers` | Verify normal client mode does not suppress local service exposure. | Parsed mux config retains configured local and remote service entries. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxListenerModeTests::test_client_mode_keeps_own_servers` |
| Listener mode ignores `own_servers` and `remote_servers` | Verify listener mode suppresses ambiguous service publication. | Listener-mode mux starts with empty local and requested-remote catalogs. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxListenerModeTests::test_listener_mode_ignores_own_servers_and_remote_servers` |
| Parse valid `remote_servers` | Verify valid remote catalog CLI specs are accepted. | Parser returns normalized service specs for valid input. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxListenerModeTests::test_parse_remote_servers_accepts_valid_specs` |
| Reject invalid `remote_servers` | Verify malformed remote catalog CLI specs are rejected. | Parser raises for invalid remote service strings. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxListenerModeTests::test_parse_remote_servers_rejects_invalid_specs` |
| Treat empty service entries as no services | Verify empty CLI service fragments are ignored safely. | Empty values do not create bogus service specs. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxListenerModeTests::test_parse_service_specs_treats_empty_config_entries_as_no_services` |
| Per-peer cleanup on disconnect | Verify listener-mode mux cleans only the disconnecting peer. | Peer-specific TCP/UDP state and installed services are removed for that peer only. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxRemoteCatalogTests::test_per_peer_cleanup_on_disconnect` |
| Start UDP and TCP listeners from remote catalog | Verify remote-installed service catalog creates listeners. | Receiving a peer catalog starts the expected UDP and TCP listeners. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxRemoteCatalogTests::test_receiver_starts_udp_and_tcp_listeners_from_remote_catalog` |
| Remote catalog replacement adds and removes services | Verify catalog replacement is differential. | Removed services stop, changed services restart, and added services start. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxRemoteCatalogTests::test_remote_catalog_replacement_adds_and_removes_services` |
| Send control install when overlay connects | Verify remote service control-plane publish is sent on connect. | Mux emits the expected `REMOTE_SERVICES_SET_V2` message when overlay becomes connected. | `pytest -q tests/unit/test_channel_mux_listener_mode.py::ChannelMuxRemoteCatalogTests::test_sends_control_install_when_overlay_connects` |

#### `tests/unit/test_channel_mux_peer_catalog.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Peer catalog scoped by peer id | Verify installed peer services are tracked independently per peer. | Service state for one peer does not overwrite another peer’s catalog. | `pytest -q tests/unit/test_channel_mux_peer_catalog.py::ChannelMuxPeerCatalogTests::test_peer_catalog_state_is_scoped_by_peer_id` |
| Peer disconnect closes that peer’s listeners | Verify disconnect cleanup is peer-local. | Only the target peer’s TCP/UDP listeners and channel state are closed. | `pytest -q tests/unit/test_channel_mux_peer_catalog.py::ChannelMuxPeerCatalogTests::test_peer_disconnect_closes_tcp_udp_listeners_for_that_peer` |

#### `tests/unit/test_connection_snapshots.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Snapshot counts listeners without clients | Verify connection snapshots still show listening services. | Snapshot includes listening rows even with zero active client channels. | `pytest -q tests/unit/test_connection_snapshots.py::ChannelMuxSnapshotTests::test_snapshot_counts_listeners_when_no_clients_connected` |
| Snapshot shows listeners and active connections | Verify mixed connection state is summarized correctly. | Snapshot includes both listening rows and connected rows with correct counters. | `pytest -q tests/unit/test_connection_snapshots.py::ChannelMuxSnapshotTests::test_snapshot_mixed_listeners_and_active_connections` |
| Peer open-connection counts exclude idle listeners | Verify peer summary counts only active peer traffic. | Runner peer snapshot excludes passive listener rows from open-connection totals. | `pytest -q tests/unit/test_connection_snapshots.py::RunnerPeerSnapshotTests::test_peer_open_connections_excludes_idle_listeners` |

#### `tests/unit/test_debug_logging_aliases.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| WS debug alias applies to library loggers | Verify user-facing websocket log alias controls underlying loggers. | Setting the alias updates effective levels for the library websocket loggers. | `pytest -q tests/unit/test_debug_logging_aliases.py::test_log_ws_session_applies_to_websockets_library_loggers` |

#### `tests/unit/test_peer_resolution.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| `localhost` IPv6 fallback on `gaierror` | Verify IPv6 localhost fallback is deterministic. | Resolver returns IPv6 loopback when `getaddrinfo` fails for `localhost` and IPv6 is requested. | `pytest -q tests/unit/test_peer_resolution.py::test_resolve_localhost_ipv6_uses_loopback_fallback_on_gaierror` |
| `localhost` IPv4 fallback on `gaierror` | Verify IPv4 localhost fallback is deterministic. | Resolver returns IPv4 loopback when `getaddrinfo` fails for `localhost` and IPv4 is requested. | `pytest -q tests/unit/test_peer_resolution.py::test_resolve_localhost_ipv4_uses_loopback_fallback_on_gaierror` |
| Non-localhost resolution failure propagates | Verify non-localhost failures are not silently rewritten. | Resolver raises the original failure for non-localhost names. | `pytest -q tests/unit/test_peer_resolution.py::test_resolve_non_localhost_propagates_resolution_failure` |

#### `tests/unit/test_runner_config_persistence.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Config update persists to config file | Verify runtime config writes are durable. | Updating config through the runner writes the expected persisted config contents. | `pytest -q tests/unit/test_runner_config_persistence.py::test_update_config_persists_to_config_file` |

#### `tests/unit/test_runner_events.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Restart event binds to active loop | Verify restart event wiring uses the running asyncio loop. | Restart event is created and bound without cross-loop misuse. | `pytest -q tests/unit/test_runner_events.py::RunnerEventBindingTests::test_restart_event_binds_to_running_loop` |
| Shutdown event binds to active loop | Verify shutdown event wiring uses the running asyncio loop. | Shutdown event is created and bound without cross-loop misuse. | `pytest -q tests/unit/test_runner_events.py::RunnerEventBindingTests::test_shutdown_event_binds_to_running_loop` |

#### `tests/unit/test_runner_overlay_transports.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Build sessions uses per-transport ports | Verify multi-transport runner setup respects each transport port. | Built sessions inherit the expected transport-specific listen/peer ports. | `pytest -q tests/unit/test_runner_overlay_transports.py::RunnerOverlayTransportTests::test_build_sessions_from_overlay_uses_per_transport_ports` |
| Overlay port lookup uses transport port | Verify helper port selection matches transport type. | Port lookup returns the correct port for each overlay transport. | `pytest -q tests/unit/test_runner_overlay_transports.py::RunnerOverlayTransportTests::test_overlay_port_for_uses_transport_port` |
| Parse comma-separated overlay transports | Verify multi-transport CLI parsing works. | Parser accepts comma-separated transport lists and preserves ordering. | `pytest -q tests/unit/test_runner_overlay_transports.py::RunnerOverlayTransportTests::test_parse_overlay_transports_accepts_comma_separated_values` |
| Reject multi-transport clients | Verify unsupported client-side multi-transport configs are blocked. | Parser rejects invalid multi-transport client combinations. | `pytest -q tests/unit/test_runner_overlay_transports.py::RunnerOverlayTransportTests::test_parse_overlay_transports_rejects_multi_transport_clients` |

#### `tests/unit/test_ws_multi_peer.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Inbound mux rewrite allocates unique server channels | Verify WS listener gives each peer/channel pair a distinct mux channel. | Inbound rewrites produce unique server mux channels per peer. | `pytest -q tests/unit/test_ws_multi_peer.py::WebSocketMultiPeerMuxRewriteTests::test_inbound_mux_rewrite_allocates_distinct_server_channels_per_peer` |
| Outbound mux rewrite returns to original peer channel | Verify reverse mux routing goes back to the owning peer channel. | Outbound rewrite resolves to the original peer and peer-local channel id. | `pytest -q tests/unit/test_ws_multi_peer.py::WebSocketMultiPeerMuxRewriteTests::test_outbound_mux_rewrite_routes_back_to_original_peer_channel` |
| Unregister removes only target peer channels | Verify listener cleanup is peer-local. | Removing one peer unregisters only that peer’s mux rewrite entries. | `pytest -q tests/unit/test_ws_multi_peer.py::WebSocketMultiPeerMuxRewriteTests::test_unregister_peer_channels_only_removes_target_peer` |
| `send_app` routes to matching server peer queue | Verify WS listener payload send chooses the correct peer queue. | Application payloads enqueue onto the owning server peer context only. | `pytest -q tests/unit/test_ws_multi_peer.py::WebSocketMultiPeerSendTests::test_send_app_routes_to_matching_server_peer_queue` |

#### `tests/unit/test_ws_payload_mode.py`

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Base64 text mode send/receive | Verify base64 text payload mode preserves bytes. | Encoded text frames decode back to the original binary payload. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_base64_mode_encodes_and_decodes_text_frames` |
| Binary frames accepted in text modes | Verify text payload modes remain compatible with binary frames. | Binary websocket frames are still accepted and decoded correctly. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_binary_frames_are_still_accepted_in_text_modes` |
| Binary mode keeps bytes unchanged | Verify binary mode is pass-through. | Sent binary payload remains unchanged on the wire path. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_binary_mode_keeps_bytes_on_send` |
| Early flush preserves message boundaries | Verify early-buffer flush does not merge websocket messages. | Flushed early messages keep original per-message boundaries. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_early_flush_preserves_websocket_message_boundaries` |
| Invalid text frame rejected | Verify malformed text-mode frames do not decode silently. | Invalid payload encoding is rejected instead of yielding corrupt data. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_invalid_text_frames_are_rejected` |
| JSON-base64 text mode send/receive | Verify JSON-base64 mode preserves bytes. | JSON wrapper plus base64 decode returns original payload bytes. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketPayloadModeTests::test_json_base64_mode_encodes_and_decodes_text_frames` |
| Early buffered send updates peer-tx after flush | Verify transmit accounting happens when buffered data really sends. | Peer-tx byte counters are notified after the flush succeeds. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketTxLoopTests::test_early_buffered_send_notifies_peer_tx_after_flush` |
| TX accounting after successful send | Verify TX accounting does not run before a send completes. | Counters move only after successful websocket send completion. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketTxLoopTests::test_tx_accounting_happens_after_successful_send` |
| TX timeout closes websocket | Verify stuck outbound websocket send forces teardown. | Timed-out transmit closes the websocket and stops the TX loop. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketTxLoopTests::test_tx_timeout_forces_websocket_close` |
| Configure websocket socket keepalive | Verify socket tuning applies when a raw socket exists. | Keepalive and TCP user timeout are set on the websocket socket. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketSocketConfigTests::test_configure_ws_socket_sets_keepalive_and_tcp_user_timeout` |
| Configure websocket socket skips missing socket | Verify socket tuning is optional. | Missing socket handle is tolerated without exception. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketSocketConfigTests::test_configure_ws_socket_skips_missing_socket` |
| Grace disconnect fires after delay | Verify reconnect grace waits before disconnecting. | Disconnect callback fires only after the configured grace interval. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketReconnectGraceTests::test_disconnect_fires_after_grace_when_not_reconnected` |
| Quick reconnect cancels pending disconnect | Verify reconnect grace cancels stale disconnect tasks. | Reconnecting inside the grace window prevents the disconnect callback. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketReconnectGraceTests::test_quick_reconnect_cancels_pending_disconnect` |
| Zero grace disconnects immediately | Verify zero-grace mode removes the delay. | Disconnect callback fires immediately when grace is zero. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketReconnectGraceTests::test_zero_grace_disconnects_immediately` |
| HTTP preflight requests default page | Verify WS static HTTP preflight probes the expected path. | Preflight sends an HTTP request for the default page. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketHttpPreflightTests::test_http_preflight_requests_default_page` |
| HTTP preflight requires success status | Verify preflight rejects failed HTTP responses. | Non-success status causes the preflight path to fail. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketHttpPreflightTests::test_http_preflight_requires_success_status` |
| Client websocket compression disabled | Verify client websocket connections disable per-message compression. | Connect kwargs disable websocket compression. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketCompressionConfigTests::test_connect_disables_websocket_compression` |
| Server websocket compression disabled | Verify websocket server disables per-message compression. | Serve kwargs disable websocket compression when supported. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketCompressionConfigTests::test_start_server_disables_websocket_compression` |
| Static HTTP debug probes scheduled | Verify server startup schedules static HTTP debug probes. | Starting the server creates the expected modern static-HTTP probe tasks. | `pytest -q tests/unit/test_ws_payload_mode.py::WebSocketStaticHttpDebugTests::test_start_server_schedules_static_http_probes_for_modern_requests` |

### Integration tests

All rows in this section use the overlay subprocess/socket harness. For the heavier end-to-end cases, prepend `RUN_OVERLAY_E2E=1`.

#### `tests/integration/test_overlay_e2e.py` basic transport cases

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Basic case01 UDP over own UDP IPv4 | Verify native UDP overlay on IPv4 forwards UDP payloads. | Overlay connects and a UDP probe returns the expected bounced payload. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case01_udp_over_own_udp_ipv4]'` |
| Basic case02 UDP over own UDP overlay IPv6 to IPv4 client service | Verify IPv6 overlay can forward to an IPv4-side UDP service. | Overlay connects and the IPv4 UDP service returns the expected payload. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case02_udp_over_own_udp_overlay_ipv6_clients_ipv4]'` |
| Basic case03 UDP over own UDP IPv6 end to end | Verify IPv6 overlay and IPv6 UDP service work together. | Overlay connects and the IPv6 UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case03_udp_over_own_udp_overlay_ipv6_clients_ipv6]'` |
| Basic case04 TCP over own UDP IPv4 | Verify TCP channels can ride over the native UDP overlay. | TCP client connects through overlay and receives expected bounced reply. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case04_tcp_over_own_udp_clients_ipv4]'` |
| Basic case05 TCP over own UDP IPv6 | Verify IPv6 TCP channels can ride over the native UDP overlay. | IPv6 TCP client connects through overlay and receives expected bounced reply. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case05_tcp_over_own_udp_clients_ipv6]'` |
| Basic case06 UDP over TCP overlay IPv4 | Verify TCP overlay transport forwards UDP application traffic. | TCP overlay connects and the UDP probe returns the expected payload. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case06_overlay_tcp_ipv4]'` |
| Basic case07 UDP over TCP overlay IPv6 | Verify IPv6 TCP overlay transport forwards UDP traffic. | IPv6 TCP overlay connects and the UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case07_overlay_tcp_ipv6]'` |
| Basic case08 UDP over WS overlay IPv4 | Verify websocket overlay transport forwards UDP traffic. | WS overlay connects and the UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case08_overlay_ws_ipv4]'` |
| Basic case09 UDP over WS overlay IPv6 | Verify IPv6 websocket overlay transport forwards UDP traffic. | IPv6 WS overlay connects and the UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case09_overlay_ws_ipv6]'` |
| Basic case10 UDP over QUIC overlay IPv4 | Verify QUIC overlay transport forwards UDP traffic. | QUIC overlay connects and the UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case10_overlay_quic_ipv4]'` |
| Basic case11 UDP over QUIC overlay IPv6 | Verify IPv6 QUIC overlay transport forwards UDP traffic. | IPv6 QUIC overlay connects and the UDP probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_basic[case11_overlay_quic_ipv6]'` |

#### `tests/integration/test_overlay_e2e.py` reconnect cases

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Reconnect case01 UDP over own UDP IPv4 | Verify UDP overlay recovers from client and server restarts. | Initial probe succeeds, both restart phases disconnect/reconnect correctly, and the final probe succeeds. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case01_udp_over_own_udp_ipv4]'` |
| Reconnect case02 UDP overlay IPv6 to IPv4 client service | Verify mixed-family UDP overlay reconnect remains stable. | Both restart cycles recover and UDP probing succeeds before and after each restart. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case02_udp_over_own_udp_overlay_ipv6_clients_ipv4]'` |
| Reconnect case03 UDP over own UDP IPv6 | Verify IPv6 UDP overlay reconnect remains stable. | Both restart cycles recover and IPv6 UDP probing succeeds before and after each restart. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case03_udp_over_own_udp_overlay_ipv6_clients_ipv6]'` |
| Reconnect case04 TCP over own UDP IPv4 | Verify TCP-over-UDP overlay recovers across restart cycles. | TCP probing succeeds before and after both restart phases. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case04_tcp_over_own_udp_clients_ipv4]'` |
| Reconnect case05 TCP over own UDP IPv6 | Verify IPv6 TCP-over-UDP overlay recovers across restart cycles. | IPv6 TCP probing succeeds before and after both restart phases. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case05_tcp_over_own_udp_clients_ipv6]'` |
| Reconnect case06 UDP over TCP overlay IPv4 | Verify TCP overlay reconnect remains stable. | TCP overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case06_overlay_tcp_ipv4]'` |
| Reconnect case07 UDP over TCP overlay IPv6 | Verify IPv6 TCP overlay reconnect remains stable. | IPv6 TCP overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case07_overlay_tcp_ipv6]'` |
| Reconnect case08 UDP over WS overlay IPv4 | Verify WS overlay reconnect remains stable. | WS overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case08_overlay_ws_ipv4]'` |
| Reconnect case09 UDP over WS overlay IPv6 | Verify IPv6 WS overlay reconnect remains stable. | IPv6 WS overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case09_overlay_ws_ipv6]'` |
| Reconnect case10 UDP over QUIC overlay IPv4 | Verify QUIC overlay reconnect remains stable. | QUIC overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case10_overlay_quic_ipv4]'` |
| Reconnect case11 UDP over QUIC overlay IPv6 | Verify IPv6 QUIC overlay reconnect remains stable. | IPv6 QUIC overlay disconnects and reconnects correctly and UDP probing recovers. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case11_overlay_quic_ipv6]'` |
| Reconnect localhost case01 UDP IPv4 | Verify localhost plus IPv4 resolve policy stays stable across reconnects. | Restart cycles recover and localhost resolves consistently to IPv4. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case01_udp_over_own_udp_localhost_ipv4]'` |
| Reconnect localhost case01 UDP IPv6 | Verify localhost plus IPv6 resolve policy stays stable across reconnects. | Restart cycles recover and localhost resolves consistently to IPv6. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case01_udp_over_own_udp_localhost_ipv6]'` |
| Reconnect localhost case06 TCP overlay IPv4 | Verify localhost TCP overlay respects IPv4 resolution through reconnects. | Restart cycles recover and localhost TCP overlay keeps IPv4 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case06_overlay_tcp_localhost_ipv4]'` |
| Reconnect localhost case06 TCP overlay IPv6 | Verify localhost TCP overlay respects IPv6 resolution through reconnects. | Restart cycles recover and localhost TCP overlay keeps IPv6 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case06_overlay_tcp_localhost_ipv6]'` |
| Reconnect localhost case08 WS overlay IPv4 | Verify localhost WS overlay respects IPv4 resolution through reconnects. | Restart cycles recover and localhost WS overlay keeps IPv4 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case08_overlay_ws_localhost_ipv4]'` |
| Reconnect localhost case08 WS overlay IPv6 | Verify localhost WS overlay respects IPv6 resolution through reconnects. | Restart cycles recover and localhost WS overlay keeps IPv6 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case08_overlay_ws_localhost_ipv6]'` |
| Reconnect localhost case10 QUIC overlay IPv4 | Verify localhost QUIC overlay respects IPv4 resolution through reconnects. | Restart cycles recover and localhost QUIC overlay keeps IPv4 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case10_overlay_quic_localhost_ipv4]'` |
| Reconnect localhost case10 QUIC overlay IPv6 | Verify localhost QUIC overlay respects IPv6 resolution through reconnects. | Restart cycles recover and localhost QUIC overlay keeps IPv6 addressing. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_reconnect[case10_overlay_quic_localhost_ipv6]'` |

#### `tests/integration/test_overlay_e2e.py` listener and concurrent cases

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Listener case12 WS listener with two clients | Verify one WS listener can host two peer clients. | Both clients connect, both UDP services answer, and listener peer reporting shows two peer sessions. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_listener_two_clients[case12_overlay_ws_ipv4_listener_two_clients]'` |
| Concurrent case13 WS single peer mixed channels | Verify one WS peer can carry several concurrent TCP channels and extra UDP mappings. | Five held-open TCP channels and two UDP mappings all succeed with correct connection visibility. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_concurrent_tcp_channels[case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels]'` |
| Concurrent case14 WS and myudp two-client listener | Verify a mixed WS plus myudp listener supports two simultaneous peers with TCP and UDP services. | Both clients connect, all TCP/UDP probes succeed, and active TCP rows are visible on the server. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_concurrent_tcp_channels[case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp]'` |
| Concurrent case15 myudp two-client listener | Verify a pure-myudp listener supports two simultaneous peers with TCP and UDP services. | Both myudp clients connect, all TCP/UDP probes succeed, and `/api/peers` reports both peer endpoints. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_concurrent_tcp_channels[case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp]'` |
| Restart regression on case13 | Verify a server restart closes active TCP but allows UDP to resume on the same client UDP socket. | TCP closes across restart, UDP resumes after reconnect, and the UDP source port stays stable. | `RUN_OVERLAY_E2E=1 pytest -q 'tests/integration/test_overlay_e2e.py::test_overlay_e2e_server_restart_closes_tcp_preserves_udp[case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels]'` |

#### `tests/integration/test_overlay_e2e.py` admin auth cases

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| Admin API available when auth disabled | Verify admin API remains open when auth is explicitly disabled. | `/api/status` returns `200` without login even if username/password are configured. | `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_admin_api_available_when_auth_disabled` |
| Admin API unavailable without correct auth | Verify protected admin API rejects unauthenticated clients. | `/api/status` returns `401` with `authenticated=false` before login. | `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_admin_api_unavailable_without_correct_auth` |
| Admin API available after correct auth | Verify challenge-response login unlocks the protected API. | Successful login returns authenticated state and `/api/status` then returns `200`. | `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_admin_api_available_after_correct_auth` |
| Admin API auth isolated per concurrent HTTP client | Verify one authenticated browser session does not unlock another session. | Authenticated opener gets `200`, second unauthenticated opener still gets `401`. | `RUN_OVERLAY_E2E=1 pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_admin_api_auth_isolated_per_concurrent_http_client` |

#### `tests/integration/test_overlay_e2e.py` lightweight CLI-routing checks

| Scenario | Objective | Test criteria | How to start test |
|---|---|---|---|
| CLI routing infers concurrent mode from case13 | Verify selecting case13 auto-picks concurrent mode. | Parsed CLI args select `case13` and infer the concurrent runner. | `pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case13` |
| CLI routing infers concurrent mode from case14 | Verify selecting case14 auto-picks concurrent mode. | Parsed CLI args select `case14` and infer the concurrent runner. | `pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case14` |
| CLI routing infers concurrent mode from case15 | Verify selecting case15 auto-picks concurrent mode. | Parsed CLI args select `case15` and infer the concurrent runner. | `pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_cli_routing_infers_concurrent_mode_from_case15` |
| CLI routing keeps explicit mode override | Verify explicit `--mode` is not replaced by inference. | Parsed CLI args preserve the caller-specified mode override. | `pytest -q tests/integration/test_overlay_e2e.py::test_overlay_e2e_cli_routing_keeps_explicit_mode_override` |
