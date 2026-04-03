# Testing Guide

This repository currently collects:

- `63` integration tests in [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
- `49` unit tests in `tests/unit/`

## Get started

### Environment and install constraints

- Python `>= 3.9` is required, as declared in [pyproject.toml](/home/ohnoohweh/quic_br/pyproject.toml).
- Runtime dependencies include `aioquic` and `websockets`.
- Test execution additionally uses `pytest` and `pytest-xdist`.
- The integration suite opens real sockets, starts subprocesses, and is intended to run on a local machine where loopback networking and subprocess creation are available.

Recommended setup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
```

That installs:

- the project itself
- `pytest`
- `pytest-xdist`

Useful verification:

```bash
python --version
pytest --version
pytest -h | grep '\-n'
```

If `-n` appears in pytest help, `pytest-xdist` is available.

### Documentation guard

This repository now treats `docs/README_TESTING.md` as required companion documentation for test-suite changes.

Enforcement layers:

- CI runs `python scripts/check_readme_testing_guard.py --base-ref <base>` on every push and pull request.
- The guard fails if any file under `tests/` changed but `docs/README_TESTING.md` did not.
- Contributors can run the same rule locally before committing with `python scripts/check_readme_testing_guard.py --staged`.

### bridge.py integration gate

Changes to `src/obstacle_bridge/bridge.py` are now expected to pass the full integration suite before merge.

Enforcement layers:

- CI publishes the stable check `bridge.py Integration Gate`.
- That check runs `pytest -q -n 16 tests/integration/test_overlay_e2e.py` whenever `src/obstacle_bridge/bridge.py` changed.
- When `src/obstacle_bridge/bridge.py` did not change, the same check reports success without running the heavy suite.
- To make merge impossible on failures, configure branch protection in GitHub to require the `bridge.py Integration Gate` status check.

### What to run for regression testing

Recommended full regression flow:

```bash
pytest -q tests/unit
pytest -q -n 16 tests/integration/test_overlay_e2e.py
```

Why this split is recommended:

- unit tests are already fast and deterministic
- the integration harness benefits strongly from parallel execution
- the integration file has been port-randomized and worker-isolated specifically for `pytest-xdist`

If you want a single non-parallel command, this also works:

```bash
pytest -q
```

For frequent full end-to-end regression on a capable development machine, the preferred command is:

```bash
pytest -q -n 16 tests/integration/test_overlay_e2e.py
```

## Test patterns

The repository uses a few recurring test patterns.

### 1. Real subprocess integration tests

The overlay integration harness starts real `ObstacleBridge.py` processes, real bounce-back services, and real admin web endpoints. It verifies externally visible behavior rather than internal implementation details.

Typical checks:

- overlay reaches `CONNECTED`
- UDP or TCP probes traverse the overlay successfully
- restart and reconnect behavior works
- multi-client listener behavior remains correct
- admin API reports the expected runtime state

### 2. Parallel-safe integration execution

The integration harness rewrites transport, service, probe, bounce, and admin ports into worker-specific ranges. This allows:

```bash
pytest -q -n 16 tests/integration/test_overlay_e2e.py
```

without different cases colliding on the same local ports.

### 3. Delay/loss man-in-the-middle tests

The `myudp` delay/loss coverage is now part of the main integration harness. A loopback UDP proxy sits between peer client and peer server and can:

- add propagation delay
- drop selected DATA frames
- drop selected CONTROL frames

This gives controlled reproduction of retransmission and missed-frame behavior using the real bridge processes instead of an in-memory simulator.

### 4. API/auth integration tests

The admin web interface is tested through real HTTP requests against the running bridge process. These tests verify:

- auth disabled behavior
- auth required behavior
- successful login behavior
- per-client session isolation

### 5. Focused unit tests

Unit tests cover narrowly scoped logic that is easier and faster to validate without starting full bridge processes, for example:

- config parsing
- per-peer channel catalog logic
- connection snapshot formatting
- websocket payload and reconnect behavior
- runner event/config helpers

## Test catalog

The catalog is ordered as:

1. integration tests
2. unit tests

## Integration tests

Integration coverage currently lives in [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py) and collects `63` tests.

The supporting project-level intent documents are:

- [REQUIREMENTS.md](/home/ohnoohweh/quic_br/docs/REQUIREMENTS.md)
- [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md)
- [DEVELOPMENT_PROCESS.md](/home/ohnoohweh/quic_br/docs/DEVELOPMENT_PROCESS.md)

### Integration entrypoints

| Entry point | Scope | Objective | How to start |
|---|---|---|---|
| `test_overlay_e2e_basic` | Base transport smoke coverage | Verify that each primary overlay transport can carry the configured UDP or TCP service mapping end to end | `pytest -q tests/integration/test_overlay_e2e.py -k basic` |
| `test_overlay_e2e_reconnect` | Restart and reconnect flows | Verify disconnect detection, recovery, and post-restart functionality across base and localhost variants | `pytest -q tests/integration/test_overlay_e2e.py -k reconnect` |
| `test_overlay_e2e_listener_two_clients` | Multi-client listener | Verify that a listener can serve two clients and reports them correctly in admin APIs | `pytest -q tests/integration/test_overlay_e2e.py -k listener_two_clients` |
| `test_overlay_e2e_concurrent_tcp_channels` | Mixed service concurrency | Verify concurrent TCP channels, additional UDP mappings, and multi-client coexistence on shared listeners | `pytest -q tests/integration/test_overlay_e2e.py -k concurrent_tcp_channels` |
| `test_overlay_e2e_myudp_delay_loss` | Delayed/lossy myudp behavior | Verify retransmission, large payload handling, and control/data loss behavior through a real loopback MITM proxy | `pytest -q tests/integration/test_overlay_e2e.py -k myudp_delay_loss` |
| `test_overlay_e2e_server_restart_closes_tcp_preserves_udp` | Restart-specific regression | Verify the special restart behavior for the concurrent WS case | `pytest -q tests/integration/test_overlay_e2e.py -k server_restart_closes_tcp_preserves_udp` |
| `test_overlay_e2e_admin_api_*` | Admin web auth/API | Verify auth-disabled, auth-required, authenticated, and session-isolated API behavior | `pytest -q tests/integration/test_overlay_e2e.py -k admin_api` |
| `test_overlay_e2e_cli_routing_*` and allocator checks | Harness self-tests | Verify CLI mode inference and worker-safe port allocation logic | `pytest -q tests/integration/test_overlay_e2e.py -k "cli_routing or alloc_admin_ports or materialize_case_ports or case_port_offset"` |

### First traceability mapping for the integration suite

This first mapping is intentionally coarse. It links current integration entrypoints to the initial requirement set so future iterations can tighten coverage and identify gaps.

| Integration entrypoint | Primary requirement IDs | Notes |
|---|---|---|
| `test_overlay_e2e_basic` | `REQ-OVL-001`, `REQ-OVL-002`, `REQ-OVL-003`, `REQ-OVL-004`, `REQ-OVL-005`, `REQ-OVL-006` | Covers the primary happy-path transport combinations for UDP/TCP carriage across the supported overlays |
| `test_overlay_e2e_reconnect` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Covers disconnect, reconnect, restart recovery, and localhost-resolution reconnect variants |
| `test_overlay_e2e_listener_two_clients` | `REQ-LST-001`, `REQ-LST-005`, `REQ-ADM-006` | First multi-client listener proof for WS listener behavior and peer reporting |
| `test_overlay_e2e_concurrent_tcp_channels` | `REQ-LST-001`, `REQ-LST-002`, `REQ-LST-003`, `REQ-LST-004`, `REQ-LST-005`, `REQ-LST-006`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-ADM-006` | Covers mixed-service concurrency, multi-client listener behavior, and distinct peer visibility for WS/myudp/TCP/QUIC listeners |
| `test_overlay_e2e_myudp_delay_loss` | `REQ-MYU-001`, `REQ-MYU-002`, `REQ-MYU-003`, `REQ-MYU-004`, `REQ-MYU-005`, `REQ-MYU-006` | Covers delayed path, dropped DATA/CONTROL frames, large payloads, and bidirectional loss behavior |
| `test_overlay_e2e_server_restart_closes_tcp_preserves_udp` | `REQ-LIFE-004`, `REQ-MUX-001`, `REQ-MUX-002` | Special restart regression for the concurrent WS case |
| `test_overlay_e2e_admin_api_available_when_auth_disabled` | `REQ-ADM-002` | Auth-disabled API accessibility |
| `test_overlay_e2e_admin_api_unavailable_without_correct_auth` | `REQ-ADM-003` | Auth-required API lockout behavior |
| `test_overlay_e2e_admin_api_available_after_correct_auth` | `REQ-ADM-004` | Successful challenge/login unlock behavior |
| `test_overlay_e2e_admin_api_auth_isolated_per_concurrent_http_client` | `REQ-ADM-005` | Session isolation across concurrent HTTP clients |
| `test_overlay_e2e_cli_routing_*` and allocator checks | `REQ-TST-001`, `REQ-TST-003`, `REQ-TST-004` | Harness self-tests that protect the integrity and repeatability of the integration test system itself |

### Scenario-level traceability

This deeper mapping links concrete integration scenarios to requirement IDs. It is still a first draft, but it already makes it much easier to ask:

- which requirement is covered by which concrete scenario?
- which requirement only has coarse coverage?
- which scenario is carrying too much responsibility?

### Integration scenario catalog

#### Basic overlay scenarios

| Scenario | Requirement IDs | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `case01_udp_over_own_udp_ipv4` | `REQ-OVL-001`, `REQ-OVL-006`, `REQ-ADM-006` | Verify plain UDP forwarding over native UDP overlay on IPv4 | UDP overlay connects, admin becomes reachable, and the UDP probe returns the expected bounced payload | `pytest -q tests/integration/test_overlay_e2e.py -k case01_udp_over_own_udp_ipv4` |
| `case02_udp_over_own_udp_overlay_ipv6_clients_ipv4` | `REQ-OVL-001`, `REQ-OVL-006` | Verify IPv6 overlay with IPv4 application-side service | IPv6 overlay connects and the IPv4 UDP service still works end to end | `pytest -q tests/integration/test_overlay_e2e.py -k case02_udp_over_own_udp_overlay_ipv6_clients_ipv4` |
| `case03_udp_over_own_udp_overlay_ipv6_clients_ipv6` | `REQ-OVL-001`, `REQ-OVL-006` | Verify all-IPv6 UDP over UDP forwarding | Overlay reaches `CONNECTED` and IPv6 UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case03_udp_over_own_udp_overlay_ipv6_clients_ipv6` |
| `case04_tcp_over_own_udp_clients_ipv4` | `REQ-OVL-002`, `REQ-OVL-006`, `REQ-ADM-006` | Verify TCP service transport over native UDP overlay on IPv4 | TCP listener becomes reachable and a TCP probe gets the expected response | `pytest -q tests/integration/test_overlay_e2e.py -k case04_tcp_over_own_udp_clients_ipv4` |
| `case05_tcp_over_own_udp_clients_ipv6` | `REQ-OVL-002`, `REQ-OVL-006` | Verify IPv6 TCP service transport over native UDP overlay | IPv6 TCP listener becomes reachable and payload exchange succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case05_tcp_over_own_udp_clients_ipv6` |
| `case06_overlay_tcp_ipv4` | `REQ-OVL-003`, `REQ-OVL-006` | Verify UDP application transport over TCP overlay on IPv4 | TCP overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case06_overlay_tcp_ipv4` |
| `case07_overlay_tcp_ipv6` | `REQ-OVL-003`, `REQ-OVL-006` | Verify UDP application transport over TCP overlay on IPv6 | IPv6 TCP overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case07_overlay_tcp_ipv6` |
| `case08_overlay_ws_ipv4` | `REQ-OVL-004`, `REQ-OVL-006` | Verify UDP application transport over WebSocket overlay on IPv4 | WS overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case08_overlay_ws_ipv4` |
| `case09_overlay_ws_ipv6` | `REQ-OVL-004`, `REQ-OVL-006` | Verify UDP application transport over WebSocket overlay on IPv6 | IPv6 WS overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case09_overlay_ws_ipv6` |
| `case10_overlay_quic_ipv4` | `REQ-OVL-005`, `REQ-OVL-006` | Verify UDP application transport over QUIC overlay on IPv4 | QUIC overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case10_overlay_quic_ipv4` |
| `case11_overlay_quic_ipv6` | `REQ-OVL-005`, `REQ-OVL-006` | Verify UDP application transport over QUIC overlay on IPv6 | IPv6 QUIC overlay connects and UDP probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k case11_overlay_quic_ipv6` |

#### Reconnect and localhost variants

| Scenario | Requirement IDs | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `case01_*`, `case06_*`, `case08_*`, `case10_*` reconnect variants | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003` | Verify disconnect/restart/reconnect behavior | Initial probe succeeds, disconnected probe fails, restarted peer reconnects, and final probe succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k reconnect` |
| `case01_udp_over_own_udp_localhost_ipv4` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv4 peer resolution path | Localhost resolves correctly and reconnect flow works | `pytest -q tests/integration/test_overlay_e2e.py -k case01_udp_over_own_udp_localhost_ipv4` |
| `case01_udp_over_own_udp_localhost_ipv6` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv6 peer resolution path | Localhost resolves correctly and reconnect flow works | `pytest -q tests/integration/test_overlay_e2e.py -k case01_udp_over_own_udp_localhost_ipv6` |
| `case06_overlay_tcp_localhost_ipv4` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv4 TCP overlay reconnect path | TCP overlay reconnects and probe succeeds again | `pytest -q tests/integration/test_overlay_e2e.py -k case06_overlay_tcp_localhost_ipv4` |
| `case06_overlay_tcp_localhost_ipv6` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv6 TCP overlay reconnect path | IPv6 TCP overlay reconnects and probe succeeds again | `pytest -q tests/integration/test_overlay_e2e.py -k case06_overlay_tcp_localhost_ipv6` |
| `case08_overlay_ws_localhost_ipv4` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv4 WS reconnect path | WS reconnect path works through localhost resolution | `pytest -q tests/integration/test_overlay_e2e.py -k case08_overlay_ws_localhost_ipv4` |
| `case08_overlay_ws_localhost_ipv6` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv6 WS reconnect path | IPv6 WS reconnect path works through localhost resolution | `pytest -q tests/integration/test_overlay_e2e.py -k case08_overlay_ws_localhost_ipv6` |
| `case10_overlay_quic_localhost_ipv4` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv4 QUIC reconnect path | QUIC reconnect path works through localhost resolution | `pytest -q tests/integration/test_overlay_e2e.py -k case10_overlay_quic_localhost_ipv4` |
| `case10_overlay_quic_localhost_ipv6` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Verify localhost IPv6 QUIC reconnect path | IPv6 QUIC reconnect path works through localhost resolution | `pytest -q tests/integration/test_overlay_e2e.py -k case10_overlay_quic_localhost_ipv6` |

#### Listener and concurrent multi-client scenarios

| Scenario | Requirement IDs | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `case12_overlay_ws_ipv4_listener_two_clients` | `REQ-LST-001`, `REQ-LST-005`, `REQ-ADM-006` | Verify one WS listener can serve two clients | Both clients connect, both UDP services answer, `/api/status` keeps `overlay.peer=n/a`, `/api/peers` reports both peers, and the passive listening row stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case12_overlay_ws_ipv4_listener_two_clients` |
| `case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels` | `REQ-MUX-001`, `REQ-MUX-002`, `REQ-ADM-006` | Verify several concurrent TCP channels plus extra UDP mappings on one WS peer | Five TCP channels remain observable in `/api/connections`, replies are correct, UDP mappings work, and counters update | `pytest -q tests/integration/test_overlay_e2e.py -k case13_overlay_ws_ipv4_single_peer_concurrent_tcp_channels` |
| `case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp` | `REQ-LST-001`, `REQ-LST-002`, `REQ-LST-005`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-ADM-006` | Verify mixed WS and myudp clients on one listener | Both clients connect, all TCP/UDP probes succeed, server `/api/connections` shows expected active TCP rows, and the passive listening row in `/api/peers` stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp` |
| `case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp` | `REQ-LST-002`, `REQ-LST-005`, `REQ-LST-006`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-ADM-006` | Verify two myudp clients on one listener | Both myudp clients connect, all configured UDP/TCP services work, distinct peer endpoints are visible, and the passive listening row in `/api/peers` stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case15_overlay_listener_myudp_two_clients_concurrent_udp_tcp` |
| `case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp` | `REQ-LST-003`, `REQ-LST-005`, `REQ-LST-006`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-ADM-006` | Verify two TCP overlay clients on one listener | Both TCP clients connect, all configured UDP/TCP services work, distinct peer endpoints are visible, and the passive listening row in `/api/peers` stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case16_overlay_listener_tcp_two_clients_concurrent_udp_tcp` |
| `case17_overlay_listener_quic_two_clients_concurrent_udp_tcp` | `REQ-LST-004`, `REQ-LST-005`, `REQ-LST-006`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-ADM-006` | Verify two QUIC overlay clients on one listener | Both QUIC clients connect, all configured UDP/TCP services work, distinct peer endpoints are visible, and the passive listening row in `/api/peers` stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case17_overlay_listener_quic_two_clients_concurrent_udp_tcp` |
| `case13` restart regression | `REQ-LIFE-004`, `REQ-MUX-001`, `REQ-MUX-002` | Verify TCP channels close correctly while UDP service survives server restart handling | Restart-specific expectations hold for the concurrent WS scenario | `pytest -q tests/integration/test_overlay_e2e.py -k server_restart_closes_tcp_preserves_udp` |

#### myudp delay/loss scenarios

| Scenario | Requirement IDs | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `tc0_idle_connectivity` | `REQ-MYU-001` | Verify delayed path can still establish idle connectivity | Both peers connect through the proxy with delay enabled | `pytest -q tests/integration/test_overlay_e2e.py -k tc0_idle_connectivity` |
| `tc1_small_client_to_server` | `REQ-MYU-001` | Verify small client-to-server UDP payload over delayed path | Small payload reaches the remote side and reply is correct | `pytest -q tests/integration/test_overlay_e2e.py -k tc1_small_client_to_server` |
| `tc1a_drop_first_data_client_to_server` | `REQ-MYU-002` | Verify retransmission after one dropped DATA frame | First selected DATA frame is dropped and final payload still arrives correctly | `pytest -q tests/integration/test_overlay_e2e.py -k tc1a_drop_first_data_client_to_server` |
| `tc1b_drop_first_control_server_to_client` | `REQ-MYU-003` | Verify recovery when one CONTROL frame is dropped | Selected CONTROL drop does not prevent successful delivery | `pytest -q tests/integration/test_overlay_e2e.py -k tc1b_drop_first_control_server_to_client` |
| `tc2_small_server_to_client` | `REQ-MYU-001` | Verify reverse-direction small UDP payload over delayed path | Server-to-client payload arrives correctly | `pytest -q tests/integration/test_overlay_e2e.py -k tc2_small_server_to_client` |
| `tc3_2000_client_to_server` | `REQ-MYU-004` | Verify medium payload over delayed path | 2000-byte payload survives fragmentation/reassembly path correctly | `pytest -q tests/integration/test_overlay_e2e.py -k tc3_2000_client_to_server` |
| `tc4_2000_server_to_client` | `REQ-MYU-004` | Verify reverse-direction medium payload over delayed path | 2000-byte reverse payload arrives correctly | `pytest -q tests/integration/test_overlay_e2e.py -k tc4_2000_server_to_client` |
| `tc5_concurrent_bidir` | `REQ-MYU-005` | Verify simultaneous bidirectional myudp traffic | Client-to-server and server-to-client probes both succeed concurrently | `pytest -q tests/integration/test_overlay_e2e.py -k tc5_concurrent_bidir` |
| `tc6_20k_drop_2_3` | `REQ-MYU-002`, `REQ-MYU-004` | Verify large-payload retransmission with two dropped DATA frames | 20 KiB payload arrives correctly after dropping frames 2 and 3 | `pytest -q tests/integration/test_overlay_e2e.py -k tc6_20k_drop_2_3` |
| `tc7_20k_drop_2_3_20` | `REQ-MYU-002`, `REQ-MYU-004` | Verify large-payload retransmission with three dropped DATA frames | 20 KiB payload arrives correctly after dropping frames 2, 3, and 20 | `pytest -q tests/integration/test_overlay_e2e.py -k tc7_20k_drop_2_3_20` |
| `tc8_20k_drop_2_3_21` | `REQ-MYU-002`, `REQ-MYU-004` | Verify large-payload retransmission with another late drop pattern | 20 KiB payload arrives correctly after dropping frames 2, 3, and 21 | `pytest -q tests/integration/test_overlay_e2e.py -k tc8_20k_drop_2_3_21` |
| `tc9_20k_drop_2_3_20_21` | `REQ-MYU-002`, `REQ-MYU-004` | Verify larger missed-set pressure on the retransmit path | 20 KiB payload arrives correctly after dropping frames 2, 3, 20, and 21 | `pytest -q tests/integration/test_overlay_e2e.py -k tc9_20k_drop_2_3_20_21` |
| `tc10_full_missed_list_pressure` | `REQ-MYU-002`, `REQ-MYU-004`, `REQ-MYU-006` | Verify heavy early loss pressure and large missed-list handling | All large payloads eventually arrive correctly despite aggressive selected early DATA loss | `pytest -q tests/integration/test_overlay_e2e.py -k tc10_full_missed_list_pressure` |

#### Admin API/auth and harness self-tests

| Scenario | Requirement IDs | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `test_overlay_e2e_admin_api_available_when_auth_disabled` | `REQ-ADM-002` | Verify API is reachable with auth disabled | Auth-disabled server allows API access without login | `pytest -q tests/integration/test_overlay_e2e.py -k auth_disabled` |
| `test_overlay_e2e_admin_api_unavailable_without_correct_auth` | `REQ-ADM-003` | Verify locked API rejects unauthenticated access | API remains unavailable until correct auth completes | `pytest -q tests/integration/test_overlay_e2e.py -k unavailable_without_correct_auth` |
| `test_overlay_e2e_admin_api_available_after_correct_auth` | `REQ-ADM-004` | Verify challenge/login unlocks API | Correct authentication enables API access | `pytest -q tests/integration/test_overlay_e2e.py -k available_after_correct_auth` |
| `test_overlay_e2e_admin_api_auth_isolated_per_concurrent_http_client` | `REQ-ADM-005` | Verify session isolation | One authenticated HTTP client does not unlock another client session | `pytest -q tests/integration/test_overlay_e2e.py -k auth_isolated` |
| `test_overlay_e2e_cli_routing_*` | `REQ-TST-001`, `REQ-TST-004` | Verify CLI routing logic | Selected cases infer the right harness mode and explicit override is preserved | `pytest -q tests/integration/test_overlay_e2e.py -k cli_routing` |
| `test_overlay_e2e_materialize_case_ports_shifts_overlay_and_service_ports` | `REQ-TST-004` | Verify port rewriting | Overlay, bounce, probe, and service ports shift consistently | `pytest -q tests/integration/test_overlay_e2e.py -k materialize_case_ports` |
| `test_overlay_e2e_alloc_admin_ports_isolates_xdist_workers` | `REQ-TST-004` | Verify admin port worker isolation | Admin ports stay in the dedicated admin band and differ across workers | `pytest -q tests/integration/test_overlay_e2e.py -k alloc_admin_ports` |
| `test_overlay_e2e_case_port_offset_stays_in_range_for_many_workers` | `REQ-TST-004` | Verify allocator range safety | Service ports stay within the allowed worker-safe range even for many workers | `pytest -q tests/integration/test_overlay_e2e.py -k case_port_offset_stays_in_range` |

## Unit tests

Unit coverage currently collects `49` tests from `tests/unit/`.

### Unit-side traceability

Unit tests usually do not prove full black-box behavior on their own. Their main job is to protect component contracts, local invariants, and architecture-sensitive rules that would be expensive or ambiguous to validate only through end-to-end tests.

The component view they support is described in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md). The `Architectural component` column below uses the stable component IDs defined there so the traceability stays durable even if section titles are reworded later.

### First traceability mapping for the unit suite

| Unit test file | Architectural component | Related requirement/supporting IDs | Defended invariant or contract | How to start |
|---|---|---|---|---|
| `tests/unit/test_channel_mux_listener_mode.py` | `ARC-CMP-003` | `REQ-MUX-003`, `REQ-MUX-004`, `REQ-TST-002` | Listener mode must ignore ambiguous local publishing, parse service specs consistently, and manage remote catalog install/replace/cleanup correctly | `pytest -q tests/unit/test_channel_mux_listener_mode.py` |
| `tests/unit/test_channel_mux_peer_catalog.py` | `ARC-CMP-003` | `REQ-MUX-003`, `REQ-MUX-004`, `REQ-TST-002` | Peer-scoped remote service state must remain isolated and must be cleaned up per disconnected peer | `pytest -q tests/unit/test_channel_mux_peer_catalog.py` |
| `tests/unit/test_connection_snapshots.py` | `ARC-CMP-005` | `REQ-LST-006`, `REQ-ADM-006`, `REQ-TST-002` | Snapshot rendering must distinguish passive listeners from active connections, keep passive listener rows zeroed, and expose per-peer session stats on active listener-side peers correctly | `pytest -q tests/unit/test_connection_snapshots.py` |
| `tests/unit/test_debug_logging_aliases.py` | `ARC-CMP-005` | `REQ-TST-002` | Logging alias configuration must reach the intended websocket-related loggers | `pytest -q tests/unit/test_debug_logging_aliases.py` |
| `tests/unit/test_peer_resolution.py` | `ARC-CMP-004` | `REQ-OVL-007`, `REQ-TST-002` | Localhost resolution fallback must behave deterministically while non-localhost failures still propagate | `pytest -q tests/unit/test_peer_resolution.py` |
| `tests/unit/test_runner_config_persistence.py` | `ARC-CMP-004` | `REQ-TST-002` | Runtime config updates must persist back to the configured file correctly | `pytest -q tests/unit/test_runner_config_persistence.py` |
| `tests/unit/test_runner_events.py` | `ARC-CMP-004` | `REQ-TST-002` | Restart and shutdown events must bind to the active event loop correctly | `pytest -q tests/unit/test_runner_events.py` |
| `tests/unit/test_runner_overlay_transports.py` | `ARC-CMP-004`, `ARC-CMP-001` | `REQ-OVL-003`, `REQ-OVL-004`, `REQ-OVL-005`, `REQ-TST-002` | Overlay transport parsing and per-transport session/port construction must remain consistent with supported transport rules | `pytest -q tests/unit/test_runner_overlay_transports.py` |
| `tests/unit/test_ws_multi_peer.py` | `ARC-CMP-001`, `ARC-CMP-003` | `REQ-LST-001`, `REQ-MUX-001`, `REQ-MUX-003`, `REQ-TST-002` | WS multi-peer mux rewriting and outbound routing must remain peer-safe and channel-safe | `pytest -q tests/unit/test_ws_multi_peer.py` |
| `tests/unit/test_ws_payload_mode.py` | `ARC-CMP-001`, `ARC-CMP-005` | `REQ-OVL-004`, `REQ-LIFE-002`, `REQ-TST-002` | WS payload encoding, tx timing, reconnect grace, preflight behavior, compression config, and debug static HTTP behavior must stay internally consistent | `pytest -q tests/unit/test_ws_payload_mode.py` |

### Unit test catalog

| File | Scope | Objective | How to start |
|---|---|---|---|
| `tests/unit/test_channel_mux_listener_mode.py` | ChannelMux listener semantics | Verify listener mode ignores ambiguous local config, parses service specs correctly, and manages remote catalogs/lifecycle correctly | `pytest -q tests/unit/test_channel_mux_listener_mode.py` |
| `tests/unit/test_channel_mux_peer_catalog.py` | Per-peer remote service state | Verify peer-specific listener state is scoped and cleaned up per peer | `pytest -q tests/unit/test_channel_mux_peer_catalog.py` |
| `tests/unit/test_connection_snapshots.py` | Admin snapshot formatting | Verify connection and peer snapshot rendering, including listener rows, active-vs-idle distinctions, zeroed passive-listener stats, and correct per-peer listener-side myudp counters | `pytest -q tests/unit/test_connection_snapshots.py` |
| `tests/unit/test_debug_logging_aliases.py` | Logging alias wiring | Verify websocket logging aliases configure the intended library loggers | `pytest -q tests/unit/test_debug_logging_aliases.py` |
| `tests/unit/test_peer_resolution.py` | Host resolution behavior | Verify localhost fallback and non-localhost resolution error behavior | `pytest -q tests/unit/test_peer_resolution.py` |
| `tests/unit/test_runner_config_persistence.py` | Config update persistence | Verify config updates are written back to the configured file correctly | `pytest -q tests/unit/test_runner_config_persistence.py` |
| `tests/unit/test_runner_events.py` | Runner event binding | Verify restart and shutdown events bind to the running loop correctly | `pytest -q tests/unit/test_runner_events.py` |
| `tests/unit/test_runner_overlay_transports.py` | Overlay transport parsing/building | Verify transport list parsing and per-transport session/port creation behavior | `pytest -q tests/unit/test_runner_overlay_transports.py` |
| `tests/unit/test_ws_multi_peer.py` | WebSocket multi-peer mux logic | Verify inbound and outbound mux rewriting and peer-specific send routing | `pytest -q tests/unit/test_ws_multi_peer.py` |
| `tests/unit/test_ws_payload_mode.py` | WebSocket framing/runtime behavior | Verify payload encoding modes, tx loop behavior, socket config, reconnect grace, HTTP preflight, compression, and debug static HTTP behavior | `pytest -q tests/unit/test_ws_payload_mode.py` |

### Run the full unit suite

```bash
pytest -q tests/unit
```
