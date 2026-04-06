# Testing Guide

This repository currently collects:

- `116` integration tests in [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py)
- `104` unit tests in `tests/unit/`

## Get started

### Environment and install constraints

- Python `>= 3.9` is required, as declared in [pyproject.toml](/home/ohnoohweh/quic_br/pyproject.toml).
- Runtime dependencies include `aioquic`, `cryptography`, and `websockets`.
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
- When `src/obstacle_bridge/bridge.py` changed, CI now runs two jobs:
  - Linux shared coverage: `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"`
  - Windows-specific coverage: `pytest -q -n 4 tests/integration/test_overlay_e2e.py -m "windows_only"`
- When `src/obstacle_bridge/bridge.py` did not change, the gate reports success without running the heavy suites.
- To make merge impossible on failures, configure branch protection in GitHub to require both `Integration Gate (Linux shared)` and `Integration Gate (Windows-specific)`.

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

For CI-aligned OS splitting, use:

```bash
pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"
pytest -q -n 4 tests/integration/test_overlay_e2e.py -m "windows_only"
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

Admin ports are additionally reserved from a dedicated band starting at `ADMIN_PORT_BASE`, above the normal service-port allocation range. This prevents the admin web listener from colliding with overlay or service sockets during highly parallel `xdist` runs.

The harness also partitions the regular admin-port allocator and the Secure Link admin-port allocator into disjoint sub-ranges. Normal integration cases stay below `SECURE_LINK_ADMIN_BASE`, while Secure Link cases allocate at or above that base, so unrelated WS and Secure Link subprocesses cannot race for the same admin port across different `xdist` workers.

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
- websocket payload, proxy-env handling, and reconnect behavior
- runner event/config helpers

## Test catalog

The catalog is ordered as:

1. integration tests
2. unit tests

## Integration tests

Integration coverage currently lives in [tests/integration/test_overlay_e2e.py](/home/ohnoohweh/quic_br/tests/integration/test_overlay_e2e.py) and collects `120` tests.

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
| `test_overlay_e2e_admin_api_*` | Admin web auth/API | Verify auth-disabled, auth-required, authenticated, session-isolated API behavior, and live WebSocket telemetry availability for both open and cookie-authenticated sessions | `pytest -q tests/integration/test_overlay_e2e.py -k admin_api` |
| `test_overlay_e2e_*secure_link_psk*` | Secure-link Phase 1 PSK runtime slice | Verify the delivered PSK secure-link slice reaches protected connected state across supported transports, rejects mismatched PSKs, preserves peer isolation for multi-client listener scenarios, and keeps `/api/peers` transport-specific secure-link peer stats aligned with live protected traffic | `pytest -q tests/integration/test_overlay_e2e.py -k secure_link_psk` |
| `test_overlay_e2e_ws_proxy_*` | WebSocket proxy behavior | Verify proxy success, bypass, scope, handshake ordering, failure handling, and explicit override behavior for WS peer clients, with Windows-only cases for system-default and Negotiate auth | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_` |
| `test_overlay_e2e_ws_static_http_root_*` | WS listener static HTTP behavior | Verify repeated plain HTTP reads keep returning the static root page and that two plain HTTP requests on the same WS-listener TCP connection succeed before any upgrade, both in the simpler secure-link `ws` case and in the mixed `ws,myudp` listener case with an authenticated `myudp` peer while overlay traffic remains healthy | `pytest -q tests/integration/test_overlay_e2e.py -k ws_static_http_root` |
| `test_overlay_e2e_ws_overlay_*proxy_env` | WebSocket proxy env behavior | Verify WS peer clients honor `HTTP_PROXY` and `NO_PROXY` in real subprocess runs | `pytest -q tests/integration/test_overlay_e2e.py -k "proxy_env"` |
| `test_overlay_e2e_cli_routing_*` and allocator checks | Harness self-tests | Verify CLI mode inference and worker-safe port allocation logic | `pytest -q tests/integration/test_overlay_e2e.py -k "cli_routing or alloc_admin_ports or materialize_case_ports or case_port_offset"` |
| `pytest -m "not windows_only"` | Linux shared CI subset | Run all OS-independent integration scenarios on Linux without masking Windows-specific obligations behind skips | `pytest -q -n 16 tests/integration/test_overlay_e2e.py -m "not windows_only"` |
| `pytest -m "windows_only"` | Windows-specific CI subset | Run integration scenarios that require Windows system proxy behavior or Windows Negotiate proxy auth | `pytest -q -n 4 tests/integration/test_overlay_e2e.py -m "windows_only"` |

### Failure-injection policy for integration tests

Integration tests should prefer black-box stimulation against the normal deliverable whenever the requirement is externally observable.

- First choice: stimulate behavior through normal network traffic, process restart, config, admin/API calls that are part of the delivered product surface, or environmental setup.
- Only use failure injection when external stimulation would add disproportionate harness complexity compared with the value of the requirement being defended.
- If failure injection is used, it must be enabled only in a controlled test variant of the deliverable, with a narrowly scoped change set that is explicit in the test harness.
- Failure-injection hooks must not be reachable in the normal runtime by default.
- The failure-injection variant must be used only by the specific tests that actually require failure injection.
- Any integration test that does not require failure injection must run against the unmodified normal runtime variant.
- Tests using failure injection must say so explicitly in their criteria, so reviewers can see where the suite depends on a test-only variant rather than the ordinary shipped surface.

### First traceability mapping for the integration suite

This first mapping is intentionally coarse. It links current integration entrypoints to the initial requirement set so future iterations can tighten coverage and identify gaps.

| Integration entrypoint | Primary requirement IDs | Notes |
|---|---|---|
| `test_overlay_e2e_basic` | `REQ-OVL-001`, `REQ-OVL-002`, `REQ-OVL-003`, `REQ-OVL-004`, `REQ-OVL-005`, `REQ-OVL-006` | Covers the primary happy-path transport combinations for UDP/TCP carriage across the supported overlays |
| `test_overlay_e2e_reconnect` | `REQ-LIFE-001`, `REQ-LIFE-002`, `REQ-LIFE-003`, `REQ-OVL-007` | Covers disconnect, reconnect, restart recovery, and localhost-resolution reconnect variants |
| `test_overlay_e2e_listener_two_clients` | `REQ-LST-001`, `REQ-LST-005`, `REQ-ADM-006` | First multi-client listener proof for WS listener behavior and peer reporting |
| `test_overlay_e2e_concurrent_tcp_channels` | `REQ-LST-001`, `REQ-LST-002`, `REQ-LST-003`, `REQ-LST-004`, `REQ-LST-005`, `REQ-LST-006`, `REQ-LST-007`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-MUX-005`, `REQ-ADM-006` | Covers mixed-service concurrency, multi-client listener behavior, distinct peer visibility, and the baseline peer-independence model for WS/myudp/TCP/QUIC listeners |
| `test_overlay_e2e_myudp_delay_loss` | `REQ-MYU-001`, `REQ-MYU-002`, `REQ-MYU-003`, `REQ-MYU-004`, `REQ-MYU-005`, `REQ-MYU-006` | Covers delayed path, dropped DATA/CONTROL frames, large payloads, and bidirectional loss behavior |
| `test_overlay_e2e_server_restart_closes_tcp_preserves_udp` | `REQ-LIFE-004`, `REQ-MUX-001`, `REQ-MUX-002` | Special restart regression for the concurrent WS case |
| `test_overlay_e2e_admin_api_available_when_auth_disabled` | `REQ-ADM-002` | Auth-disabled API accessibility |
| `test_overlay_e2e_admin_api_unavailable_without_correct_auth` | `REQ-ADM-003` | Auth-required API lockout behavior |
| `test_overlay_e2e_admin_api_available_after_correct_auth` | `REQ-ADM-004` | Successful challenge/login unlock behavior |
| `test_overlay_e2e_admin_api_auth_isolated_per_concurrent_http_client` | `REQ-ADM-005` | Session isolation across concurrent HTTP clients |
| `test_overlay_e2e_admin_live_ws_available_when_auth_disabled` | `REQ-ADM-006` | Live admin WebSocket stream availability and snapshot payload coverage when auth is disabled |
| `test_overlay_e2e_admin_live_ws_unavailable_without_correct_auth` | `REQ-ADM-003`, `REQ-ADM-006` | Live admin WebSocket stream must reject unauthenticated clients when auth is enabled |
| `test_overlay_e2e_admin_live_ws_available_after_correct_auth` | `REQ-ADM-004`, `REQ-ADM-006` | Live admin WebSocket stream must accept authenticated clients carrying the admin session cookie |
| `test_overlay_e2e_tcp_secure_link_psk_happy_path`, `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected`, `test_overlay_e2e_tcp_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, `test_overlay_e2e_myudp_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, `test_overlay_e2e_quic_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, `test_overlay_e2e_ws_secure_link_psk_listener_two_clients`, `test_overlay_e2e_secure_link_psk_happy_path_other_transports`, `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic`, `test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold`, `test_overlay_e2e_myudp_secure_link_psk_rekeys_after_time_threshold_under_live_traffic`, `test_overlay_e2e_tcp_secure_link_psk_operator_forced_rekey`, `test_overlay_e2e_tcp_secure_link_psk_reconnects_with_fresh_session`, `test_overlay_e2e_tcp_secure_link_psk_replay_after_reconnect_is_rejected`, `test_overlay_e2e_tcp_secure_link_psk_replay_after_rekey_is_rejected`, and `test_overlay_e2e_tcp_secure_link_psk_malformed_frame_fails_closed_subprocess` | `REQ-AUT-001`, `REQ-AUT-002`, `REQ-AUT-003`, `REQ-AUT-004`, `REQ-AUT-005`, `REQ-AUT-006`, `REQ-AUT-007`, `REQ-AUT-008`, `REQ-AUT-009`, `REQ-AUT-010` | End-to-end validation of the delivered PSK secure-link slice across `myudp`, `tcp`, `ws`, and `quic`, including wrong-PSK rejection, peer-scoped admin/API observability, multi-peer listener behavior, reconnect with fresh session installation, replay rejection after reconnect and rekey, malformed-frame fail-closed behavior, bounded retry/backoff visibility, and frame-, time-, and peer-targeted operator-triggered rekey coverage, including time-threshold rotation that still fires while protected `myudp` traffic remains active. The replay/malformed subprocess cases use the separate test-only `obstacle_bridge.bridge_FI` entrypoint rather than the normal runtime surface. |
| `test_overlay_e2e_ws_static_http_root_*` | `REQ-LST-007`, `REQ-MUX-005` | Verifies that repeated plain HTTP reads on the WS listener remain request-scoped, that two plain HTTP requests on one TCP connection succeed before any later upgrade, and that those HTTP paths do not disturb healthy secure-link peer traffic in either the simpler WS case or the mixed `ws,myudp` listener case, including when the healthy peer is using the separate `myudp` listener on the same process |
| `test_overlay_e2e_ws_overlay_uses_http_proxy_env` | `REQ-WSP-001`, `REQ-WSP-007`, `PROC-TST-001` | WS peer clients must honor `HTTP_PROXY` and establish proxy-routed overlay traffic successfully |
| `test_overlay_e2e_ws_proxy_is_scoped_to_peer_client_only` | `REQ-WSP-002` | Proxy behavior must stay scoped to WS peer-client mode and not imply listener-side proxy use |
| `test_overlay_e2e_http_proxy_env_does_not_apply_to_non_ws_transports` | `REQ-WSP-003` | HTTP proxy configuration must not silently become cross-transport behavior for `myudp`, `tcp`, or `quic` |
| `test_overlay_e2e_ws_proxy_tunnel_precedes_websocket_handshake` | `REQ-WSP-004` | CONNECT tunnel establishment must precede the websocket handshake on the proxied path |
| `test_overlay_e2e_ws_proxy_failure_keeps_overlay_state_machine_healthy` | `REQ-WSP-005` | Proxy failure must leave the overlay disconnected but operational and observable through admin state |
| `test_overlay_e2e_ws_proxy_system_default_on_windows_uses_system_proxy` | `REQ-WSP-006` | On Windows, the default WS peer-client path must honor system proxy discovery when available |
| `test_overlay_e2e_ws_overlay_honors_no_proxy_env` | `REQ-WSP-007`, `PROC-TST-001` | WS peer clients must bypass proxy routing when `NO_PROXY` matches the target |
| `test_overlay_e2e_ws_proxy_manual_override_uses_explicit_proxy` and `test_overlay_e2e_ws_proxy_off_override_disables_platform_default_proxy` | `REQ-WSP-008` | Explicit application configuration must be able to force manual proxy use or direct connection |
| `test_overlay_e2e_ws_proxy_negotiate_auth_on_windows` | `REQ-WSP-009` | On Windows, WS proxy traversal must support Negotiate-authenticated CONNECT flows |
| `test_overlay_e2e_ws_direct_preflight_requires_http_200_before_upgrade` | `REQ-WSP-011` | Direct WS peer clients must complete the `GET /` preflight and refuse the later upgrade path when that preflight does not return `200 OK` |
| `test_overlay_e2e_ws_direct_preflight_requires_http_200_before_upgrade` and `tests/unit/test_ws_payload_mode.py::{test_connect_reports_dns_resolution_failures_as_failed,test_connect_reports_proxy_negotiation_failures_as_failed}` | `REQ-WSP-012` | WS peer-client bootstrap/open failures must become user-visible `FAILED` status with transport-level reason/detail |
| `test_overlay_e2e_cli_routing_*` and allocator checks | `PROC-TST-001`, `PROC-TST-003`, `PROC-TST-004` | Harness self-tests that protect the integrity and repeatability of the integration test system itself |

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
| `case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp` | `REQ-LST-001`, `REQ-LST-002`, `REQ-LST-005`, `REQ-LST-007`, `REQ-MUX-001`, `REQ-MUX-002`, `REQ-MUX-003`, `REQ-MUX-004`, `REQ-MUX-005`, `REQ-ADM-006` | Verify mixed WS and myudp clients on one listener | Both clients connect, all TCP/UDP probes succeed, server `/api/connections` shows expected active TCP rows, and the passive listening row in `/api/peers` stays zeroed with `rtt=n/a`, `udp/tcp open=0`, `rx/tx bytes=0`, `decode_errors=0`, `inflight=0`, and zero myudp counters | `pytest -q tests/integration/test_overlay_e2e.py -k case14_overlay_listener_ws_and_myudp_two_clients_concurrent_udp_tcp` |
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
| `test_overlay_e2e_admin_live_ws_available_when_auth_disabled` | `REQ-ADM-006` | Verify live admin WebSocket telemetry is reachable | Auth-disabled server exposes `/api/live`, and the client receives `status`, `connections`, `peers`, and `meta` snapshots over one WebSocket session | `pytest -q tests/integration/test_overlay_e2e.py -k admin_live_ws_available_when_auth_disabled` |
| `test_overlay_e2e_admin_live_ws_unavailable_without_correct_auth` | `REQ-ADM-003`, `REQ-ADM-006` | Verify live admin WebSocket telemetry is protected by admin auth | Auth-enabled server rejects `/api/live` until the client completes the normal admin login flow | `pytest -q tests/integration/test_overlay_e2e.py -k admin_live_ws_unavailable_without_correct_auth` |
| `test_overlay_e2e_admin_live_ws_available_after_correct_auth` | `REQ-ADM-004`, `REQ-ADM-006` | Verify authenticated live admin WebSocket telemetry | After HTTP challenge/login sets the session cookie, `/api/live` accepts the client and streams `status`, `connections`, `peers`, and `meta` snapshots | `pytest -q tests/integration/test_overlay_e2e.py -k admin_live_ws_available_after_correct_auth` |
| `test_overlay_e2e_ws_overlay_uses_http_proxy_env` | `REQ-WSP-007` | Verify WS overlay honors `HTTP_PROXY` in a real client subprocess | Client connects through a local HTTP CONNECT proxy, the overlay reaches `CONNECTED`, UDP probes succeed, and the proxy records at least one CONNECT request | `pytest -q tests/integration/test_overlay_e2e.py -k ws_overlay_uses_http_proxy_env` |
| `test_overlay_e2e_ws_overlay_honors_no_proxy_env` | `REQ-WSP-007` | Verify `NO_PROXY` bypasses `HTTP_PROXY` for loopback WS targets | Client still reaches `CONNECTED` and serves probes while the local HTTP CONNECT proxy records zero CONNECT requests | `pytest -q tests/integration/test_overlay_e2e.py -k ws_overlay_honors_no_proxy_env` |
| `test_overlay_e2e_ws_proxy_is_scoped_to_peer_client_only` | `REQ-WSP-002` | Verify listener-side WS processes do not initiate proxy CONNECT behavior | WS listener still accepts the client and serves probes while the configured proxy records zero CONNECT requests | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_is_scoped_to_peer_client_only` |
| `test_overlay_e2e_http_proxy_env_does_not_apply_to_non_ws_transports` | `REQ-WSP-003` | Verify `HTTP_PROXY` does not affect non-WS overlay transports | `myudp`, `tcp`, and `quic` overlay clients still connect directly and the HTTP CONNECT proxy records zero requests | `pytest -q tests/integration/test_overlay_e2e.py -k http_proxy_env_does_not_apply_to_non_ws_transports` |
| `test_overlay_e2e_ws_proxy_tunnel_precedes_websocket_handshake` | `REQ-WSP-004` | Verify CONNECT tunneling happens before websocket handshake bytes are sent upstream | Proxy records CONNECT first and then sees the tunneled websocket HTTP `GET` request line | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_tunnel_precedes_websocket_handshake` |
| `test_overlay_e2e_ws_proxy_failure_keeps_overlay_state_machine_healthy` | `REQ-WSP-005` | Verify failed proxy routing leaves the overlay disconnected without crashing the processes | Admin stays reachable, peer state remains not connected, and application probes fail cleanly | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_failure_keeps_overlay_state_machine_healthy` |
| `test_overlay_e2e_ws_proxy_manual_override_uses_explicit_proxy` | `REQ-WSP-008` | Verify manual proxy override wins over platform-default bypass state | Even with `NO_PROXY` set for loopback, explicit manual proxy configuration forces CONNECT tunneling and traffic still succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_manual_override_uses_explicit_proxy` |
| `test_overlay_e2e_ws_proxy_off_override_disables_platform_default_proxy` | `REQ-WSP-008` | Verify explicit direct-connect override disables platform-default proxy routing | Even with `HTTP_PROXY` set, `--ws-proxy-mode off` keeps the WS client on a direct path and the proxy records zero CONNECT requests | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_off_override_disables_platform_default_proxy` |
| `test_overlay_e2e_ws_proxy_system_default_on_windows_uses_system_proxy` | `REQ-WSP-006` | Verify Windows default system proxy mode through the integration harness | On Windows, the default WS peer-client path uses system proxy discovery and successfully reaches the listener through the proxy | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_system_default_on_windows_uses_system_proxy` |
| `test_overlay_e2e_ws_proxy_negotiate_auth_on_windows` | `REQ-WSP-009` | Verify Windows Negotiate-authenticated proxy traversal | On Windows, a proxy that challenges with `Proxy-Authenticate: Negotiate` is satisfied and the overlay still reaches `CONNECTED` | `pytest -q tests/integration/test_overlay_e2e.py -k ws_proxy_negotiate_auth_on_windows` |
| `test_overlay_e2e_ws_direct_preflight_requires_http_200_before_upgrade` | `REQ-WSP-011` | Verify the direct WS client refuses upgrade when the listener cannot serve `GET /` successfully | The client and server stay observable but disconnected, the direct client log records the `GET /` preflight failure, the listener log records the plain HTTP `426` decision, and no WebSocket upgrade request is logged | `pytest -q tests/integration/test_overlay_e2e.py -k ws_direct_preflight_requires_http_200_before_upgrade` |
| `test_overlay_e2e_ws_direct_preflight_requires_http_200_before_upgrade` and `tests/unit/test_ws_payload_mode.py::{test_connect_reports_dns_resolution_failures_as_failed,test_connect_reports_proxy_negotiation_failures_as_failed}` | `REQ-WSP-012` | Verify WS bootstrap/open failures become user-visible failed connection state | Direct bootstrap failure, DNS-resolution failure, and proxy-negotiation failure all leave the client disconnected with `peer_state=FAILED` and a non-empty transport-level failure reason/detail until a later success clears it | `pytest -q tests/integration/test_overlay_e2e.py -k ws_direct_preflight_requires_http_200_before_upgrade` and `pytest -q tests/unit/test_ws_payload_mode.py -k 'connect_reports_dns_resolution_failures_as_failed or connect_reports_proxy_negotiation_failures_as_failed'` |

### Current certificate-mode secure-link coverage

The certificate-based secure-link slice is now delivered through Phase 2 trust validation and Phase 3 operational controls, and it is defended by both unit and subprocess integration coverage.

Certificate-mode tests now generate their root, certificate, signature, and private-key material at runtime through [tests/fixtures/secure_link_cert/__init__.py](/home/ohnoohweh/quic_br/tests/fixtures/secure_link_cert/__init__.py), so the repository no longer carries checked-in secure-link cert artifacts.

The delivered certificate-mode criteria now include:

- trust-anchor-validated mutual authentication before protected traffic is accepted
- role, validity-window, deployment-scope, and revoked-serial rejection before the protected data phase
- peer-scoped identity and trust diagnostics through `/api/peers`
- operator-forced rekey after a healthy authenticated cert-mode session is established
- live operator-triggered reload of revocation material, local identity material, or both through `/api/secure-link/reload`
- aggregate reload/apply result visibility through `/api/status`
- peer-scoped disconnect/trust-enforcement diagnostics after live reload/apply actions

| Test | Active requirement IDs exercised | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `test_overlay_e2e_secure_link_cert_happy_path_transports` | `REQ-AUT-011`, `REQ-AUT-012`, `REQ-AUT-013`, `REQ-AUT-014` | Verify cert-mode secure-link authenticates and carries protected overlay traffic across `tcp`, `myudp`, `ws`, and `quic` | Each supported transport reaches `CONNECTED`, the protected probe succeeds, and `/api/peers` reports `secure_link.mode=cert`, `secure_link.state=authenticated`, `trust_validation_state=trusted`, and peer identity fields such as subject id/name, roles, deployment id, serial, issuer, and trust-anchor id | `pytest -q tests/integration/test_overlay_e2e.py -k secure_link_cert_happy_path_transports` |
| `test_overlay_e2e_tcp_secure_link_cert_rejection_matrix` | `REQ-AUT-011`, `REQ-AUT-012`, `REQ-AUT-013`, `REQ-AUT-014` | Verify cert-mode rejects mismatched trust anchors, wrong roles, invalid validity windows, deployment mismatch, and revoked serials before protected data starts | Client and server stay not connected, the probe does not succeed, and `/api/peers` reports `secure_link.state=failed` together with the expected trust failure category and trust failure detail for each rejection case | `pytest -q tests/integration/test_overlay_e2e.py -k secure_link_cert_rejection_matrix` |
| `test_overlay_e2e_tcp_secure_link_cert_operator_forced_rekey` | `REQ-AUT-014` | Verify operator-forced rekey works for a selected authenticated cert-mode peer | After the first protected probe, `POST /api/secure-link/rekey` for the active peer row returns `ok=true`, the peer row rotates to a fresh `secure_link.session_id`, and the later protected probe still succeeds with `last_event=rekey_completed` and `last_rekey_trigger=operator` | `pytest -q tests/integration/test_overlay_e2e.py -k secure_link_cert_operator_forced_rekey` |
| `test_overlay_e2e_tcp_secure_link_cert_revocation_reload_happy_path` | `REQ-AUT-015`, `REQ-AUT-016`, `REQ-AUT-019` | Verify live revocation reload drops a now-revoked authenticated cert-mode peer without process restart | After a healthy authenticated session is established, updating the revoked-serial file and calling `POST /api/secure-link/reload` with `scope=revocation` returns `ok=true`, `/api/status` reports the aggregate reload result, and `/api/peers` shows the affected peer dropped with `trust_failure_reason=revoked_serial`, `disconnect_reason=revocation_applied`, and reload/enforcement timestamps | `pytest -q tests/integration/test_overlay_e2e.py -k cert_revocation_reload_happy_path` |
| `test_overlay_e2e_tcp_secure_link_cert_revocation_reload_noop` | `REQ-AUT-015`, `REQ-AUT-019` | Verify live revocation reload can succeed without disrupting a healthy peer when no new serial is revoked | Reloading unchanged revocation material returns `ok=true`, `/api/status` reports the successful reload summary, the authenticated peer remains healthy, and no disconnect/trust-enforcement state is introduced spuriously | `pytest -q tests/integration/test_overlay_e2e.py -k cert_revocation_reload_noop` |
| `test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_happy_path` | `REQ-AUT-017`, `REQ-AUT-018`, `REQ-AUT-019` | Verify live local-identity reload atomically activates new local material and forces existing peers to re-authenticate under the new generation | Replacing the local cert bundle with a valid new generation and calling `POST /api/secure-link/reload` with `scope=local_identity` returns `ok=true`, `/api/status` reports the new material generation, the old authenticated peer is dropped with `disconnect_reason=local_identity_reloaded`, and a fresh authenticated peer row appears under the new generation | `pytest -q tests/integration/test_overlay_e2e.py -k cert_local_identity_reload_happy_path` |
| `test_overlay_e2e_tcp_secure_link_cert_local_identity_reload_rejected` | `REQ-AUT-017`, `REQ-AUT-019` | Verify an invalid local cert-material reload is rejected atomically and does not partially replace healthy runtime material | Replacing the local bundle with malformed or invalid data and calling `POST /api/secure-link/reload` with `scope=local_identity` returns `ok=false`, `/api/status` reports the failed reload result, and the existing authenticated session remains healthy on the previous material | `pytest -q tests/integration/test_overlay_e2e.py -k cert_local_identity_reload_rejected` |
| `test_overlay_e2e_tcp_secure_link_cert_full_reload_applies_atomically` | `REQ-AUT-015`, `REQ-AUT-016`, `REQ-AUT-017`, `REQ-AUT-018`, `REQ-AUT-019` | Verify combined reload of revocation and local identity applies atomically and enforces the resulting trust state immediately | Calling `POST /api/secure-link/reload` with `scope=all` after updating both revocation and local cert inputs returns `ok=true`, `/api/status` reports the combined reload result and new material generation, and `/api/peers` shows the expected disconnect/trust-enforcement behavior under the new inputs | `pytest -q tests/integration/test_overlay_e2e.py -k cert_full_reload_applies_atomically` |

### Current secure-link PSK test criteria notes

The first Phase 1 PSK prototype now exposes its secure-link state through the peer-facing admin/API surface:

- `/api/peers` exposes a per-peer `secure_link` block
- current states include `disabled`, `waiting_transport`, `waiting_hello`, `handshaking`, `authenticated`, `failed`, and `listening`
- current observability includes mode, authenticated flag, `rekey_in_progress`, `last_rekey_trigger`, `rekey_due_unix_ts`, `failure_code`, `failure_reason`, `failure_detail`, `failure_unix_ts`, `failure_session_id`, `consecutive_failures`, `retry_backoff_sec`, `next_retry_unix_ts`, `handshake_attempts_total`, `last_event`, `last_event_unix_ts`, `last_authenticated_unix_ts`, `authenticated_sessions_total`, and `rekeys_completed_total`

`/api/status` remains intentionally limited to common runtime summary information such as uptime, aggregate open-channel counts, and aggregate traffic rates.

Certificate mode now uses those richer fields directly, including peer identity metadata and trust-validation failure categories, and the WebAdmin peer security block renders those cert-specific fields instead of leaving them API-only.

### Current secure-link PSK coverage

The repository now contains a narrow Phase 1 prototype for:

- `overlay_transport=myudp`
- `overlay_transport=tcp`
- `overlay_transport=ws`
- `overlay_transport=quic`
- `secure_link_mode=psk`
- `secure_link_rekey_after_frames`
- `secure_link_rekey_after_seconds`
- admin-driven peer-targeted `POST /api/secure-link/rekey` with a JSON body carrying the selected `peer_id`

This runtime slice is now reflected by active `REQ-AUT-*` requirements, and the certificate-mode secure-link follow-up has now been promoted into active `REQ-AUT-011` through `REQ-AUT-019`.

| Test | Active requirement IDs exercised | Objective | Test criteria | How to start |
|---|---|---|---|---|
| `test_overlay_e2e_tcp_secure_link_psk_happy_path` | `REQ-AUT-001`, `REQ-AUT-002`, `REQ-AUT-004`, `REQ-AUT-009` | Verify the first TCP secure-link wrapper can complete a PSK handshake and carry protected overlay traffic | Both admin endpoints come up, client and server reach `CONNECTED`, `/api/peers` reports `secure_link.state=authenticated`, the active peer row reports `last_event=authenticated`, `handshake_attempts_total>=1`, `authenticated_sessions_total>=1`, and a populated `last_authenticated_unix_ts`, the hidden failure-injection endpoint returns `404` in the normal runtime, and the usual UDP probe over `case06_overlay_tcp_ipv4` succeeds with secure-link enabled on both sides | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_happy_path` |
| `test_overlay_e2e_tcp_secure_link_psk_wrong_secret_rejected` | `REQ-AUT-003`, `REQ-AUT-004`, `REQ-AUT-008`, `REQ-AUT-009` | Verify mismatched PSKs prevent the protected data phase and do not devolve into an uncontrolled retry loop | Client and server stay not connected, the probe does not succeed, and the peer-scoped admin/API view reports `secure_link.state=failed` with `failure_code=1`, `failure_reason=bad_psk`, a human-readable `failure_detail`, a bounded retry window with `consecutive_failures>=2` and a populated `next_retry_unix_ts`, plus `last_event=retry_scheduled`, a populated `failure_session_id`, and `handshake_attempts_total>=2` while both processes remain alive and observable for debugging | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_wrong_secret_rejected` |
| `test_overlay_e2e_secure_link_psk_happy_path_other_transports` | `REQ-AUT-001`, `REQ-AUT-002`, `REQ-AUT-004` | Verify the same PSK secure-link boundary can carry protected overlay traffic over `myudp`, `ws`, and `quic` in addition to the original TCP slice | Each supported transport reaches `CONNECTED`, `/api/peers` reports `secure_link.state=authenticated`, the protected overlay probe succeeds, and the processes remain healthy and observable throughout the run | `pytest -q tests/integration/test_overlay_e2e.py -k secure_link_psk_happy_path_other_transports` |
| `test_overlay_e2e_tcp_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, `test_overlay_e2e_myudp_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, `test_overlay_e2e_quic_secure_link_psk_listener_two_clients_concurrent_udp_tcp`, and `test_overlay_e2e_ws_secure_link_psk_listener_two_clients` | `REQ-AUT-001`, `REQ-AUT-002`, `REQ-AUT-004`, `REQ-AUT-005` | Verify the PSK secure-link runtime slice preserves multi-peer listener behavior beyond the original TCP-only slice | Listener reports multiple distinct authenticated peers, the transport-appropriate service probes succeed for both clients, and secure-link observability shows authenticated peer state without cross-peer mix-up | `pytest -q tests/integration/test_overlay_e2e.py -k "secure_link_psk_listener_two_clients"` |
| `test_overlay_e2e_tcp_secure_link_psk_rekeys_under_live_traffic` | `REQ-AUT-004`, `REQ-AUT-006`, `REQ-AUT-009` | Verify the PSK runtime can rekey to a fresh secure-link session under live traffic without breaking the overlay | After the first protected probe, `/api/peers` reports a changed `secure_link.session_id` while both sides remain authenticated, the active peer row reports `last_event=rekey_completed`, `rekeys_completed_total>=1`, `authenticated_sessions_total>=2`, and a second probe still succeeds over the same TCP overlay path | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_rekeys_under_live_traffic` |
| `test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold` | `REQ-AUT-004`, `REQ-AUT-009`, `REQ-AUT-010` | Verify the PSK runtime can trigger rekey from a time threshold after protected traffic has been established | After the first protected probe, the client admin/API reports a changed `secure_link.session_id`, `last_event=rekey_completed`, `last_rekey_trigger=time_threshold`, `rekeys_completed_total>=1`, and a later protected probe still succeeds over the same TCP overlay path | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_rekeys_after_time_threshold` |
| `test_overlay_e2e_tcp_secure_link_psk_rekeys_after_time_threshold_while_idle` | `REQ-AUT-009`, `REQ-AUT-010` | Verify the PSK runtime arms and completes time-based rekey on an authenticated client session even before any later protected application probe is sent | Immediately after authentication, the client peer row publishes a non-empty `rekey_due_unix_ts`; after the configured threshold elapses, the client admin/API reports a changed `secure_link.session_id`, `last_event=rekey_completed`, `last_rekey_trigger=time_threshold`, `rekeys_completed_total>=1`, and a protected probe sent after the idle rekey still succeeds over the same TCP overlay path | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_rekeys_after_time_threshold_while_idle` |
| `test_overlay_e2e_myudp_secure_link_psk_rekeys_after_time_threshold_under_live_traffic` | `REQ-AUT-009`, `REQ-AUT-010` | Verify time-threshold rekey on `myudp` is tied to the authenticated session lifetime rather than postponed by continuous protected traffic | After authentication, the client peer row publishes a time-based rekey deadline; repeated protected probes continue to succeed across the threshold window, the client admin/API still reports a changed `secure_link.session_id` with `last_event=rekey_completed` and `last_rekey_trigger=time_threshold`, and a later probe still succeeds on the same `myudp` overlay path | `pytest -q tests/integration/test_overlay_e2e.py -k myudp_secure_link_psk_rekeys_after_time_threshold_under_live_traffic` |
| `test_overlay_e2e_tcp_secure_link_psk_operator_forced_rekey` | `REQ-AUT-004`, `REQ-AUT-009`, `REQ-AUT-010` | Verify an operator can force PSK rekey for a selected peer through the admin API without breaking a healthy overlay session | After the first protected probe, `POST /api/secure-link/rekey` with the active peer row id returns `ok=true`, the client admin/API reports a changed `secure_link.session_id`, `last_event=rekey_completed`, `last_rekey_trigger=operator`, `rekeys_completed_total>=1`, and a later protected probe still succeeds over the same TCP overlay path | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_operator_forced_rekey` |
| `test_overlay_e2e_myudp_secure_link_psk_rekey_done_delay_keeps_same_udp_channel_healthy` | `REQ-AUT-010` | Verify operator-driven rekey on `myudp` does not starve a live UDP channel when `REKEY_DONE` is delayed after the server has already switched | A test proxy delays only server-to-client `REKEY_DONE`, the client remains on the pre-rekey session long enough to expose the cutover gap, and a UDP datagram sent on the same client socket during that window still receives its bounced reply instead of timing out | `pytest -q tests/integration/test_overlay_e2e.py -k myudp_secure_link_psk_rekey_done_delay_keeps_same_udp_channel_healthy` |
| `test_overlay_e2e_tcp_secure_link_psk_reconnects_with_fresh_session` | `REQ-AUT-006`, `REQ-AUT-009` | Verify reconnect installs a fresh secure-link session instead of reusing the previous session lifecycle | After client restart and successful reconnect, the server-side peer row reports a different `secure_link.session_id` than before disconnect, and a new protected probe still succeeds | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_reconnects_with_fresh_session` |
| `test_overlay_e2e_myudp_secure_link_psk_recovery_after_prior_time_threshold_rekey_reports_fresh_authentication` | `REQ-AUT-009`, `REQ-AUT-010` | Verify a fresh myudp recovery after an earlier time-threshold rekey is reported as a new authentication lifecycle rather than as another time-threshold rekey | After a client-side time-threshold rekey has completed, a real myudp outage and recovery yields a new `secure_link.session_id` whose peer row reports `last_event=authenticated`, an empty `last_rekey_trigger`, and `rekeys_completed_total=0`, while protected traffic succeeds again | `pytest -q tests/integration/test_overlay_e2e.py -k myudp_secure_link_psk_recovery_after_prior_time_threshold_rekey_reports_fresh_authentication` |
| `test_overlay_e2e_myudp_secure_link_psk_client_restart_after_prior_time_threshold_rekey_drops_stale_pre_restart_row` | `REQ-AUT-009`, `REQ-AUT-010` | Verify one-sided myudp client restart after an earlier time-threshold rekey does not leave the stale pre-restart secure-link row visible on the surviving server | After a client-side time-threshold rekey has completed, restarting only the myudp client and sending protected traffic again forces the surviving server `/api/peers` view to expose only the recovered authenticated row for that host instead of also retaining the stale pre-restart row with rekey history | `pytest -q tests/integration/test_overlay_e2e.py -k client_restart_after_prior_time_threshold_rekey_drops_stale_pre_restart_row` |
| `test_overlay_e2e_tcp_secure_link_psk_replay_after_reconnect_is_rejected` | `REQ-AUT-006`, `REQ-AUT-007` | Verify stale protected frames from the pre-reconnect session are rejected after a fresh session is installed | After reconnect, replaying a previously accepted frame from the old session through the test-only admin-authenticated secure-link failure-injection hook forces `secure_link.state=failed` with `failure_code=4` / `failure_reason=decode`, and the protected probe fails instead of being forwarded | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_replay_after_reconnect_is_rejected` |
| `test_overlay_e2e_tcp_secure_link_psk_replay_after_rekey_is_rejected` | `REQ-AUT-006`, `REQ-AUT-007` | Verify stale protected frames from the pre-rekey session are rejected after live rekey installs a fresh session | After rekey, replaying a previously accepted frame from the old session through the test-only admin-authenticated secure-link failure-injection hook forces `secure_link.state=failed` with `failure_code=4` / `failure_reason=decode`, and the protected probe fails instead of being forwarded | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_replay_after_rekey_is_rejected` |
| `test_overlay_e2e_tcp_secure_link_psk_malformed_frame_fails_closed_subprocess` | `REQ-AUT-007` | Verify malformed secure-link input fails closed in the real subprocess runtime, not only in unit tests | Injecting malformed raw secure-link bytes through the test-only admin-authenticated secure-link failure-injection hook forces `secure_link.state=failed` with `failure_code=4` / `failure_reason=decode`, and the protected probe fails instead of being forwarded | `pytest -q tests/integration/test_overlay_e2e.py -k tcp_secure_link_psk_malformed_frame_fails_closed_subprocess` |
| `test_overlay_e2e_cli_routing_*` | `PROC-TST-001`, `PROC-TST-004` | Verify CLI routing logic | Selected cases infer the right harness mode and explicit override is preserved | `pytest -q tests/integration/test_overlay_e2e.py -k cli_routing` |
| `test_overlay_e2e_materialize_case_ports_shifts_overlay_and_service_ports` | `PROC-TST-004` | Verify port rewriting | Overlay, bounce, probe, and service ports shift consistently | `pytest -q tests/integration/test_overlay_e2e.py -k materialize_case_ports` |
| `test_overlay_e2e_alloc_admin_ports_isolates_xdist_workers` | `PROC-TST-004` | Verify admin port worker isolation | Admin ports stay in the dedicated admin band and differ across workers | `pytest -q tests/integration/test_overlay_e2e.py -k alloc_admin_ports` |
| `test_overlay_e2e_case_port_offset_stays_in_range_for_many_workers` | `PROC-TST-004` | Verify allocator range safety | Service ports stay within the allowed worker-safe range even for many workers | `pytest -q tests/integration/test_overlay_e2e.py -k case_port_offset_stays_in_range` |

## Unit tests

Unit coverage currently collects `106` tests from `tests/unit/`.

### Unit-side traceability

Unit tests usually do not prove full black-box behavior on their own. Their main job is to protect component contracts, local invariants, and architecture-sensitive rules that would be expensive or ambiguous to validate only through end-to-end tests.

The component view they support is described in [ARCHITECTURE.md](/home/ohnoohweh/quic_br/docs/ARCHITECTURE.md). The `Architectural component` column below uses the stable component IDs defined there so the traceability stays durable even if section titles are reworded later.

### First traceability mapping for the unit suite

| Unit test file | Architectural component | Related requirement/supporting IDs | Defended invariant or contract | How to start |
|---|---|---|---|---|
| `tests/unit/test_channel_mux_listener_mode.py` | `ARC-CMP-003` | `REQ-MUX-003`, `REQ-MUX-004`, `REQ-MUX-005`, `PROC-TST-002` | Listener mode must ignore ambiguous local publishing, parse service specs consistently, and manage remote catalog install/replace/cleanup correctly without falling back to listener-global shortcuts | `pytest -q tests/unit/test_channel_mux_listener_mode.py` |
| `tests/unit/test_channel_mux_peer_catalog.py` | `ARC-CMP-003` | `REQ-MUX-003`, `REQ-MUX-004`, `REQ-MUX-005`, `PROC-TST-002` | Peer-scoped remote service state must remain isolated and must be cleaned up per disconnected peer rather than by process-global replacement | `pytest -q tests/unit/test_channel_mux_peer_catalog.py` |
| `tests/unit/test_connection_snapshots.py` | `ARC-CMP-005` | `REQ-LST-006`, `REQ-ADM-006`, `REQ-AUT-004`, `PROC-TST-002` | Snapshot rendering must distinguish passive listeners from active connections, keep passive listener rows zeroed, expose per-peer session stats on active listener-side peers correctly, and preserve secure-link-wrapped `myudp` peer counters in `/api/peers` | `pytest -q tests/unit/test_connection_snapshots.py` |
| `tests/unit/test_admin_web_payloads.py` | `ARC-CMP-005` | `REQ-WSP-012`, `REQ-AUT-004`, `REQ-AUT-009`, `REQ-AUT-010`, `REQ-AUT-014`, `REQ-AUT-016`, `REQ-AUT-019`, `PROC-TST-002` | Admin payload builders must keep transport-level connection failure visibility intact, keep peer-scoped secure-link visibility fields intact, keep `/api/status` limited to aggregate runtime summary, and preserve Phase 2/3 certificate identity, reload-result, and disconnect-enforcement fields so WebAdmin can render peer-scoped security state and operator controls consistently | `pytest -q tests/unit/test_admin_web_payloads.py` |
| `tests/unit/test_secure_link_cert.py` | `ARC-CMP-006` | `REQ-AUT-011`, `REQ-AUT-012`, `REQ-AUT-013`, `REQ-AUT-014`, `REQ-AUT-015`, `REQ-AUT-016`, `REQ-AUT-017`, `REQ-AUT-018`, `PROC-TST-002` | Certificate-mode secure-link loading, trust validation, role/validity/deployment/revocation rejection, peer identity diagnostics, live revocation reload, atomic local-identity reload, and shared rekey/session behavior must remain internally consistent at the secure-link layer boundary | `pytest -q tests/unit/test_secure_link_cert.py` |
| `tests/unit/test_secure_link_psk.py` | `ARC-CMP-006` | `REQ-AUT-001`, `REQ-AUT-002`, `REQ-AUT-003`, `REQ-AUT-006`, `REQ-AUT-007`, `REQ-AUT-008`, `REQ-AUT-009`, `REQ-AUT-010`, `PROC-TST-002` | PSK handshake, wrong-secret rejection, bounded retry backoff, stronger operational diagnostics, malformed/out-of-order fail-closed behavior, per-peer routing, frame/time/operator rekey rotation, and nonce/counter lifecycle guards must remain internally consistent at the secure-link layer boundary | `pytest -q tests/unit/test_secure_link_psk.py` |
| `tests/unit/test_debug_logging_aliases.py` | `ARC-CMP-005` | `PROC-TST-002` | Logging alias configuration must reach the intended websocket-related loggers, and the secure-link logger must stay quiet at `WARNING` by default unless the operator explicitly raises it | `pytest -q tests/unit/test_debug_logging_aliases.py` |
| `tests/unit/test_peer_resolution.py` | `ARC-CMP-004` | `REQ-OVL-007`, `PROC-TST-002` | Localhost resolution fallback must behave deterministically while non-localhost failures still propagate | `pytest -q tests/unit/test_peer_resolution.py` |
| `tests/unit/test_runner_config_persistence.py` | `ARC-CMP-004` | `PROC-TST-002` | Runtime config updates must persist back to the configured file correctly | `pytest -q tests/unit/test_runner_config_persistence.py` |
| `tests/unit/test_runner_events.py` | `ARC-CMP-004` | `PROC-TST-002` | Restart and shutdown events must bind to the active event loop correctly | `pytest -q tests/unit/test_runner_events.py` |
| `tests/unit/test_runner_overlay_transports.py` | `ARC-CMP-004`, `ARC-CMP-001` | `REQ-OVL-003`, `REQ-OVL-004`, `REQ-OVL-005`, `REQ-AUT-011`, `REQ-AUT-015`, `REQ-AUT-017`, `REQ-AUT-019`, `PROC-TST-002` | Overlay transport parsing, secure-link wrapping, startup validation, and peer-targeted operator control routing must remain consistent with supported transport and cert-mode runtime rules | `pytest -q tests/unit/test_runner_overlay_transports.py` |
| `tests/unit/test_ws_multi_peer.py` | `ARC-CMP-001`, `ARC-CMP-003` | `REQ-LST-001`, `REQ-MUX-001`, `REQ-MUX-003`, `PROC-TST-002` | WS multi-peer mux rewriting and outbound routing must remain peer-safe and channel-safe | `pytest -q tests/unit/test_ws_multi_peer.py` |
| `tests/unit/test_ws_payload_mode.py` | `ARC-CMP-001`, `ARC-CMP-005` | `REQ-OVL-004`, `REQ-WSP-010`, `REQ-WSP-011`, `REQ-WSP-012`, `REQ-LIFE-002`, `PROC-TST-002` | WS payload encoding, including the grouped `semi-text-shape` transfer form, tx timing, reconnect grace, direct-path HTTP preflight body download and refusal behavior, user-visible bootstrap/open failure reporting, platform-default proxy resolution, compression config, and debug static HTTP behavior must stay internally consistent | `pytest -q tests/unit/test_ws_payload_mode.py` |

### Unit test catalog

| File | Scope | Objective | How to start |
|---|---|---|---|
| `tests/unit/test_channel_mux_listener_mode.py` | ChannelMux listener semantics | Verify listener mode ignores ambiguous local config, parses service specs correctly, and manages remote catalogs/lifecycle correctly | `pytest -q tests/unit/test_channel_mux_listener_mode.py` |
| `tests/unit/test_channel_mux_peer_catalog.py` | Per-peer remote service state | Verify peer-specific listener state is scoped and cleaned up per peer | `pytest -q tests/unit/test_channel_mux_peer_catalog.py` |
| `tests/unit/test_connection_snapshots.py` | Admin snapshot formatting | Verify connection and peer snapshot rendering, including listener rows, active-vs-idle distinctions, connection uptime, correct per-peer listener-side myudp counters, and correct counter preservation through secure-link wrappers | `pytest -q tests/unit/test_connection_snapshots.py` |
| `tests/unit/test_admin_web_payloads.py` | Admin payload shaping | Verify `/api/peers` keeps peer-scoped secure-link visibility, identity, reload, and disconnect fields intact, while `/api/config` hides the PSK secret and marks it read-only and `/api/status` remains limited to aggregate runtime summary fields for WebAdmin/API consumers | `pytest -q tests/unit/test_admin_web_payloads.py` |
| `tests/unit/test_debug_logging_aliases.py` | Logging alias wiring | Verify websocket logging aliases configure the intended library loggers | `pytest -q tests/unit/test_debug_logging_aliases.py` |
| `tests/unit/test_peer_resolution.py` | Host resolution behavior | Verify localhost fallback and non-localhost resolution error behavior | `pytest -q tests/unit/test_peer_resolution.py` |
| `tests/unit/test_runner_config_persistence.py` | Config update persistence | Verify config updates are written back to the configured file correctly | `pytest -q tests/unit/test_runner_config_persistence.py` |
| `tests/unit/test_runner_events.py` | Runner event binding | Verify restart and shutdown events bind to the running loop correctly | `pytest -q tests/unit/test_runner_events.py` |
| `tests/unit/test_runner_overlay_transports.py` | Overlay transport parsing/building | Verify transport list parsing, secure-link wrapping, startup material validation, and peer-targeted secure-link operator control routing | `pytest -q tests/unit/test_runner_overlay_transports.py` |
| `tests/unit/test_secure_link_cert.py` | Secure-link certificate mode | Verify certificate material loading, trust validation, role/validity/deployment/revocation rejection, live reload/apply behavior, and cert-mode rekey behavior | `pytest -q tests/unit/test_secure_link_cert.py` |
| `tests/unit/test_ws_multi_peer.py` | WebSocket multi-peer mux logic | Verify inbound and outbound mux rewriting and peer-specific send routing | `pytest -q tests/unit/test_ws_multi_peer.py` |
| `tests/unit/test_ws_payload_mode.py` | WebSocket framing/runtime behavior | Verify payload encoding modes, including grouped `semi-text-shape`, tx loop behavior, socket config, reconnect grace, HTTP preflight, platform-default proxy handling (`system` on Windows and `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` on Linux/POSIX), compression, and debug static HTTP behavior | `pytest -q tests/unit/test_ws_payload_mode.py` |

### Run the full unit suite

```bash
pytest -q tests/unit
```
