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

- if only concurrent TCP case(s) are selected (currently `case13_*`), the concurrent runner is used,
- if selected cases are reconnect-only localhost variants, reconnect runner is used,
- otherwise the basic suite path is used.

## Overlay E2E catalog

The overlay harness currently covers 15 documented test targets:

- 14 named transport/topology cases in `CASES`
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
