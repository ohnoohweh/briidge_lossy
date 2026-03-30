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

- `test_overlay_e2e.py`: single-pass smoke checks across all configured transports and address-family combinations.
- `test_overlay_e2e_reconnect.py`: smoke + reconnect/state-transition regression flows (and one dedicated two-client WS listener scenario).

Both scripts are **standalone Python runners** (not pytest functions). They start a local bounce-back server, launch one or more `ObstacleBridge.py` processes, wait for tunnel readiness, then probe through the overlay and fail with process/log dumps if a step breaks.

---

## 1) `test_overlay_e2e.py`

### Start the suite

Run all default cases:

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

### Implemented tests

Default case set (`DEFAULT_CASES`) currently includes 11 smoke scenarios:

1. `case01_udp_over_own_udp_ipv4`
2. `case02_udp_over_own_udp_overlay_ipv6_clients_ipv4`
3. `case03_udp_over_own_udp_overlay_ipv6_clients_ipv6`
4. `case04_tcp_over_own_udp_clients_ipv4`
5. `case05_tcp_over_own_udp_clients_ipv6`
6. `case06_overlay_tcp_ipv4`
7. `case07_overlay_tcp_ipv6`
8. `case08_overlay_ws_ipv4`
9. `case09_overlay_ws_ipv6`
10. `case10_overlay_quic_ipv4`
11. `case11_overlay_quic_ipv6`

Each case validates that a probe payload (`0x01 0x30`) traverses the configured bridge path and returns the expected transformed payload (`0x02 0x30`) from the bounce service.

---

## 2) `test_overlay_e2e_reconnect.py`

### Start the suite

Run default smoke mode (all reconnect-harness cases):

```bash
python tests/integration/test_overlay_e2e_reconnect.py
```

Run reconnect regression mode:

```bash
python tests/integration/test_overlay_e2e_reconnect.py --reconnect
```

Run only one case in reconnect mode with custom transition timeout:

```bash
python tests/integration/test_overlay_e2e_reconnect.py \
  --cases case08_overlay_ws_ipv4 \
  --reconnect \
  --reconnect-timeout 45
```

List cases:

```bash
python tests/integration/test_overlay_e2e_reconnect.py --list-cases
```

### Options

- `--cases <case...>`: run only selected case names (default: all).
- `--list-cases`: print supported names and exit.
- `--log-dir <dir>`: output directory for child-process logs.
- `--settle-seconds <float>`: override case startup delay.
- `--require-aioquic`: fail fast if `aioquic` is unavailable.
- `--reconnect`: switch from smoke probe mode to reconnect transition mode.
- `--reconnect-timeout <float>`: timeout used for connected/disconnected admin-state waits.

### Implemented tests

Default case set currently includes base transport checks plus localhost-resolution variants:

- Base IPv4 cases:
  - `case01_udp_over_own_udp_ipv4`
  - `case06_overlay_tcp_ipv4`
  - `case08_overlay_ws_ipv4`
  - `case10_overlay_quic_ipv4`
  - `case12_overlay_ws_ipv4_listener_two_clients`
- Localhost + resolve-family variants for UDP/TCP/WS/QUIC:
  - `*_localhost_ipv4`
  - `*_localhost_ipv6`

Behavior by mode:

- **Smoke mode (default)**
  - Runs single pass probe validation for each case.
  - For `case12_overlay_ws_ipv4_listener_two_clients`, runs the dedicated two-client listener flow and verifies both clients can independently traverse the same WS listener.

- **Reconnect mode (`--reconnect`)**
  - Runs a staged restart/disconnect/reconnect workflow with admin API checks:
    1. Verify initial connectivity.
    2. Restart server and wait for connected state recovery.
    3. Stop server and verify disconnection + probe failure.
    4. Restart server and verify recovery.
    5. Stop client and verify disconnection + probe failure.
    6. Restart client and verify recovery.

These checks ensure overlay transport resiliency and control-plane state tracking (connected/not connected) for restart events.
