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

### Implemented tests

`DEFAULT_CASES` is now unified and currently includes 20 cases: the original 11 smoke cases, reconnect-focused localhost variants (`*_localhost_ipv4` / `*_localhost_ipv6`), and `case12_overlay_ws_ipv4_listener_two_clients`.

Use `--list-cases` to print the exact active set from the harness.

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

Behavior:

- Runs a staged restart/disconnect/reconnect workflow with admin API checks:
  1. Verify initial connectivity.
  2. Restart server and wait for connected state recovery.
  3. Stop server and verify disconnection + probe failure.
  4. Restart server and verify recovery.
  5. Stop client and verify disconnection + probe failure.
  6. Restart client and verify recovery.

These checks ensure overlay transport resiliency and control-plane state tracking (connected/not connected) for restart events.
