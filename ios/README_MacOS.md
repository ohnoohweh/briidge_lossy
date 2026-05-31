# ObstacleBridge macOS Swift Host Runner

This document covers the current macOS Swift port that lives next to the iOS work in this directory.

## Scope of the macOS port

Goal and current scope:

- macOS executable fully based on Swift, so integration work can iterate at runtime level without a Python seam in data or control flow
- complete hot path implemented end to end in Swift
- Admin Web can be opened from Safari and observed live against the Swift runtime
- myUDP overlay path works with SecureLink and Compression on the Swift side
- mixed and multiple TCP and UDP `own_servers` are working
- `remote_servers` can be used
- TUN device support and routing support are in scope
- Admin Web config display, config change, config save, restart, and statistics are in scope
- connection statistics are working, including live `/api/connections`, `/api/peers`, and `/api/meta` data from the Swift runtime

The current macOS runtime owner is implemented in [ios/native/ObstacleBridgeMacRunner/ObstacleBridgeMacHostRunner.swift](ios/native/ObstacleBridgeMacRunner/ObstacleBridgeMacHostRunner.swift).

## Prerequisites

- macOS with Xcode command line tools installed
- `swiftc` available on `PATH`
- Python test environment available if you want to run the repo pytest slices

Check the compiler:

```bash
xcrun --find swiftc
swiftc --version
```

## Compile

From repository root:

```bash
./ios/scripts/build_macos_app.sh
```

This script uses the same compile surface used by the focused macOS host-runner tests in [ios/tests/test_macos_swift_host_runner.py](ios/tests/test_macos_swift_host_runner.py), refreshes the shared build timestamp metadata before compiling, and writes a sidecar with the same `build` fields used by the iOS and Python admin payloads.

Build outputs:

- binary: `ios/build/macos/ObstacleBridgeMacHostRunner`
- sidecar build identification: `ios/build/macos/ObstacleBridgeMacHostRunner.build-info.json`

The sidecar file contains the build timestamp, commit, dirty state, and diff hash so locally built macOS artifacts can be identified as easily as the iOS app builds.

## Runtime config

The runner accepts `--runtime-config`, but if you omit it the executable defaults to `ObstacleBridge.cfg` in the current working directory.

CLI usage:

```bash
ios/build/macos/ObstacleBridgeMacHostRunner \
  [--runtime-config <path>] \
  [--bind-host <host>] \
  [--status-port <port>] \
  [--hold-sec <seconds>]
```

Notes:

- grouped and flat config shapes are accepted through the shared runtime-config parser
- when `--runtime-config` is omitted, `ObstacleBridge.cfg` is loaded from the shell's current working directory
- if `admin_web_dir` is not set, the runner first looks for `admin_web` under the config root and then falls back to `./admin_web`
- the static Admin Web assets used by the runner come from the repo `admin_web/` directory unless overridden
- the Admin Web config view exposes a `channel_mux` section in the Swift runner schema with the essential `own_servers` and `remote_servers` catalogs
- the Admin Web config view also exposes a `runner` section, including `overlay_transport`, `client_restart_if_disconnected`, and `overlay_reconnect_retry_delay_ms`
- the Admin Web config view now also exposes `udp_session` and `tcp_session` sections with the expected overlay endpoint knobs such as bind, own-port, peer, and peer-port
- for TCP client overlays, `overlay_reconnect_retry_delay_ms` controls reconnect retry cadence and `client_restart_if_disconnected` triggers a local runner restart cycle after the configured disconnected interval
- set both `admin_web_username` and `admin_web_password` to enable the same challenge-based Admin Web login flow used by the Python implementation
- when the Swift runner persists config changes, secret fields such as `secure_link_psk` and `admin_web_password` are written back using the same Python-compatible `enc:v1:` encrypted-at-rest envelope instead of plaintext JSON
- the macOS runner now exposes the same `admin_web_*` config keys as Python for UI behavior and control gating, including `admin_web_first_tab`, `admin_web_security_advisor_disable`, `admin_web_security_advisor_startup_disable`, `admin_web_landing_page_disable`, and `admin_web_token`
- when `admin_web_token` is set, `POST /api/restart`, `POST /api/reconnect`, and `POST /api/shutdown` require `Authorization: Bearer <token>` like the Python implementation

Checked-in example:

[/Users/ohnoohweh/briidge_lossy/ios/examples/macos_runtime.json](/Users/ohnoohweh/briidge_lossy/ios/examples/macos_runtime.json)

Contents:

```json
{
  "admin_web": {
    "admin_web": true,
    "admin_web_bind": "127.0.0.1",
    "admin_web_port": 18080,
    "admin_web_dir": "admin_web",
    "admin_web_path": "/",
    "admin_web_name": "macOS Swift"
  },
  "overlay_transport": "myudp",
  "udp_peer": "127.0.0.1",
  "udp_peer_port": 19001,
  "secure_link": true,
  "secure_link_mode": "psk",
  "secure_link_psk": "test-shared-secret",
  "compress_layer": true,
  "compress_layer_algo": "zlib",
  "own_servers": [
    {
      "listen": {
        "protocol": "tcp",
        "bind": "127.0.0.1",
        "port": 18010
      },
      "target": {
        "protocol": "tcp",
        "host": "127.0.0.1",
        "port": 8010
      },
      "name": "example tcp own_server"
    },
    {
      "listen": {
        "protocol": "udp",
        "bind": "127.0.0.1",
        "port": 18011
      },
      "target": {
        "protocol": "udp",
        "host": "127.0.0.1",
        "port": 8011
      },
      "name": "example udp own_server"
    }
  ]
}
```

## Start

From repository root:

```bash
./ios/scripts/run_macos_app.sh
```

If the runner starts successfully it keeps serving until stopped.

The wrapper script stages a temporary macOS home under `/tmp`, points the iOS-style documents root at that temp area, and removes it automatically on exit so repo-local folders such as `.tmp-home` do not accumulate.

Useful toggles:

- `KEEP_TEMP_HOME=1 ./ios/scripts/run_macos_app.sh` keeps the generated temp home for inspection
- `OBSTACLEBRIDGE_TMP_HOME=/tmp/my-obstaclebridge-home ./ios/scripts/run_macos_app.sh` reuses a specific temp location
- `./ios/scripts/run_macos_app.sh --runtime-config ios/examples/macos_runtime.json --status-port 18081 --hold-sec 30` forwards custom runner arguments unchanged

Open Admin Web in Safari:

```bash
open http://127.0.0.1:18080/
```

Useful API checks:

```bash
curl http://127.0.0.1:18080/api/status
curl http://127.0.0.1:18080/api/meta
curl http://127.0.0.1:18080/api/connections
curl http://127.0.0.1:18080/api/peers
```

Useful finite run for scripting:

```bash
ios/build/macos/ObstacleBridgeMacHostRunner \
  --runtime-config ios/examples/macos_runtime.json \
  --status-port 18080 \
  --hold-sec 30
```

## Test

Focused macOS Swift host-runner checks:

```bash
pytest -q ios/tests/test_macos_swift_host_runner.py
```

If you want a smaller slice while iterating, run selected tests from that file. It covers:

- Admin Web startup and static asset serving
- `/api/status`, `/api/meta`, `/api/connections`, `/api/peers`, `/api/config`, `/api/logs`
- restart, reconnect, and shutdown control actions
- side-by-side parity checks against Python `AdminWebUI` for `admin_ui`, `security_advisor`, and token-gated control actions
- own-server TCP and UDP proxying
- wrapped overlay paths with compression and SecureLink
- live connection and peer statistics

## What is Swift-owned on macOS

On the current macOS host runner, the following are Swift-owned in the hot path:

- overlay transport runtime
- SecureLink wrapper
- compression wrapper
- TCP and UDP own-server runtime ownership
- Admin Web HTTP and websocket server transport
- Admin API route handling
- live connection and peer statistics exposed to Admin Web

That makes macOS the current repo surface for validating the Swift runtime end to end with Safari and focused integration tests.