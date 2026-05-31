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

## macOS Packet Tunnel extension architecture

This repo now has the shared packet-tunnel configuration building blocks needed for a native macOS packet-tunnel target, but it does not yet ship a dedicated macOS `NEPacketTunnelProvider` app-extension target in the checked-in Xcode surfaces.

Current status:

- available today: the macOS host runner in [ios/native/ObstacleBridgeMacRunner/ObstacleBridgeMacHostRunner.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeMacRunner/ObstacleBridgeMacHostRunner.swift)
- available today: the shared packet-tunnel network-settings helper in [ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift)
- available today: reference packet-tunnel providers in [ios/native/IPServer/PacketTunnelProvider.swift](/Users/ohnoohweh/briidge_lossy/ios/native/IPServer/PacketTunnelProvider.swift) and [ios/native/ObstacleBridgeTunnel/PacketTunnelProvider.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeTunnel/PacketTunnelProvider.swift)
- not checked in yet: a macOS containing app plus macOS packet-tunnel extension bundle wired for signing, installation, and `NETunnelProviderManager` lifecycle on macOS

The practical consequence is that macOS packet-tunnel work should currently be understood as an architecture and integration path, not as a finished one-command installer like the host runner.

## What gets installed

The target macOS packet-tunnel product should be split into two signed components:

- a containing macOS app that owns onboarding, config import, profile installation, start and stop controls, and diagnostics
- a packet-tunnel app extension that owns `NEPacketTunnelProvider.startTunnel`, `NEPacketTunnelNetworkSettings`, packet I/O, and the long-lived traffic runtime

The containing app should install and control the tunnel through `NETunnelProviderManager`, matching the same architectural separation already used on iOS.

Shared runtime responsibilities are already factored so the macOS packet-tunnel target can reuse them:

- grouped and flat `ObstacleBridge.cfg` parsing from [ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeShared/ObstacleBridgeRuntimeConfig.swift)
- packet-tunnel route, address, DNS, and MTU derivation from [ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift)
- overlay bootstrap planning, SecureLink, compression, and transport helpers from the `ios/native/ObstacleBridgeShared/` sources

## Install requirements

To install a real macOS packet-tunnel build, you will need all of the following locally:

- macOS with Xcode and command line tools installed
- an Apple Developer account and signing team that can sign Network Extension packet-tunnel targets
- a containing macOS app target and a packet-tunnel extension target signed with the same team
- matching App Group entitlements so the app and extension can share `ObstacleBridge.cfg`, logs, and runtime snapshots
- the `com.apple.developer.networking.networkextension` entitlement for packet-tunnel use

The repo already contains the extension-side Swift reference code, but the signed macOS app-extension packaging layer still needs to be created in Xcode.

## Install flow

When the macOS packet-tunnel target is packaged, the install flow should look like this:

1. Build the containing macOS app and packet-tunnel extension with the same signing team and App Group.
2. Copy or archive the app into `/Applications` like a normal signed macOS app.
3. Launch the containing app once so it can create or refresh the shared App Group config and register the `NETunnelProviderManager` profile.
4. Approve the VPN or Network Extension prompt from macOS when the app saves the tunnel profile.
5. Start the tunnel from the containing app or from System Settings after the profile is registered.

The repo does not yet automate those steps for macOS, so today the closest executable surface is still the standalone host runner documented above.

## Use flow

The intended runtime flow for the macOS packet-tunnel architecture is:

1. The containing app writes or syncs `ObstacleBridge.cfg` into the shared App Group container.
2. The containing app creates a minimal `NETunnelProviderProtocol` profile and starts the tunnel through `NETunnelProviderManager`.
3. The macOS packet-tunnel extension reads `providerConfiguration` plus the shared App Group config.
4. The extension resolves effective tunnel settings through [ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift](/Users/ohnoohweh/briidge_lossy/ios/native/ObstacleBridgeShared/ObstacleBridgePacketTunnelConfiguration.swift) with this precedence:
  `providerConfiguration.network_settings` -> `runtime_config.TUN_routing` -> built-in defaults.
5. The extension applies `NEPacketTunnelNetworkSettings`, starts the packet I/O bridge, and boots the shared ObstacleBridge runtime layers.
6. The containing app reads status, peer, connection, and resolved tunnel-setting snapshots back through app-to-extension messaging and App Group files.

That resolved network payload now includes the effective tunnel addresses, routes, DNS servers, and MTU under `effective_tunnel_network_settings` in the richer packet-tunnel provider snapshot path.

## Config behavior

For the packet-tunnel architecture, route and address setup should come from the same config model already used by the shared helper:

- `providerConfiguration.network_settings` is the highest-priority explicit tunnel configuration
- `runtime_config.TUN_routing` is the fallback source for tunnel addresses, prefixes, included routes, excluded routes, DNS servers, and MTU
- built-in defaults are used only when neither of the above supplies a value

This means a macOS packet-tunnel target can use the same `ObstacleBridge.cfg` shape already used by iOS and the host-runner tests, including grouped JSON with `TUN_routing` and `iOS_TUN_connector` style sections.

## What to use today

Until the dedicated macOS packet-tunnel app-extension target is added, use the repo in two stages:

1. Use the host runner for end-to-end runtime validation, Admin Web inspection, and overlay behavior checks.
2. Use the shared packet-tunnel helper and the existing packet-tunnel providers as the source of truth for how the future macOS extension should derive and publish tunnel network settings.

In practice that means:

- compile and run the host runner with `./ios/scripts/build_macos_app.sh` and `./ios/scripts/run_macos_app.sh`
- keep `ObstacleBridge.cfg` authoritative for grouped runtime settings
- treat the packet-tunnel providers and shared helper as the install and lifecycle blueprint for the future macOS extension bundle

## Validation while the macOS extension target is not yet packaged

Use these checks while iterating on the architecture:

```bash
./.venv/bin/pytest ios/tests/test_ios_packet_tunnel_provider_probe.py -q
./.venv/bin/pytest ios/tests/test_m3_native_sources.py -q -k 'packet_tunnel or shared_packet_tunnel_configuration'
./.venv/bin/pytest ios/tests/test_macos_swift_host_runner.py -q
```

These do not install a macOS packet-tunnel extension, but they validate the shared route and address derivation, the packet-tunnel provider compile surface, and the current macOS Swift runtime owner that the future extension will reuse.