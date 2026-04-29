# ObstacleBridge iOS Prototype

This directory contains the BeeWare companion app prototype and native iOS packet tunnel POC sources.

Current scope:

- briefcase-ready project metadata for an iOS app container
- shared ObstacleBridge import/preview logic wired into iOS-side helpers
- profile persistence that keeps plaintext secrets out of normal profile files
- focused tests for invite/config import preview and profile secret redaction
- M2 dependency spike harness for `websockets`, `cryptography`, `aioquic`, and asyncio TCP/UDP loopback checks
- M2.5 minimal two-tab UI (`Configuration` + `Status`) for setup and reachability checks
- M3 packet tunnel provider configuration helpers and native `NEPacketTunnelProvider` POC source
- native iOS crypto bridging for the subset of `cryptography` primitives ObstacleBridge actually uses
- packaged WebAdmin assets plus in-app and simulator-hosted WebAdmin validation paths
- standalone iOS E2E probe application used by simulator/device integration tests, kept outside the ObstacleBridge app bundle

Current iOS testing statistics:

- `38` tests in `ios/tests/`
- `7` iOS-focused integration tests across `tests/integration/test_ios_e2e.py` and `tests/integration/test_ios_simulator_e2e.py`

## Local developer checks

From repository root:

```bash
pytest -q ios/tests/test_invite_import.py ios/tests/test_ios_profile_config.py ios/tests/test_ios_app_facade.py
```

```bash
pytest -q ios/tests/test_dependency_spike.py ios/tests/test_m25_ui.py
```

```bash
pytest -q ios/tests/test_m3_tunnel.py ios/tests/test_m3_native_sources.py
```

```bash
pytest -q ios/tests/test_native_crypto.py ios/tests/test_ios_e2e_app_runner.py
```

```bash
pytest -q tests/integration/test_ios_e2e.py
```

## Briefcase bootstrap

From `ios/`:

```bash
python -m pip install briefcase
briefcase create iOS
briefcase build iOS
```

The app module is `obstacle_bridge_ios.app:main`.

The E2E probe module is a separate Briefcase app target, `obstacle_bridge_ios_e2e`. It is intentionally outside the companion app source tree so test-only probes do not become hidden behavior in the ObstacleBridge iOS application.

The E2E app can now be used in three modes:

- `--host-websocket-probe` for basic simulator-to-host reachability
- `--ws-udp-echo-probe` and `--ws-secure-link-probe` for overlay and SecureLink transport checks
- `--runtime-config <json>` for booting a packaged runtime from JSON config and keeping it alive for host-side inspection such as WebAdmin checks

Build or run the E2E app target explicitly when working on simulator/device integration tests:

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro" -- --host-websocket-probe ws://127.0.0.1:<port>/obstaclebridge-ios-e2e
```

## M2 dependency spike run

Run on simulator:

```bash
briefcase run iOS -u --no-input -d "iPhone 17 Pro" -- --m2-dependency-spike
```

Then retrieve the generated JSON report from the iOS app container:

```bash
APP_DATA_DIR="$(xcrun simctl get_app_container booted com.obstaclebridge.obstacle-bridge-ios data)"
cat "${APP_DATA_DIR}/Documents/ObstacleBridge/m2-dependency-spike-latest.json"
```

Run on a physical iOS device by replacing `-d` with the connected device UDID or name.

## M2.5 UI behavior

- `Configuration` tab: builds and saves a profile with overlay peer settings and localhost TCP/UDP exposure intent.
- `Status` tab: runs a TCP reachability check to the configured peer endpoint and shows pass/fail + latency.
- System-wide traffic usage from other apps (for example Safari) is a Network Extension packet-tunnel concern and belongs to M3.

## M3 packet tunnel POC

Source of truth:

- `ios/src/obstacle_bridge_ios/m3_tunnel.py` builds the `NETunnelProviderProtocol.providerConfiguration` payload from an existing iOS profile.
- `ios/native/ObstacleBridgeTunnel/PacketTunnelProvider.swift` starts/stops the native packet tunnel extension and applies `NEPacketTunnelNetworkSettings`.
- `ios/native/ObstacleBridgeTunnel/ObstacleBridgeExtensionRuntime.swift` is the extension-owned runtime boundary for the network stack. The provider configuration now carries the full `obstacle_bridge_config` and declares WebAdmin, ChannelMux, compression, SecureLink, overlay transports, and packet I/O as packet-tunnel-extension layers.
- `ios/native/ObstacleBridgeTunnel/PacketFlowBridge.swift` reads packets from `NEPacketTunnelFlow`, sends them to one TCP peer as length-prefixed packet frames, receives frames, and writes packets back to `NEPacketTunnelFlow`.
- `ios/native/ObstacleBridgeTunnel/TunnelStatus.swift` defines the app-message status/counter response.

The M3 bridge now treats the packet tunnel extension as the owner of the network runtime. The current native source still needs the production runtime implementation behind `ObstacleBridgeExtensionRuntime` plus entitlement/device validation before it can replace the foreground BeeWare runtime on physical iPhone.

The native files are not generated Briefcase output. Add them to an Xcode packet tunnel extension target with the bundle identifier used when calling `build_m3_vpn_profile(...)`, then install through `NETunnelProviderManager`.

## iOS simulator to macOS host connection test

The opt-in simulator integration test starts a WebSocket echo server on the macOS host, launches the standalone iOS E2E app in the simulator, and runs the headless app probe:

```bash
OBSTACLEBRIDGE_RUN_IOS_SIMULATOR=1 pytest -q tests/integration/test_ios_simulator_e2e.py -m ios_simulator
```

Useful overrides:

- `OBSTACLEBRIDGE_IOS_SIMULATOR_DEVICE="iPhone 17 Pro"` chooses the simulator device passed to Briefcase.
- `OBSTACLEBRIDGE_IOS_SIMULATOR_TIMEOUT=600` controls the Briefcase launch timeout.
- `BRIEFCASE=/path/to/briefcase` chooses the Briefcase executable when it is not on `PATH`.

The E2E app entrypoint used by this test is:

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro" -- --host-websocket-probe ws://127.0.0.1:<port>/obstaclebridge-ios-e2e
```

The simulator lane also includes a WS overlay plus UDP service probe. Pytest starts a host-side ObstacleBridge WS listener and UDP echo target, then launches the standalone E2E app so it can bind a local UDP port, stimulate that port, and verify the UDP response that crossed the WS overlay:

```bash
OBSTACLEBRIDGE_RUN_IOS_SIMULATOR=1 pytest -q tests/integration/test_ios_simulator_e2e.py -m ios_simulator
```

The same simulator lane now also includes a WS SecureLink probe plus a packaged-runtime path that lets the iOS runtime expose WebAdmin locally and publish it back to the macOS host through `remote_servers`.

Equivalent E2E app command shape:

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro" -- --ws-udp-echo-probe ws://127.0.0.1:<ws-port>/obstaclebridge-ios-e2e --local-udp-port 18081 --target-udp-host 127.0.0.1 --target-udp-port <udp-echo-port> --payload-hex 01696f732d73696d756c61746f722d77732d756470 --expected-hex 02696f732d73696d756c61746f722d77732d756470
```

Equivalent SecureLink E2E app command shape:

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro" -- --ws-secure-link-probe ws://127.0.0.1:<ws-port>/obstaclebridge-ios-e2e --secure-link-psk <shared-psk>
```

Equivalent runtime-config command shape:

```bash
briefcase run iOS -a obstacle_bridge_ios_e2e -u --no-input -d "iPhone 17 Pro" -- --runtime-config /absolute/path/to/runtime.json --hold-sec 900
```
