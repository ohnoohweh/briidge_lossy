# ObstacleBridge iOS Prototype (M1)

This directory contains the milestone-1 BeeWare companion-app prototype.

Current scope:

- briefcase-ready project metadata for an iOS app container
- shared ObstacleBridge import/preview logic wired into iOS-side helpers
- profile persistence that keeps plaintext secrets out of normal profile files
- focused tests for invite/config import preview and profile secret redaction
- M2 dependency spike harness for `websockets`, `cryptography`, `aioquic`, and asyncio TCP/UDP loopback checks
- M2.5 minimal two-tab UI (`Configuration` + `Status`) for setup and reachability checks

## Local developer checks

From repository root:

```bash
pytest -q ios/tests/test_invite_import.py ios/tests/test_ios_profile_config.py ios/tests/test_ios_app_facade.py
```

```bash
pytest -q ios/tests/test_dependency_spike.py ios/tests/test_m25_ui.py
```

## Briefcase bootstrap

From `ios/`:

```bash
python -m pip install briefcase
briefcase create iOS
briefcase build iOS
```

The app module is `obstacle_bridge_ios.app:main`.

## M2 dependency spike run

Run on simulator:

```bash
briefcase run iOS -u --no-input -d "iPhone 17 Pro" -- --m2-dependency-spike
```

Then retrieve the generated JSON report from the iOS app container:

```bash
APP_DATA_DIR="$(xcrun simctl get_app_container booted com.obstaclebridge.obstacle-bridge-ios data)"
cat "${APP_DATA_DIR}/Documents/.obstaclebridge-ios/m2-dependency-spike-latest.json" || \
cat "${APP_DATA_DIR}/.obstaclebridge-ios/m2-dependency-spike-latest.json"
```

Run on a physical iOS device by replacing `-d` with the connected device UDID or name.

## M2.5 UI behavior

- `Configuration` tab: builds and saves a profile with overlay peer settings and localhost TCP/UDP exposure intent.
- `Status` tab: runs a TCP reachability check to the configured peer endpoint and shows pass/fail + latency.
- System-wide traffic usage from other apps (for example Safari) is a Network Extension packet-tunnel concern and belongs to M3.
