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
- reusable iOS probe helpers under `ios/e2e_app/src/obstacle_bridge_ios_e2e` used by host-side integration tests without a separate app target

Current iOS testing statistics:

- `38` tests in `ios/tests/`
- `7` iOS-focused integration tests across `tests/integration/test_ios_e2e.py` and `tests/integration/test_ios_simulator_e2e.py`

## Local developer checks

From repository root:

```bash
./ios/scripts/run_ios_pytest.sh -q ios/tests/test_invite_import.py ios/tests/test_ios_profile_config.py ios/tests/test_ios_app_facade.py
```

```bash
./ios/scripts/run_ios_pytest.sh -q ios/tests/test_dependency_spike.py ios/tests/test_m25_ui.py
```

```bash
./ios/scripts/run_ios_pytest.sh -q ios/tests/test_m3_tunnel.py ios/tests/test_m3_native_sources.py
```

```bash
./ios/scripts/run_ios_pytest.sh -q tests/integration/test_ios_e2e.py
```

```bash
./ios/scripts/run_ios_pytest.sh -q ios/tests/test_native_crypto.py ios/tests/test_ios_e2e_app_runner.py
```

`run_ios_pytest.sh` stages `OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT` under `/tmp` by default and removes it on exit, so repo-local temp folders such as `.tmp-ios-docs` do not accumulate while iterating.

Useful toggles:

- `KEEP_TEMP_DOCS_ROOT=1 ./ios/scripts/run_ios_pytest.sh ...` keeps the generated temp documents root for inspection
- `OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT=/tmp/my-ios-docs ./ios/scripts/run_ios_pytest.sh ...` reuses a specific temp location

## Briefcase bootstrap

From `ios/`:

```bash
python -m pip install briefcase
briefcase create iOS
briefcase build iOS
```

The app module is `obstacle_bridge_ios.app:main`.

Custom iOS app artwork lives under `ios/resources/`. The Briefcase app config points
`icon` at `resources/obstaclebridge-icon`, so rerunning `briefcase create iOS` or
`briefcase update iOS` will regenerate the Xcode asset catalog from those repo-owned
PNG sizes instead of using the default BeeWare artwork.

The reusable probe helpers remain under `ios/e2e_app/src/obstacle_bridge_ios_e2e` for host-side/unit integration coverage, but there is no separate Briefcase-managed iOS E2E application target anymore.

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
- `ios/native/IPServer/PacketTunnelProvider.swift` is the packet-tunnel extension entrypoint and applies `NEPacketTunnelNetworkSettings` before booting the shared Python runtime.
- `ios/native/IPServer/ObstacleBridgePythonBridge.m` bootstraps the packaged Python runtime inside the extension so WebAdmin, ChannelMux, and the lower Python layers can execute in the packet-tunnel process.

The M3 bridge is intentionally a POC transport (`tcp-length-prefixed-packets`) so packet-flow behavior can be validated before M4 secure-link parity. Production secure-link, DNS/route hardening, and App Store entitlement/distribution validation remain M4+ work.

The native files are not generated Briefcase output. The repo-owned Xcode patcher now injects the `IPServer` packet-tunnel target after `briefcase create iOS`, and the app can then install it through `NETunnelProviderManager`.

## iOS simulator to macOS host connection test

The opt-in simulator integration test documentation below describes the legacy standalone E2E app lane. That app target has been removed; the remaining host-side probe helpers still live under `ios/e2e_app/src/obstacle_bridge_ios_e2e` until those simulator flows are migrated into the main iOS app lifecycle.

```bash
OBSTACLEBRIDGE_RUN_IOS_SIMULATOR=1 pytest -q tests/integration/test_ios_simulator_e2e.py -m ios_simulator
```

Useful overrides:

- `OBSTACLEBRIDGE_IOS_SIMULATOR_DEVICE="iPhone 17 Pro"` chooses the simulator device passed to Briefcase.
- `OBSTACLEBRIDGE_IOS_SIMULATOR_TIMEOUT=600` controls the Briefcase launch timeout.
- `BRIEFCASE=/path/to/briefcase` chooses the Briefcase executable when it is not on `PATH`.

The simulator lane also includes a WS overlay plus UDP service probe. Pytest starts a host-side ObstacleBridge WS listener and UDP echo target, then uses the legacy probe harness to bind a local UDP port, stimulate that port, and verify the UDP response that crossed the WS overlay:

```bash
OBSTACLEBRIDGE_RUN_IOS_SIMULATOR=1 pytest -q tests/integration/test_ios_simulator_e2e.py -m ios_simulator
```

The same simulator lane now also includes a WS SecureLink probe plus a packaged-runtime path that lets the iOS runtime expose WebAdmin locally and publish it back to the macOS host through `remote_servers`.


Example config route all traffic through tunnel
```json
{
  "admin_web": {
    "admin_web": true,
    "admin_web_auth_disable": true,
    "admin_web_bind": "127.0.0.1",
    "admin_web_first_tab": "status",
    "admin_web_landing_page_disable": false,
    "admin_web_name": "iOS",
    "admin_web_password": "",
    "admin_web_path": "/",
    "admin_web_port": 18090,
    "admin_web_security_advisor_disable": false,
    "admin_web_security_advisor_startup_disable": true,
    "admin_web_token": "",
    "admin_web_username": "",
    "log_admin_web": "INFO"
  },
  "channel_mux": {
    "log_channel_mux": "INFO",
    "mux_tcp_bp_latency_ms": 300,
    "mux_tcp_bp_poll_interval_ms": 50,
    "mux_tcp_bp_threshold": 1,
    "own_servers": [
      {
        "lifecycle_hooks": null,
        "listen": {
          "bind": "127.0.0.1",
          "port": 18010,
          "protocol": "tcp"
        },
        "name": "HTTP direct test",
        "options": null,
        "target": {
          "host": "127.0.0.1",
          "port": 8010,
          "protocol": "tcp"
        }
      },
      {
        "lifecycle_hooks": null,
        "listen": {
          "ifname": "ios-utun",
          "mtu": 1600,
          "protocol": "tun"
        },
        "name": "iOS FullTunnel",
        "options": null,
        "target": {
          "ifname": "obtun2",
          "mtu": 1600,
          "protocol": "tun"
        }
      }
    ],
    "remote_servers": [
      {
        "lifecycle_hooks": {
          "listener": {
            "on_created": {
              "argv": [
                "./scripts/server-tun-hook.sh",
                "up",
                "{ifname}"
              ],
              "env": {
                "ENABLE_TCPMSS": "1",
                "ENABLE_TUN_TCPDUMP": "1",
                "PEER_ADDR": "192.168.106.1",
                "PEER_ADDR6": "fd20:106::1",
                "TCPDUMP_PCAP_PATH": "/tmp/ObstacleBridge.pcap",
                "TCPDUMP_PIDFILE": "/tmp/ObstacleBridge.tcpdump.pid",
                "TCPDUMP_STDERR_LOG": "/tmp/ObstacleBridge.tcpdump.log",
                "TUN_ADDR": "192.168.106.2/30",
                "TUN_ADDR6": "fd20:106::2/126",
                "TUN_SUBNET": "192.168.106.0/30",
                "TUN_SUBNET6": "fd20:106::/126",
                "WAN_IF": "eth0"
              }
            },
            "on_stopped": {
              "argv": [
                "./scripts/server-tun-hook.sh",
                "down",
                "{ifname}"
              ],
              "env": {
                "ENABLE_TCPMSS": "1",
                "ENABLE_TUN_TCPDUMP": "1",
                "PEER_ADDR": "192.168.106.1",
                "PEER_ADDR6": "fd20:106::1",
                "TCPDUMP_PCAP_PATH": "/tmp/ObstacleBridge_ios.pcap",
                "TCPDUMP_PIDFILE": "/tmp/ObstacleBridge_ios.tcpdump.pid",
                "TCPDUMP_STDERR_LOG": "/tmp/ObstacleBridge_ios.tcpdump.log",
                "TUN_ADDR": "192.168.106.2/30",
                "TUN_ADDR6": "fd20:106::2/126",
                "TUN_SUBNET": "192.168.106.0/30",
                "TUN_SUBNET6": "fd20:106::/126",
                "WAN_IF": "eth0"
              }
            }
          }
        },
        "listen": {
          "ifname": "obtun2",
          "mtu": 1600,
          "protocol": "tun"
        },
        "name": "Fedora FullTunnel",
        "options": null,
        "target": {
          "ifname": "ios-utun",
          "mtu": 1600,
          "protocol": "tun"
        }
      }
    ]
  },
  "compress_layer": {
    "compress_layer": true,
    "compress_layer_algo": "zlib",
    "compress_layer_level": 3,
    "compress_layer_min_bytes": 64,
    "compress_layer_types": "data,data_frag",
    "log_compress_layer": "CRITICAL"
  },
  "debug_logging": {
    "admin_web_log_max_lines": 1200,
    "console_level": "DEBUG",
    "debug_stderr": false,
    "file_level": "DEBUG",
    "log": "WARNING",
    "log_debug_logging": "CRITICAL",
    "log_file_backup_count": 5,
    "log_file_max_bytes": 0
  },
  "iOS_TUN_connector": {
    "bind_host": "0.0.0.0",
    "bind_port": 5555,
    "ifname": "ios-utun",
    "mtu": 1600,
    "packetflow_connector": "udp",
    "peer_host": "10.10.1.12",
    "peer_port": 5555
  },
  "TUN_routing": {
    "included_routes": [
      "0.0.0.0/0"
    ],
    "excluded_routes": [
      "127.0.0.0/8"
    ],
    "included_routes6": [
      "::/0"
    ],
    "excluded_routes6": [
      "::1/128"
    ],
    "mtu": 1600
  },
  "quic_session": {
    "log_quic_session": "INFO",
    "quic_alpn": "hq-29",
    "quic_bind": "::",
    "quic_cert": null,
    "quic_insecure": false,
    "quic_key": null,
    "quic_max_size": 65535,
    "quic_own_port": 443,
    "quic_peer": null,
    "quic_peer_port": 443
  },
  "runner": {
    "client_restart_if_disconnected": 0.0,
    "log_runner": "DEBUG",
    "overlay_reconnect_retry_delay_ms": 30000,
    "overlay_transport": "myudp"
  },
  "secure_link": {
    "log_secure_link": "INFO",
    "secure_link": true,
    "secure_link_cert_body": "",
    "secure_link_cert_reload_on_restart": true,
    "secure_link_cert_sig": "",
    "secure_link_mode": "psk",
    "secure_link_private_key": "",
    "secure_link_recover_after_failure": true,
    "secure_link_recover_delay_seconds": 30.0,
    "secure_link_rekey_after_frames": 0,
    "secure_link_rekey_after_seconds": 60.0,
    "secure_link_require": false,
    "secure_link_retry_backoff_initial_ms": 1000,
    "secure_link_retry_backoff_max_ms": 5000,
    "secure_link_revoked_serials": "",
    "secure_link_root_pub": ""
  },
  "stats_board": {
    "log_stats_board": "CRITICAL",
    "no_dashboard": true,
    "status": false
  },
  "tcp_session": {
    "log_tcp_session": "INFO",
    "tcp_bind": "::",
    "tcp_bp_latency_ms": 300,
    "tcp_bp_poll_interval_ms": 50,
    "tcp_bp_wbuf_threshold": 131072,
    "tcp_own_port": 8081,
    "tcp_peer": null,
    "tcp_peer_port": 443
  },
  "udp_session": {
    "log_udp_session": "INFO",
    "max_inflight": 200,
    "peer_resolve_family": "prefer-ipv6",
    "udp_bind": "0.0.0.0",
    "udp_own_port": 0,
    "udp_peer_port": 4433
  },
  "ws_session": {
    "log_ws_session": "INFO",
    "ws_bind": "::",
    "ws_max_size": 65535,
    "ws_own_port": 0,
    "ws_path": "/",
    "ws_payload_mode": "binary",
    "ws_peer_port": 8080,
    "ws_proxy_auth": "none",
    "ws_proxy_host": "",
    "ws_proxy_mode": "off",
    "ws_proxy_port": 8080,
    "ws_reconnect_grace": 3.0,
    "ws_send_timeout": 3.0,
    "ws_subprotocol": null,
    "ws_tcp_user_timeout_ms": 10000,
    "ws_tls": false
  }
}
```

Route effectively no VPN traffic through tunnel, still have TCP and UDP tunnels
```json
  "TUN_routing": {
    "included_routes": [
      "198.18.0.254/32"
    ],
    "excluded_routes": [
      "127.0.0.0/8"
    ],
    "included_routes6": [
      "2001:db8:ffff::254/128"
    ],
    "excluded_routes6": [
      "::1/128"
    ],
    "mtu": 1600
  },
```  

Use NEPacketProvider to UDP interface

Assumes Linux machine is in same WLAN as iPhone
Linux machine has IP 10.10.1.6 assigned

```json  
"iOS_TUN_connector": {
  "packetflow_connector": "simple_udp_peer",
  "peer_host": "10.10.1.6",
  "peer_port": 5555,
  "bind_host": "0.0.0.0",
  "bind_port": 5555,
  "ifname": "ios-utun",
  "mtu": 1280
}
```  

On Linux machine
```bash  
./run_test.sh
```

as soon it is running open 2nd shell
```bash  
./run_test_setup.sh
```

