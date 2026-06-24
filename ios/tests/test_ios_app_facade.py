from __future__ import annotations

import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios import app as ios_app_module
from obstacle_bridge_ios.app import ObstacleBridgeIOSApp, _load_grouped_runtime_config, _write_startup_artifacts


def test_app_default_facade_reports_extension_as_runtime_owner(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "Documents"
    monkeypatch.setattr(ObstacleBridgeIOSApp, "DOCUMENTS_ROOT", root)
    monkeypatch.setattr(ObstacleBridgeIOSApp, "CONFIG_DIR", root / "config")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "CONFIG_FILE", root / "config" / "ObstacleBridge.cfg")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "PROFILES_DIR", root / "profiles")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "LOGS_DIR", root / "logs")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "LOG_FILE", root / "logs" / "obstaclebridge.log")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "ADMIN_WEB_DIR", root / "admin_web")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "WEB_DIR", root / "web")

    app = ObstacleBridgeIOSApp()

    snapshot = app.connection_snapshot()

    assert snapshot["started"] is False
    assert snapshot["runtime_mode"] == "swift_udp"
    assert snapshot["runtime_owner"] == "IPServer Network Extension"
    assert snapshot["active_profile_id"] is None
    assert snapshot["config"]["admin_web"]["admin_web"] is True
    assert snapshot["config"]["iOS_TUN_connector"]["packetflow_connector"] == "swift_udp"
    assert snapshot["config"]["channel_mux"]["own_servers"] == []
    assert snapshot["config"]["channel_mux"]["remote_servers"] == []


def test_load_grouped_runtime_config_preserves_saved_transport_fields(tmp_path: Path) -> None:
    root = tmp_path / "Documents"
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "ObstacleBridge.cfg").write_text(
        json.dumps(
            {
                "tcp_session": {
                    "overlay_transport": "tcp",
                    "tcp_peer": "bridge.example.net",
                    "tcp_peer_port": 4433,
                },
                "admin_web": {
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": 18080,
                },
            }
        ),
        encoding="utf-8",
    )

    config = _load_grouped_runtime_config(root)

    assert config["tcp_session"]["overlay_transport"] == "tcp"
    assert config["tcp_session"]["tcp_peer"] == "bridge.example.net"
    assert config["tcp_session"]["tcp_peer_port"] == 4433
    assert config["admin_web"]["admin_web"] is True
    assert config["admin_web"]["admin_web_bind"] == "127.0.0.1"
    assert config["admin_web"]["admin_web_port"] == 18080
    assert config["iOS_TUN_connector"]["packetflow_connector"] == "swift_udp"
    assert config["iOS_TUN_connector"]["bind_host"] == "127.0.0.1"
    assert config["iOS_TUN_connector"]["peer_host"] == "127.0.0.1"
    assert config["iOS_TUN_connector"]["peer_port"] == 5556
    assert config["TUN_routing"]["tunnel_address"] == "192.168.106.1"
    assert config["TUN_routing"]["tunnel_gateway"] == "192.168.106.2"
    assert config["TUN_routing"]["included_routes"] == ["0.0.0.0/0"]
    assert config["TUN_routing"]["excluded_routes"] == ["127.0.0.0/8"]
    assert config["TUN_routing"]["tunnel_address6"] == "fd20:106::1"
    assert config["TUN_routing"]["tunnel_gateway6"] == "fd20:106::2"
    assert config["TUN_routing"]["included_routes6"] == ["::/0"]
    assert config["TUN_routing"]["excluded_routes6"] == ["::1/128"]
    assert config["TUN_routing"]["dns_servers"] == ["1.1.1.1"]
    assert config["TUN_routing"]["mtu"] == 1600
    assert config["TUN_routing"]["log_TUN_routing"] == "CRITICAL"
    assert "log_file" in config["debug_logging"]


def test_app_facade_reports_swift_host_runner_mode_from_config(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "Documents"
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "ObstacleBridge.cfg").write_text(
        json.dumps(
            {
                "admin_web": {
                    "admin_web": True,
                    "admin_web_bind": "127.0.0.1",
                    "admin_web_port": 18090,
                },
                "iOS_TUN_connector": {
                    "packetflow_connector": "swift_host_runner",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ObstacleBridgeIOSApp, "DOCUMENTS_ROOT", root)
    monkeypatch.setattr(ObstacleBridgeIOSApp, "CONFIG_DIR", root / "config")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "CONFIG_FILE", root / "config" / "ObstacleBridge.cfg")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "PROFILES_DIR", root / "profiles")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "LOGS_DIR", root / "logs")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "LOG_FILE", root / "logs" / "obstaclebridge.log")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "ADMIN_WEB_DIR", root / "admin_web")
    monkeypatch.setattr(ObstacleBridgeIOSApp, "WEB_DIR", root / "web")

    app = ObstacleBridgeIOSApp()

    snapshot = app.connection_snapshot()

    assert snapshot["runtime_mode"] == "swift_host_runner"
    assert snapshot["runtime_owner"] == "ObstacleBridgeApp swift_host_runner"
    assert snapshot["webadmin_url"] == "http://127.0.0.1:18090/"


def test_startup_artifacts_seed_documents_config_logs_and_web_files(tmp_path: Path) -> None:
    root = tmp_path / "Documents" / "ObstacleBridge"

    result = _write_startup_artifacts(root)

    assert result == root
    assert (root / "config" / "ObstacleBridge.cfg").is_file()
    assert (root / "logs").is_dir()
    assert (root / "profiles").is_dir()
    assert (root / "admin_web" / "index.html").is_file()
    assert (root / "web" / "index.html").is_file()

    manifest = json.loads((root / "documents-manifest.json").read_text(encoding="utf-8"))
    assert manifest["config_file"] == str(root / "config" / "ObstacleBridge.cfg")
    assert manifest["log_file"] == str(root / "logs" / "obstaclebridge.log")
    assert manifest["diagnostics_file"] == str(root / "logs" / "ios-diagnostics.jsonl")
    assert manifest["admin_web_files_copied"] is True
    assert manifest["web_files_copied"] is True
    config_payload = json.loads((root / "config" / "ObstacleBridge.cfg").read_text(encoding="utf-8"))
    assert config_payload["iOS_TUN_connector"]["packetflow_connector"] == "swift_udp"
    assert config_payload["channel_mux"]["own_servers"] == []
    assert config_payload["channel_mux"]["remote_servers"] == []


def test_resolve_toga_webview_class_uses_widget_module_fallback(monkeypatch) -> None:
    sentinel = object()
    fake_toga = types.SimpleNamespace()
    fake_module = types.SimpleNamespace(WebView=sentinel)

    monkeypatch.setattr(ios_app_module, "toga", fake_toga)
    monkeypatch.setattr(ios_app_module.importlib, "import_module", lambda name: fake_module)

    assert ios_app_module._resolve_toga_webview_class() is sentinel


def test_webadmin_url_from_config_normalizes_wildcard_bind() -> None:
    assert (
        ObstacleBridgeIOSApp.webadmin_url_from_config(
            {
                "admin_web": True,
                "admin_web_bind": "0.0.0.0",
                "admin_web_port": 19090,
                "admin_web_path": "admin",
            }
        )
        == "http://127.0.0.1:19090/admin"
    )


def test_webadmin_url_from_config_uses_ios_tun_address_when_running_on_ios(monkeypatch) -> None:
    monkeypatch.setattr(ios_app_module.sys, "platform", "ios")

    assert (
        ObstacleBridgeIOSApp.webadmin_url_from_config(
            {
                "admin_web": True,
                "admin_web_bind": "0.0.0.0",
                "admin_web_port": 18090,
                "channel_mux": {
                    "own_servers": [
                        {
                            "listen": {"protocol": "tun", "ifname": "ios-utun", "mtu": 1280},
                            "target": {"protocol": "tun", "ifname": "obtun1", "mtu": 1280},
                            "lifecycle_hooks": {
                                "listener": {
                                    "on_created": {
                                        "argv": {"linux": ["./scripts/client-tun-hook.sh", "up", "{ifname}"]},
                                        "env": {"TUN_ADDR": "192.168.105.9/30"},
                                    }
                                }
                            },
                        }
                    ]
                },
            }
        )
        == "http://127.0.0.1:18090/"
    )


def test_main_dispatches_probe_mode_without_starting_toga(monkeypatch) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(ios_app_module, "toga", None)

    def fake_run_probe_mode(argv: list[str]) -> int | None:
        calls.append(list(argv))
        return 0

    monkeypatch.setattr(ios_app_module, "_run_probe_mode", fake_run_probe_mode)

    result = ios_app_module.main(["--host-websocket-probe", "ws://127.0.0.1:18080/test"])

    assert result == 0
    assert calls == [["--host-websocket-probe", "ws://127.0.0.1:18080/test"]]
