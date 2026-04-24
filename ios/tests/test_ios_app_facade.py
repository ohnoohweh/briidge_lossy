from __future__ import annotations

import types
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge.bridge import _encrypt_config_secret
from obstacle_bridge.onboarding import encode_invite_token
from obstacle_bridge_ios import app as ios_app_module
from obstacle_bridge_ios.app import ObstacleBridgeIOSApp
from obstacle_bridge_ios.m25_ui import M25Config
from obstacle_bridge_ios.profiles import ProfileStore
from obstacle_bridge_ios.secure_store import InMemorySecretStore


class _FakeClient:
    def __init__(self) -> None:
        self.started = False
        self.last_config = None
        self.start_calls = 0
        self.stop_calls = 0

    async def start(self, config=None, packet_io=None) -> None:
        self.started = True
        self.last_config = config
        self.start_calls += 1

    async def stop(self) -> None:
        self.started = False
        self.stop_calls += 1

    def snapshot(self) -> dict:
        return {"started": self.started, "config": dict(self.last_config or {})}


def test_app_import_and_store_profile_keeps_plaintext_secrets_out_of_disk(tmp_path: Path) -> None:
    app = ObstacleBridgeIOSApp()
    app.profile_store = ProfileStore(tmp_path, secret_store=InMemorySecretStore())

    invite_token = encode_invite_token(
        {
            "version": 1,
            "connection": {
                "transport": "tcp",
                "endpoint_host": "bridge.example.net",
                "endpoint_port": 4433,
            },
            "secure_link_mode": "psk",
            "secure_link_psk": _encrypt_config_secret("ios-m1-psk"),
        }
    )

    stored = app.import_and_store_profile(
        invite_token,
        profile_id="ios-m1-site-a",
        display_name="Site A",
    )

    assert stored["profile_id"] == "ios-m1-site-a"
    profile_path = tmp_path / "ios-m1-site-a.json"
    on_disk_text = profile_path.read_text(encoding="utf-8")
    on_disk = json.loads(on_disk_text)

    assert on_disk["obstacle_bridge"]["secure_link_psk"] == ""
    assert on_disk["obstacle_bridge"]["secure_link_psk_present"] is True
    assert "ios-m1-psk" not in on_disk_text


def test_app_preview_import_handles_runtime_config_json() -> None:
    app = ObstacleBridgeIOSApp()

    preview = app.preview_import(
        json.dumps(
            {
                "overlay_transport": "ws",
                "ws_peer": "bridge.example.net",
                "ws_peer_port": 443,
                "secure_link_mode": "psk",
                "admin_web": False,
            }
        )
    )

    assert preview["kind"] == "config"
    assert preview["preview"]["overlay_transport"] == "ws"


def test_app_exposes_m2_dependency_spike_runner() -> None:
    app = ObstacleBridgeIOSApp()
    report = app.run_m2_dependency_spike()

    assert report["milestone"] == "M2"
    assert isinstance(report["checks"], list)


def test_app_builds_profile_from_m25_config() -> None:
    app = ObstacleBridgeIOSApp()
    profile = app.build_profile_from_m25_config(
        M25Config(
            profile_id="ios-m25-a",
            display_name="M2.5",
            transport="tcp",
            peer_host="bridge.example.net",
            peer_port=4433,
            local_tcp_port=18080,
            local_udp_port=18081,
            target_host="127.0.0.1",
            target_tcp_port=8080,
            target_udp_port=8081,
        )
    )

    assert profile["profile_id"] == "ios-m25-a"
    assert profile["obstacle_bridge"]["overlay_transport"] == "tcp"


def test_app_builds_m3_vpn_profile_from_saved_profile_contract() -> None:
    app = ObstacleBridgeIOSApp()
    profile = app.build_profile_from_m25_config(
        M25Config(
            profile_id="ios-m3-a",
            display_name="M3",
            transport="tcp",
            peer_host="bridge.example.net",
            peer_port=4433,
            local_tcp_port=18080,
            local_udp_port=18081,
            target_host="127.0.0.1",
            target_tcp_port=8080,
            target_udp_port=8081,
        )
    )

    vpn_profile = app.build_m3_vpn_profile(
        profile,
        provider_bundle_identifier="com.obstaclebridge.ObstacleBridge.PacketTunnel",
    )

    assert vpn_profile["install_path"] == "NETunnelProviderManager"
    assert vpn_profile["provider_configuration"]["milestone"] == "M3"
    assert vpn_profile["provider_configuration"]["peer"]["host"] == "bridge.example.net"


def test_app_connect_profile_starts_runtime_with_obstacle_bridge_section(tmp_path: Path) -> None:
    app = ObstacleBridgeIOSApp()
    app.profile_store = ProfileStore(tmp_path, secret_store=InMemorySecretStore())
    app.client = _FakeClient()

    saved = app.save_profile(
        {
            "profile_id": "ios-connect-a",
            "display_name": "Connect A",
            "obstacle_bridge": {
                "overlay_transport": "ws",
                "ws_peer": "127.0.0.1",
                "ws_peer_port": 8080,
            },
        }
    )

    snapshot = app.connect_profile(profile=saved)

    assert snapshot["started"] is True
    assert snapshot["active_profile_id"] == "ios-connect-a"
    assert app.client.start_calls == 1
    assert app.client.last_config["overlay_transport"] == "ws"
    assert app.client.last_config["ws_peer_port"] == 8080
    assert app.client.last_config["admin_web"] is True
    assert app.client.last_config["admin_web_bind"] == "127.0.0.1"
    assert app.client.last_config["admin_web_port"] == 18080
    assert snapshot["webadmin_url"] == "http://127.0.0.1:18080/"


def test_app_disconnect_profile_stops_runtime_and_clears_active_profile(tmp_path: Path) -> None:
    app = ObstacleBridgeIOSApp()
    app.profile_store = ProfileStore(tmp_path, secret_store=InMemorySecretStore())
    app.client = _FakeClient()

    app.connect_profile(
        profile={
            "profile_id": "ios-connect-b",
            "display_name": "Connect B",
            "obstacle_bridge": {
                "overlay_transport": "tcp",
                "tcp_peer": "127.0.0.1",
                "tcp_peer_port": 8081,
            },
        }
    )
    snapshot = app.disconnect_profile()

    assert snapshot["started"] is False
    assert snapshot["active_profile_id"] is None
    assert app.client.stop_calls == 1


def test_app_start_embedded_webadmin_starts_default_runtime() -> None:
    app = ObstacleBridgeIOSApp()
    app.client = _FakeClient()

    snapshot = app.start_embedded_webadmin()

    assert snapshot["started"] is True
    assert app.client.start_calls == 1
    assert app.client.last_config["admin_web"] is True
    assert app.client.last_config["admin_web_bind"] == "127.0.0.1"
    assert app.client.last_config["admin_web_port"] == 18080
    assert snapshot["webadmin_url"] == "http://127.0.0.1:18080/"


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


def test_webadmin_url_from_config_returns_none_when_disabled() -> None:
    assert ObstacleBridgeIOSApp.webadmin_url_from_config({"admin_web": False}) is None
