from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios import ipserver_extension
from obstacle_bridge_ios.ipserver_runtime import IPServerRuntimeController


class _FakeController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def start_embedded_webadmin(self, runtime_config=None) -> dict[str, object]:
        self.calls.append(("start_embedded_webadmin", runtime_config))
        return {"started": True, "webadmin_url": "http://127.0.0.1:18080/"}

    def connect_profile(self, *, profile=None, profile_id=None) -> dict[str, object]:
        self.calls.append(("connect_profile", profile if profile is not None else profile_id))
        return {"started": True, "active_profile_id": profile_id or "inline"}

    def disconnect_profile(self) -> dict[str, object]:
        self.calls.append(("disconnect_profile", None))
        return {"started": False}

    def connection_snapshot(self) -> dict[str, object]:
        self.calls.append(("connection_snapshot", None))
        return {"started": False, "active_profile_id": None}

    def diagnostics_snapshot(self) -> dict[str, object]:
        self.calls.append(("diagnostics_snapshot", None))
        return {"event_log": "/tmp/ios-diagnostics.jsonl"}


def test_handle_message_starts_embedded_webadmin(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = ipserver_extension.handle_message({"command": "start_embedded_webadmin"})

    assert response["ok"] is True
    assert response["result"]["started"] is True
    assert controller.calls == [("start_embedded_webadmin", None)]


def test_handle_message_starts_with_provider_runtime_config(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = ipserver_extension.handle_message(
        {
            "command": "start_embedded_webadmin",
            "provider_configuration": {
                "runtime_config": {
                    "overlay_transport": "myudp",
                    "udp_peer": "bridge.example.net",
                    "udp_peer_port": 4433,
                }
            },
        }
    )

    assert response["ok"] is True
    assert controller.calls == [
        (
            "start_embedded_webadmin",
            {
                "overlay_transport": "myudp",
                "udp_peer": "bridge.example.net",
                "udp_peer_port": 4433,
            },
        )
    ]


def test_handle_message_connects_profile_by_id(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = ipserver_extension.handle_message(
        json.dumps({"command": "connect_profile", "profile_id": "ios-profile-a"})
    )

    assert response["ok"] is True
    assert response["result"]["active_profile_id"] == "ios-profile-a"
    assert controller.calls == [("connect_profile", "ios-profile-a")]


def test_handle_message_disconnects_profile(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = ipserver_extension.handle_message({"command": "disconnect_profile"})

    assert response["ok"] is True
    assert response["result"]["started"] is False
    assert controller.calls == [("disconnect_profile", None)]


def test_handle_message_json_returns_error_payload_for_unknown_command(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = json.loads(ipserver_extension.handle_message_json({"command": "nope"}))

    assert response["ok"] is False
    assert response["error_type"] == "ValueError"
    assert "unsupported command" in response["error"]


def test_handle_message_returns_diagnostics_snapshot(monkeypatch) -> None:
    controller = _FakeController()
    monkeypatch.setattr(ipserver_extension, "_controller", lambda: controller)

    response = ipserver_extension.handle_message({"command": "diagnostics_snapshot"})

    assert response["ok"] is True
    assert response["result"]["event_log"] == "/tmp/ios-diagnostics.jsonl"
    assert controller.calls == [("diagnostics_snapshot", None)]


def test_ios_extension_runtime_disables_admin_web_auth_for_grouped_config() -> None:
    config = {
        "admin_web": {
            "admin_web_auth_disable": False,
            "admin_web_username": "alice",
            "admin_web_password": "enc:v1:deadbeef",
        }
    }

    normalized = IPServerRuntimeController._normalize_ios_extension_admin_web(config)

    assert normalized["admin_web"]["admin_web_auth_disable"] is True
    assert normalized["admin_web"]["admin_web_username"] == ""
    assert normalized["admin_web"]["admin_web_password"] == ""
    assert normalized["debug_logging"]["ios_admin_web_auth_policy"] == "disabled_in_extension_runtime"


def test_ios_extension_runtime_disables_admin_web_auth_for_flat_config() -> None:
    config = {
        "admin_web_auth_disable": False,
        "admin_web_username": "alice",
        "admin_web_password": "enc:v1:deadbeef",
    }

    normalized = IPServerRuntimeController._normalize_ios_extension_admin_web(config)

    assert normalized["admin_web_auth_disable"] is True
    assert normalized["admin_web_username"] == ""
    assert normalized["admin_web_password"] == ""
    assert normalized["ios_admin_web_auth_policy"] == "disabled_in_extension_runtime"
