from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios import ipserver_extension
from obstacle_bridge_ios import ipserver_runtime
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


def test_disable_extension_python_logging_disables_root_logger(monkeypatch) -> None:
    calls: list[int] = []
    sentinel = object()

    def _fake_disable(level: int) -> None:
        calls.append(level)

    monkeypatch.setattr(ipserver_runtime.logging, "disable", _fake_disable)

    root = ipserver_runtime.logging.getLogger()
    original_handlers = list(root.handlers)
    root.handlers = [sentinel]  # type: ignore[list-item]
    try:
        ipserver_runtime._disable_extension_python_logging()
    finally:
        root.handlers = original_handlers

    assert calls == [ipserver_runtime.logging.CRITICAL]
    assert sentinel not in root.handlers


def test_runtime_config_from_profile_disables_extension_logging() -> None:
    runtime_cfg = IPServerRuntimeController._runtime_config_from_profile(
        {
            "obstacle_bridge": {
                "overlay_transport": "myudp",
                "log": "DEBUG",
                "file_level": "DEBUG",
                "console_level": "INFO",
                "log_file": "/tmp/obstaclebridge.log",
            }
        }
    )

    assert runtime_cfg["log"] == "CRITICAL"
    assert runtime_cfg["file_level"] == "CRITICAL"
    assert runtime_cfg["console_level"] == "CRITICAL"
    assert runtime_cfg["log_file"] == ""


def test_runtime_config_with_ios_defaults_disables_grouped_extension_logging() -> None:
    runtime_cfg = IPServerRuntimeController._runtime_config_with_ios_defaults(
        {
            "debug_logging": {
                "log": "DEBUG",
                "file_level": "DEBUG",
                "console_level": "INFO",
                "log_file": "/tmp/obstaclebridge.log",
            }
        }
    )

    assert runtime_cfg["debug_logging"]["log"] == "CRITICAL"
    assert runtime_cfg["debug_logging"]["file_level"] == "CRITICAL"
    assert runtime_cfg["debug_logging"]["console_level"] == "CRITICAL"
    assert runtime_cfg["debug_logging"]["log_file"] == ""


def test_simple_udp_peer_settings_can_be_loaded_from_grouped_config(monkeypatch) -> None:
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_HOST", raising=False)
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_PEER_PORT", raising=False)

    settings = ipserver_runtime._simple_udp_peer_settings(
        {
            "iOS_TUN_connector": {
                "packetflow_connector": "simple_udp_peer",
                "peer_host": "10.10.1.6",
                "peer_port": 5555,
                "bind_host": "0.0.0.0",
                "bind_port": 5555,
            }
        }
    )

    assert settings == {
        "connector_mode": "simple_udp_peer",
        "peer_host": "10.10.1.6",
        "peer_port": 5555,
        "bind_host": "0.0.0.0",
        "bind_port": 5555,
        "ifname": "ios-utun",
        "mtu": 1280,
    }


def test_packetflow_connector_mode_prefers_grouped_ios_tun_connector(monkeypatch) -> None:
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)

    mode = ipserver_runtime._packetflow_connector_mode(
        {
            "iOS_TUN_connector": {
                "packetflow_connector": "swift_udp",
            }
        }
    )

    assert mode == "swift_udp"


def test_packetflow_connector_mode_normalizes_swift_udp_peer(monkeypatch) -> None:
    monkeypatch.delenv("OBSTACLEBRIDGE_IOS_PACKETFLOW_CONNECTOR", raising=False)

    mode = ipserver_runtime._packetflow_connector_mode(
        {
            "iOS_TUN_connector": {
                "packetflow_connector": "swift_udp_peer",
            }
        }
    )

    assert mode == "swift_udp"


def test_start_embedded_webadmin_can_boot_simple_udp_peer_runtime(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        ipserver_runtime,
        "log_provider_event",
        lambda _root, event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(ipserver_runtime, "log_event", lambda *_args, **_kwargs: None)

    class FakeClient:
        def __init__(self, config, config_path=None, apply_logging=False):
            self.config = config
            self.runner = None
            self.start_calls: list[dict[str, object]] = []
            self.stop_calls = 0
            self._args = None

        async def start(self, config=None, packet_io=None) -> None:
            self.start_calls.append(dict(config or {}))

        async def stop(self) -> None:
            self.stop_calls += 1

        def snapshot(self) -> dict[str, object]:
            return {"started": False, "config": self.config}

    class FakeSimpleRuntime:
        def __init__(self, documents_root, loop):
            self.documents_root = documents_root
            self.loop = loop
            self.start_calls: list[tuple[dict[str, object], str]] = []
            self.stop_calls = 0
            self.config: dict[str, object] = {}

        async def start(self, config, *, tunnel_address: str) -> None:
            self.config = dict(config)
            self.start_calls.append((dict(config), tunnel_address))

        async def stop(self) -> None:
            self.stop_calls += 1

        def snapshot(self) -> dict[str, object]:
            return {"started": True, "status": {"runtime_mode": "simple_udp_peer"}, "config": self.config}

    monkeypatch.setattr(ipserver_runtime, "ObstacleBridgeClient", FakeClient)
    monkeypatch.setattr(ipserver_runtime, "_SimpleUDPPeerRuntime", FakeSimpleRuntime)

    def _run_async_sync(self, awaitable):
        return asyncio.run(awaitable)

    monkeypatch.setattr(IPServerRuntimeController, "_run_async_sync", _run_async_sync)
    monkeypatch.setattr(IPServerRuntimeController, "_ensure_runtime_loop", lambda self: SimpleNamespace())

    controller = IPServerRuntimeController()
    snapshot = controller.start_embedded_webadmin(
        {
            "iOS_TUN_connector": {
                "packetflow_connector": "simple_udp_peer",
                "peer_host": "10.10.1.6",
                "peer_port": 5555,
            }
        }
    )

    assert snapshot["started"] is True
    assert snapshot["status"]["runtime_mode"] == "simple_udp_peer"
    assert isinstance(controller._simple_udp_peer_runtime, FakeSimpleRuntime)
    assert controller._simple_udp_peer_runtime.start_calls
    assert controller.client.start_calls == []
    assert any(event == "python_runtime_start_completed" and fields.get("runtime_mode") == "simple_udp_peer" for event, fields in events)


def test_start_embedded_webadmin_can_boot_client_with_swift_udp(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        ipserver_runtime,
        "log_provider_event",
        lambda _root, event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(ipserver_runtime, "log_event", lambda *_args, **_kwargs: None)

    class FakeClient:
        def __init__(self, config, config_path=None, apply_logging=False):
            self.config = config
            self.runner = SimpleNamespace()
            self.start_calls: list[dict[str, object]] = []
            self.stop_calls = 0
            self._args = None

        async def start(self, config=None, packet_io=None) -> None:
            self.start_calls.append(dict(config or {}))

        async def stop(self) -> None:
            self.stop_calls += 1

        def snapshot(self) -> dict[str, object]:
            return {"started": True, "config": self.config}

    monkeypatch.setattr(ipserver_runtime, "ObstacleBridgeClient", FakeClient)

    def _run_async_sync(self, awaitable):
        return asyncio.run(awaitable)

    monkeypatch.setattr(IPServerRuntimeController, "_run_async_sync", _run_async_sync)

    controller = IPServerRuntimeController()
    snapshot = controller.start_embedded_webadmin(
        {
            "iOS_TUN_connector": {
                "bind_host": "127.0.0.1",
                "bind_port": 5555,
                "packetflow_connector": "swift_udp",
                "peer_host": "127.0.0.1",
                "peer_port": 5556,
            },
            "channel_mux": {
                "own_servers": [
                    {
                        "name": "http",
                        "listen": {"bind": "127.0.0.1", "port": 18010, "protocol": "tcp"},
                        "target": {"host": "127.0.0.1", "port": 8010, "protocol": "tcp"},
                    },
                    {
                        "name": "tun",
                        "listen": {"ifname": "ios-utun", "mtu": 1600, "protocol": "tun"},
                        "target": {"ifname": "obtun2", "mtu": 1600, "protocol": "tun"},
                    },
                ]
            },
        }
    )

    assert snapshot["started"] is True
    assert controller._simple_udp_peer_runtime is None
    assert len(controller.client.start_calls) == 1
    started_config = controller.client.start_calls[0]
    own_servers = started_config["channel_mux"]["own_servers"]
    assert len(own_servers) == 2
    assert [entry["listen"]["protocol"] for entry in own_servers] == ["tcp", "tun"]
    ios_tun_connector = started_config["iOS_TUN_connector"]
    assert ios_tun_connector["bind_host"] == "127.0.0.1"
    assert ios_tun_connector["peer_host"] == "127.0.0.1"
    assert ios_tun_connector["bind_port"] == 5555
    assert ios_tun_connector["peer_port"] == 5556
    assert any(event == "python_runtime_start_completed" and fields.get("runtime_mode") == "obstaclebridge" for event, fields in events)


def test_start_embedded_webadmin_preserves_ws_and_compress_runtime_config(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        ipserver_runtime,
        "log_provider_event",
        lambda _root, event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(ipserver_runtime, "log_event", lambda *_args, **_kwargs: None)

    class FakeClient:
        def __init__(self, config, config_path=None, apply_logging=False):
            self.config = config
            self.runner = SimpleNamespace()
            self.start_calls: list[dict[str, object]] = []
            self.stop_calls = 0
            self._args = None

        async def start(self, config=None, packet_io=None) -> None:
            self.start_calls.append(dict(config or {}))

        async def stop(self) -> None:
            self.stop_calls += 1

        def snapshot(self) -> dict[str, object]:
            return {"started": True, "config": self.config}

    monkeypatch.setattr(ipserver_runtime, "ObstacleBridgeClient", FakeClient)

    def _run_async_sync(self, awaitable):
        return asyncio.run(awaitable)

    monkeypatch.setattr(IPServerRuntimeController, "_run_async_sync", _run_async_sync)

    controller = IPServerRuntimeController()
    snapshot = controller.start_embedded_webadmin(
        {
            "overlay_transport": "ws",
            "ws_peer": "bridge.example.net",
            "ws_peer_port": 8443,
            "ws_payload_mode": "base64",
            "ws_send_timeout": 7.5,
            "compress_layer": True,
            "compress_layer_algo": "zlib",
            "compress_layer_level": 5,
            "compress_layer_min_bytes": 96,
            "compress_layer_types": "data,data_ack",
            "iOS_TUN_connector": {
                "bind_host": "127.0.0.1",
                "bind_port": 5555,
                "packetflow_connector": "swift_udp",
                "peer_host": "127.0.0.1",
                "peer_port": 5556,
            },
        }
    )

    assert snapshot["started"] is True
    assert controller._simple_udp_peer_runtime is None
    assert len(controller.client.start_calls) == 1
    started_config = controller.client.start_calls[0]
    assert started_config["overlay_transport"] == "ws"
    assert started_config["ws_peer"] == "bridge.example.net"
    assert started_config["ws_peer_port"] == 8443
    assert started_config["ws_payload_mode"] == "base64"
    assert started_config["compress_layer"] is True
    assert started_config["compress_layer_algo"] == "zlib"
    assert started_config["compress_layer_level"] == 5
    assert started_config["compress_layer_min_bytes"] == 96
    assert started_config["compress_layer_types"] == "data,data_ack"
    assert started_config["iOS_TUN_connector"]["packetflow_connector"] == "swift_udp"
    assert any(
        event == "python_runtime_config_prepared" and fields.get("packetflow_connector") == "swift_udp"
        for event, fields in events
    )


def test_embedded_restart_reload_reads_grouped_config_and_restarts_client(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        ipserver_runtime,
        "log_provider_event",
        lambda _root, event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(ipserver_runtime, "log_event", lambda *_args, **_kwargs: None)

    class FakeClient:
        def __init__(self, config, config_path=None, apply_logging=False):
            self.config = config
            self.config_path = config_path
            self.apply_logging = apply_logging
            self.runner = SimpleNamespace()
            self.stop_calls = 0
            self.start_calls: list[dict[str, object]] = []

        async def stop(self) -> None:
            self.stop_calls += 1

        async def start(self, config=None, packet_io=None) -> None:
            if config is not None:
                self.config = config
            self.start_calls.append(dict(config or {}))

        def snapshot(self) -> dict[str, object]:
            return {"started": True, "config": self.config}

    monkeypatch.setattr(ipserver_runtime, "ObstacleBridgeClient", FakeClient)
    monkeypatch.setattr(
        ipserver_runtime,
        "_load_grouped_runtime_config",
        lambda _root: {
            "runner": {"overlay_transport": "myudp"},
            "udp_session": {"udp_peer": "bridge.example.net", "udp_peer_port": 4433},
        },
    )
    monkeypatch.setattr(IPServerRuntimeController, "_ensure_runtime_loop", lambda self: asyncio.get_running_loop())
    
    async def _fast_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _fast_sleep)

    controller = IPServerRuntimeController()
    old_client = controller.client

    async def run() -> None:
        controller._request_embedded_restart()
        future = controller._embedded_restart_future
        assert future is not None
        await future

    asyncio.run(run())

    assert old_client.stop_calls == 1
    assert controller.client is not old_client
    assert controller.client.start_calls
    assert controller.client.start_calls[-1]["runner"]["overlay_transport"] == "myudp"
    assert controller.client.start_calls[-1]["udp_session"]["udp_peer"] == "bridge.example.net"
    assert any(event == "python_runtime_restart_started" for event, _fields in events)
    assert any(event == "python_runtime_restart_completed" for event, _fields in events)


def test_embedded_restart_times_out_old_runtime_stop(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        ipserver_runtime,
        "log_provider_event",
        lambda _root, event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(ipserver_runtime, "log_event", lambda *_args, **_kwargs: None)

    class FakeOldClient:
        def __init__(self, config, config_path=None, apply_logging=False):
            self.config = config
            self.runner = SimpleNamespace()

        async def stop(self) -> None:
            await asyncio.sleep(999)

        async def start(self, config=None, packet_io=None) -> None:
            return None

        def snapshot(self) -> dict[str, object]:
            return {"started": True, "config": self.config}

    class FakeNewClient(FakeOldClient):
        pass

    created: list[FakeOldClient] = []

    def _client_factory(config, config_path=None, apply_logging=False):
        cls = FakeOldClient if not created else FakeNewClient
        obj = cls(config, config_path=config_path, apply_logging=apply_logging)
        created.append(obj)
        return obj

    monkeypatch.setattr(ipserver_runtime, "ObstacleBridgeClient", _client_factory)
    monkeypatch.setattr(
        ipserver_runtime,
        "_load_grouped_runtime_config",
        lambda _root: {"runner": {"overlay_transport": "myudp"}},
    )
    monkeypatch.setattr(IPServerRuntimeController, "_ensure_runtime_loop", lambda self: asyncio.get_running_loop())

    controller = IPServerRuntimeController()
    controller.EMBEDDED_RESTART_STOP_TIMEOUT_SEC = 0.01

    async def run() -> None:
        controller._request_embedded_restart()
        future = controller._embedded_restart_future
        assert future is not None
        with pytest.raises(asyncio.TimeoutError):
            await future

    import pytest

    asyncio.run(run())

    assert any(event == "python_runtime_restart_stop_old_runtime_timed_out" for event, _fields in events)
