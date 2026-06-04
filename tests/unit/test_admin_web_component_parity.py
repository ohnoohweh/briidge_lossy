from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from obstacle_bridge.bridge import AdminWebUI


ROOT = Path(__file__).resolve().parents[2]
SWIFT_CHANNELMUX_CODEC_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeChannelMuxCodec.swift"
SWIFT_OVERLAY_STACK_PLANNER_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeOverlayStackPlanner.swift"
SWIFT_RUNTIME_CONFIG_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeRuntimeConfig.swift"
SWIFT_ADMIN_WEB_SUPPORT_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeAdminWebSupport.swift"
SWIFT_ADMIN_SNAPSHOT_SUPPORT_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeAdminSnapshotSupport.swift"
SWIFT_ADMIN_API_SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgeAdminAPI.swift"
SWIFT_ADMIN_COMPONENT_RUNNER_SOURCE = ROOT / "tests" / "fixtures" / "admin_web_component_runner.swift"


class _PythonAdminRunnerStub:
    def __init__(self, connections_snapshot: dict[str, object] | None = None) -> None:
        self.args = argparse.Namespace(admin_web_name="Lab Node")
        self._connections_snapshot = connections_snapshot or {}

    def get_connections_snapshot(self) -> dict[str, object]:
        return self._connections_snapshot


def _python_admin_ui_payload(runtime_config: dict[str, object], *, platform: str) -> dict[str, object]:
    args = argparse.Namespace(
        admin_web=True,
        admin_web_bind="127.0.0.1",
        admin_web_port=18080,
        admin_web_path="/",
        admin_web_landing_page_disable=False,
        admin_web_security_advisor_disable=False,
        admin_web_security_advisor_startup_disable=False,
        admin_web_first_tab="home",
        admin_web_token="",
        admin_web_auth_disable=False,
        admin_web_username="",
        admin_web_password="",
        secure_link_mode="off",
        secure_link_psk="",
        _first_start_detected=False,
        _config_file_state="unknown",
    )
    for key, value in runtime_config.items():
        setattr(args, key, value)
    ui = AdminWebUI(args, _PythonAdminRunnerStub())
    with mock.patch.dict(os.environ, {"OBSTACLEBRIDGE_ADMIN_UI_PLATFORM": platform}, clear=False):
        return ui._build_admin_ui_payload()


def _python_security_advisor_payload(runtime_config: dict[str, object]) -> dict[str, object]:
    args = argparse.Namespace(
        admin_web=True,
        admin_web_bind="127.0.0.1",
        admin_web_port=18080,
        admin_web_path="/",
        admin_web_landing_page_disable=False,
        admin_web_security_advisor_disable=False,
        admin_web_security_advisor_startup_disable=False,
        admin_web_first_tab="home",
        admin_web_token="",
        admin_web_auth_disable=False,
        admin_web_username="",
        admin_web_password="",
        secure_link_mode="off",
        secure_link_psk="",
        _first_start_detected=False,
        _config_file_state="unknown",
    )
    for key, value in runtime_config.items():
        setattr(args, key, value)
    ui = AdminWebUI(args, _PythonAdminRunnerStub())
    return ui._build_security_advisor_payload()


def _python_tun_routing_payload(connections_snapshot: dict[str, object]) -> dict[str, object]:
    args = argparse.Namespace(
        admin_web=True,
        admin_web_bind="127.0.0.1",
        admin_web_port=18080,
        admin_web_path="/",
        admin_web_landing_page_disable=False,
        admin_web_security_advisor_disable=False,
        admin_web_security_advisor_startup_disable=False,
        admin_web_first_tab="home",
        admin_web_token="",
        admin_web_auth_disable=False,
        admin_web_username="",
        admin_web_password="",
        secure_link_mode="off",
        secure_link_psk="",
        _first_start_detected=False,
        _config_file_state="unknown",
    )
    ui = AdminWebUI(args, _PythonAdminRunnerStub(connections_snapshot))
    return ui._build_tun_routing_payload()


@pytest.fixture(scope="session")
def swift_admin_web_component_runner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        pytest.skip("swiftc is required for Swift admin web parity tests")
    output_dir = tmp_path_factory.mktemp("swift_admin_web_component")
    binary = output_dir / "admin_web_component_runner"
    command = [
        swiftc,
        "-o",
        str(binary),
        str(SWIFT_CHANNELMUX_CODEC_SOURCE),
        str(SWIFT_OVERLAY_STACK_PLANNER_SOURCE),
        str(SWIFT_RUNTIME_CONFIG_SOURCE),
        str(SWIFT_ADMIN_WEB_SUPPORT_SOURCE),
        str(SWIFT_ADMIN_SNAPSHOT_SUPPORT_SOURCE),
        str(SWIFT_ADMIN_API_SOURCE),
        str(SWIFT_ADMIN_COMPONENT_RUNNER_SOURCE),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"failed to compile Swift Admin Web component runner\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return binary


def _run_swift_component(binary: Path, request: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        [str(binary)],
        input=json.dumps(request),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Swift admin web component runner failed\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def test_swift_admin_ui_payload_matches_python(swift_admin_web_component_runner: Path) -> None:
    runtime_config = {
        "overlay_transport": "ws",
        "ws_peer": "bridge.example.net",
        "ws_peer_port": 8443,
        "admin_web_first_tab": "logs",
        "admin_web_security_advisor_startup_disable": True,
        "admin_web_security_advisor_disable": False,
        "admin_web_landing_page_disable": True,
        "_config_file_state": "loaded",
    }
    python = _python_admin_ui_payload(runtime_config, platform="ios")
    runtime_dependencies = json.loads(json.dumps(python["runtime_dependencies"]))
    python["runtime_dependencies"] = runtime_dependencies
    swift = _run_swift_component(
        swift_admin_web_component_runner,
        {
            "action": "admin_ui_payload",
            "runtime_config": runtime_config,
            "platform": "ios",
            "runtime_dependencies": runtime_dependencies,
        },
    )
    assert swift["payload"] == python


def test_swift_security_advisor_payload_matches_python(swift_admin_web_component_runner: Path) -> None:
    runtime_config = {
        "admin_web": True,
        "admin_web_bind": "0.0.0.0",
        "admin_web_auth_disable": True,
        "secure_link_mode": "psk",
        "secure_link_psk": "short-psk",
    }
    python = _python_security_advisor_payload(runtime_config)
    swift = _run_swift_component(
        swift_admin_web_component_runner,
        {
            "action": "security_advisor_payload",
            "runtime_config": runtime_config,
            "bind_host_fallback": "127.0.0.1",
        },
    )
    assert swift["payload"] == python


def test_swift_tun_routing_snapshot_matches_python(swift_admin_web_component_runner: Path) -> None:
    connections_snapshot = {
        "udp": [],
        "tcp": [],
        "tun": [
            {
                "peer_id": "0:1",
                "protocol": "tun",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_id": 3,
                "service_name": "shared-tun",
                "local": {"ifname": "obtun0", "mtu": 1500},
                "remote_destination": {"ifname": "obtun1", "mtu": 1500},
                "stats": {"rx_bytes": 0, "tx_bytes": 0, "rx_msgs": 0, "tx_msgs": 0},
                "shared_tun_ownership": {
                    "mode": "server_shared",
                    "peer_count": 2,
                    "address_count": 4,
                    "peer_refs": ["linux-client", "ios-client"],
                    "peers": [
                        {"peer_ref": "linux-client", "ipv4": ["192.168.107.2"], "ipv6": ["fd20:107::2"]},
                        {"peer_ref": "ios-client", "ipv4": ["192.168.107.4"], "ipv6": ["fd20:107::4"]},
                    ],
                    "active_peer_bindings": [
                        {"peer_id": 7, "preferred_chan_id": 301, "bound_chan_ids": [301]},
                    ],
                    "drop_counters": {
                        "total": 3,
                        "by_reason": {
                            "unknown_destination": 2,
                            "source_not_owned_by_peer": 1,
                        },
                    },
                    "recent_drops": [
                        {
                            "reason": "unknown_destination",
                            "direction": "local_to_peer",
                            "peer_id": None,
                            "chan_id": None,
                            "ip_version": 4,
                            "source_ip": None,
                            "destination_ip": "192.168.107.9",
                            "route_class": "unicast",
                            "packet_bytes": 21,
                        }
                    ],
                },
            },
            {
                "peer_id": "0:2",
                "protocol": "tun",
                "role": "server",
                "state": "connected",
                "chan_id": 18,
                "svc_id": 4,
                "service_name": "plain-tun",
                "local": {"ifname": "obtun2", "mtu": 1500},
                "remote_destination": {"ifname": "obtun3", "mtu": 1500},
                "stats": {"rx_bytes": 1, "tx_bytes": 2, "rx_msgs": 3, "tx_msgs": 4},
            },
        ],
        "counts": {
            "udp": 0,
            "tcp": 0,
            "tun": 2,
            "udp_listening": 0,
            "tcp_listening": 0,
            "tun_listening": 1,
        },
    }
    python = _python_tun_routing_payload(connections_snapshot)
    swift = _run_swift_component(
        swift_admin_web_component_runner,
        {
            "action": "derive_tun_routing_snapshot",
            "connections_snapshot": connections_snapshot,
        },
    )
    assert swift["payload"] == python


def test_swift_admin_api_tun_routing_route_matches_python(swift_admin_web_component_runner: Path) -> None:
    connections_snapshot = {
        "udp": [],
        "tcp": [],
        "tun": [
            {
                "peer_id": "0:1",
                "protocol": "tun",
                "role": "server",
                "state": "listening",
                "chan_id": None,
                "svc_id": 3,
                "service_name": "shared-tun",
                "shared_tun_ownership": {"active_peer_bindings": [{"peer_id": 7}]},
            }
        ],
        "counts": {"udp": 0, "tcp": 0, "tun": 1, "udp_listening": 0, "tcp_listening": 0, "tun_listening": 1},
    }
    tun_routing = _python_tun_routing_payload(connections_snapshot)
    swift = _run_swift_component(
        swift_admin_web_component_runner,
        {
            "action": "admin_api_request",
            "request": {"method": "GET", "path": "/api/tun-routing/status"},
            "connections_snapshot": connections_snapshot,
            "tun_routing_snapshot": tun_routing,
        },
    )
    assert swift["ok"] is True
    assert swift["status_line"] == "HTTP/1.1 200 OK"
    assert swift["body_json"] == tun_routing


def test_swift_admin_api_live_topic_tun_routing_matches_python(swift_admin_web_component_runner: Path) -> None:
    connections_snapshot = {
        "udp": [],
        "tcp": [],
        "tun": [{"state": "connected", "chan_id": 11, "shared_tun_ownership": {"active_peer_bindings": []}}],
    }
    tun_routing = _python_tun_routing_payload(connections_snapshot)
    swift = _run_swift_component(
        swift_admin_web_component_runner,
        {
            "action": "admin_api_live_topic_payload",
            "topic": "tun_routing",
            "connections_snapshot": connections_snapshot,
            "tun_routing_snapshot": tun_routing,
        },
    )
    assert swift["payload"] == tun_routing
