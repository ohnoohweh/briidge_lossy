from __future__ import annotations

import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ios" / "src"))

from obstacle_bridge_ios.m25_ui import M25Config, profile_from_m25_config, tcp_status_probe


def test_profile_from_m25_config_builds_localhost_tcp_udp_entries() -> None:
    profile = profile_from_m25_config(
        M25Config(
            profile_id="ios-m25-a",
            display_name="M2.5",
            transport="ws",
            peer_host="bridge.example.net",
            peer_port=443,
            local_tcp_port=18080,
            local_udp_port=18081,
            target_host="10.0.0.10",
            target_tcp_port=8080,
            target_udp_port=8081,
        )
    )

    ob = profile["obstacle_bridge"]
    assert ob["overlay_transport"] == "ws"
    assert ob["ws_peer"] == "bridge.example.net"
    assert ob["ws_peer_port"] == 443
    assert len(ob["own_servers"]) == 2
    assert ob["own_servers"][0]["listen"]["bind"] == "127.0.0.1"
    assert ob["own_servers"][0]["listen"]["protocol"] == "tcp"
    assert ob["own_servers"][1]["listen"]["protocol"] == "udp"


def test_tcp_status_probe_reports_success_for_reachable_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        result = tcp_status_probe("127.0.0.1", port, timeout_sec=1.0)

    assert result["ok"] is True
    assert "succeeded" in result["detail"]


def test_tcp_status_probe_reports_failure_for_closed_port() -> None:
    result = tcp_status_probe("127.0.0.1", 1, timeout_sec=0.1)
    assert result["ok"] is False
    assert "failed" in result["detail"]
