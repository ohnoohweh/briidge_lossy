from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "swift" / "Sources" / "ObstacleBridgeCore"


def test_runtime_config_peer_exclusions_are_portable_and_dual_stack(tmp_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for the portable runtime-config policy test")
    probe = tmp_path / "RuntimeConfigPolicyProbe.swift"
    binary = tmp_path / "runtime-config-policy-probe"
    probe.write_text(textwrap.dedent("""
        import Foundation

        @main
        struct RuntimeConfigPolicyProbe {
            static func main() throws {
                let websocket = ObstacleBridgeRuntimeConfigPolicy.overlayPeerExcludedRoutes(from: [
                    "overlay_transport": "ws",
                    "ws_peer": "ignored.example",
                    "ws_peer_port": 443,
                    "ws_bind": "::",
                    "ws_peer_addresses": ["192.0.2.80; [2001:db8::80]"],
                ])
                let mapped = ObstacleBridgeRuntimeConfigPolicy.overlayPeerExcludedRoutes(from: [
                    "overlay_transport": "tcp",
                    "tcp_peer": "::ffff:198.51.100.10",
                    "tcp_peer_port": 443,
                    "tcp_bind": "::",
                ])
                let ipv4Only = ObstacleBridgeRuntimeConfigPolicy.overlayPeerExcludedRoutes(from: [
                    "overlay_transport": "tcp",
                    "tcp_peer": "2001:db8::44",
                    "tcp_peer_port": 443,
                    "tcp_peer_resolve_family": "ipv4",
                ])
                let output: [String: Any] = [
                    "websocket4": websocket.ipv4,
                    "websocket6": websocket.ipv6,
                    "mapped4": mapped.ipv4,
                    "mapped6": mapped.ipv6,
                    "ipv4_only4": ipv4Only.ipv4,
                    "ipv4_only6": ipv4Only.ipv6,
                ]
                FileHandle.standardOutput.write(
                    try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
                )
            }
        }
        """), encoding="utf-8")
    completed = subprocess.run(
        [
            swiftc,
            "-o", str(binary),
            str(CORE / "ObstacleBridgePacketTunnelRoutePolicy.swift"),
            str(CORE / "ObstacleBridgeRuntimeConfigPolicy.swift"),
            str(probe),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"swiftc failed:\n{completed.stderr}")
    output = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    assert json.loads(output.stdout) == {
        "websocket4": ["192.0.2.80/32"],
        "websocket6": ["::ffff:192.0.2.80/128", "2001:db8::80/128"],
        "mapped4": ["198.51.100.10/32"],
        "mapped6": ["::ffff:198.51.100.10/128"],
        "ipv4_only4": [],
        "ipv4_only6": [],
    }
