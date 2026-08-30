from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ios" / "native" / "ObstacleBridgeShared" / "ObstacleBridgePeerAddressProtocolRuntime.swift"


def test_ios_peer_address_protocol_reflects_ipv4_and_ipv6_without_delivering_control(tmp_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for the Swift peer-address protocol test")
    probe = tmp_path / "PeerAddressProtocolProbe.swift"
    binary = tmp_path / "peer-address-protocol-probe"
    probe.write_text(textwrap.dedent("""
        import Foundation

        @main
        struct PeerAddressProtocolProbe {
            static func reflected(_ host: String) -> String {
                let client = ObstacleBridgePeerAddressProtocolRuntime(clientMode: true)
                let server = ObstacleBridgePeerAddressProtocolRuntime(clientMode: false)
                let request = client.handleTransportConnected().first!
                let reply = server.handleInboundFrame(request, observedPeerHost: host)
                _ = client.handleInboundFrame(reply.emittedFrames.first!)
                return client.observedPublicIP
            }

            static func main() throws {
                let ordinary = ObstacleBridgePeerAddressProtocolRuntime(clientMode: true)
                    .handleInboundFrame(Data([0x01, 0x02]))
                let output: [String: Any] = [
                    "ipv4": reflected("198.51.100.44"),
                    "ipv6": reflected("2001:db8::44"),
                    "mapped_ipv4": reflected("::ffff:198.51.100.44"),
                    "ordinary_consumed": ordinary.consumed,
                ]
                FileHandle.standardOutput.write(
                    try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
                )
            }
        }
        """), encoding="utf-8")
    completed = subprocess.run(
        [swiftc, "-o", str(binary), str(SOURCE), str(probe)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"swiftc failed:\n{completed.stderr}")
    output = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    assert json.loads(output.stdout) == {
        "ipv4": "198.51.100.44",
        "ipv6": "2001:db8::44",
        "mapped_ipv4": "198.51.100.44",
        "ordinary_consumed": False,
    }
