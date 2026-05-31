from __future__ import annotations

import json
import shutil
import socket
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
IPSERVER_NATIVE_DIR = ROOT / "ios" / "native" / "IPServer"


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _compile_swift_packet_tunnel_provider_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for PacketTunnelProvider probe tests")
    command = [
        swiftc,
        "-DOB_IPSERVER_SWIFT_SMOKE",
        "-DOB_IPSERVER_SWIFT_PROBE",
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminAPI.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTunRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTcpRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTCPTransportOwner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketPayloadCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeWebSocketOverlayRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeTcpOverlayRuntime.swift"),
        str(IPSERVER_NATIVE_DIR / "ObstacleBridgePacketFlowBridge.swift"),
        str(IPSERVER_NATIVE_DIR / "PacketTunnelProvider.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_packet_tunnel_provider_probe_serves_multiple_tcp_connections_in_admin_snapshot(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-probe"
    bind_port_a = _unused_tcp_port()
    bind_port_b = _unused_tcp_port()
    listener_port = _unused_tcp_port()
    target_port = _unused_tcp_port()
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation
            import Darwin

            enum ProbeError: Error {
                case invalidArgs
                case timeout(String)
                case socket(String)
                case badState(String)
            }

            private func waitForCondition(timeout: Double, intervalMicros: useconds_t = 20_000, _ condition: () -> Bool) -> Bool {
                let deadline = Date().timeIntervalSince1970 + timeout
                while Date().timeIntervalSince1970 < deadline {
                    if condition() {
                        return true
                    }
                    usleep(intervalMicros)
                }
                return condition()
            }

            private func setSocketTimeout(_ fd: Int32, seconds: Int) {
                var value = timeval(tv_sec: seconds, tv_usec: 0)
                _ = withUnsafePointer(to: &value) {
                    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
                }
                _ = withUnsafePointer(to: &value) {
                    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
                }
            }

            private func makeListeningSocket(port: Int) throws -> Int32 {
                let fd = socket(AF_INET, SOCK_STREAM, 0)
                guard fd >= 0 else {
                    throw ProbeError.socket("socket")
                }
                var reuse: Int32 = 1
                _ = withUnsafePointer(to: &reuse) {
                    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size))
                }
                var addr = sockaddr_in()
                addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = in_port_t(UInt16(port).bigEndian)
                addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
                let bindResult = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard bindResult == 0 else {
                    close(fd)
                    throw ProbeError.socket("bind")
                }
                guard listen(fd, 8) == 0 else {
                    close(fd)
                    throw ProbeError.socket("listen")
                }
                setSocketTimeout(fd, seconds: 5)
                return fd
            }

            private func connectSocket(port: Int) throws -> Int32 {
                let fd = socket(AF_INET, SOCK_STREAM, 0)
                guard fd >= 0 else {
                    throw ProbeError.socket("socket")
                }
                setSocketTimeout(fd, seconds: 5)
                var addr = sockaddr_in()
                addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = in_port_t(UInt16(port).bigEndian)
                addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
                let result = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard result == 0 else {
                    close(fd)
                    throw ProbeError.socket("connect")
                }
                return fd
            }

            private func writeAll(_ fd: Int32, data: Data) throws {
                try data.withUnsafeBytes { rawBuffer in
                    guard let baseAddress = rawBuffer.baseAddress else {
                        return
                    }
                    var offset = 0
                    while offset < rawBuffer.count {
                        let sent = send(fd, baseAddress.advanced(by: offset), rawBuffer.count - offset, 0)
                        if sent <= 0 {
                            throw ProbeError.socket("send")
                        }
                        offset += sent
                    }
                }
            }

            private func tcpCount(from snapshot: [String: Any]) -> Int {
                ((snapshot["counts"] as? [String: Any])?["tcp"] as? Int) ?? 0
            }

                private func statsReady(_ snapshot: [String: Any], key: String) -> Bool {
                    guard let rows = snapshot["tcp"] as? [[String: Any]], rows.count >= 2 else {
                        return false
                    }
                    return rows.allSatisfy { row in
                        guard let stats = row["stats"] as? [String: Any] else {
                            return false
                        }
                        return ((stats[key] as? Int) ?? 0) > 0
                    }
                }

            @main
            struct PacketTunnelProviderProbeMain {
                static func main() throws {
                    guard CommandLine.arguments.count == 5 else {
                        throw ProbeError.invalidArgs
                    }
                    guard
                        let bindPortA = Int(CommandLine.arguments[1]),
                        let bindPortB = Int(CommandLine.arguments[2]),
                        let listenerPort = Int(CommandLine.arguments[3]),
                        let targetPort = Int(CommandLine.arguments[4])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let serviceSpec = ObstacleBridgeChannelMuxCodec.ServiceSpec(
                        svcID: 1,
                        lProto: "tcp",
                        lBind: "127.0.0.1",
                        lPort: listenerPort,
                        rProto: "tcp",
                        rHost: "127.0.0.1",
                        rPort: targetPort,
                        name: "probe_tcp_service",
                        lifecycleHooks: nil,
                        options: nil
                    )

                        let passiveServerFD = try makeListeningSocket(port: targetPort)
                        defer { close(passiveServerFD) }

                    let bridgeA = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "127.0.0.1",
                        bindPort: bindPortA,
                        peerHost: "127.0.0.1",
                        peerPort: bindPortB,
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.1",
                        tcpServiceSpecs: [serviceSpec]
                    )
                    let bridgeB = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "127.0.0.1",
                        bindPort: bindPortB,
                        peerHost: "127.0.0.1",
                        peerPort: bindPortA,
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.2",
                        tcpServiceSpecs: []
                    )
                    defer {
                        bridgeA.stop()
                        bridgeB.stop()
                    }

                    bridgeA.start()
                    bridgeB.start()

                    guard waitForCondition(timeout: 5.0, { bridgeA.overlayEstablished() && bridgeB.overlayEstablished() }) else {
                        throw ProbeError.timeout("overlay_established")
                    }

                    let clientOne = try connectSocket(port: listenerPort)
                    let clientTwo = try connectSocket(port: listenerPort)
                    defer {
                        close(clientOne)
                        close(clientTwo)
                    }

                    try writeAll(clientOne, data: Data("alpha".utf8))
                    try writeAll(clientTwo, data: Data("bravo".utf8))

                    guard waitForCondition(timeout: 5.0, {
                            tcpCount(from: bridgeA.adminConnectionsSnapshot()) >= 2
                    }) else {
                        throw ProbeError.timeout("admin_connections_snapshot")
                    }

                        guard waitForCondition(timeout: 5.0, {
                            statsReady(bridgeA.adminConnectionsSnapshot(), key: "tx_bytes")
                        }) else {
                            throw ProbeError.timeout("admin_connection_traffic")
                        }

                    let payload: [String: Any] = [
                        "bridge_a_snapshot": bridgeA.bridgeSnapshot(),
                        "bridge_b_snapshot": bridgeB.bridgeSnapshot(),
                        "bridge_a_connections": bridgeA.adminConnectionsSnapshot(),
                        "bridge_b_connections": bridgeB.adminConnectionsSnapshot(),
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_packet_tunnel_provider_probe(source_path, binary_path)
    completed = subprocess.run(
        [str(binary_path), str(bind_port_a), str(bind_port_b), str(listener_port), str(target_port)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )

    payload = json.loads(completed.stdout)
    bridge_a_rows = payload["bridge_a_connections"]["tcp"]
    bridge_b_rows = payload["bridge_b_connections"]["tcp"]

    assert payload["bridge_a_connections"]["counts"]["tcp"] == 2
    assert sorted(row["chan_id"] for row in bridge_a_rows) == [1, 2]
    assert all(row["role"] == "server" for row in bridge_a_rows)
    assert all(row["state"] == "connected" for row in bridge_a_rows)
    assert all(row["stats"]["tx_bytes"] > 0 for row in bridge_a_rows)