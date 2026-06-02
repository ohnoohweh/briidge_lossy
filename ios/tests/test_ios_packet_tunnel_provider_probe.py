from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from swift_test_support import require_swift_modules


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"
IPSERVER_NATIVE_DIR = ROOT / "ios" / "native" / "IPServer"


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _unused_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _unused_udp_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        ports: list[int] = []
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
            ports.append(int(sock.getsockname()[1]))
        return ports
    finally:
        for sock in sockets:
            sock.close()


def _compile_swift_packet_tunnel_provider_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = require_swift_modules(
        "CryptoKit",
        "zlib",
        missing_swiftc_reason="swiftc is required for PacketTunnelProvider probe tests",
        missing_module_reason="PacketTunnelProvider probe tests require a Swift toolchain with CryptoKit and zlib support",
    )
    command = [
        swiftc,
        "-DOB_IPSERVER_SWIFT_SMOKE",
        "-DOB_IPSERVER_SWIFT_PROBE",
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminAPI.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminAuth.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminConfigChallenge.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminConfigSupport.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeConfigSecretCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminSnapshotSupport.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeAdminWebSupport.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeNativeCrypto.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOnboarding.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeNativeServiceSpec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeNativeProxyConnections.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayConnectionSupport.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgePeerAddressResolver.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxUdpRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTunRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayTransportOwner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTcpRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTCPTransportOwner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgePacketTunnelConfiguration.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeWebAdminServer.swift"),
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
    bind_port_a, bind_port_b = _unused_udp_ports(2)
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


def test_ios_packet_tunnel_provider_probe_resolves_multi_host_peer_with_family_preference(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderPeerResolutionProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-peer-resolution-probe"
    bind_port_v6 = _unused_udp_port()
    bind_port_v4 = _unused_udp_port()
    peer_port_v6 = _unused_udp_port()
    peer_port_v4 = _unused_udp_port()
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case invalidArgs
            }

            @main
            struct PacketTunnelProviderPeerResolutionProbeMain {
                static func main() throws {
                    guard CommandLine.arguments.count == 5 else {
                        throw ProbeError.invalidArgs
                    }
                    guard
                        let bindPortV6 = Int(CommandLine.arguments[1]),
                        let bindPortV4 = Int(CommandLine.arguments[2]),
                        let peerPortV6 = Int(CommandLine.arguments[3]),
                        let peerPortV4 = Int(CommandLine.arguments[4])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let preferBridge = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "::",
                        bindPort: bindPortV6,
                        peerHost: "[::1],127.0.0.1",
                        peerPort: peerPortV6,
                        peerResolveFamily: "prefer-ipv6",
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.1",
                        tcpServiceSpecs: []
                    )
                    let fallbackBridge = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "127.0.0.1",
                        bindPort: bindPortV4,
                        peerHost: "[::1],127.0.0.1",
                        peerPort: peerPortV4,
                        peerResolveFamily: "prefer-ipv6",
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.2",
                        tcpServiceSpecs: []
                    )

                    let payload: [String: Any] = [
                        "prefer": preferBridge.bridgeSnapshot(),
                        "fallback": fallbackBridge.bridgeSnapshot(),
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
        [str(binary_path), str(bind_port_v6), str(bind_port_v4), str(peer_port_v6), str(peer_port_v4)],
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
    assert payload["prefer"]["resolved_peer_family"] == "ipv6"
    assert payload["prefer"]["resolved_peer_host"] == "::1"
    assert payload["prefer"]["resolved_peer_port"] == peer_port_v6
    assert payload["fallback"]["resolved_peer_family"] == "ipv4"
    assert payload["fallback"]["resolved_peer_host"] == "127.0.0.1"
    assert payload["fallback"]["resolved_peer_port"] == peer_port_v4


def test_ios_packet_tunnel_provider_probe_uses_tun_routing_for_full_route_and_address_setup(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderTunRoutingProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-tun-routing-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            @main
            struct PacketTunnelProviderTunRoutingProbeMain {
                static func main() throws {
                    let configuration = try ObstacleBridgePacketTunnelConfiguration(
                        [
                            "peer": ["host": "127.0.0.1"],
                            "runtime_config": [
                                "TUN_routing": [
                                    "tunnel_address": ["192.168.205.1"],
                                    "tunnel_prefix": 29,
                                    "included_routes": ["198.18.0.0/15"],
                                    "excluded_routes": ["127.0.0.0/8"],
                                    "tunnel_address6": ["fd20:205::1"],
                                    "tunnel_prefix6": 124,
                                    "included_routes6": ["2001:db8:205::/64"],
                                    "excluded_routes6": ["::1/128"],
                                    "dns_servers": ["9.9.9.9"],
                                    "mtu": 1600,
                                ],
                            ],
                        ],
                        defaults: ObstacleBridgePacketTunnelDefaults(
                            tunnelAddress: "192.168.106.1",
                            tunnelPrefix: 30,
                            includedRoutes: ["0.0.0.0/0"],
                            excludedRoutes: [],
                            tunnelAddress6: "fd20:106::1",
                            tunnelPrefix6: 126,
                            includedRoutes6: ["::/0"],
                            excludedRoutes6: []
                        )
                    )

                    let payload: [String: Any] = [
                        "tunnel_address": configuration.tunnelAddress,
                        "tunnel_subnet_mask": configuration.tunnelSubnetMask,
                        "included_routes": configuration.includedRoutes.map {
                            ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask]
                        },
                        "excluded_routes": configuration.excludedRoutes.map {
                            ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask]
                        },
                        "tunnel_address6": configuration.tunnelAddress6,
                        "tunnel_prefix6": configuration.tunnelPrefix6,
                        "included_routes6": configuration.includedRoutes6.map {
                            ["destination": $0.destinationAddress, "prefix": $0.networkPrefixLength]
                        },
                        "excluded_routes6": configuration.excludedRoutes6.map {
                            ["destination": $0.destinationAddress, "prefix": $0.networkPrefixLength]
                        },
                        "dns_servers": configuration.dnsServers,
                        "mtu": configuration.mtu,
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
        [str(binary_path)],
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
    assert payload["tunnel_address"] == "192.168.205.1"
    assert payload["tunnel_subnet_mask"] == "255.255.255.248"
    assert payload["included_routes"] == [{"destination": "198.18.0.0", "subnet_mask": "255.254.0.0"}]
    assert payload["excluded_routes"] == [{"destination": "127.0.0.0", "subnet_mask": "255.0.0.0"}]
    assert payload["tunnel_address6"] == "fd20:205::1"
    assert payload["tunnel_prefix6"] == 124
    assert payload["included_routes6"] == [{"destination": "2001:db8:205::", "prefix": 64}]
    assert payload["excluded_routes6"] == [{"destination": "::1", "prefix": 128}]
    assert payload["dns_servers"] == ["9.9.9.9"]
    assert payload["mtu"] == 1600


def test_ios_packet_tunnel_provider_probe_accepts_non_capturing_onboarding_network_settings(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderOnboardingRoutesProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-onboarding-routes-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            @main
            struct PacketTunnelProviderOnboardingRoutesProbeMain {
                static func main() throws {
                    let configuration = try ObstacleBridgePacketTunnelConfiguration(
                        [
                            "peer": ["host": "bootstrap.invalid"],
                            "network_settings": [
                                "tunnel_address": "192.168.106.1",
                                "tunnel_prefix": 30,
                                "included_routes": [],
                                "excluded_routes": [],
                                "tunnel_address6": "fd20:106::1",
                                "tunnel_prefix6": 126,
                                "included_routes6": [],
                                "excluded_routes6": [],
                                "dns_servers": ["1.1.1.1"],
                                "mtu": 1400,
                            ],
                            "runtime_config": [
                                "iOS_TUN_connector": [
                                    "packetflow_connector": "swift_udp",
                                    "bind_host": "127.0.0.1",
                                    "bind_port": 5555,
                                    "peer_host": "",
                                    "peer_port": 0,
                                ],
                            ],
                        ],
                        defaults: ObstacleBridgePacketTunnelDefaults(
                            tunnelAddress: "192.168.106.1",
                            tunnelPrefix: 30,
                            includedRoutes: ["0.0.0.0/0"],
                            excludedRoutes: ["127.0.0.0/8"],
                            tunnelAddress6: "fd20:106::1",
                            tunnelPrefix6: 126,
                            includedRoutes6: ["::/0"],
                            excludedRoutes6: ["::1/128"]
                        )
                    )

                    let payload: [String: Any] = [
                        "tunnel_address": configuration.tunnelAddress,
                        "included_routes": configuration.includedRoutes.map {
                            ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask]
                        },
                        "excluded_routes": configuration.excludedRoutes.map {
                            ["destination": $0.destinationAddress, "subnet_mask": $0.subnetMask]
                        },
                        "tunnel_address6": configuration.tunnelAddress6,
                        "included_routes6": configuration.includedRoutes6.map {
                            ["destination": $0.destinationAddress, "prefix": $0.networkPrefixLength]
                        },
                        "excluded_routes6": configuration.excludedRoutes6.map {
                            ["destination": $0.destinationAddress, "prefix": $0.networkPrefixLength]
                        },
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
        [str(binary_path)],
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
    assert payload["tunnel_address"] == "192.168.106.1"
    assert payload["included_routes"] == []
    assert payload["excluded_routes"] == []
    assert payload["tunnel_address6"] == "fd20:106::1"
    assert payload["included_routes6"] == []
    assert payload["excluded_routes6"] == []


def test_ios_packet_tunnel_provider_probe_swift_udp_empty_connector_peer_falls_back_to_overlay_peer(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderSwiftUDPFallbackProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-swift-udp-fallback-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            @main
            struct PacketTunnelProviderSwiftUDPFallbackProbeMain {
                static func main() throws {
                    let payload: [String: Any] = [
                        "overlay_transport": "myudp",
                        "udp_peer": "38.180.143.5",
                        "udp_peer_port": 4433,
                        "iOS_TUN_connector": [
                            "packetflow_connector": "swift_udp",
                            "bind_host": "0.0.0.0",
                            "bind_port": 5555,
                            "peer_host": "",
                            "peer_port": 0,
                            "ifname": "ios-utun",
                            "mtu": 1600,
                        ],
                    ]
                    guard let config = ObstacleBridgeRuntimeConfig.swiftUDPPeerConfig(from: payload, defaultMTU: 1600) else {
                        throw NSError(domain: "PacketTunnelProviderProbe", code: 1, userInfo: [NSLocalizedDescriptionKey: "swiftUDPPeerConfig returned nil"])
                    }
                    let result: [String: Any] = [
                        "runtime_mode": config.runtimeMode,
                        "peer_host": config.peerHost,
                        "peer_port": config.peerPort,
                        "bind_host": config.bindHost,
                        "bind_port": config.bindPort,
                    ]
                    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_packet_tunnel_provider_probe(source_path, binary_path)
    completed = subprocess.run(
        [str(binary_path)],
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
    assert payload["runtime_mode"] == "swift_udp"
    assert payload["peer_host"] == "38.180.143.5"
    assert payload["peer_port"] == 4433
    assert payload["bind_host"] == "127.0.0.1"
    assert payload["bind_port"] == 5555


def test_ios_packet_tunnel_provider_probe_rotates_to_next_peer_candidate_after_idle_timeout(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderPeerFallbackProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-peer-fallback-probe"
    bind_port = _unused_udp_port()
    peer_port = _unused_udp_port()
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case invalidArgs
            }

            @main
            struct PacketTunnelProviderPeerFallbackProbeMain {
                static func main() throws {
                    guard CommandLine.arguments.count == 3 else {
                        throw ProbeError.invalidArgs
                    }
                    guard
                        let bindPort = Int(CommandLine.arguments[1]),
                        let peerPort = Int(CommandLine.arguments[2])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let bridge = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "::",
                        bindPort: bindPort,
                        peerHost: "[::1],127.0.0.1",
                        peerPort: peerPort,
                        peerResolveFamily: "prefer-ipv6",
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.1",
                        tcpServiceSpecs: []
                    )

                    bridge.start()
                    Thread.sleep(forTimeInterval: 4.2)
                    let payload = bridge.bridgeSnapshot()
                    bridge.stop()

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
        [str(binary_path), str(bind_port), str(peer_port)],
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
    assert payload["resolved_peer_candidate_count"] == 2
    assert payload["resolved_peer_index"] == 1
    assert payload["resolved_peer_port"] == peer_port
    assert payload["resolved_peer_host"] != "::1"


def test_ios_packet_tunnel_provider_probe_immediately_rotates_after_unreachable_ipv6_send_error(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderImmediatePeerFallbackProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-immediate-peer-fallback-probe"
    bind_port = _unused_udp_port()
    peer_port = _unused_udp_port()
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case invalidArgs
            }

            @main
            struct PacketTunnelProviderImmediatePeerFallbackProbeMain {
                static func main() throws {
                    guard CommandLine.arguments.count == 3 else {
                        throw ProbeError.invalidArgs
                    }
                    guard
                        let bindPort = Int(CommandLine.arguments[1]),
                        let peerPort = Int(CommandLine.arguments[2])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let bridge = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "::",
                        bindPort: bindPort,
                        peerHost: "[2001:db8::10],127.0.0.1",
                        peerPort: peerPort,
                        peerResolveFamily: "prefer-ipv6",
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.1",
                        tcpServiceSpecs: []
                    )

                    bridge.start()
                    Thread.sleep(forTimeInterval: 0.35)
                    let payload = bridge.bridgeSnapshot()
                    bridge.stop()

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
        [str(binary_path), str(bind_port), str(peer_port)],
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
    assert payload["resolved_peer_candidate_count"] == 2
    assert payload["resolved_peer_index"] == 1
    assert payload["resolved_peer_family"] == "ipv6"
    assert payload["resolved_peer_host"].endswith("127.0.0.1")
    assert payload["resolved_peer_port"] == peer_port


def test_ios_packet_tunnel_provider_probe_decrypts_embedded_runtime_config(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderDecryptProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-decrypt-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case decodeFailed
                case badValue
            }

            @main
            struct PacketTunnelProviderDecryptProbeMain {
                static func main() throws {
                    let grouped: [String: Any] = [
                        "secure_link": [
                            "secure_link": true,
                            "secure_link_mode": "psk",
                            "secure_link_psk": "correct horse battery staple",
                        ],
                        "udp_session": [
                            "udp_peer": "38.180.143.5",
                            "udp_peer_port": 4433,
                        ],
                        "runner": [
                            "overlay_transport": "myudp",
                        ],
                    ]
                    let encrypted = try PacketTunnelProvider.probeEncodedProviderRuntimeConfig(
                        runtimeConfig: grouped
                    )
                    let providerConfiguration: [String: Any] = [
                        "schema": "obstaclebridge.ios.packet-tunnel.v1",
                        "runtime_config": encrypted,
                    ]
                    guard let decoded = PacketTunnelProvider.probeDecodedProviderRuntimeConfig(
                        providerConfiguration: providerConfiguration
                    ) else {
                        throw ProbeError.decodeFailed
                    }
                    let flattened = ObstacleBridgeRuntimeConfig.flatten(decoded)
                    guard (flattened["secure_link_psk"] as? String) == "correct horse battery staple" else {
                        throw ProbeError.badValue
                    }
                    let output: [String: Any] = [
                        "psk": flattened["secure_link_psk"] as? String ?? "",
                        "udp_peer": flattened["udp_peer"] as? String ?? "",
                        "udp_peer_port": flattened["udp_peer_port"] as? Int ?? 0,
                    ]
                    let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_packet_tunnel_provider_probe(source_path, binary_path)
    completed = subprocess.run(
        [str(binary_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"decrypt probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )

    payload = json.loads(completed.stdout)
    assert payload["psk"] == "correct horse battery staple"
    assert payload["udp_peer"] == "38.180.143.5"
    assert payload["udp_peer_port"] == 4433


def test_ios_packet_tunnel_provider_probe_exposes_myudp_runtime_stats(tmp_path: Path) -> None:
    source_path = tmp_path / "PacketTunnelProviderMyudpRuntimeProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-myudp-runtime-probe"
    bind_port_a, bind_port_b = _unused_udp_ports(2)
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case invalidArgs
                case timeout
                case badSnapshot
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

            @main
            struct PacketTunnelProviderMyudpRuntimeProbeMain {
                static func main() throws {
                    guard CommandLine.arguments.count == 3 else {
                        throw ProbeError.invalidArgs
                    }
                    guard
                        let bindPortA = Int(CommandLine.arguments[1]),
                        let bindPortB = Int(CommandLine.arguments[2])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let psk = "probe-runtime-psk"
                    let adapterA = ObstacleBridgeOverlayLayerTransportAdapter(
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(clientMode: true, psk: psk)
                        )
                    )
                    let adapterB = ObstacleBridgeOverlayLayerTransportAdapter(
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(clientMode: false, psk: psk)
                        )
                    )

                    let bridgeA = try PacketTunnelProviderSwiftUDPBridgeProbe(
                        runtimeMode: "swift_udp",
                        bindHost: "127.0.0.1",
                        bindPort: bindPortA,
                        peerHost: "127.0.0.1",
                        peerPort: bindPortB,
                        mtu: 1400,
                        tunIfname: "ios-utun",
                        tunnelAddress: "192.168.106.1",
                        tcpServiceSpecs: [],
                        overlayLayerTransportAdapter: adapterA
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
                        tcpServiceSpecs: [],
                        overlayLayerTransportAdapter: adapterB
                    )

                    bridgeA.start()
                    bridgeB.start()
                    defer {
                        bridgeA.stop()
                        bridgeB.stop()
                    }

                    guard waitForCondition(timeout: 3.0, {
                        bridgeA.overlayEstablished() && bridgeB.overlayEstablished()
                    }) else {
                        throw ProbeError.timeout
                    }

                    let snapshot = bridgeA.bridgeSnapshot()
                    guard let runtime = snapshot["myudp_runtime"] as? [String: Any] else {
                        throw ProbeError.badSnapshot
                    }
                    let payload: [String: Any] = [
                        "has_runtime": true,
                        "rtt_est_ms": runtime["rtt_est_ms"] as? Double ?? -1,
                        "transmit_delay_est_ms": runtime["transmit_delay_est_ms"] as? Double ?? -1,
                        "has_last_rx_wall_ns": (runtime["last_rx_wall_ns"] as? UInt64 ?? 0) > 0,
                        "protocol_stats_present": runtime["protocol_stats"] != nil,
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
        [str(binary_path), str(bind_port_a), str(bind_port_b)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"myudp runtime probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )

    payload = json.loads(completed.stdout)
    assert payload["has_runtime"] is True
    assert payload["rtt_est_ms"] >= 0
    assert payload["transmit_delay_est_ms"] >= 0
    assert payload["has_last_rx_wall_ns"] is True
    assert payload["protocol_stats_present"] is True


def test_ios_packet_tunnel_provider_probe_secure_link_tcp_own_server_roundtrips_payload(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "PacketTunnelProviderOwnServerRoundtripProbe.swift"
    binary_path = tmp_path / "packet-tunnel-provider-own-server-roundtrip-probe"
    bind_port_a, bind_port_b = _unused_udp_ports(2)
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
                case accept(String)
                case shortRead(String)
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
                guard listen(fd, 4) == 0 else {
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

            private func readOnce(_ fd: Int32, maxBytes: Int = 4096) throws -> Data {
                var buffer = [UInt8](repeating: 0, count: maxBytes)
                let received = recv(fd, &buffer, maxBytes, 0)
                if received < 0 {
                    throw ProbeError.socket("recv")
                }
                if received == 0 {
                    throw ProbeError.shortRead("eof")
                }
                return Data(buffer[0..<received])
            }

            @main
            struct PacketTunnelProviderOwnServerRoundtripProbeMain {
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

                    let psk = "probe-own-server-psk"
                    let adapterA = ObstacleBridgeOverlayLayerTransportAdapter(
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(clientMode: true, psk: psk)
                        )
                    )
                    let adapterB = ObstacleBridgeOverlayLayerTransportAdapter(
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(clientMode: false, psk: psk)
                        )
                    )

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
                        tcpServiceSpecs: [serviceSpec],
                        overlayLayerTransportAdapter: adapterA
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
                        tcpServiceSpecs: [],
                        overlayLayerTransportAdapter: adapterB
                    )
                    defer {
                        bridgeA.stop()
                        bridgeB.stop()
                    }

                    bridgeA.start()
                    bridgeB.start()

                    guard waitForCondition(timeout: 5.0, {
                        bridgeA.overlayEstablished() && bridgeB.overlayEstablished()
                    }) else {
                        throw ProbeError.timeout("overlay_established")
                    }
                    guard waitForCondition(timeout: 5.0, {
                        (bridgeA.secureLinkStatus()["authenticated"] as? Bool ?? false)
                        && (bridgeB.secureLinkStatus()["authenticated"] as? Bool ?? false)
                    }) else {
                        throw ProbeError.timeout("secure_link_authenticated")
                    }

                    var targetAccepted = false
                    var targetReadText = ""
                    var targetAcceptError = ""
                    var targetReadError = ""
                    let reply = Data("own-server-roundtrip-response".utf8)
                    DispatchQueue.global().async {
                        var acceptedAddr = sockaddr()
                        var acceptedLen: socklen_t = socklen_t(MemoryLayout<sockaddr>.size)
                        let targetFD = accept(passiveServerFD, &acceptedAddr, &acceptedLen)
                        guard targetFD >= 0 else {
                            targetAcceptError = "accept"
                            return
                        }
                        targetAccepted = true
                        defer { close(targetFD) }
                        setSocketTimeout(targetFD, seconds: 5)
                        do {
                            let targetRead = try readOnce(targetFD)
                            targetReadText = String(data: targetRead, encoding: .utf8) ?? ""
                            try writeAll(targetFD, data: reply)
                            usleep(750_000)
                        } catch {
                            targetReadError = String(describing: error)
                        }
                    }

                    let clientFD = try connectSocket(port: listenerPort)
                    defer { close(clientFD) }
                    let request = Data("own-server-roundtrip-request".utf8)
                    try writeAll(clientFD, data: request)

                    guard waitForCondition(timeout: 5.0, { targetAccepted || !targetAcceptError.isEmpty }) else {
                        throw ProbeError.timeout("target_accept_wait")
                    }
                    guard targetAccepted else {
                        throw ProbeError.accept(targetAcceptError)
                    }

                    guard waitForCondition(timeout: 5.0, { !targetReadText.isEmpty || !targetReadError.isEmpty }) else {
                        throw ProbeError.timeout("target_read_wait")
                    }
                    guard targetReadError.isEmpty else {
                        throw ProbeError.socket("target_read:\(targetReadError)")
                    }

                    var clientReadText = ""
                    var clientReadError = ""
                    DispatchQueue.global().async {
                        do {
                            let clientRead = try readOnce(clientFD)
                            clientReadText = String(data: clientRead, encoding: .utf8) ?? ""
                        } catch {
                            clientReadError = String(describing: error)
                        }
                    }

                    guard waitForCondition(timeout: 5.0, { !clientReadText.isEmpty || !clientReadError.isEmpty }) else {
                        throw ProbeError.timeout("client_read_wait")
                    }
                    guard clientReadError.isEmpty else {
                        throw ProbeError.socket("client_read:\(clientReadError)")
                    }

                    guard waitForCondition(timeout: 5.0, {
                        let rows = bridgeA.adminConnectionsSnapshot()["tcp"] as? [[String: Any]] ?? []
                        return rows.contains { row in
                            let stats = row["stats"] as? [String: Any] ?? [:]
                            return ((stats["rx_bytes"] as? Int) ?? 0) > 0 && ((stats["tx_bytes"] as? Int) ?? 0) > 0
                        }
                    }) else {
                        throw ProbeError.timeout("admin_connection_traffic")
                    }

                    let payload: [String: Any] = [
                        "target_received": targetReadText,
                        "client_received": clientReadText,
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
            f"own-server roundtrip probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )

    payload = json.loads(completed.stdout)
    assert payload["target_received"] == "own-server-roundtrip-request"
    assert payload["client_received"] == "own-server-roundtrip-response"
    assert any(
        (row.get("stats", {}).get("rx_bytes", 0) > 0 and row.get("stats", {}).get("tx_bytes", 0) > 0)
        for row in payload["bridge_a_connections"]["tcp"]
    )
