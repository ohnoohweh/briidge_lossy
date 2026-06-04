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


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _compile_swift_tcp_transport_owner_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = require_swift_modules(
        "CryptoKit",
        "zlib",
        missing_swiftc_reason="swiftc is required for shared TCP transport owner tests",
        missing_module_reason="shared TCP transport owner tests require a Swift toolchain with CryptoKit and zlib support",
    )
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTcpRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTCPTransportOwner.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_shared_tcp_transport_owner_probe_covers_provider_accept_and_inbound_paths(tmp_path: Path) -> None:
    source_path = tmp_path / "TCPTransportOwnerProbe.swift"
    binary_path = tmp_path / "tcp-transport-owner-probe"
    local_service_port = _unused_tcp_port()
    target_service_port = _unused_tcp_port()
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation
            import Network
            import Darwin

            enum ProbeError: Error {
                case invalidArgs
                case timeout(String)
                case listenerFailed(String)
                case socket(String)
                case badState(String)
            }

            struct CapturedFrame {
                var chanID: Int
                var proto: String
                var mtype: String
                var bodyText: String
                var serviceID: Int?
                var remoteHost: String?
                var remotePort: Int?

                func jsonObject() -> [String: Any] {
                    var out: [String: Any] = [
                        "chan_id": chanID,
                        "proto": proto,
                        "mtype": mtype,
                        "body_text": bodyText,
                    ]
                    out["service_id"] = serviceID ?? NSNull()
                    out["remote_host"] = remoteHost ?? NSNull()
                    out["remote_port"] = remotePort ?? NSNull()
                    return out
                }
            }

            private func waitOrThrow(_ semaphore: DispatchSemaphore, timeout: Double, label: String) throws {
                if semaphore.wait(timeout: .now() + timeout) != .success {
                    throw ProbeError.timeout(label)
                }
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
                var reuse = 1
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

            private func readExact(_ fd: Int32, size: Int) throws -> Data {
                var output = Data(count: size)
                var offset = 0
                try output.withUnsafeMutableBytes { rawBuffer in
                    guard let baseAddress = rawBuffer.baseAddress else {
                        throw ProbeError.socket("read buffer")
                    }
                    while offset < size {
                        let received = recv(fd, baseAddress.advanced(by: offset), size - offset, 0)
                        if received < 0 {
                            throw ProbeError.socket("recv")
                        }
                        if received == 0 {
                            throw ProbeError.socket("unexpected eof")
                        }
                        offset += received
                    }
                }
                return output
            }

            private func recvEOF(_ fd: Int32) -> Bool {
                var byte: UInt8 = 0
                let received = recv(fd, &byte, 1, 0)
                return received == 0
            }

            private func frameName(_ type: ObstacleBridgeChannelMuxCodec.MType) -> String {
                switch type {
                case .data:
                    return "data"
                case .open:
                    return "open"
                case .close:
                    return "close"
                case .remoteServicesSetV1:
                    return "remote_services_set_v1"
                case .remoteServicesSetV2:
                    return "remote_services_set_v2"
                case .dataFrag:
                    return "data_frag"
                case .remoteServicesSetV2Chunk:
                    return "remote_services_set_v2_chunk"
                case .openChunk:
                    return "open_chunk"
                }
            }

            private func protoName(_ proto: ObstacleBridgeChannelMuxCodec.Proto) -> String {
                switch proto {
                case .udp:
                    return "udp"
                case .tcp:
                    return "tcp"
                case .tun:
                    return "tun"
                }
            }

            private func captureFrame(_ frame: ObstacleBridgeChannelMuxCodec.MuxFrame) -> CapturedFrame {
                let bodyText = String(data: frame.body, encoding: .utf8) ?? ""
                let parsed = frame.mtype == .open ? ObstacleBridgeChannelMuxCodec.parseOpenPayload(frame.body) : nil
                return CapturedFrame(
                    chanID: frame.chanID,
                    proto: protoName(frame.proto),
                    mtype: frameName(frame.mtype),
                    bodyText: bodyText,
                    serviceID: parsed?.spec.svcID,
                    remoteHost: parsed?.spec.rHost,
                    remotePort: parsed?.spec.rPort
                )
            }

            private func snapshotFrames(_ queue: DispatchQueue, _ frames: inout [CapturedFrame]) -> [CapturedFrame] {
                queue.sync { frames }
            }

            private func snapshotStrings(_ queue: DispatchQueue, _ values: inout [String]) -> [String] {
                queue.sync { values }
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
            struct TCPTransportOwnerProbe {
                static func main() throws {
                    guard CommandLine.arguments.count == 3,
                          let localPort = Int(CommandLine.arguments[1]),
                          let targetPort = Int(CommandLine.arguments[2])
                    else {
                        throw ProbeError.invalidArgs
                    }

                    let ownerQueue = DispatchQueue(label: "probe.owner")
                    let captureQueue = DispatchQueue(label: "probe.capture")
                    let localAcceptSemaphore = DispatchSemaphore(value: 0)
                    let listenerReadySemaphore = DispatchSemaphore(value: 0)
                    let targetAcceptSemaphore = DispatchSemaphore(value: 0)

                    var frames: [CapturedFrame] = []
                    var metrics: [String] = []
                    var errors: [String] = []
                    var listenerFailure: String?
                    var acceptedLocalChanID: Int?
                    var targetAcceptedFD: Int32 = -1

                    let owner = ObstacleBridgeChannelMuxTCPTransportOwner(
                        runtime: ObstacleBridgeChannelMuxTcpRuntime(
                            instanceID: 0x1111222233334444,
                            connectionSeq: 0x01020304
                        ),
                        queue: ownerQueue,
                        eventPrefix: "swift_udp",
                        eventSink: { event, fields in
                            captureQueue.sync {
                                errors.append("\(event):\(fields)")
                            }
                        },
                        muxFrameSink: { emitted in
                            captureQueue.sync {
                                for payload in emitted {
                                    if let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) {
                                        frames.append(captureFrame(frame))
                                    }
                                }
                            }
                        },
                        metricSink: { metric in
                            captureQueue.sync {
                                metrics.append(metric)
                            }
                        }
                    )

                    let localSpec = ObstacleBridgeChannelMuxCodec.ServiceSpec(
                        svcID: 7,
                        lProto: "tcp",
                        lBind: "127.0.0.1",
                        lPort: localPort,
                        rProto: "tcp",
                        rHost: "198.51.100.10",
                        rPort: 443,
                        name: "ios_local_service",
                        lifecycleHooks: nil,
                        options: nil
                    )
                    let listenerPort = NWEndpoint.Port(rawValue: UInt16(localPort))!
                    let listener = try NWListener(using: .tcp, on: listenerPort)
                    listener.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            listenerReadySemaphore.signal()
                        case .failed(let error):
                            listenerFailure = error.localizedDescription
                            listenerReadySemaphore.signal()
                        default:
                            break
                        }
                    }
                    listener.newConnectionHandler = { connection in
                        ownerQueue.async {
                            acceptedLocalChanID = owner.acceptLocalConnection(connection, spec: localSpec)
                            localAcceptSemaphore.signal()
                        }
                    }
                    listener.start(queue: ownerQueue)
                    try waitOrThrow(listenerReadySemaphore, timeout: 5.0, label: "local listener ready")
                    if let listenerFailure {
                        throw ProbeError.listenerFailed(listenerFailure)
                    }

                    let targetListenFD = try makeListeningSocket(port: targetPort)
                    DispatchQueue.global().async {
                        let accepted = accept(targetListenFD, nil, nil)
                        if accepted >= 0 {
                            setSocketTimeout(accepted, seconds: 5)
                            targetAcceptedFD = accepted
                        }
                        targetAcceptSemaphore.signal()
                    }

                    let localClientFD = try connectSocket(port: localPort)
                    defer {
                        close(localClientFD)
                        if targetAcceptedFD >= 0 {
                            close(targetAcceptedFD)
                        }
                        close(targetListenFD)
                        listener.cancel()
                        owner.stop()
                    }
                    try waitOrThrow(localAcceptSemaphore, timeout: 5.0, label: "local accept")
                    guard acceptedLocalChanID != nil else {
                        throw ProbeError.badState("owner rejected local connection")
                    }

                    try writeAll(localClientFD, data: Data("hello-from-local".utf8))
                    guard waitForCondition(timeout: 5.0, {
                        let current = snapshotFrames(captureQueue, &frames)
                        return current.contains(where: { $0.serviceID == 7 && $0.mtype == "open" })
                            && current.contains(where: { $0.bodyText == "hello-from-local" && $0.mtype == "data" })
                    }) else {
                        throw ProbeError.timeout("server path mux emission")
                    }

                    let serverFrames = snapshotFrames(captureQueue, &frames).filter { $0.serviceID == 7 || $0.bodyText == "hello-from-local" }
                    guard let serverOpen = serverFrames.first(where: { $0.mtype == "open" }) else {
                        throw ProbeError.badState("missing server open frame")
                    }
                    ownerQueue.async {
                        owner.handleInboundMuxFrame(
                            ObstacleBridgeChannelMuxCodec.MuxFrame(
                                chanID: serverOpen.chanID,
                                proto: .tcp,
                                counter: 1,
                                mtype: .data,
                                body: Data("reply-from-mux".utf8)
                            )
                        )
                    }
                    let serverReply = try readExact(localClientFD, size: "reply-from-mux".utf8.count)
                    ownerQueue.async {
                        owner.handleInboundMuxFrame(
                            ObstacleBridgeChannelMuxCodec.MuxFrame(
                                chanID: serverOpen.chanID,
                                proto: .tcp,
                                counter: 2,
                                mtype: .close,
                                body: Data()
                            )
                        )
                    }
                    guard waitForCondition(timeout: 5.0, { recvEOF(localClientFD) }) else {
                        throw ProbeError.timeout("server path close")
                    }

                    let inboundSpec = ObstacleBridgeChannelMuxCodec.ServiceSpec(
                        svcID: 11,
                        lProto: "tcp",
                        lBind: "127.0.0.1",
                        lPort: 0,
                        rProto: "tcp",
                        rHost: "127.0.0.1",
                        rPort: targetPort,
                        name: "ios_remote_service",
                        lifecycleHooks: nil,
                        options: nil
                    )
                    let openPayload = try ObstacleBridgeChannelMuxCodec.buildOpenPayload(
                        instanceID: 0xAABBCCDDEEFF0011,
                        connectionSeq: 0x0A0B0C0D,
                        spec: inboundSpec
                    )
                    ownerQueue.async {
                        owner.handleInboundMuxFrame(
                            ObstacleBridgeChannelMuxCodec.MuxFrame(
                                chanID: 41,
                                proto: .tcp,
                                counter: 1,
                                mtype: .open,
                                body: openPayload
                            )
                        )
                    }
                    try waitOrThrow(targetAcceptSemaphore, timeout: 5.0, label: "target accept")
                    guard targetAcceptedFD >= 0 else {
                        throw ProbeError.badState("missing target accept fd")
                    }
                    ownerQueue.async {
                        owner.handleInboundMuxFrame(
                            ObstacleBridgeChannelMuxCodec.MuxFrame(
                                chanID: 41,
                                proto: .tcp,
                                counter: 2,
                                mtype: .data,
                                body: Data("hello-from-mux".utf8)
                            )
                        )
                    }
                    let targetReceived = try readExact(targetAcceptedFD, size: "hello-from-mux".utf8.count)
                    try writeAll(targetAcceptedFD, data: Data("hello-from-target".utf8))
                    guard waitForCondition(timeout: 5.0, {
                        snapshotFrames(captureQueue, &frames).contains {
                            $0.chanID == 41 && $0.mtype == "data" && $0.bodyText == "hello-from-target"
                        }
                    }) else {
                        throw ProbeError.timeout("client path outbound mux emission")
                    }
                    close(targetAcceptedFD)
                    targetAcceptedFD = -1
                    guard waitForCondition(timeout: 5.0, {
                        snapshotFrames(captureQueue, &frames).contains { $0.chanID == 41 && $0.mtype == "close" }
                    }) else {
                        throw ProbeError.timeout("client path close frame")
                    }

                    let result: [String: Any] = [
                        "server_path": [
                            "accepted_chan_id": serverOpen.chanID,
                            "open_remote_host": serverOpen.remoteHost ?? "",
                            "open_remote_port": serverOpen.remotePort ?? -1,
                            "received_text": String(data: serverReply, encoding: .utf8) ?? "",
                            "closed_after_remote_close": true,
                        ],
                        "client_path": [
                            "target_received_text": String(data: targetReceived, encoding: .utf8) ?? "",
                            "outbound_reply_frame_present": true,
                            "close_frame_present": true,
                        ],
                        "frame_types": snapshotFrames(captureQueue, &frames).map { $0.mtype },
                        "metrics": snapshotStrings(captureQueue, &metrics),
                        "errors": snapshotStrings(captureQueue, &errors),
                    ]
                    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_tcp_transport_owner_probe(source_path, binary_path)
    completed = subprocess.run(
        [str(binary_path), str(local_service_port), str(target_service_port)],
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

    assert payload["server_path"] == {
        "accepted_chan_id": 1,
        "open_remote_host": "198.51.100.10",
        "open_remote_port": 443,
        "received_text": "reply-from-mux",
        "closed_after_remote_close": True,
    }
    assert payload["client_path"] == {
        "target_received_text": "hello-from-mux",
        "outbound_reply_frame_present": True,
        "close_frame_present": True,
    }
    assert payload["metrics"] == ["server_accepted", "client_dialed"]
    assert sorted(event.split(":", 1)[0] for event in payload["errors"]) == [
        "swift_udp_tcp_server_connection_ready",
        "swift_udp_tcp_server_data_mux",
        "swift_udp_tcp_server_data_read",
        "swift_udp_tcp_server_receive_done",
    ]
    assert any('"chan_id": 1' in event for event in payload["errors"])
    assert any('"bytes": 16' in event for event in payload["errors"])
    assert any('"sent": true' in event for event in payload["errors"])
    assert any('"is_complete": true' in event for event in payload["errors"])
    assert payload["frame_types"] == ["open", "data", "data", "close"]
