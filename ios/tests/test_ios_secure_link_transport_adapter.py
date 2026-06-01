from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from swift_test_support import require_swift_module


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"


def _compile_swift_secure_link_transport_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = require_swift_module(
        module_name="CryptoKit",
        missing_swiftc_reason="swiftc is required for Swift SecureLink transport adapter tests",
        missing_module_reason="Swift SecureLink transport adapter tests require a Swift toolchain with CryptoKit support",
    )
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_secure_link_transport_adapter_queues_first_payload_until_handshake_completes(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkTransportAdapterProbe.swift"
    binary_path = tmp_path / "secure-link-transport-adapter-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportAdapterProbe {
                static func main() throws {
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: { 0x0102030405060708 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 }
                        )
                    )

                    let queuedSend = try client.handleOutboundPayload(Data("hello-secure".utf8))
                    guard let clientHello = queuedSend.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }

                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    let clientProofFrame = clientAuth.emittedFrames.first
                    let flushedClientDataFrame = clientAuth.emittedFrames.dropFirst().first
                    guard let clientProofFrame else {
                        throw ProbeError.badState("missing client proof")
                    }
                    guard let flushedClientDataFrame else {
                        throw ProbeError.badState("missing flushed client data")
                    }

                    let serverAuth = server.handleInboundFrame(clientProofFrame)
                    let serverData = server.handleInboundFrame(flushedClientDataFrame)
                    let serverSend = try server.handleOutboundPayload(Data("reply-secure".utf8))
                    guard let serverReplyFrame = serverSend.emittedFrames.first else {
                        throw ProbeError.badState("missing server reply")
                    }
                    let clientData = client.handleInboundFrame(serverReplyFrame)

                    let payload: [String: Any] = [
                        "queued_client_frames": queuedSend.emittedFrames.count,
                        "client_auth_frames": clientAuth.emittedFrames.count,
                        "server_auth_frames": serverAuth.emittedFrames.count,
                        "server_received": serverData.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
                        "client_received": clientData.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "server_authenticated": server.statusSnapshot().authenticated,
                        "client_session_id": String(client.statusSnapshot().sessionID),
                        "server_session_id": String(server.statusSnapshot().sessionID),
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_secure_link_transport_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)

    assert payload == {
        "queued_client_frames": 1,
        "client_auth_frames": 2,
        "server_auth_frames": 0,
        "server_received": ["hello-secure"],
        "client_received": ["reply-secure"],
        "client_authenticated": True,
        "server_authenticated": True,
        "client_session_id": "72623859790382856",
        "server_session_id": "72623859790382856",
    }


def test_ios_secure_link_transport_adapter_can_prime_handshake_on_transport_connect(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkTransportConnectProbe.swift"
    binary_path = tmp_path / "secure-link-transport-connect-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportConnectProbe {
                static func main() throws {
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: { 0x0102030405060708 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 }
                        )
                    )

                    let primed = try client.handleTransportConnected()
                    guard let clientHello = primed.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello on transport connect")
                    }

                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    guard let clientProofFrame = clientAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing client proof")
                    }

                    _ = server.handleInboundFrame(clientProofFrame)
                    let serverSend = try server.handleOutboundPayload(Data("reply-secure".utf8))
                    guard let serverReplyFrame = serverSend.emittedFrames.first else {
                        throw ProbeError.badState("missing server reply")
                    }
                    let clientData = client.handleInboundFrame(serverReplyFrame)

                    let payload: [String: Any] = [
                        "primed_client_frames": primed.emittedFrames.count,
                        "client_auth_frames": clientAuth.emittedFrames.count,
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "server_authenticated": server.statusSnapshot().authenticated,
                        "client_received": clientData.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_secure_link_transport_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)

    assert payload == {
        "primed_client_frames": 1,
        "client_auth_frames": 1,
        "client_authenticated": True,
        "server_authenticated": True,
        "client_received": ["reply-secure"],
    }
