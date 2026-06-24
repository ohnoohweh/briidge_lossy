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


def _compile_swift_secure_link_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = require_swift_module(
        module_name="CryptoKit",
        missing_swiftc_reason="swiftc is required for Swift SecureLink runtime tests",
        missing_module_reason="Swift SecureLink runtime tests require a Swift toolchain with CryptoKit support",
    )
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_secure_link_psk_runtime_probe_authenticates_and_exchanges_data(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkRuntimeProbe.swift"
    binary_path = tmp_path / "secure-link-runtime-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkRuntimeProbe {
                static func main() throws {
                    let client = ObstacleBridgeSecureLinkPskRuntime(
                        clientMode: true,
                        psk: "shared-psk",
                        randomBytes: { count in Data(repeating: 0x11, count: count) },
                        sessionIDProvider: { 0x0102030405060708 }
                    )
                    let server = ObstacleBridgeSecureLinkPskRuntime(
                        clientMode: false,
                        psk: "shared-psk",
                        randomBytes: { count in Data(repeating: 0x22, count: count) },
                        sessionIDProvider: { 0 }
                    )

                    let clientHello = try client.beginClientHandshake()
                    guard let clientHelloFrame = clientHello.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }

                    let serverHello = server.handleInboundFrame(clientHelloFrame)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    let clientProofFrame = clientAuth.emittedFrames.first
                    let serverAuth = clientProofFrame.map { server.handleInboundFrame($0) }
                    let serverAckFrame = serverAuth?.emittedFrames.first
                    let clientAck = serverAckFrame.map { client.handleInboundFrame($0) }

                    let clientSend = try? client.sendApp(Data("hello-secure".utf8))
                    let clientDataFrame = clientSend?.emittedFrames.first
                    let serverData = clientDataFrame.map { server.handleInboundFrame($0) }

                    let serverSend = try? server.sendApp(Data("reply-secure".utf8))
                    let serverDataFrame = serverSend?.emittedFrames.first
                    let clientData = serverDataFrame.map { client.handleInboundFrame($0) }

                    let payload: [String: Any] = [
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "client_peer_confirmed_authenticated": client.statusSnapshot().peerConfirmedAuthenticated,
                        "server_authenticated": server.statusSnapshot().authenticated,
                        "server_peer_confirmed_authenticated": server.statusSnapshot().peerConfirmedAuthenticated,
                        "client_auth_emitted_frames": clientAuth.emittedFrames.count,
                        "server_auth_emitted_frames": serverAuth?.emittedFrames.count ?? -1,
                        "client_ack_emitted_frames": clientAck?.emittedFrames.count ?? -1,
                        "server_received": serverData?.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" } ?? [],
                        "client_received": clientData?.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" } ?? [],
                        "client_tx_counter": String(client.statusSnapshot().txCounter),
                        "server_tx_counter": String(server.statusSnapshot().txCounter),
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
    _compile_swift_secure_link_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)

    assert payload == {
        "client_authenticated": True,
        "client_peer_confirmed_authenticated": True,
        "server_authenticated": True,
        "server_peer_confirmed_authenticated": True,
        "client_auth_emitted_frames": 1,
        "server_auth_emitted_frames": 1,
        "client_ack_emitted_frames": 0,
        "server_received": ["hello-secure"],
        "client_received": ["reply-secure"],
        "client_tx_counter": "3",
        "server_tx_counter": "3",
        "client_session_id": "72623859790382856",
        "server_session_id": "72623859790382856",
    }
