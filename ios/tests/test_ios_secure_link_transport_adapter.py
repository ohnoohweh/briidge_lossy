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
                    guard let clientProofFrame else {
                        throw ProbeError.badState("missing client proof")
                    }

                    let serverAuth = server.handleInboundFrame(clientProofFrame)
                    guard let serverAckFrame = serverAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing server ack")
                    }
                    let clientAck = client.handleInboundFrame(serverAckFrame)
                    guard let flushedClientDataFrame = clientAck.emittedFrames.first else {
                        throw ProbeError.badState("missing flushed client data after peer confirmation")
                    }
                    let serverData = server.handleInboundFrame(flushedClientDataFrame)
                    let serverSend = try server.handleOutboundPayload(Data("reply-secure".utf8))
                    guard let serverReplyFrame = serverSend.emittedFrames.first else {
                        throw ProbeError.badState("missing server reply")
                    }
                    let clientData = client.handleInboundFrame(serverReplyFrame)

                    let payload: [String: Any] = [
                        "queued_client_frames": queuedSend.emittedFrames.count,
                        "client_auth_frames": clientAuth.emittedFrames.count,
                        "client_ack_frames": clientAck.emittedFrames.count,
                        "server_auth_frames": serverAuth.emittedFrames.count,
                        "server_auth_delivered": serverAuth.deliveredPayloads.count,
                        "server_received": serverData.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
                        "client_received": clientData.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "client_peer_confirmed": client.statusSnapshot().peerConfirmedAuthenticated,
                        "client_telemetry_build_ok": client.statusSnapshot().clientHandshakeTelemetryBuildSucceeded,
                        "client_telemetry_payload_bytes": client.statusSnapshot().clientHandshakeTelemetryPayloadBytes,
                        "client_telemetry_payload_sha": client.statusSnapshot().clientHandshakeTelemetryPayloadSHA256Prefix,
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
        "client_ack_frames": 1,
        "client_auth_frames": 1,
        "client_peer_confirmed": True,
        "client_telemetry_build_ok": True,
        "client_telemetry_payload_bytes": 553,
        "client_telemetry_payload_sha": "5e82f807754bb0fb",
        "server_auth_frames": 1,
        "server_auth_delivered": 0,
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

                    let serverAuth = server.handleInboundFrame(clientProofFrame)
                    guard let serverAckFrame = serverAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing server ack")
                    }
                    let clientAck = client.handleInboundFrame(serverAckFrame)
                    let serverSend = try server.handleOutboundPayload(Data("reply-secure".utf8))
                    guard let serverReplyFrame = serverSend.emittedFrames.first else {
                        throw ProbeError.badState("missing server reply")
                    }
                    let clientData = client.handleInboundFrame(serverReplyFrame)

                    let payload: [String: Any] = [
                        "primed_client_frames": primed.emittedFrames.count,
                        "client_auth_frames": clientAuth.emittedFrames.count,
                        "client_ack_frames": clientAck.emittedFrames.count,
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "client_peer_confirmed": client.statusSnapshot().peerConfirmedAuthenticated,
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
        "client_ack_frames": 0,
        "primed_client_frames": 1,
        "client_auth_frames": 1,
        "client_authenticated": True,
        "client_peer_confirmed": True,
        "server_authenticated": True,
        "client_received": ["reply-secure"],
    }


def test_ios_secure_link_transport_adapter_reconnect_edge_reprimes_after_authenticated_failure_like_python(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportRecoveryProbe.swift"
    binary_path = tmp_path / "secure-link-transport-recovery-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportRecoveryProbe {
                static func main() throws {
                    var clientSessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if clientSessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return clientSessionIDs.removeFirst()
                            }
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

                    let firstPrime = try client.handleTransportConnected()
                    guard let firstHello = firstPrime.emittedFrames.first,
                          let parsedFirstHello = ObstacleBridgeSecureLinkPskCodec.parseFrame(firstHello),
                          parsedFirstHello.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing first client hello")
                    }

                    let serverHello = server.handleInboundFrame(firstHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }
                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    guard let clientProofFrame = clientAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing client proof")
                    }
                    _ = server.handleInboundFrame(clientProofFrame)
                    guard client.statusSnapshot().authenticated else {
                        throw ProbeError.badState("client did not authenticate")
                    }

                    let failure = client.handleInboundFrame(Data([0x00, 0x01, 0x02]))
                    guard failure.authFailCode == ObstacleBridgeSecureLinkPskRuntime.authFailDecode else {
                        throw ProbeError.badState("authenticated failure did not fail closed")
                    }
                    let failedStatus = client.statusSnapshot()

                    client.handleTransportDisconnected()
                    let disconnectedStatus = client.statusSnapshot()
                    let secondPrime = try client.handleTransportConnected()
                    guard let secondHello = secondPrime.emittedFrames.first,
                          let parsedSecondHello = ObstacleBridgeSecureLinkPskCodec.parseFrame(secondHello),
                          parsedSecondHello.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing recovery client hello")
                    }

                    let payload: [String: Any] = [
                        "first_session_id": String(parsedFirstHello.sessionID),
                        "failed_auth_code": failedStatus.authFailCode,
                        "failed_authenticated": failedStatus.authenticated,
                        "disconnected_session_id": String(disconnectedStatus.sessionID),
                        "disconnected_auth_code": disconnectedStatus.authFailCode,
                        "second_session_id": String(parsedSecondHello.sessionID),
                        "second_emitted_frames": secondPrime.emittedFrames.count,
                        "second_authenticated": secondPrime.authenticated,
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
        "first_session_id": "72623859790382856",
        "failed_auth_code": 4,
        "failed_authenticated": False,
        "disconnected_session_id": "0",
        "disconnected_auth_code": 0,
        "second_session_id": "72623859790382857",
        "second_emitted_frames": 1,
        "second_authenticated": False,
    }


def test_ios_secure_link_transport_adapter_times_out_unconfirmed_handshake_and_restarts(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportHandshakeTimeoutProbe.swift"
    binary_path = tmp_path / "secure-link-transport-handshake-timeout-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportHandshakeTimeoutProbe {
                static func main() throws {
                    var now: TimeInterval = 10
                    var clientSessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if clientSessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return clientSessionIDs.removeFirst()
                            },
                            timeProvider: { now }
                        )
                    )

                    let primed = try client.handleTransportConnected()
                    guard let clientHello = primed.emittedFrames.first,
                          let parsedHello = ObstacleBridgeSecureLinkPskCodec.parseFrame(clientHello),
                          parsedHello.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing initial client hello")
                    }

                    let clientNonce = parsedHello.payload.prefix(32)
                    let serverNonce = Data(repeating: 0x22, count: 32)
                    let proof = ObstacleBridgeSecureLinkPskCodec.serverProof(
                        psk: Data("shared-psk".utf8),
                        sessionID: parsedHello.sessionID,
                        clientNonce: Data(clientNonce),
                        serverNonce: serverNonce
                    )
                    let serverHello = ObstacleBridgeSecureLinkPskCodec.buildFrame(
                        slType: ObstacleBridgeSecureLinkPskRuntime.typeServerHello,
                        sessionID: parsedHello.sessionID,
                        counter: 0,
                        payload: serverNonce + Data([UInt8(ObstacleBridgeSecureLinkPskRuntime.capabilityPSKV1)]) + proof
                    )

                    let localAuth = client.handleInboundFrame(serverHello)
                    let localStatus = client.statusSnapshot()
                    guard localStatus.authenticated, !localStatus.peerConfirmedAuthenticated else {
                        throw ProbeError.badState("client did not enter local-only auth phase")
                    }
                    now += 61
                    let timedOutStatus = client.statusSnapshot()
                    let reprobe = try client.handleTransportConnected()
                    guard let secondHello = reprobe.emittedFrames.first,
                          let parsedSecondHello = ObstacleBridgeSecureLinkPskCodec.parseFrame(secondHello),
                          parsedSecondHello.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing restarted client hello")
                    }

                    let payload: [String: Any] = [
                        "local_auth_frames": localAuth.emittedFrames.count,
                        "timed_out_authenticated": timedOutStatus.authenticated,
                        "timed_out_peer_confirmed": timedOutStatus.peerConfirmedAuthenticated,
                        "timed_out_auth_fail_code": timedOutStatus.authFailCode,
                        "first_session_id": String(parsedHello.sessionID),
                        "second_session_id": String(parsedSecondHello.sessionID),
                        "reprobe_frames": reprobe.emittedFrames.count,
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
        "first_session_id": "72623859790382856",
        "local_auth_frames": 1,
        "reprobe_frames": 1,
        "second_session_id": "72623859790382857",
        "timed_out_auth_fail_code": 5,
        "timed_out_authenticated": False,
        "timed_out_peer_confirmed": False,
    }


def test_ios_secure_link_transport_adapter_retries_pending_client_hello_while_still_handshaking(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportRetryPendingHandshakeProbe.swift"
    binary_path = tmp_path / "secure-link-transport-retry-pending-handshake-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportRetryPendingHandshakeProbe {
                static func main() throws {
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: { 0x0102030405060708 }
                        )
                    )

                    let firstPrime = try client.handleTransportConnected()
                    guard let firstHello = firstPrime.emittedFrames.first,
                          let firstParsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(firstHello),
                          firstParsed.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing first client hello")
                    }

                    let secondPrime = try client.handleTransportConnected()
                    guard let secondHello = secondPrime.emittedFrames.first,
                          let secondParsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(secondHello),
                          secondParsed.slType == ObstacleBridgeSecureLinkPskRuntime.typeClientHello
                    else {
                        throw ProbeError.badState("missing retried client hello")
                    }

                    let payload: [String: Any] = [
                        "first_emitted_frames": firstPrime.emittedFrames.count,
                        "second_emitted_frames": secondPrime.emittedFrames.count,
                        "first_session_id": String(firstParsed.sessionID),
                        "second_session_id": String(secondParsed.sessionID),
                        "same_payload": firstHello == secondHello,
                        "authenticated": client.statusSnapshot().authenticated,
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
        "authenticated": False,
        "first_emitted_frames": 1,
        "first_session_id": "72623859790382856",
        "same_payload": True,
        "second_emitted_frames": 1,
        "second_session_id": "72623859790382856",
    }


def test_ios_secure_link_transport_adapter_does_not_reprobe_peer_confirmation_after_local_auth(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportRetryPeerConfirmationProbe.swift"
    binary_path = tmp_path / "secure-link-transport-retry-peer-confirmation-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportRetryPeerConfirmationProbe {
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

                    let firstPrime = try client.handleTransportConnected()
                    guard let clientHello = firstPrime.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }
                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let localAuth = client.handleInboundFrame(serverHelloFrame)
                    guard localAuth.emittedFrames.count == 1 else {
                        throw ProbeError.badState("missing first client proof")
                    }
                    let firstProof = localAuth.emittedFrames[0]
                    guard client.statusSnapshot().authenticated, !client.statusSnapshot().peerConfirmedAuthenticated else {
                        throw ProbeError.badState("client not in local-auth-only phase")
                    }

                    let retryPrime = try client.handleTransportConnected()
                    guard let firstParsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(firstProof)
                    else {
                        throw ProbeError.badState("missing parsed proof frame")
                    }

                    let payload: [String: Any] = [
                        "first_counter": String(firstParsed.counter),
                        "retry_frames": retryPrime.emittedFrames.count,
                        "client_authenticated": client.statusSnapshot().authenticated,
                        "client_peer_confirmed": client.statusSnapshot().peerConfirmedAuthenticated,
                        "session_id": String(client.statusSnapshot().sessionID),
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
        "client_authenticated": True,
        "client_peer_confirmed": False,
        "first_counter": "1",
        "retry_frames": 0,
        "session_id": "72623859790382856",
    }


def test_ios_secure_link_runtime_reuses_server_hello_for_duplicate_client_hello_same_session(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkRuntimeDuplicateClientHelloProbe.swift"
    binary_path = tmp_path / "secure-link-runtime-duplicate-client-hello-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkRuntimeDuplicateClientHelloProbe {
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

                    let firstServerHello = server.handleInboundFrame(clientHelloFrame)
                    let secondServerHello = server.handleInboundFrame(clientHelloFrame)
                    guard let firstServerHelloFrame = firstServerHello.emittedFrames.first,
                          let secondServerHelloFrame = secondServerHello.emittedFrames.first
                    else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let localAuth = client.handleInboundFrame(firstServerHelloFrame)
                    guard let clientProofFrame = localAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing client proof")
                    }
                    _ = server.handleInboundFrame(clientProofFrame)

                    let payload: [String: Any] = [
                        "same_server_hello": firstServerHelloFrame == secondServerHelloFrame,
                        "server_authenticated": server.statusSnapshot().authenticated,
                        "server_peer_confirmed": server.statusSnapshot().peerConfirmedAuthenticated,
                        "server_auth_fail_code": server.statusSnapshot().authFailCode,
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
        "same_server_hello": True,
        "server_authenticated": True,
        "server_peer_confirmed": True,
        "server_auth_fail_code": 0,
    }


def test_ios_secure_link_runtime_ignores_duplicate_server_hello_after_client_proof_emit(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkRuntimeDuplicateServerHelloAfterProofProbe.swift"
    binary_path = tmp_path / "secure-link-runtime-duplicate-server-hello-after-proof-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkRuntimeDuplicateServerHelloAfterProofProbe {
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

                    let localAuth = client.handleInboundFrame(serverHelloFrame)
                    guard let clientProofFrame = localAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing client proof")
                    }

                    let duplicateServerHello = client.handleInboundFrame(serverHelloFrame)
                    let clientStatus = client.statusSnapshot()

                    let payload: [String: Any] = [
                        "duplicate_frames": duplicateServerHello.emittedFrames.count,
                        "client_authenticated": clientStatus.authenticated,
                        "client_peer_confirmed": clientStatus.peerConfirmedAuthenticated,
                        "client_auth_fail_code": clientStatus.authFailCode,
                        "proof_sent": clientStatus.clientHandshakeProofSent,
                        "proof_counter": String(clientStatus.clientHandshakeProofCounter),
                        "server_received_initial_proof": server.handleInboundFrame(clientProofFrame).authenticated,
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
        "client_auth_fail_code": 0,
        "client_authenticated": True,
        "client_peer_confirmed": False,
        "duplicate_frames": 0,
        "proof_counter": "1",
        "proof_sent": True,
        "server_received_initial_proof": True,
    }


def test_ios_secure_link_runtime_ignores_stale_old_session_data_during_client_reconnect_handshake(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkRuntimeIgnoreStaleOldSessionProbe.swift"
    binary_path = tmp_path / "secure-link-runtime-ignore-stale-old-session-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkRuntimeIgnoreStaleOldSessionProbe {
                static func main() throws {
                    var clientSessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if clientSessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return clientSessionIDs.removeFirst()
                            }
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

                    let firstPrime = try client.handleTransportConnected()
                    guard let firstHello = firstPrime.emittedFrames.first else {
                        throw ProbeError.badState("missing first client hello")
                    }
                    let firstServerHello = server.handleInboundFrame(firstHello)
                    guard let firstServerHelloFrame = firstServerHello.emittedFrames.first else {
                        throw ProbeError.badState("missing first server hello")
                    }
                    let firstClientAuth = client.handleInboundFrame(firstServerHelloFrame)
                    guard let firstClientProof = firstClientAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing first client proof")
                    }
                    let firstServerAuth = server.handleInboundFrame(firstClientProof)
                    guard let firstServerAck = firstServerAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing first server ack")
                    }
                    _ = client.handleInboundFrame(firstServerAck)

                    let staleServerData = try server.handleOutboundPayload(Data("stale-server-data".utf8))
                    guard let staleFrame = staleServerData.emittedFrames.first else {
                        throw ProbeError.badState("missing stale data frame")
                    }

                    client.handleTransportDisconnected()
                    let secondPrime = try client.handleTransportConnected()
                    guard let secondHello = secondPrime.emittedFrames.first else {
                        throw ProbeError.badState("missing second client hello")
                    }
                    let secondStatusBefore = client.statusSnapshot()

                    let staleResult = client.handleInboundFrame(staleFrame)
                    let staleStatus = client.statusSnapshot()

                    let secondServerHello = server.handleInboundFrame(secondHello)
                    guard let secondServerHelloFrame = secondServerHello.emittedFrames.first else {
                        throw ProbeError.badState("missing second server hello")
                    }
                    let secondClientAuth = client.handleInboundFrame(secondServerHelloFrame)
                    guard let secondClientProof = secondClientAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing second client proof")
                    }
                    let secondServerAuth = server.handleInboundFrame(secondClientProof)
                    guard let secondServerAck = secondServerAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing second server ack")
                    }
                    _ = client.handleInboundFrame(secondServerAck)
                    let finalStatus = client.statusSnapshot()

                    let payload: [String: Any] = [
                        "second_session_before": String(secondStatusBefore.sessionID),
                        "stale_frames": staleResult.emittedFrames.count,
                        "stale_auth_fail_code": staleStatus.authFailCode,
                        "stale_session_after": String(staleStatus.sessionID),
                        "final_authenticated": finalStatus.authenticated,
                        "final_peer_confirmed": finalStatus.peerConfirmedAuthenticated,
                        "final_session": String(finalStatus.sessionID),
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
        "final_authenticated": True,
        "final_peer_confirmed": True,
        "final_session": "72623859790382857",
        "second_session_before": "72623859790382857",
        "stale_auth_fail_code": 0,
        "stale_frames": 0,
        "stale_session_after": "72623859790382857",
    }


def test_ios_secure_link_transport_adapter_queues_local_auth_payloads_without_extra_probe(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportNoExtraProbeWhileAwaitingAck.swift"
    binary_path = tmp_path / "secure-link-transport-no-extra-probe-while-awaiting-ack"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportNoExtraProbeWhileAwaitingAck {
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

                    let firstPrime = try client.handleTransportConnected()
                    guard let clientHello = firstPrime.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }
                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let localAuth = client.handleInboundFrame(serverHelloFrame)
                    guard localAuth.emittedFrames.count == 1 else {
                        throw ProbeError.badState("missing first client proof")
                    }
                    let proofFrame = localAuth.emittedFrames[0]
                    guard let proofParsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(proofFrame) else {
                        throw ProbeError.badState("missing parsed proof frame")
                    }

                    let firstQueued = try client.handleOutboundPayload(Data("queued-one".utf8))
                    let secondQueued = try client.handleOutboundPayload(Data("queued-two".utf8))
                    let statusBeforeAck = client.statusSnapshot()

                    let serverAuth = server.handleInboundFrame(proofFrame)
                    guard let serverAckFrame = serverAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing server ack")
                    }
                    let clientAck = client.handleInboundFrame(serverAckFrame)

                    let flushedCounters = clientAck.emittedFrames.compactMap { frame -> UInt64? in
                        ObstacleBridgeSecureLinkPskCodec.parseFrame(frame)?.counter
                    }

                    let payload: [String: Any] = [
                        "first_queued_frames": firstQueued.emittedFrames.count,
                        "second_queued_frames": secondQueued.emittedFrames.count,
                        "queued_payloads_before_ack": statusBeforeAck.peerConfirmedAuthenticated ? -1 : firstQueued.queuedPayloads + (secondQueued.queuedPayloads - firstQueued.queuedPayloads),
                        "peer_confirmed_before_ack": statusBeforeAck.peerConfirmedAuthenticated,
                        "tx_counter_before_ack": String(statusBeforeAck.txCounter),
                        "proof_counter": String(proofParsed.counter),
                        "ack_flush_frames": clientAck.emittedFrames.count,
                        "ack_flush_counters": flushedCounters.map(String.init),
                        "peer_confirmed_after_ack": client.statusSnapshot().peerConfirmedAuthenticated,
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
        "ack_flush_counters": ["2", "3"],
        "ack_flush_frames": 2,
        "first_queued_frames": 0,
        "peer_confirmed_after_ack": True,
        "peer_confirmed_before_ack": False,
        "proof_counter": "1",
        "queued_payloads_before_ack": 2,
        "second_queued_frames": 0,
        "tx_counter_before_ack": "2",
    }


def test_ios_secure_link_transport_adapter_psk_rekey_rotates_session_and_flushes_queued_payloads(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "SecureLinkTransportRekeyProbe.swift"
    binary_path = tmp_path / "secure-link-transport-rekey-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportRekeyProbe {
                static func main() throws {
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            rekeyAfterFrames: 1,
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                struct Counter {
                                    static var value: UInt64 = 0x0102030405060708
                                }
                                defer { Counter.value += 1 }
                                return Counter.value
                            }
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

                    let firstPrime = try client.handleTransportConnected()
                    guard let clientHello = firstPrime.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }
                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }
                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    guard let clientProof = clientAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing client proof")
                    }
                    let serverAuth = server.handleInboundFrame(clientProof)
                    guard let serverAck = serverAuth.emittedFrames.first else {
                        throw ProbeError.badState("missing server ack")
                    }
                    _ = client.handleInboundFrame(serverAck)

                    let initialSession = client.statusSnapshot().sessionID
                    let firstSend = try client.handleOutboundPayload(Data("before-rekey".utf8))
                    guard firstSend.emittedFrames.count == 2 else {
                        throw ProbeError.badState("expected data frame plus rekey hello")
                    }
                    let firstData = server.handleInboundFrame(firstSend.emittedFrames[0])
                    let rekeyReply = server.handleInboundFrame(firstSend.emittedFrames[1])
                    guard let rekeyReplyFrame = rekeyReply.emittedFrames.first else {
                        throw ProbeError.badState("missing rekey reply")
                    }
                    guard firstData.deliveredPayloads.map({ String(data: $0, encoding: .utf8) ?? "" }) == ["before-rekey"] else {
                        throw ProbeError.badState("server did not receive pre-rekey payload")
                    }

                    let clientCommit = client.handleInboundFrame(rekeyReplyFrame)
                    guard let rekeyCommit = clientCommit.emittedFrames.first else {
                        throw ProbeError.badState("missing rekey commit")
                    }
                    let queuedSend = try client.handleOutboundPayload(Data("after-rekey".utf8))
                    guard queuedSend.emittedFrames.isEmpty else {
                        throw ProbeError.badState("expected payload queue during rekey commit hold")
                    }

                    let serverDone = server.handleInboundFrame(rekeyCommit)
                    guard let rekeyDone = serverDone.emittedFrames.first else {
                        throw ProbeError.badState("missing rekey done")
                    }
                    let clientAfterDone = client.handleInboundFrame(rekeyDone)
                    guard clientAfterDone.emittedFrames.count == 2 else {
                        throw ProbeError.badState("expected flushed payload plus next rekey hello")
                    }
                    let secondData = server.handleInboundFrame(clientAfterDone.emittedFrames[0])
                    guard secondData.deliveredPayloads.map({ String(data: $0, encoding: .utf8) ?? "" }) == ["after-rekey"] else {
                        throw ProbeError.badState("server did not receive post-rekey payload")
                    }
                    guard let nextRekeyHello = ObstacleBridgeSecureLinkPskCodec.parseFrame(clientAfterDone.emittedFrames[1]),
                          nextRekeyHello.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyHello
                    else {
                        throw ProbeError.badState("expected next rekey hello after flushed payload")
                    }

                    let clientStatus = client.statusSnapshot()
                    let serverStatus = server.statusSnapshot()
                    let payload: [String: Any] = [
                        "initial_session_id": String(initialSession),
                        "new_session_id": String(clientStatus.sessionID),
                        "client_rekeys_completed_total": clientStatus.rekeysCompletedTotal,
                        "server_rekeys_completed_total": serverStatus.rekeysCompletedTotal,
                        "client_last_rekey_trigger": clientStatus.lastRekeyTrigger,
                        "client_pending_session_id": String(clientStatus.pendingSessionID),
                        "client_hold_after_commit": clientStatus.clientRekeyHoldAfterCommit,
                        "client_authenticated": clientStatus.authenticated,
                        "client_peer_confirmed": clientStatus.peerConfirmedAuthenticated,
                        "server_authenticated": serverStatus.authenticated,
                        "server_peer_confirmed": serverStatus.peerConfirmedAuthenticated,
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
        "client_authenticated": True,
        "client_hold_after_commit": False,
        "client_last_rekey_trigger": "frame_threshold",
        "client_peer_confirmed": True,
        "client_pending_session_id": "72623859790382858",
        "client_rekeys_completed_total": 1,
        "initial_session_id": "72623859790382856",
        "new_session_id": "72623859790382857",
        "server_authenticated": True,
        "server_peer_confirmed": True,
        "server_rekeys_completed_total": 1,
    }
