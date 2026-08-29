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
                            sessionIDProvider: { 0x0102030405060708 },
                            unixTimeProvider: { 1700000000.0 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 },
                            unixTimeProvider: { 1700000001.0 }
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
                        "client_last_event": client.statusSnapshot().lastEvent,
                        "server_last_event": server.statusSnapshot().lastEvent,
                        "client_last_event_unix_ts": client.statusSnapshot().lastEventUnixTs ?? 0,
                        "server_last_event_unix_ts": server.statusSnapshot().lastEventUnixTs ?? 0,
                        "client_authenticated_sessions_total": client.statusSnapshot().authenticatedSessionsTotal,
                        "server_authenticated_sessions_total": server.statusSnapshot().authenticatedSessionsTotal,
                        "client_rekey_supported": client.statusSnapshot().rekeySupported,
                        "server_rekey_supported": server.statusSnapshot().rekeySupported,
                        "client_rekey_in_progress": client.statusSnapshot().rekeyInProgress,
                        "server_rekey_in_progress": server.statusSnapshot().rekeyInProgress,
                        "client_rekeys_completed_total": client.statusSnapshot().rekeysCompletedTotal,
                        "server_rekeys_completed_total": server.statusSnapshot().rekeysCompletedTotal,
                        "client_last_rekey_trigger": client.statusSnapshot().lastRekeyTrigger,
                        "server_last_rekey_trigger": server.statusSnapshot().lastRekeyTrigger,
                        "client_disconnect_reason": client.statusSnapshot().disconnectReason,
                        "server_disconnect_reason": server.statusSnapshot().disconnectReason,
                        "client_disconnect_detail": client.statusSnapshot().disconnectDetail,
                        "server_disconnect_detail": server.statusSnapshot().disconnectDetail,
                        "client_trust_validation_state": client.statusSnapshot().trustValidationState,
                        "server_trust_validation_state": server.statusSnapshot().trustValidationState,
                        "client_frames_passed_total": client.statusSnapshot().framesPassedTotal,
                        "server_frames_passed_total": server.statusSnapshot().framesPassedTotal,
                        "client_frames_dropped_total": client.statusSnapshot().framesDroppedTotal,
                        "server_frames_dropped_total": server.statusSnapshot().framesDroppedTotal,
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
        "server_auth_frames": 1,
        "server_received": ["hello-secure"],
        "client_received": ["reply-secure"],
        "client_authenticated": True,
        "server_authenticated": True,
        "client_session_id": "72623859790382856",
        "server_session_id": "72623859790382856",
        "client_last_event": "authenticated",
        "server_last_event": "authenticated",
        "client_last_event_unix_ts": 1700000000.0,
        "server_last_event_unix_ts": 1700000001.0,
        "client_authenticated_sessions_total": 1,
        "server_authenticated_sessions_total": 1,
        "client_rekey_supported": True,
        "server_rekey_supported": True,
        "client_rekey_in_progress": False,
        "server_rekey_in_progress": False,
        "client_rekeys_completed_total": 0,
        "server_rekeys_completed_total": 0,
        "client_last_rekey_trigger": "",
        "server_last_rekey_trigger": "",
        "client_disconnect_reason": "",
        "server_disconnect_reason": "",
        "client_disconnect_detail": "",
        "server_disconnect_detail": "",
        "client_trust_validation_state": "validated",
        "server_trust_validation_state": "validated",
        "client_frames_passed_total": 1,
        "server_frames_passed_total": 2,
        "client_frames_dropped_total": 0,
        "server_frames_dropped_total": 0,
    }


def test_ios_secure_link_transport_adapter_operator_rekey_completes_and_updates_counters(tmp_path: Path) -> None:
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
                    var sessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if sessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return sessionIDs.removeFirst()
                            },
                            unixTimeProvider: { 1700000002.0 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 },
                            unixTimeProvider: { 1700000003.0 }
                        )
                    )

                    let clientHello = try client.handleTransportConnected().emittedFrames.first!
                    let serverHello = server.handleInboundFrame(clientHello).emittedFrames.first!
                    let clientProof = client.handleInboundFrame(serverHello).emittedFrames.first!
                    _ = server.handleInboundFrame(clientProof)
                    let warmupReply = try server.handleOutboundPayload(Data("reply-before-rekey".utf8)).emittedFrames.first!
                    _ = client.handleInboundFrame(warmupReply)

                    let rekeyStart = try client.requestSecureLinkRekey()
                    guard let rekeyHello = rekeyStart.emittedFrames.first,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyHello)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyHello
                    else {
                        throw ProbeError.badState("missing rekey hello")
                    }
                    if !client.statusSnapshot().rekeyInProgress {
                        throw ProbeError.badState("client did not enter rekey state")
                    }

                    let rekeyReply = server.handleInboundFrame(rekeyHello)
                    guard let rekeyReplyFrame = rekeyReply.emittedFrames.first,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyReplyFrame)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyReply
                    else {
                        throw ProbeError.badState("missing rekey reply")
                    }

                    let rekeyCommit = client.handleInboundFrame(rekeyReplyFrame)
                    guard let rekeyCommitFrame = rekeyCommit.emittedFrames.first,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyCommitFrame)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyCommit
                    else {
                        throw ProbeError.badState("missing rekey commit")
                    }
                    if !client.statusSnapshot().appDataSendingBlocked {
                        throw ProbeError.badState("client did not block outbound app data after commit")
                    }

                    let rekeyDone = server.handleInboundFrame(rekeyCommitFrame)
                    guard let rekeyDoneFrame = rekeyDone.emittedFrames.first,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyDoneFrame)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyDone
                    else {
                        throw ProbeError.badState("missing rekey done")
                    }

                    let postDone = client.handleInboundFrame(rekeyDoneFrame)
                    let postReplyFrame = try server.handleOutboundPayload(Data("reply-after-rekey".utf8)).emittedFrames.first!
                    let postReply = client.handleInboundFrame(postReplyFrame)

                    let payload: [String: Any] = [
                        "client_session_id": String(client.statusSnapshot().sessionID),
                        "server_session_id": String(server.statusSnapshot().sessionID),
                        "client_rekey_in_progress": client.statusSnapshot().rekeyInProgress,
                        "server_rekey_in_progress": server.statusSnapshot().rekeyInProgress,
                        "client_rekeys_completed_total": client.statusSnapshot().rekeysCompletedTotal,
                        "server_rekeys_completed_total": server.statusSnapshot().rekeysCompletedTotal,
                        "client_authenticated_sessions_total": client.statusSnapshot().authenticatedSessionsTotal,
                        "server_authenticated_sessions_total": server.statusSnapshot().authenticatedSessionsTotal,
                        "client_last_rekey_trigger": client.statusSnapshot().lastRekeyTrigger,
                        "server_last_rekey_trigger": server.statusSnapshot().lastRekeyTrigger,
                        "client_last_event": client.statusSnapshot().lastEvent,
                        "server_last_event": server.statusSnapshot().lastEvent,
                        "client_last_event_unix_ts": client.statusSnapshot().lastEventUnixTs ?? 0,
                        "server_last_event_unix_ts": server.statusSnapshot().lastEventUnixTs ?? 0,
                        "client_disconnect_reason": client.statusSnapshot().disconnectReason,
                        "server_disconnect_reason": server.statusSnapshot().disconnectReason,
                        "client_disconnect_detail": client.statusSnapshot().disconnectDetail,
                        "server_disconnect_detail": server.statusSnapshot().disconnectDetail,
                        "client_trust_validation_state": client.statusSnapshot().trustValidationState,
                        "server_trust_validation_state": server.statusSnapshot().trustValidationState,
                        "client_app_blocked": client.statusSnapshot().appDataSendingBlocked,
                        "post_done_frames": postDone.emittedFrames.count,
                        "post_reply": postReply.deliveredPayloads.map { String(data: $0, encoding: .utf8) ?? "" },
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
        "client_session_id": "72623859790382857",
        "server_session_id": "72623859790382857",
        "client_rekey_in_progress": False,
        "server_rekey_in_progress": False,
        "client_rekeys_completed_total": 1,
        "server_rekeys_completed_total": 1,
        "client_authenticated_sessions_total": 2,
        "server_authenticated_sessions_total": 2,
        "client_last_rekey_trigger": "operator",
        "server_last_rekey_trigger": "remote",
        "client_last_event": "rekey_completed",
        "server_last_event": "rekey_completed",
        "client_last_event_unix_ts": 1700000002.0,
        "server_last_event_unix_ts": 1700000003.0,
        "client_disconnect_reason": "",
        "server_disconnect_reason": "",
        "client_disconnect_detail": "",
        "server_disconnect_detail": "",
        "client_trust_validation_state": "validated",
        "server_trust_validation_state": "validated",
        "client_app_blocked": False,
        "post_done_frames": 0,
        "post_reply": ["reply-after-rekey"],
    }


def test_ios_secure_link_transport_adapter_frame_threshold_rekey_matches_python_semantics(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkTransportFrameThresholdProbe.swift"
    binary_path = tmp_path / "secure-link-transport-frame-threshold-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportFrameThresholdProbe {
                static func main() throws {
                    var sessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            rekeyAfterFrames: 3,
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if sessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return sessionIDs.removeFirst()
                            },
                            unixTimeProvider: { 1700000004.0 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 },
                            unixTimeProvider: { 1700000005.0 }
                        )
                    )

                    let clientHello = try client.handleTransportConnected().emittedFrames.first!
                    let serverHello = server.handleInboundFrame(clientHello).emittedFrames.first!
                    let clientProof = client.handleInboundFrame(serverHello).emittedFrames.first!
                    _ = server.handleInboundFrame(clientProof)
                    let warmupReply = try server.handleOutboundPayload(Data("warmup".utf8)).emittedFrames.first!
                    _ = client.handleInboundFrame(warmupReply)

                    for index in 1...2 {
                        let outbound = try client.handleOutboundPayload(Data("payload-\(index)".utf8))
                        if outbound.emittedFrames.count != 1 {
                            throw ProbeError.badState("unexpected rekey before threshold")
                        }
                        _ = server.handleInboundFrame(outbound.emittedFrames[0])
                    }

                    let thresholdSend = try client.handleOutboundPayload(Data("payload-3".utf8))
                    guard thresholdSend.emittedFrames.count == 2 else {
                        throw ProbeError.badState("threshold send did not emit data plus rekey hello")
                    }
                    guard let dataFrame = thresholdSend.emittedFrames.first,
                          let rekeyHello = thresholdSend.emittedFrames.dropFirst().first,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyHello)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyHello
                    else {
                        throw ProbeError.badState("missing rekey hello at threshold")
                    }

                    _ = server.handleInboundFrame(dataFrame)
                    let rekeyReply = server.handleInboundFrame(rekeyHello).emittedFrames.first!
                    let rekeyCommit = client.handleInboundFrame(rekeyReply).emittedFrames.first!
                    let rekeyDone = server.handleInboundFrame(rekeyCommit).emittedFrames.first!
                    _ = client.handleInboundFrame(rekeyDone)

                    let payload: [String: Any] = [
                        "client_session_id": String(client.statusSnapshot().sessionID),
                        "server_session_id": String(server.statusSnapshot().sessionID),
                        "client_rekeys_completed_total": client.statusSnapshot().rekeysCompletedTotal,
                        "server_rekeys_completed_total": server.statusSnapshot().rekeysCompletedTotal,
                        "client_last_rekey_trigger": client.statusSnapshot().lastRekeyTrigger,
                        "server_last_rekey_trigger": server.statusSnapshot().lastRekeyTrigger,
                        "client_authenticated_sessions_total": client.statusSnapshot().authenticatedSessionsTotal,
                        "server_authenticated_sessions_total": server.statusSnapshot().authenticatedSessionsTotal,
                        "client_last_event": client.statusSnapshot().lastEvent,
                        "server_last_event": server.statusSnapshot().lastEvent,
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
        "client_session_id": "72623859790382857",
        "server_session_id": "72623859790382857",
        "client_rekeys_completed_total": 1,
        "server_rekeys_completed_total": 1,
        "client_last_rekey_trigger": "frame_threshold",
        "server_last_rekey_trigger": "remote",
        "client_authenticated_sessions_total": 2,
        "server_authenticated_sessions_total": 2,
        "client_last_event": "rekey_completed",
        "server_last_event": "rekey_completed",
    }


def test_ios_secure_link_transport_adapter_time_threshold_rekey_can_fire_while_idle(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkTransportTimeThresholdProbe.swift"
    binary_path = tmp_path / "secure-link-transport-time-threshold-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportTimeThresholdProbe {
                static func main() throws {
                    var monoTime = 100.0
                    var sessionIDs: [UInt64] = [0x0102030405060708, 0x0102030405060709]
                    let client = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            rekeyAfterSeconds: 5.0,
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: {
                                if sessionIDs.isEmpty {
                                    return 0x0102030405060710
                                }
                                return sessionIDs.removeFirst()
                            },
                            timeProvider: { monoTime },
                            unixTimeProvider: { 1700000006.0 }
                        )
                    )
                    let server = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x22, count: count) },
                            sessionIDProvider: { 0 },
                            timeProvider: { monoTime },
                            unixTimeProvider: { 1700000007.0 }
                        )
                    )

                    let clientHello = try client.handleTransportConnected().emittedFrames.first!
                    let serverHello = server.handleInboundFrame(clientHello).emittedFrames.first!
                    let clientProof = client.handleInboundFrame(serverHello).emittedFrames.first!
                    _ = server.handleInboundFrame(clientProof)
                    let warmupReply = try server.handleOutboundPayload(Data("warmup".utf8)).emittedFrames.first!
                    _ = client.handleInboundFrame(warmupReply)

                    monoTime += 4.0
                    if !(try client.pollDueFrames().emittedFrames.isEmpty) {
                        throw ProbeError.badState("time-based rekey fired too early")
                    }

                    monoTime += 2.0
                    let due = try client.pollDueFrames()
                    guard let rekeyHello = due.emittedFrames.first,
                          due.emittedFrames.count == 1,
                          ObstacleBridgeSecureLinkPskCodec.parseFrame(rekeyHello)?.slType == ObstacleBridgeSecureLinkPskRuntime.typeRekeyHello
                    else {
                        throw ProbeError.badState("missing time-based rekey hello")
                    }

                    let rekeyReply = server.handleInboundFrame(rekeyHello).emittedFrames.first!
                    let rekeyCommit = client.handleInboundFrame(rekeyReply).emittedFrames.first!
                    let rekeyDone = server.handleInboundFrame(rekeyCommit).emittedFrames.first!
                    _ = client.handleInboundFrame(rekeyDone)

                    let payload: [String: Any] = [
                        "client_session_id": String(client.statusSnapshot().sessionID),
                        "server_session_id": String(server.statusSnapshot().sessionID),
                        "client_rekeys_completed_total": client.statusSnapshot().rekeysCompletedTotal,
                        "server_rekeys_completed_total": server.statusSnapshot().rekeysCompletedTotal,
                        "client_last_rekey_trigger": client.statusSnapshot().lastRekeyTrigger,
                        "server_last_rekey_trigger": server.statusSnapshot().lastRekeyTrigger,
                        "client_authenticated_sessions_total": client.statusSnapshot().authenticatedSessionsTotal,
                        "server_authenticated_sessions_total": server.statusSnapshot().authenticatedSessionsTotal,
                        "client_last_event": client.statusSnapshot().lastEvent,
                        "server_last_event": server.statusSnapshot().lastEvent,
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
        "client_session_id": "72623859790382857",
        "server_session_id": "72623859790382857",
        "client_rekeys_completed_total": 1,
        "server_rekeys_completed_total": 1,
        "client_last_rekey_trigger": "time_threshold",
        "server_last_rekey_trigger": "remote",
        "client_authenticated_sessions_total": 2,
        "server_authenticated_sessions_total": 2,
        "client_last_event": "rekey_completed",
        "server_last_event": "rekey_completed",
    }


def test_ios_secure_link_transport_adapter_retry_and_recovery_policy_matches_python_shape(tmp_path: Path) -> None:
    source_path = tmp_path / "SecureLinkTransportRetryRecoveryProbe.swift"
    binary_path = tmp_path / "secure-link-transport-retry-recovery-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct SecureLinkTransportRetryRecoveryProbe {
                static func main() throws {
                    var mono = 100.0
                    var unix = 2000.0

                    let retryClient = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x11, count: count) },
                            sessionIDProvider: { 0x0102030405060708 },
                            timeProvider: { mono },
                            unixTimeProvider: { unix }
                        ),
                        retryBackoffInitialMS: 1000,
                        retryBackoffMaxMS: 5000,
                        timeProvider: { mono },
                        unixTimeProvider: { unix }
                    )

                    let firstHandshake = try retryClient.handleTransportConnected()
                    guard firstHandshake.emittedFrames.count == 1 else {
                        throw ProbeError.badState("missing initial client hello")
                    }
                    let retryFailure = retryClient.handleInboundFrame(Data([0x00, 0x01, 0x02]))
                    guard retryFailure.authFailCode == ObstacleBridgeSecureLinkPskRuntime.authFailDecode else {
                        throw ProbeError.badState("expected decode failure")
                    }
                    let retryStatus = retryClient.statusSnapshot()
                    if retryStatus.retryBackoffSec != 1.0 || retryStatus.nextRetryUnixTs != 2001.0 {
                        throw ProbeError.badState("retry schedule mismatch")
                    }
                    mono = 101.0
                    unix = 2001.0
                    let retriedHandshake = try retryClient.pollDueFrames()
                    guard retriedHandshake.emittedFrames.count == 1 else {
                        throw ProbeError.badState("expected scheduled retry client hello")
                    }
                    let retryStatusAfterPoll = retryClient.statusSnapshot()

                    mono = 300.0
                    unix = 4000.0
                    let authClient = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: true,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x33, count: count) },
                            sessionIDProvider: { 0x1112131415161718 },
                            timeProvider: { mono },
                            unixTimeProvider: { unix }
                        ),
                        retryBackoffInitialMS: 1000,
                        retryBackoffMaxMS: 5000,
                        timeProvider: { mono },
                        unixTimeProvider: { unix }
                    )
                    let authServer = ObstacleBridgeSecureLinkPskTransportAdapter(
                        runtime: ObstacleBridgeSecureLinkPskRuntime(
                            clientMode: false,
                            psk: "shared-psk",
                            randomBytes: { count in Data(repeating: 0x44, count: count) },
                            sessionIDProvider: { 0 },
                            timeProvider: { mono },
                            unixTimeProvider: { unix }
                        )
                    )

                    let authHello = try authClient.handleTransportConnected().emittedFrames.first!
                    let authServerHello = authServer.handleInboundFrame(authHello).emittedFrames.first!
                    let authClientProof = authClient.handleInboundFrame(authServerHello).emittedFrames.first!
                    _ = authServer.handleInboundFrame(authClientProof)
                    let warmupReply = try authServer.handleOutboundPayload(Data("warmup".utf8)).emittedFrames.first!
                    _ = authClient.handleInboundFrame(warmupReply)
                    if !authClient.statusSnapshot().authenticated {
                        throw ProbeError.badState("expected authenticated client")
                    }

                    let recoveryFailure = authClient.handleInboundFrame(Data([0x00, 0x01, 0x02]))
                    guard recoveryFailure.authFailCode == ObstacleBridgeSecureLinkPskRuntime.authFailDecode else {
                        throw ProbeError.badState("expected decode failure after authentication")
                    }
                    let recoveryStatus = authClient.statusSnapshot()
                    if recoveryStatus.retryBackoffSec != 0.0 || recoveryStatus.nextRetryUnixTs != nil {
                        throw ProbeError.badState("authenticated failure should not schedule retry backoff")
                    }
                    let payload: [String: Any] = [
                        "retry_consecutive_failures": retryStatus.consecutiveFailures,
                        "retry_retry_backoff_sec": retryStatus.retryBackoffSec,
                        "retry_next_retry_unix_ts": retryStatus.nextRetryUnixTs ?? NSNull(),
                        "retry_handshake_attempts_total": retryStatusAfterPoll.handshakeAttemptsTotal,
                        "retry_backoff_after_poll_sec": retryStatusAfterPoll.retryBackoffSec,
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
        "retry_consecutive_failures": 1,
        "retry_retry_backoff_sec": 1.0,
        "retry_next_retry_unix_ts": 2001.0,
        "retry_handshake_attempts_total": 2,
        "retry_backoff_after_poll_sec": 0.0,
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
