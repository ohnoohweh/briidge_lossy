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

from swift_test_support import require_swift_modules


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"


def _compile_swift_overlay_layer_transport_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = require_swift_modules(
        "CryptoKit",
        "zlib",
        missing_swiftc_reason="swiftc is required for Swift overlay layer transport adapter tests",
        missing_module_reason="Swift overlay layer transport adapter tests require a Swift toolchain with CryptoKit and zlib support",
    )
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeCompressLayerRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeSecureLinkPskTransportAdapter.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayLayerTransportAdapter.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_overlay_layer_transport_adapter_wraps_compress_then_secure_link(tmp_path: Path) -> None:
    source_path = tmp_path / "OverlayLayerTransportAdapterProbe.swift"
    binary_path = tmp_path / "overlay-layer-transport-adapter-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            @main
            struct OverlayLayerTransportAdapterProbe {
                static func main() throws {
                    let clientCompress = ObstacleBridgeCompressLayerRuntime(
                        configuredEnabled: true,
                        isPeerClient: true,
                        transportName: "udp",
                        level: 3,
                        minBytes: 32
                    )
                    let serverCompress = ObstacleBridgeCompressLayerRuntime(
                        configuredEnabled: true,
                        isPeerClient: false,
                        transportName: "udp",
                        level: 3,
                        minBytes: 32
                    )
                    let client = ObstacleBridgeOverlayLayerTransportAdapter(
                        compressRuntime: clientCompress,
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(
                                clientMode: true,
                                psk: "shared-psk",
                                randomBytes: { count in Data(repeating: 0x11, count: count) },
                                sessionIDProvider: { 0x0102030405060708 }
                            )
                        )
                    )
                    let server = ObstacleBridgeOverlayLayerTransportAdapter(
                        compressRuntime: serverCompress,
                        secureLinkAdapter: ObstacleBridgeSecureLinkPskTransportAdapter(
                            runtime: ObstacleBridgeSecureLinkPskRuntime(
                                clientMode: false,
                                psk: "shared-psk",
                                randomBytes: { count in Data(repeating: 0x22, count: count) },
                                sessionIDProvider: { 0 }
                            )
                        )
                    )

                    let clientMux = try ObstacleBridgeChannelMuxCodec.packMux(
                        chanID: 7,
                        proto: .tcp,
                        counter: 1,
                        mtype: .data,
                        body: Data(repeating: 0x41, count: 256)
                    )
                    let serverMux = try ObstacleBridgeChannelMuxCodec.packMux(
                        chanID: 9,
                        proto: .udp,
                        counter: 2,
                        mtype: .data,
                        body: Data(repeating: 0x42, count: 192)
                    )

                    let clientQueued = try client.handleOutboundPayload(clientMux)
                    guard let clientHello = clientQueued.emittedFrames.first else {
                        throw ProbeError.badState("missing client hello")
                    }

                    let serverHello = server.handleInboundFrame(clientHello)
                    guard let serverHelloFrame = serverHello.emittedFrames.first else {
                        throw ProbeError.badState("missing server hello")
                    }

                    let clientAuth = client.handleInboundFrame(serverHelloFrame)
                    guard clientAuth.emittedFrames.count >= 2 else {
                        throw ProbeError.badState("missing client proof or flushed payload")
                    }
                    let serverProof = server.handleInboundFrame(clientAuth.emittedFrames[0])
                    let serverData = server.handleInboundFrame(clientAuth.emittedFrames[1])
                    guard let deliveredClientMux = serverData.deliveredPayloads.first,
                          let unpackedClientMux = ObstacleBridgeChannelMuxCodec.unpackMux(deliveredClientMux)
                    else {
                        throw ProbeError.badState("missing decompressed client mux")
                    }

                    let serverSend = try server.handleOutboundPayload(serverMux)
                    guard let serverReplyFrame = serverSend.emittedFrames.first else {
                        throw ProbeError.badState("missing server reply")
                    }
                    let clientData = client.handleInboundFrame(serverReplyFrame)
                    guard let deliveredServerMux = clientData.deliveredPayloads.first,
                          let unpackedServerMux = ObstacleBridgeChannelMuxCodec.unpackMux(deliveredServerMux)
                    else {
                        throw ProbeError.badState("missing decompressed server mux")
                    }

                    let payload: [String: Any] = [
                        "queued_client_frames": clientQueued.emittedFrames.count,
                        "client_auth_frames": clientAuth.emittedFrames.count,
                        "server_auth_frames": serverProof.emittedFrames.count,
                        "client_compress_applied": clientCompress.statusSnapshot().compressAppliedTotal,
                        "server_decompress_ok": serverCompress.statusSnapshot().decompressOKTotal,
                        "server_compress_applied": serverCompress.statusSnapshot().compressAppliedTotal,
                        "client_decompress_ok": clientCompress.statusSnapshot().decompressOKTotal,
                        "server_received_chan": unpackedClientMux.chanID,
                        "server_received_proto": unpackedClientMux.proto.rawValue,
                        "server_received_mtype": unpackedClientMux.mtype.rawValue,
                        "server_received_bytes": unpackedClientMux.body.count,
                        "client_received_chan": unpackedServerMux.chanID,
                        "client_received_proto": unpackedServerMux.proto.rawValue,
                        "client_received_mtype": unpackedServerMux.mtype.rawValue,
                        "client_received_bytes": unpackedServerMux.body.count,
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_overlay_layer_transport_probe(source_path, binary_path)
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
        "client_compress_applied": 1,
        "server_decompress_ok": 1,
        "server_compress_applied": 1,
        "client_decompress_ok": 1,
        "server_received_chan": 7,
        "server_received_proto": 1,
        "server_received_mtype": 0,
        "server_received_bytes": 256,
        "client_received_chan": 9,
        "client_received_proto": 0,
        "client_received_mtype": 0,
        "client_received_bytes": 192,
    }


def test_ios_overlay_layer_transport_adapter_distinguishes_inflow_from_app_ready_during_reauth(tmp_path: Path) -> None:
    source_path = tmp_path / "OverlayLayerTransportAdapterReauthProbe.swift"
    binary_path = tmp_path / "overlay-layer-transport-adapter-reauth-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            @main
            struct OverlayLayerTransportAdapterReauthProbe {
                static func main() throws {
                    let secureStatus = ObstacleBridgeSecureLinkPskRuntime.StatusSnapshot(
                        clientMode: true,
                        authenticated: false,
                        peerConfirmedAuthenticated: true,
                        sessionID: 0x0102030405060708,
                        txCounter: 1,
                        rxCounter: 1,
                        authFailCode: 0,
                        lastEvent: "transport_peer_disconnected",
                        lastEventUnixTs: 1700000200.0,
                        authenticatedSessionsTotal: 1,
                        rekeySupported: true,
                        rekeyInProgress: false,
                        rekeysCompletedTotal: 0,
                        lastRekeyTrigger: "",
                        disconnectReason: "",
                        disconnectDetail: "",
                        trustValidationState: "validated",
                        appDataSendingBlocked: true,
                        framesPassedTotal: 2,
                        framesDroppedTotal: 0,
                        handshakeAttemptsTotal: 1,
                        consecutiveFailures: 0,
                        retryBackoffSec: 0.0,
                        nextRetryUnixTs: nil,
                        recoveryEnabled: true,
                        recoveryDelaySec: 30.0,
                        recoveryReconnectSec: 0.0,
                        nextRecoveryReconnectUnixTs: nil
                    )
                    let layers = ObstacleBridgeOverlayLayerTransportAdapter.connectionLayersSnapshot(
                        transport: "tcp",
                        transportConnected: true,
                        transportEpoch: 9,
                        compressionEnabled: false,
                        secureLinkStatus: secureStatus,
                        preserveConnectedDuringEpochRestart: true
                    )
                    let payload: [String: Any] = [
                        "layer_count": layers.count,
                        "transport_connected": (layers.first?["connected"] as? Bool) ?? false,
                        "secure_state": (layers.last?["state"] as? String) ?? "",
                        "secure_connected": (layers.last?["connected"] as? Bool) ?? false,
                        "secure_app_ready": (layers.last?["app_ready"] as? Bool) ?? true,
                        "preserve_connected": (layers.last?["preserve_connected_during_epoch_restart"] as? Bool) ?? false,
                        "app_ready": ObstacleBridgeOverlayLayerTransportAdapter.appReady(from: layers),
                        "inflow_allowed": ObstacleBridgeOverlayLayerTransportAdapter.inflowAllowed(from: layers),
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_overlay_layer_transport_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)

    assert payload == {
        "layer_count": 2,
        "transport_connected": True,
        "secure_state": "reauthenticating",
        "secure_connected": True,
        "secure_app_ready": False,
        "preserve_connected": True,
        "app_ready": False,
        "inflow_allowed": True,
    }
