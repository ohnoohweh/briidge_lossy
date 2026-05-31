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
        "server_auth_frames": 0,
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