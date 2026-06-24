from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHARED_NATIVE_DIR = ROOT / "ios" / "native" / "ObstacleBridgeShared"


def _compile_swift_udp_tun_probe(source_path: Path, binary_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for swift_udp TUN helper tests")
    command = [
        swiftc,
        "-o",
        str(binary_path),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeOverlayStackPlanner.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeRuntimeConfig.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeChannelMuxTunRuntime.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlaySessionCodec.swift"),
        str(SHARED_NATIVE_DIR / "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
        str(source_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"swiftc failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )


def test_ios_swift_udp_tun_helper_probe_covers_provider_tun_path(tmp_path: Path) -> None:
    source_path = tmp_path / "SwiftUDPTunProbe.swift"
    binary_path = tmp_path / "swift-udp-tun-probe"
    source_path.write_text(
        textwrap.dedent(
            r"""
            import Foundation

            enum ProbeError: Error {
                case badState(String)
            }

            struct CapturedMuxFrame {
                var chanID: Int
                var mtype: String
                var packetText: String
                var allocated: Bool?

                func jsonObject() -> [String: Any] {
                    [
                        "chan_id": chanID,
                        "mtype": mtype,
                        "packet_text": packetText,
                        "allocated": allocated ?? NSNull(),
                    ]
                }
            }

            private func mtypeName(_ value: ObstacleBridgeChannelMuxCodec.MType) -> String {
                switch value {
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

            final class SwiftUDPTunBridgeHarness {
                let mtu: Int
                let tunSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec
                let muxRuntime: ObstacleBridgeChannelMuxTunRuntime
                let overlayRuntime: ObstacleBridgeUdpOverlayPeerRuntime

                init(instanceID: UInt64, connectionSeq: UInt32, tunIfname: String, mtu: Int) {
                    self.mtu = mtu
                    self.tunSpec = ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: mtu)
                    self.muxRuntime = ObstacleBridgeChannelMuxTunRuntime(
                        instanceID: instanceID,
                        connectionSeq: connectionSeq,
                        localSpec: ObstacleBridgeRuntimeConfig.localTunServiceSpec(ifname: tunIfname, mtu: mtu)
                    )
                    self.overlayRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
                }

                func sendLocalPacket(_ packet: Data, nowNS: UInt64) throws -> (datagrams: [Data], muxFrames: [CapturedMuxFrame]) {
                    guard let snapshot = try muxRuntime.handleLocalTunPacket(
                        packet: packet,
                        mtu: mtu,
                        spec: tunSpec,
                        overlayConnected: true,
                        acceptingEnabled: true
                    ) else {
                        throw ProbeError.badState("local tun packet rejected")
                    }
                    var datagrams: [Data] = []
                    var muxFrames: [CapturedMuxFrame] = []
                    for payload in snapshot.frames {
                        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
                            throw ProbeError.badState("failed to unpack outbound mux frame")
                        }
                        let packetText = frame.mtype == .data ? (String(data: frame.body, encoding: .utf8) ?? "") : ""
                        muxFrames.append(
                            CapturedMuxFrame(
                                chanID: frame.chanID,
                                mtype: mtypeName(frame.mtype),
                                packetText: packetText,
                                allocated: frame.mtype == .open ? snapshot.allocatedChannel : nil
                            )
                        )
                        let overlaySnapshot = try overlayRuntime.sendApplicationPayload(payload, nowNS: nowNS, echoNS: 0)
                        datagrams.append(contentsOf: overlaySnapshot.frames)
                    }
                    return (datagrams, muxFrames)
                }

                func receiveDatagrams(_ datagrams: [Data], nowNS: UInt64) throws -> [Data] {
                    var packets: [Data] = []
                    for datagram in datagrams {
                        guard let frame = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(datagram) else {
                            throw ProbeError.badState("failed to parse overlay frame")
                        }
                        guard frame.ptype == ObstacleBridgeUdpOverlayCodec.ptypeData else {
                            continue
                        }
                        guard let snapshot = overlayRuntime.handleInboundDataFrame(
                            frame: datagram,
                            nowNS: nowNS,
                            txNS: frame.txNS,
                            echoNS: frame.echoNS,
                            sendPortPresent: true
                        ) else {
                            throw ProbeError.badState("failed to process inbound overlay data")
                        }
                        for payload in snapshot.completedPayloads {
                            guard let muxFrame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
                                throw ProbeError.badState("failed to unpack inbound mux payload")
                            }
                            switch muxFrame.mtype {
                            case .open:
                                _ = muxRuntime.handleInboundTunOpen(chanID: muxFrame.chanID, payload: muxFrame.body)
                            case .openChunk:
                                _ = muxRuntime.handleInboundTunOpenChunk(chanID: muxFrame.chanID, payload: muxFrame.body)
                            case .data:
                                let tunSnapshot = muxRuntime.handleInboundTunData(chanID: muxFrame.chanID, body: muxFrame.body, mtu: mtu)
                                if let packet = tunSnapshot.packet, tunSnapshot.delivered {
                                    packets.append(packet)
                                }
                            case .dataFrag:
                                let tunSnapshot = muxRuntime.handleInboundTunFragment(chanID: muxFrame.chanID, payload: muxFrame.body, mtu: mtu)
                                if let packet = tunSnapshot.packet, tunSnapshot.delivered {
                                    packets.append(packet)
                                }
                            case .close:
                                _ = muxRuntime.handleInboundTunClose(chanID: muxFrame.chanID)
                            default:
                                continue
                            }
                        }
                    }
                    return packets
                }
            }

            @main
            struct SwiftUDPTunProbe {
                static func main() throws {
                    let sender = SwiftUDPTunBridgeHarness(
                        instanceID: 0x1000000000000001,
                        connectionSeq: 0x10101010,
                        tunIfname: "ios-utun",
                        mtu: 1400
                    )
                    let receiver = SwiftUDPTunBridgeHarness(
                        instanceID: 0x2000000000000002,
                        connectionSeq: 0x20202020,
                        tunIfname: "ios-utun",
                        mtu: 1400
                    )

                    let senderPacket = Data("packet-from-sender".utf8)
                    let firstSend = try sender.sendLocalPacket(senderPacket, nowNS: 1_000_000)
                    let receiverPackets = try receiver.receiveDatagrams(firstSend.datagrams, nowNS: 2_000_000)

                    let receiverReply = Data("packet-from-receiver".utf8)
                    let replySend = try receiver.sendLocalPacket(receiverReply, nowNS: 3_000_000)
                    let senderPackets = try sender.receiveDatagrams(replySend.datagrams, nowNS: 4_000_000)

                    let payload: [String: Any] = [
                        "tun_spec": [
                            "l_proto": sender.tunSpec.lProto,
                            "l_bind": sender.tunSpec.lBind,
                            "l_port": sender.tunSpec.lPort,
                            "r_proto": sender.tunSpec.rProto,
                            "r_host": sender.tunSpec.rHost,
                            "r_port": sender.tunSpec.rPort,
                        ],
                        "first_send_mux_frames": firstSend.muxFrames.map { $0.jsonObject() },
                        "first_send_overlay_frame_count": firstSend.datagrams.count,
                        "receiver_packets": receiverPackets.map { String(data: $0, encoding: .utf8) ?? "" },
                        "reply_send_mux_frames": replySend.muxFrames.map { $0.jsonObject() },
                        "reply_send_overlay_frame_count": replySend.datagrams.count,
                        "sender_packets": senderPackets.map { String(data: $0, encoding: .utf8) ?? "" },
                    ]
                    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
                    FileHandle.standardOutput.write(data)
                }
            }
            """
        ),
        encoding="utf-8",
    )
    _compile_swift_udp_tun_probe(source_path, binary_path)
    completed = subprocess.run([str(binary_path)], capture_output=True, text=True, check=False, timeout=30)
    if completed.returncode != 0:
        raise AssertionError(
            f"probe failed with exit code {completed.returncode}:\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)

    assert payload["tun_spec"] == {
        "l_proto": "tun",
        "l_bind": "ios-utun",
        "l_port": 1400,
        "r_proto": "tun",
        "r_host": "ios-utun",
        "r_port": 1400,
    }
    assert payload["first_send_mux_frames"] == [
        {
            "chan_id": 1,
            "mtype": "open",
            "packet_text": "",
            "allocated": True,
        },
        {
            "chan_id": 1,
            "mtype": "data",
            "packet_text": "packet-from-sender",
            "allocated": None,
        },
    ]
    assert payload["first_send_overlay_frame_count"] == 2
    assert payload["receiver_packets"] == ["packet-from-sender"]
    assert payload["reply_send_mux_frames"] == [
        {
            "chan_id": 1,
            "mtype": "data",
            "packet_text": "packet-from-receiver",
            "allocated": None,
        }
    ]
    assert payload["reply_send_overlay_frame_count"] == 1
    assert payload["sender_packets"] == ["packet-from-receiver"]