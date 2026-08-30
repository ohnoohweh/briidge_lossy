from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / "ios" / "native" / "ObstacleBridgeShared"


def test_swift_myudp2_batch_codec_and_stream_receive_state(tmp_path: Path) -> None:
    swiftc = shutil.which("swiftc")
    if not swiftc:
        pytest.skip("swiftc is required for the myUDP2 Swift codec probe")

    source = tmp_path / "MyUDP2CodecProbe.swift"
    binary = tmp_path / "myudp2-codec-probe"
    source.write_text(
        textwrap.dedent(
            """
            import Foundation

            enum ProbeError: Error { case failed(String) }

            @main
            struct MyUDP2CodecProbe {
                static func main() throws {
                    let chunks = [
                        ObstacleBridgeUdpOverlayCodec.StreamChunk(counter: 7, data: Data([0x61, 0x62, 0x63])),
                        ObstacleBridgeUdpOverlayCodec.StreamChunk(counter: 8, data: Data([0x64, 0x65])),
                    ]
                    let batch = try ObstacleBridgeUdpOverlayCodec.encodeDataBatch(chunks)
                    guard batch == Data([0x01, 0x02, 0x00, 0x07, 0x00, 0x07, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00, 0x06, 0x00, 0x08, 0x00, 0x02, 0x64, 0x65]),
                          ObstacleBridgeUdpOverlayCodec.decodeDataBatch(batch) == chunks else {
                        throw ProbeError.failed("batch vector mismatch")
                    }

                    let record = try ObstacleBridgeUdpOverlayCodec.encodeStreamRecord(Data("hello".utf8))
                    let receiver = ObstacleBridgeUdpOverlaySessionCodec.StreamReceiveState()
                    guard receiver.process(.init(counter: 2, data: record.suffix(from: 3)))?.1.isEmpty == true,
                          let delivered = receiver.process(.init(counter: 1, data: record.prefix(3)))?.1,
                          delivered == [Data("hello".utf8)] else {
                        throw ProbeError.failed("stream reorder delivery mismatch")
                    }

                    let sender = ObstacleBridgeUdpOverlayPeerRuntime(maxInFlight: 4)
                    try sender.enqueueApplicationPayload(Data("one".utf8), nowNS: 10)
                    try sender.enqueueApplicationPayload(Data("two".utf8), nowNS: 10)
                    let coalesced = try sender.flushSendQueue(nowNS: 11)
                    guard coalesced.frames.count == 1,
                          let coalescedFrame = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(coalesced.frames[0]),
                          let coalescedChunks = ObstacleBridgeUdpOverlayCodec.decodeDataBatch(coalescedFrame.payload),
                          coalescedChunks.count == 2 else {
                        throw ProbeError.failed("queued records did not coalesce")
                    }

                    let retry = try sender.handleInboundControlPacket(
                        nowNS: 20,
                        txNS: 20,
                        echoNS: 0,
                        packetLastInOrder: 0,
                        packetHighest: 2,
                        packetMissed: [1],
                        sendPortPresent: true
                    )
                    guard retry.emittedCounters.contains(1),
                          let retryFrame = retry.emittedFrames.first,
                          let parsedRetry = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(retryFrame),
                          let retryChunks = ObstacleBridgeUdpOverlayCodec.decodeDataBatch(parsedRetry.payload),
                          retryChunks.count == 1,
                          retryChunks[0].counter == 1 else {
                        throw ProbeError.failed("missing chunk retry mismatch")
                    }

                    let window = ObstacleBridgeUdpOverlayPeerRuntime(maxInFlight: 1)
                    _ = try window.sendApplicationPayload(Data("first".utf8), nowNS: 30)
                    let blocked = try window.sendApplicationPayload(Data("second".utf8), nowNS: 31)
                    guard blocked.frames.isEmpty, blocked.waitingCount == 1 else {
                        throw ProbeError.failed("send window did not apply backpressure")
                    }
                    let released = try window.handleInboundControlPacket(
                        nowNS: 32,
                        txNS: 32,
                        echoNS: 0,
                        packetLastInOrder: 1,
                        packetHighest: 1,
                        packetMissed: [],
                        sendPortPresent: true
                    )
                    guard released.emittedCounters == [2], released.emittedFrames.count == 1 else {
                        throw ProbeError.failed("ack did not release queued stream data")
                    }

                    let receiverRuntime = ObstacleBridgeUdpOverlayPeerRuntime()
                    let malformed = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
                        ptype: ObstacleBridgeUdpOverlayCodec.ptypeData,
                        payload: Data([0x01, 0x00]),
                        txNS: 40,
                        echoNS: 0
                    )
                    guard receiverRuntime.handleInboundDataFrame(
                        frame: malformed, nowNS: 40, txNS: 40, echoNS: 0, sendPortPresent: true
                    ) == nil,
                    (receiverRuntime.protocolStatsSnapshot()["malformed_batches"] as? Int) == 1 else {
                        throw ProbeError.failed("malformed batch was accepted")
                    }

                    let resetRecord = try ObstacleBridgeUdpOverlayCodec.encodeStreamRecord(Data("reset".utf8))
                    let firstHalf = try ObstacleBridgeUdpOverlayCodec.buildDataBatchFrame(
                        chunks: [.init(counter: 1, data: resetRecord.prefix(3))], txNS: 50, echoNS: 0
                    )
                    _ = receiverRuntime.handleInboundDataFrame(
                        frame: firstHalf, nowNS: 50, txNS: 50, echoNS: 0, sendPortPresent: true
                    )
                    receiverRuntime.resetTransportEpoch()
                    let fresh = try ObstacleBridgeUdpOverlayCodec.buildDataBatchFrame(
                        chunks: [.init(counter: 1, data: resetRecord)], txNS: 51, echoNS: 0
                    )
                    guard receiverRuntime.handleInboundDataFrame(
                        frame: fresh, nowNS: 51, txNS: 51, echoNS: 0, sendPortPresent: true
                    )?.completedPayloads == [Data("reset".utf8)] else {
                        throw ProbeError.failed("transport epoch reset retained stream bytes")
                    }

                    let rollover = ObstacleBridgeUdpOverlayPeerRuntime(nextCounter: 65535)
                    let rolloverSnapshot = try rollover.sendApplicationPayload(Data(repeating: 0x78, count: 2000), nowNS: 60)
                    guard rolloverSnapshot.counters == [65535, 1], rolloverSnapshot.frames.count == 2 else {
                        throw ProbeError.failed("counter rollover chunk sequence mismatch")
                    }
                    print("ok")
                }
            }
            """
        ),
        encoding="utf-8",
    )
    command = [
        swiftc,
        "-o",
        str(binary),
        str(SHARED / "ObstacleBridgeChannelMuxCodec.swift"),
        str(SHARED / "ObstacleBridgeUdpOverlayCodec.swift"),
        str(SHARED / "ObstacleBridgeUdpOverlaySessionCodec.swift"),
        str(SHARED / "ObstacleBridgeUdpOverlayPeerRuntime.swift"),
        str(source),
    ]
    compiled = subprocess.run(command, capture_output=True, text=True, check=False)
    assert compiled.returncode == 0, compiled.stderr
    ran = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert ran.returncode == 0, f"STDOUT:\n{ran.stdout}\nSTDERR:\n{ran.stderr}"
    assert ran.stdout.strip() == "ok"
