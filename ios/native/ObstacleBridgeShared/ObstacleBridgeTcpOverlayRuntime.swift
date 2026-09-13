import Foundation

final class ObstacleBridgeTcpOverlayRuntime {
    private static let lenFieldSize = 4
    struct SendSnapshot {
        var txBytes: Int
        var peerTxNotifications: [Int]
        var writtenHex: [String]
        var writtenBuffers: [Data]
        var earlyBufBytes: Int
        var earlyBufHex: String?
        var connectRequested: Bool
    }

    struct ConnectSnapshot {
        var connected: Bool
        var peerHost: String
        var peerPort: Int
        var keepAliveEnabled: Bool
        var overlayConnected: Bool
        var bpTaskStarted: Bool
        var flushedHex: [String]
        var flushedBuffers: [Data]
        var earlyBufBytes: Int
    }

    struct ReceiveSnapshot {
        var completedPayloads: [Data]
        var consumedBytes: Int
        var remainingBytes: Int
        var overlayConnected: Bool
    }

    struct SocketConfigSnapshot {
        var keepAliveEnabled: Bool
    }

    struct ReconnectSnapshot {
        var requested: Bool
        var writerClosed: Bool
        var writerPresent: Bool
        var readerPresent: Bool
        var overlayConnected: Bool
        var reconnectLoopStarted: Bool
    }

    struct AcceptSnapshot {
        var peerID: Int
        var peerHost: String
        var peerPort: Int
        var keepAliveEnabled: Bool
        var overlayConnected: Bool
        var serverPeerIDs: [Int]
    }

    struct ServerOverlaySnapshot {
        var overlayConnected: Bool
        var serverPeerIDs: [Int]
    }

    struct BackpressureSnapshot {
        var signaled: Bool
    }

    private let earlyMax: Int
    private let earlyTTL: Double
    private let wbufThreshold: Int
    private var earlyBuf = Data()
    private var earlyDeadline = 0.0
    private var txBytes = 0
    private var overlayConnected = false
    private var peerHost = ""
    private var peerPort = 0
    private var nextPeerID: Int
    private var serverPeerIDs: Set<Int> = []

    init(
        earlyMax: Int = 1024 * 1024,
        earlyTTL: Double = 3.0,
        wbufThreshold: Int = 128 * 1024,
        nextPeerID: Int = 1
    ) {
        self.earlyMax = max(0, earlyMax)
        self.earlyTTL = max(0.0, earlyTTL)
        self.wbufThreshold = max(0, wbufThreshold)
        self.nextPeerID = max(1, nextPeerID)
    }

    func sendApp(payload: Data, writerPresent: Bool, peerConfigured: Bool, now: Double = 0.0) -> SendSnapshot {
        guard !payload.isEmpty else {
            return SendSnapshot(
                txBytes: txBytes,
                peerTxNotifications: [],
                writtenHex: [],
                writtenBuffers: [],
                earlyBufBytes: earlyBuf.count,
                earlyBufHex: earlyBuf.isEmpty ? nil : hexFromData(earlyBuf),
                connectRequested: false
            )
        }

        guard let wire = buildAppWire(payload) else {
            return SendSnapshot(
                txBytes: txBytes,
                peerTxNotifications: [],
                writtenHex: [],
                writtenBuffers: [],
                earlyBufBytes: earlyBuf.count,
                earlyBufHex: earlyBuf.isEmpty ? nil : hexFromData(earlyBuf),
                connectRequested: false
            )
        }
        if !writerPresent {
            bufferEarly(wireFrame: wire, now: now)
            return SendSnapshot(
                txBytes: txBytes,
                peerTxNotifications: [],
                writtenHex: [],
                writtenBuffers: [],
                earlyBufBytes: earlyBuf.count,
                earlyBufHex: hexFromData(earlyBuf),
                connectRequested: peerConfigured
            )
        }

        txBytes += wire.count
        return SendSnapshot(
            txBytes: txBytes,
            peerTxNotifications: [wire.count],
            writtenHex: [hexFromData(wire)],
            writtenBuffers: [wire],
            earlyBufBytes: earlyBuf.count,
            earlyBufHex: earlyBuf.isEmpty ? nil : hexFromData(earlyBuf),
            connectRequested: false
        )
    }

    func connect(host: String, port: Int, socketPresent: Bool) -> ConnectSnapshot {
        peerHost = host
        peerPort = port
        let flushedHex = flushEarly(writerPresent: true)
        return ConnectSnapshot(
            connected: true,
            peerHost: peerHost,
            peerPort: peerPort,
            keepAliveEnabled: socketPresent,
            overlayConnected: overlayConnected,
            bpTaskStarted: true,
            flushedHex: flushedHex,
            flushedBuffers: flushedHex.compactMap(Self.dataFromHex),
            earlyBufBytes: earlyBuf.count
        )
    }

    func handleInboundBytes(_ buffer: Data) -> ReceiveSnapshot {
        var completedPayloads: [Data] = []
        var cursor = 0
        while (buffer.count - cursor) >= Self.lenFieldSize {
            let header = Data(buffer[cursor..<(cursor + Self.lenFieldSize)])
            guard let length = try? ObstacleBridgeOverlayFrameCodec.decodeTCPBodyLength(header) else {
                cursor += Self.lenFieldSize
                continue
            }
            if length == 0 {
                cursor += Self.lenFieldSize
                continue
            }
            let totalLength = Self.lenFieldSize + Int(length)
            guard totalLength >= (Self.lenFieldSize + 1) else {
                cursor += Self.lenFieldSize
                continue
            }
            guard (buffer.count - cursor) >= totalLength else {
                break
            }
            let wire = Data(buffer[cursor..<(cursor + totalLength)])
            if let frame = try? ObstacleBridgeOverlayFrameCodec.decodeTCP(wire), frame.kind == .application {
                completedPayloads.append(frame.payload)
            }
            cursor += totalLength
        }
        overlayConnected = overlayConnected || !completedPayloads.isEmpty
        return ReceiveSnapshot(
            completedPayloads: completedPayloads,
            consumedBytes: cursor,
            remainingBytes: max(0, buffer.count - cursor),
            overlayConnected: overlayConnected
        )
    }

    func socketConfigSnapshot(socketPresent: Bool) -> SocketConfigSnapshot {
        return SocketConfigSnapshot(keepAliveEnabled: socketPresent)
    }

    func requestReconnect(runFlag: Bool, peerConfigured: Bool, writerPresent: Bool, initiallyConnected: Bool) -> ReconnectSnapshot {
        guard peerConfigured, runFlag else {
            return ReconnectSnapshot(
                requested: false,
                writerClosed: false,
                writerPresent: writerPresent,
                readerPresent: writerPresent,
                overlayConnected: initiallyConnected,
                reconnectLoopStarted: false
            )
        }
        overlayConnected = false
        return ReconnectSnapshot(
            requested: true,
            writerClosed: writerPresent,
            writerPresent: false,
            readerPresent: false,
            overlayConnected: false,
            reconnectLoopStarted: true
        )
    }

    func acceptServerPeer(peerHost: String, peerPort: Int, socketPresent: Bool) -> AcceptSnapshot {
        let peerID = allocatePeerID()
        self.peerHost = peerHost
        self.peerPort = peerPort
        serverPeerIDs.insert(peerID)
        overlayConnected = !serverPeerIDs.isEmpty
        return AcceptSnapshot(
            peerID: peerID,
            peerHost: peerHost,
            peerPort: peerPort,
            keepAliveEnabled: socketPresent,
            overlayConnected: overlayConnected,
            serverPeerIDs: serverPeerIDs.sorted()
        )
    }

    func closeServerPeer(peerID: Int) -> ServerOverlaySnapshot {
        serverPeerIDs.remove(peerID)
        overlayConnected = !serverPeerIDs.isEmpty
        return ServerOverlaySnapshot(
            overlayConnected: overlayConnected,
            serverPeerIDs: serverPeerIDs.sorted()
        )
    }

    func backpressureSnapshot(writeBufferSize: Int, threshold: Int? = nil) -> BackpressureSnapshot {
        let effectiveThreshold = max(0, threshold ?? wbufThreshold)
        return BackpressureSnapshot(signaled: writeBufferSize >= effectiveThreshold)
    }

    private func allocatePeerID() -> Int {
        let peerID = nextPeerID
        nextPeerID += 1
        return peerID
    }

    private func bufferEarly(wireFrame: Data, now: Double) {
        if earlyDeadline > 0, now > earlyDeadline {
            earlyBuf.removeAll(keepingCapacity: false)
        }
        earlyDeadline = now + earlyTTL

        let overflow = (earlyBuf.count + wireFrame.count) - earlyMax
        if overflow > 0 {
            let dropCount = min(overflow, earlyBuf.count)
            if dropCount > 0 {
                earlyBuf.removeFirst(dropCount)
            }
        }
        earlyBuf.append(wireFrame)
    }

    private func flushEarly(writerPresent: Bool) -> [String] {
        guard writerPresent, !earlyBuf.isEmpty else {
            return []
        }
        let pending = earlyBuf
        txBytes += pending.count
        earlyBuf.removeAll(keepingCapacity: false)
        earlyDeadline = 0.0
        return [hexFromData(pending)]
    }

    private func buildAppWire(_ payload: Data) -> Data? {
        try? ObstacleBridgeOverlayFrameCodec.encodeTCP(.init(kind: .application, payload: payload))
    }

    private func hexFromData(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func dataFromHex(_ text: String) -> Data? {
        guard (text.count % 2) == 0 else {
            return nil
        }
        var data = Data(capacity: text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let value = UInt8(text[index..<next], radix: 16) else {
                return nil
            }
            data.append(value)
            index = next
        }
        return data
    }

}
