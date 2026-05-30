import Foundation

final class ObstacleBridgeTcpOverlayRuntime {
    struct SendSnapshot {
        var txBytes: Int
        var peerTxNotifications: [Int]
        var writtenHex: [String]
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
        var earlyBufBytes: Int
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
                earlyBufBytes: earlyBuf.count,
                earlyBufHex: earlyBuf.isEmpty ? nil : hexFromData(earlyBuf),
                connectRequested: false
            )
        }

        let wire = buildAppWire(payload)
        if !writerPresent {
            bufferEarly(wireFrame: wire, now: now)
            return SendSnapshot(
                txBytes: txBytes,
                peerTxNotifications: [],
                writtenHex: [],
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
            earlyBufBytes: earlyBuf.count
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

    private func buildAppWire(_ payload: Data) -> Data {
        var data = Data()
        var bodyLength = UInt32(payload.count + 1).bigEndian
        withUnsafeBytes(of: &bodyLength) { rawBuffer in
            data.append(contentsOf: rawBuffer)
        }
        data.append(0x00)
        data.append(payload)
        return data
    }

    private func hexFromData(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
}