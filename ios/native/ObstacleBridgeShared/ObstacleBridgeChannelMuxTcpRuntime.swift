import Foundation

final class ObstacleBridgeChannelMuxTcpRuntime {
    struct LocalServerAcceptSnapshot {
        var chanID: Int
        var frames: [Data]
        var nextTcpID: Int
        var nextCounter: Int
        var activeChannels: [Int]
    }

    struct LocalServerDataSnapshot {
        var sent: Bool
        var frames: [Data]
        var nextCounter: Int
        var activeChannels: [Int]
    }

    struct InboundServerDataSnapshot {
        var delivered: Bool
        var writtenBuffers: [Data]
    }

    struct InboundClientOpenSnapshot {
        var accepted: Bool
        var serviceID: Int?
        var openKey: String?
        var connectRequested: Bool
        var connected: Bool
        var pendingCount: Int
        var openChannels: [Int]
        var connectedChannels: [Int]
    }

    struct InboundClientDataSnapshot {
        var buffered: Bool
        var sentImmediately: Bool
        var pendingCount: Int
        var writtenBuffers: [Data]
    }

    struct ClientConnectSnapshot {
        var connected: Bool
        var serviceID: Int?
        var openKey: String?
        var pendingCount: Int
        var flushedBuffers: [Data]
        var localAddrHost: String?
        var localAddrPort: Int?
        var peerAddrHost: String?
        var peerAddrPort: Int?
        var connectedChannels: [Int]
    }

    struct LocalClientDataSnapshot {
        var frames: [Data]
        var nextCounter: Int
    }

    struct LocalClientCloseSnapshot {
        var closed: Bool
        var chanID: Int
        var frames: [Data]
        var openChannels: [Int]
        var connectedChannels: [Int]
        var pendingChannels: [Int]
    }

    struct ClientCloseSnapshot {
        var closed: Bool
        var chanID: Int
        var openChannels: [Int]
        var connectedChannels: [Int]
        var pendingChannels: [Int]
    }

    struct ServerCloseSnapshot {
        var closed: Bool
        var chanID: Int
        var localConnectionClosed: Bool
        var frames: [Data]
        var activeChannels: [Int]
    }

    private struct ClientOpenKey: Hashable {
        var peerID: Int
        var serviceID: Int
        var localProto: Int
        var localBind: String
        var localPort: Int
        var remoteProto: Int
        var remoteHost: String
        var remotePort: Int
    }

    private struct ClientTransportState {
        var localAddrHost: String?
        var localAddrPort: Int?
        var peerAddrHost: String
        var peerAddrPort: Int
    }

    private let instanceID: UInt64
    private let connectionSeq: UInt32
    private let sessionMaxAppPayload: Int
    private var counters: [Int: Int]
    private var nextTcpID: Int
    private var controlChunkNextTxID: UInt32
    private var clientServiceIDByChannel: [Int: Int]
    private var clientOpenKeyByChannel: [Int: ClientOpenKey]
    private var clientChannelByOpenKey: [ClientOpenKey: Int]
    private var clientPending: [Int: [Data]]
    private var clientTransports: [Int: ClientTransportState]
    private var serverSpecByChannel: [Int: ObstacleBridgeChannelMuxCodec.ServiceSpec]
    private var serverActiveChannels: Set<Int>

    init(
        instanceID: UInt64 = 0,
        connectionSeq: UInt32 = 0,
        nextTcpID: Int = 1,
        sessionMaxAppPayload: Int = 65535
    ) {
        self.instanceID = instanceID
        self.connectionSeq = connectionSeq
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.counters = [:]
        self.nextTcpID = nextTcpID
        self.controlChunkNextTxID = 1
        self.clientServiceIDByChannel = [:]
        self.clientOpenKeyByChannel = [:]
        self.clientChannelByOpenKey = [:]
        self.clientPending = [:]
        self.clientTransports = [:]
        self.serverSpecByChannel = [:]
        self.serverActiveChannels = []
    }

    func handleAcceptedServerConnection(
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        overlayConnected: Bool,
        acceptingEnabled: Bool
    ) throws -> LocalServerAcceptSnapshot? {
        guard overlayConnected, acceptingEnabled else {
            return nil
        }
        let chanID = allocateTcpID()
        serverActiveChannels.insert(chanID)
        serverSpecByChannel[chanID] = spec
        let frames = try buildOpenFrames(chanID: chanID, spec: spec) ?? []
        return LocalServerAcceptSnapshot(
            chanID: chanID,
            frames: frames,
            nextTcpID: nextTcpID,
            nextCounter: counters[chanID] ?? 0,
            activeChannels: serverActiveChannels.sorted()
        )
    }

    func handleLocalServerData(chanID: Int, payload: Data, overlayConnected: Bool) throws -> LocalServerDataSnapshot {
        guard overlayConnected, serverActiveChannels.contains(chanID) else {
            return LocalServerDataSnapshot(sent: false, frames: [], nextCounter: counters[chanID] ?? 0, activeChannels: serverActiveChannels.sorted())
        }
        let frame = try ObstacleBridgeChannelMuxCodec.packMux(
            chanID: chanID,
            proto: .tcp,
            counter: nextCounter(chanID: chanID, mtype: .data),
            mtype: .data,
            body: payload
        )
        guard frame.count <= sessionMaxAppPayload else {
            return LocalServerDataSnapshot(sent: false, frames: [], nextCounter: counters[chanID] ?? 0, activeChannels: serverActiveChannels.sorted())
        }
        return LocalServerDataSnapshot(
            sent: true,
            frames: [frame],
            nextCounter: counters[chanID] ?? 0,
            activeChannels: serverActiveChannels.sorted()
        )
    }

    func handleInboundServerData(chanID: Int, body: Data) -> InboundServerDataSnapshot {
        guard serverActiveChannels.contains(chanID) else {
            return InboundServerDataSnapshot(delivered: false, writtenBuffers: [])
        }
        return InboundServerDataSnapshot(delivered: true, writtenBuffers: [body])
    }

    func handleLocalServerEOF(chanID: Int, overlayConnected: Bool) throws -> ServerCloseSnapshot {
        guard serverActiveChannels.contains(chanID) else {
            return ServerCloseSnapshot(closed: false, chanID: chanID, localConnectionClosed: false, frames: [], activeChannels: serverActiveChannels.sorted())
        }
        var frames: [Data] = []
        if overlayConnected {
            let frame = try ObstacleBridgeChannelMuxCodec.packMux(
                chanID: chanID,
                proto: .tcp,
                counter: nextCounter(chanID: chanID, mtype: .close),
                mtype: .close,
                body: Data()
            )
            if frame.count <= sessionMaxAppPayload {
                frames.append(frame)
            }
        }
        serverActiveChannels.remove(chanID)
        serverSpecByChannel.removeValue(forKey: chanID)
        return ServerCloseSnapshot(closed: true, chanID: chanID, localConnectionClosed: true, frames: frames, activeChannels: serverActiveChannels.sorted())
    }

    func handleInboundServerClose(chanID: Int) -> ServerCloseSnapshot {
        let hadChannel = serverActiveChannels.remove(chanID) != nil
        serverSpecByChannel.removeValue(forKey: chanID)
        return ServerCloseSnapshot(closed: hadChannel, chanID: chanID, localConnectionClosed: hadChannel, frames: [], activeChannels: serverActiveChannels.sorted())
    }

    func handleInboundClientOpen(chanID: Int, payload: Data, peerID: Int? = nil) -> InboundClientOpenSnapshot {
        guard let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload) else {
            return InboundClientOpenSnapshot(
                accepted: false,
                serviceID: nil,
                openKey: nil,
                connectRequested: false,
                connected: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                openChannels: clientOpenKeyByChannel.keys.sorted(),
                connectedChannels: clientTransports.keys.sorted()
            )
        }

        clientServiceIDByChannel[chanID] = parsed.spec.svcID
        guard parsed.spec.lProto.lowercased() == "tcp", parsed.spec.rProto.lowercased() == "tcp" else {
            return InboundClientOpenSnapshot(
                accepted: false,
                serviceID: parsed.spec.svcID,
                openKey: nil,
                connectRequested: false,
                connected: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                openChannels: clientOpenKeyByChannel.keys.sorted(),
                connectedChannels: clientTransports.keys.sorted()
            )
        }

        forgetClientOpenKey(chanID: chanID)
        let openKey = ClientOpenKey(
            peerID: peerID ?? 0,
            serviceID: parsed.spec.svcID,
            localProto: ObstacleBridgeChannelMuxCodec.Proto.tcp.rawValue,
            localBind: parsed.spec.lBind,
            localPort: parsed.spec.lPort,
            remoteProto: ObstacleBridgeChannelMuxCodec.Proto.tcp.rawValue,
            remoteHost: parsed.spec.rHost,
            remotePort: parsed.spec.rPort
        )
        clientOpenKeyByChannel[chanID] = openKey
        clientChannelByOpenKey[openKey] = chanID

        let connected = clientTransports[chanID] != nil
        return InboundClientOpenSnapshot(
            accepted: true,
            serviceID: parsed.spec.svcID,
            openKey: Self.clientOpenKeyString(openKey),
            connectRequested: !connected,
            connected: connected,
            pendingCount: clientPending[chanID]?.count ?? 0,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted()
        )
    }

    func handleInboundClientData(chanID: Int, body: Data) -> InboundClientDataSnapshot {
        if clientTransports[chanID] != nil {
            return InboundClientDataSnapshot(
                buffered: false,
                sentImmediately: true,
                pendingCount: clientPending[chanID]?.count ?? 0,
                writtenBuffers: [body]
            )
        }

        var queue = clientPending[chanID] ?? []
        queue.append(body)
        clientPending[chanID] = queue
        return InboundClientDataSnapshot(
            buffered: true,
            sentImmediately: false,
            pendingCount: queue.count,
            writtenBuffers: []
        )
    }

    func handleClientConnected(
        chanID: Int,
        localAddrHost: String? = nil,
        localAddrPort: Int? = nil,
        peerAddrHost: String? = nil,
        peerAddrPort: Int? = nil
    ) -> ClientConnectSnapshot {
        guard let openKey = clientOpenKeyByChannel[chanID] else {
            return ClientConnectSnapshot(
                connected: false,
                serviceID: clientServiceIDByChannel[chanID],
                openKey: nil,
                pendingCount: clientPending[chanID]?.count ?? 0,
                flushedBuffers: [],
                localAddrHost: nil,
                localAddrPort: nil,
                peerAddrHost: nil,
                peerAddrPort: nil,
                connectedChannels: clientTransports.keys.sorted()
            )
        }

        let transport = ClientTransportState(
            localAddrHost: localAddrHost,
            localAddrPort: localAddrPort,
            peerAddrHost: peerAddrHost ?? openKey.remoteHost,
            peerAddrPort: peerAddrPort ?? openKey.remotePort
        )
        clientTransports[chanID] = transport
        let flushed = clientPending.removeValue(forKey: chanID) ?? []
        return ClientConnectSnapshot(
            connected: true,
            serviceID: clientServiceIDByChannel[chanID],
            openKey: Self.clientOpenKeyString(openKey),
            pendingCount: clientPending[chanID]?.count ?? 0,
            flushedBuffers: flushed,
            localAddrHost: transport.localAddrHost,
            localAddrPort: transport.localAddrPort,
            peerAddrHost: transport.peerAddrHost,
            peerAddrPort: transport.peerAddrPort,
            connectedChannels: clientTransports.keys.sorted()
        )
    }

    func handleLocalClientData(chanID: Int, payload: Data, overlayConnected: Bool) throws -> LocalClientDataSnapshot? {
        guard overlayConnected, clientTransports[chanID] != nil else {
            return nil
        }
        let frame = try ObstacleBridgeChannelMuxCodec.packMux(
            chanID: chanID,
            proto: .tcp,
            counter: nextCounter(chanID: chanID, mtype: .data),
            mtype: .data,
            body: payload
        )
        guard frame.count <= sessionMaxAppPayload else {
            return nil
        }
        return LocalClientDataSnapshot(
            frames: [frame],
            nextCounter: counters[chanID] ?? 0
        )
    }

    func handleLocalClientEOF(chanID: Int, overlayConnected: Bool) throws -> LocalClientCloseSnapshot {
        let hadOpen = clientOpenKeyByChannel[chanID] != nil
        let hadTransport = clientTransports.removeValue(forKey: chanID) != nil
        let hadPending = clientPending.removeValue(forKey: chanID) != nil
        let hadService = clientServiceIDByChannel.removeValue(forKey: chanID) != nil
        var frames: [Data] = []
        if overlayConnected, hadOpen || hadTransport {
            let frame = try ObstacleBridgeChannelMuxCodec.packMux(
                chanID: chanID,
                proto: .tcp,
                counter: nextCounter(chanID: chanID, mtype: .close),
                mtype: .close,
                body: Data()
            )
            if frame.count <= sessionMaxAppPayload {
                frames.append(frame)
            }
        }
        forgetClientOpenKey(chanID: chanID)
        return LocalClientCloseSnapshot(
            closed: hadOpen || hadTransport || hadPending || hadService,
            chanID: chanID,
            frames: frames,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted(),
            pendingChannels: clientPending.keys.sorted()
        )
    }

    func handleInboundClientClose(chanID: Int) -> ClientCloseSnapshot {
        let hadOpen = clientOpenKeyByChannel[chanID] != nil
        let hadTransport = clientTransports.removeValue(forKey: chanID) != nil
        let hadPending = clientPending[chanID] != nil
        let hadService = clientServiceIDByChannel.removeValue(forKey: chanID) != nil
        if hadTransport {
            clientPending.removeValue(forKey: chanID)
        }
        forgetClientOpenKey(chanID: chanID)
        return ClientCloseSnapshot(
            closed: hadOpen || hadTransport || hadPending || hadService,
            chanID: chanID,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted(),
            pendingChannels: clientPending.keys.sorted()
        )
    }

    private func forgetClientOpenKey(chanID: Int) {
        let key = clientOpenKeyByChannel.removeValue(forKey: chanID)
        if let key, clientChannelByOpenKey[key] == chanID {
            clientChannelByOpenKey.removeValue(forKey: key)
        }
    }

    private func allocateTcpID() -> Int {
        var channelID = nextTcpID
        if channelID < 1 || channelID > 65535 {
            channelID = 1
        }
        let scanStart = channelID
        while serverActiveChannels.contains(channelID) {
            let next = channelID + 1
            channelID = next <= 65535 ? next : 1
            if channelID == scanStart {
                fatalError("no free TCP channel ids available")
            }
        }
        let next = channelID + 1
        nextTcpID = next <= 65535 ? next : 1
        return channelID
    }

    private func buildOpenFrames(
        chanID: Int,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec
    ) throws -> [Data]? {
        let openPayload = try ObstacleBridgeChannelMuxCodec.buildOpenPayload(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            spec: spec
        )
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + openPayload.count <= sessionMaxAppPayload {
            return [
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tcp,
                    counter: nextCounter(chanID: chanID, mtype: .open),
                    mtype: .open,
                    body: openPayload
                )
            ]
        }
        let txID = ObstacleBridgeChannelMuxCodec.nextControlChunkTxID(current: controlChunkNextTxID)
        controlChunkNextTxID = txID.next
        let chunks = ObstacleBridgeChannelMuxCodec.chunkControlPayload(
            txID: txID.txID,
            maxAppPayload: sessionMaxAppPayload,
            payload: openPayload
        )
        guard !chunks.isEmpty else {
            return nil
        }
        return try chunks.map { chunk in
            try ObstacleBridgeChannelMuxCodec.packMux(
                chanID: chanID,
                proto: .tcp,
                counter: nextCounter(chanID: chanID, mtype: .openChunk),
                mtype: .openChunk,
                body: chunk
            )
        }
    }

    private func nextCounter(chanID: Int, mtype: ObstacleBridgeChannelMuxCodec.MType) -> Int {
        if mtype == .open {
            counters[chanID] = 0
            return 0
        }
        let previous = counters[chanID] ?? 0
        let next = (previous + 1) & 0xFFFF
        counters[chanID] = next
        return next
    }

    private static func clientOpenKeyString(_ key: ClientOpenKey) -> String {
        return [
            String(key.peerID),
            String(key.serviceID),
            String(key.localProto),
            key.localBind,
            String(key.localPort),
            String(key.remoteProto),
            key.remoteHost,
            String(key.remotePort),
        ].joined(separator: ":")
    }
}