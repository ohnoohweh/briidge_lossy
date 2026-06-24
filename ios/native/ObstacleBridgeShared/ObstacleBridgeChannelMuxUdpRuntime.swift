import Foundation

final class ObstacleBridgeChannelMuxUdpRuntime {
    private static let udpFragmentHeaderSize = 8

    struct LocalServerDatagramSnapshot {
        var chanID: Int
        var allocatedChannel: Bool
        var frames: [Data]
        var nextUdpID: Int
        var nextCounter: Int
    }

    struct InboundServerDatagramSnapshot {
        var delivered: Bool
        var packet: Data?
        var addrHost: String?
        var addrPort: Int?
    }

    struct InboundServerFragmentSnapshot {
        var delivered: Bool
        var packet: Data?
        var addrHost: String?
        var addrPort: Int?
        var datagramID: Int
        var totalLen: Int
        var receivedBytes: Int
    }

    struct InboundClientOpenSnapshot {
        var accepted: Bool
        var serviceID: Int?
        var openKey: String?
        var replacedChannelID: Int?
        var duplicateActiveChannelID: Int?
        var connectRequested: Bool
        var connected: Bool
        var pendingCount: Int
        var openChannels: [Int]
        var connectedChannels: [Int]
    }

    struct InboundClientDataSnapshot {
        var buffered: Bool
        var dropped: Bool
        var sentImmediately: Bool
        var pendingCount: Int
        var sentPackets: [Data]
    }

    struct InboundClientFragmentSnapshot {
        var buffered: Bool
        var dropped: Bool
        var sentImmediately: Bool
        var pendingCount: Int
        var sentPackets: [Data]
        var datagramID: Int
        var totalLen: Int
        var receivedBytes: Int
    }

    struct ClientConnectSnapshot {
        var connected: Bool
        var serviceID: Int?
        var openKey: String?
        var pendingCount: Int
        var flushedPackets: [Data]
        var localAddrHost: String?
        var localAddrPort: Int?
        var peerAddrHost: String?
        var peerAddrPort: Int?
        var connectedChannels: [Int]
    }

    struct LocalClientDatagramSnapshot {
        var frames: [Data]
        var nextCounter: Int
        var nextFragmentDatagramID: Int
    }

    struct CloseSnapshot {
        var closed: Bool
        var chanID: Int
        var nextUdpID: Int
        var activeChannels: [Int]
    }

    struct ClientCloseSnapshot {
        var closed: Bool
        var chanID: Int
        var openChannels: [Int]
        var connectedChannels: [Int]
        var pendingChannels: [Int]
    }

    private struct ClientKey: Hashable {
        var serviceKey: String
        var addrHost: String
        var addrPort: Int
    }

    private struct ClientOpenKey: Hashable {
        var peerID: Int
        var chanID: Int
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

    private struct FragmentKey: Hashable {
        var chanID: Int
        var datagramID: Int
    }

    private struct FragmentState {
        var totalLen: Int
        var parts: [Int: Data]
        var receivedBytes: Int
    }

    private let instanceID: UInt64
    private let connectionSeq: UInt32
    private let chanIDStart: Int
    private let chanIDStride: Int
    private let sessionMaxAppPayload: Int
    private let datagramCap: Int
    private let clientPendingCap: Int
    private var nextUdpID: Int
    private var nextFragmentDatagramID: UInt32
    private var controlChunkNextTxID: UInt32
    private var counters: [Int: Int]
    private var channelByClient: [ClientKey: Int]
    private var clientByChannel: [Int: ClientKey]
    private var clientServiceIDByChannel: [Int: Int]
    private var clientOpenKeyByChannel: [Int: ClientOpenKey]
    private var clientChannelByOpenKey: [ClientOpenKey: Int]
    private var clientPending: [Int: [Data]]
    private var clientTransports: [Int: ClientTransportState]
    private var fragmentStates: [FragmentKey: FragmentState]

    init(
        instanceID: UInt64,
        connectionSeq: UInt32,
        chanIDStart: Int = 1,
        chanIDStride: Int = 1,
        nextUdpID: Int = 1,
        sessionMaxAppPayload: Int = 65535,
        datagramCap: Int = 65507,
        clientPendingCap: Int = 1024
    ) {
        self.instanceID = instanceID
        self.connectionSeq = connectionSeq
        self.chanIDStart = chanIDStart
        self.chanIDStride = max(1, chanIDStride)
        self.nextUdpID = nextUdpID
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.datagramCap = datagramCap
        self.clientPendingCap = max(1, clientPendingCap)
        self.nextFragmentDatagramID = 1
        self.controlChunkNextTxID = 1
        self.counters = [:]
        self.channelByClient = [:]
        self.clientByChannel = [:]
        self.clientServiceIDByChannel = [:]
        self.clientOpenKeyByChannel = [:]
        self.clientChannelByOpenKey = [:]
        self.clientPending = [:]
        self.clientTransports = [:]
        self.fragmentStates = [:]
    }

    func handleLocalServerDatagram(
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        serviceKey: String,
        payload: Data,
        addrHost: String,
        addrPort: Int,
        overlayConnected: Bool,
        acceptingEnabled: Bool
    ) throws -> LocalServerDatagramSnapshot? {
        guard overlayConnected, acceptingEnabled else {
            return nil
        }
        guard payload.count <= datagramCap else {
            return nil
        }

        let clientKey = ClientKey(serviceKey: serviceKey, addrHost: addrHost, addrPort: addrPort)
        let existingChanID = channelByClient[clientKey]
        let allocatedChannel = existingChanID == nil
        let chanID = existingChanID ?? allocateUdpID()
        if allocatedChannel {
            channelByClient[clientKey] = chanID
            clientByChannel[chanID] = clientKey
        }

        var frames: [Data] = []
        if allocatedChannel {
            guard let openFrames = try buildOpenFrames(chanID: chanID, spec: spec) else {
                return nil
            }
            frames.append(contentsOf: openFrames)
        }
        guard let dataFrames = try buildDataFrames(chanID: chanID, payload: payload) else {
            return nil
        }
        frames.append(contentsOf: dataFrames)

        return LocalServerDatagramSnapshot(
            chanID: chanID,
            allocatedChannel: allocatedChannel,
            frames: frames,
            nextUdpID: nextUdpID,
            nextCounter: counters[chanID] ?? 0
        )
    }

    func handleInboundServerData(chanID: Int, body: Data) -> InboundServerDatagramSnapshot {
        guard let client = clientByChannel[chanID], body.count <= datagramCap else {
            return InboundServerDatagramSnapshot(delivered: false, packet: nil, addrHost: nil, addrPort: nil)
        }
        return InboundServerDatagramSnapshot(
            delivered: true,
            packet: body,
            addrHost: client.addrHost,
            addrPort: client.addrPort
        )
    }

    func handleInboundServerFragment(chanID: Int, payload: Data) -> InboundServerFragmentSnapshot {
        let empty = InboundServerFragmentSnapshot(
            delivered: false,
            packet: nil,
            addrHost: nil,
            addrPort: nil,
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        guard clientByChannel[chanID] != nil else {
            return empty
        }
        guard payload.count >= Self.udpFragmentHeaderSize else {
            return empty
        }
        let datagramID = Self.readUInt32(payload, offset: 0)
        let totalLen = Int(Self.readUInt16(payload, offset: 4))
        let offset = Int(Self.readUInt16(payload, offset: 6))
        let chunk = payload.subdata(in: Self.udpFragmentHeaderSize..<payload.count)
        let key = FragmentKey(chanID: chanID, datagramID: Int(datagramID))

        guard totalLen > 0, totalLen <= datagramCap else {
            fragmentStates.removeValue(forKey: key)
            return InboundServerFragmentSnapshot(
                delivered: false,
                packet: nil,
                addrHost: nil,
                addrPort: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        guard offset <= totalLen, (offset + chunk.count) <= totalLen, !chunk.isEmpty else {
            return InboundServerFragmentSnapshot(
                delivered: false,
                packet: nil,
                addrHost: nil,
                addrPort: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: fragmentStates[key]?.receivedBytes ?? 0
            )
        }

        var state = fragmentStates[key] ?? FragmentState(totalLen: totalLen, parts: [:], receivedBytes: 0)
        if state.totalLen != totalLen {
            fragmentStates.removeValue(forKey: key)
            return InboundServerFragmentSnapshot(
                delivered: false,
                packet: nil,
                addrHost: nil,
                addrPort: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        if state.parts[offset] == nil {
            state.parts[offset] = chunk
            state.receivedBytes += chunk.count
        }
        fragmentStates[key] = state
        guard state.receivedBytes >= totalLen else {
            return InboundServerFragmentSnapshot(
                delivered: false,
                packet: nil,
                addrHost: nil,
                addrPort: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }

        var assembled = Data(count: totalLen)
        var cursor = 0
        for partOffset in state.parts.keys.sorted() {
            guard let part = state.parts[partOffset], partOffset == cursor else {
                return InboundServerFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    addrHost: nil,
                    addrPort: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            let nextCursor = partOffset + part.count
            guard nextCursor <= totalLen else {
                fragmentStates.removeValue(forKey: key)
                return InboundServerFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    addrHost: nil,
                    addrPort: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            assembled.replaceSubrange(partOffset..<nextCursor, with: part)
            cursor = nextCursor
        }
        guard cursor == totalLen else {
            return InboundServerFragmentSnapshot(
                delivered: false,
                packet: nil,
                addrHost: nil,
                addrPort: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }

        fragmentStates.removeValue(forKey: key)
        let delivered = handleInboundServerData(chanID: chanID, body: assembled)
        return InboundServerFragmentSnapshot(
            delivered: delivered.delivered,
            packet: delivered.packet,
            addrHost: delivered.addrHost,
            addrPort: delivered.addrPort,
            datagramID: Int(datagramID),
            totalLen: totalLen,
            receivedBytes: state.receivedBytes
        )
    }

    func handleInboundClientOpen(chanID: Int, payload: Data, peerID: Int? = nil) -> InboundClientOpenSnapshot {
        let empty = InboundClientOpenSnapshot(
            accepted: false,
            serviceID: nil,
            openKey: nil,
            replacedChannelID: nil,
            duplicateActiveChannelID: nil,
            connectRequested: false,
            connected: false,
            pendingCount: clientPending[chanID]?.count ?? 0,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted()
        )
        guard let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload) else {
            return empty
        }

        clientServiceIDByChannel[chanID] = parsed.spec.svcID
        guard parsed.spec.lProto.lowercased() == "udp", parsed.spec.rProto.lowercased() == "udp" else {
            return InboundClientOpenSnapshot(
                accepted: false,
                serviceID: parsed.spec.svcID,
                openKey: nil,
                replacedChannelID: nil,
                duplicateActiveChannelID: nil,
                connectRequested: false,
                connected: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                openChannels: clientOpenKeyByChannel.keys.sorted(),
                connectedChannels: clientTransports.keys.sorted()
            )
        }

        let openKey = ClientOpenKey(
            peerID: peerID ?? 0,
            chanID: chanID,
            serviceID: parsed.spec.svcID,
            localProto: ObstacleBridgeChannelMuxCodec.Proto.udp.rawValue,
            localBind: parsed.spec.lBind,
            localPort: parsed.spec.lPort,
            remoteProto: ObstacleBridgeChannelMuxCodec.Proto.udp.rawValue,
            remoteHost: parsed.spec.rHost,
            remotePort: parsed.spec.rPort
        )

        var replacedChannelID: Int?
        if let existingChanID = clientChannelByOpenKey[openKey], existingChanID != chanID {
            if clientTransports[existingChanID] != nil {
                return InboundClientOpenSnapshot(
                    accepted: false,
                    serviceID: parsed.spec.svcID,
                    openKey: Self.clientOpenKeyString(openKey),
                    replacedChannelID: nil,
                    duplicateActiveChannelID: existingChanID,
                    connectRequested: false,
                    connected: false,
                    pendingCount: clientPending[chanID]?.count ?? 0,
                    openChannels: clientOpenKeyByChannel.keys.sorted(),
                    connectedChannels: clientTransports.keys.sorted()
                )
            }
            forgetClientOpenKey(chanID: existingChanID)
            replacedChannelID = existingChanID
        }

        forgetClientOpenKey(chanID: chanID)
        clientOpenKeyByChannel[chanID] = openKey
        clientChannelByOpenKey[openKey] = chanID

        let connected = clientTransports[chanID] != nil
        return InboundClientOpenSnapshot(
            accepted: true,
            serviceID: parsed.spec.svcID,
            openKey: Self.clientOpenKeyString(openKey),
            replacedChannelID: replacedChannelID,
            duplicateActiveChannelID: nil,
            connectRequested: !connected,
            connected: connected,
            pendingCount: clientPending[chanID]?.count ?? 0,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted()
        )
    }

    func handleInboundClientData(chanID: Int, body: Data) -> InboundClientDataSnapshot {
        guard body.count <= datagramCap else {
            return InboundClientDataSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: []
            )
        }

        if clientTransports[chanID] != nil {
            return InboundClientDataSnapshot(
                buffered: false,
                dropped: false,
                sentImmediately: true,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [body]
            )
        }

        var queue = clientPending[chanID] ?? []
        guard queue.count < clientPendingCap else {
            clientPending[chanID] = queue
            return InboundClientDataSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: queue.count,
                sentPackets: []
            )
        }
        queue.append(body)
        clientPending[chanID] = queue
        return InboundClientDataSnapshot(
            buffered: true,
            dropped: false,
            sentImmediately: false,
            pendingCount: queue.count,
            sentPackets: []
        )
    }

    func handleInboundClientFragment(chanID: Int, payload: Data) -> InboundClientFragmentSnapshot {
        let empty = InboundClientFragmentSnapshot(
            buffered: false,
            dropped: false,
            sentImmediately: false,
            pendingCount: clientPending[chanID]?.count ?? 0,
            sentPackets: [],
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        let isKnownChannel = clientServiceIDByChannel[chanID] != nil || clientOpenKeyByChannel[chanID] != nil || clientTransports[chanID] != nil || clientPending[chanID] != nil
        guard isKnownChannel else {
            return empty
        }
        guard payload.count >= Self.udpFragmentHeaderSize else {
            return empty
        }

        let datagramID = Self.readUInt32(payload, offset: 0)
        let totalLen = Int(Self.readUInt16(payload, offset: 4))
        let offset = Int(Self.readUInt16(payload, offset: 6))
        let chunk = payload.subdata(in: Self.udpFragmentHeaderSize..<payload.count)
        let key = FragmentKey(chanID: chanID, datagramID: Int(datagramID))

        guard totalLen > 0, totalLen <= datagramCap else {
            fragmentStates.removeValue(forKey: key)
            return InboundClientFragmentSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [],
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        guard offset <= totalLen, (offset + chunk.count) <= totalLen, !chunk.isEmpty else {
            return InboundClientFragmentSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [],
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: fragmentStates[key]?.receivedBytes ?? 0
            )
        }

        var state = fragmentStates[key] ?? FragmentState(totalLen: totalLen, parts: [:], receivedBytes: 0)
        if state.totalLen != totalLen {
            fragmentStates.removeValue(forKey: key)
            return InboundClientFragmentSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [],
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        if state.parts[offset] == nil {
            state.parts[offset] = chunk
            state.receivedBytes += chunk.count
        }
        fragmentStates[key] = state
        guard state.receivedBytes >= totalLen else {
            return InboundClientFragmentSnapshot(
                buffered: false,
                dropped: false,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [],
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }

        var assembled = Data(count: totalLen)
        var cursor = 0
        for partOffset in state.parts.keys.sorted() {
            guard let part = state.parts[partOffset], partOffset == cursor else {
                return InboundClientFragmentSnapshot(
                    buffered: false,
                    dropped: false,
                    sentImmediately: false,
                    pendingCount: clientPending[chanID]?.count ?? 0,
                    sentPackets: [],
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            let nextCursor = partOffset + part.count
            guard nextCursor <= totalLen else {
                fragmentStates.removeValue(forKey: key)
                return InboundClientFragmentSnapshot(
                    buffered: false,
                    dropped: true,
                    sentImmediately: false,
                    pendingCount: clientPending[chanID]?.count ?? 0,
                    sentPackets: [],
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            assembled.replaceSubrange(partOffset..<nextCursor, with: part)
            cursor = nextCursor
        }
        guard cursor == totalLen else {
            return InboundClientFragmentSnapshot(
                buffered: false,
                dropped: false,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: [],
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }

        fragmentStates.removeValue(forKey: key)
        let delivered = handleInboundClientData(chanID: chanID, body: assembled)
        return InboundClientFragmentSnapshot(
            buffered: delivered.buffered,
            dropped: delivered.dropped,
            sentImmediately: delivered.sentImmediately,
            pendingCount: delivered.pendingCount,
            sentPackets: delivered.sentPackets,
            datagramID: Int(datagramID),
            totalLen: totalLen,
            receivedBytes: state.receivedBytes
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
                flushedPackets: [],
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
        let flushedPackets = clientPending.removeValue(forKey: chanID) ?? []
        return ClientConnectSnapshot(
            connected: true,
            serviceID: clientServiceIDByChannel[chanID],
            openKey: Self.clientOpenKeyString(openKey),
            pendingCount: clientPending[chanID]?.count ?? 0,
            flushedPackets: flushedPackets,
            localAddrHost: transport.localAddrHost,
            localAddrPort: transport.localAddrPort,
            peerAddrHost: transport.peerAddrHost,
            peerAddrPort: transport.peerAddrPort,
            connectedChannels: clientTransports.keys.sorted()
        )
    }

    func handleLocalClientDatagram(chanID: Int, payload: Data) throws -> LocalClientDatagramSnapshot? {
        guard clientServiceIDByChannel[chanID] != nil else {
            return nil
        }
        guard payload.count <= datagramCap else {
            return nil
        }
        guard let frames = try buildDataFrames(chanID: chanID, payload: payload) else {
            return nil
        }
        return LocalClientDatagramSnapshot(
            frames: frames,
            nextCounter: counters[chanID] ?? 0,
            nextFragmentDatagramID: Int(nextFragmentDatagramID)
        )
    }

    func handleInboundClientClose(chanID: Int) -> ClientCloseSnapshot {
        let hadOpen = clientOpenKeyByChannel[chanID] != nil
        let hadTransport = clientTransports.removeValue(forKey: chanID) != nil
        let hadPending = clientPending.removeValue(forKey: chanID) != nil
        let hadServiceID = clientServiceIDByChannel.removeValue(forKey: chanID) != nil
        forgetClientOpenKey(chanID: chanID)
        fragmentStates = fragmentStates.filter { $0.key.chanID != chanID }
        return ClientCloseSnapshot(
            closed: hadOpen || hadTransport || hadPending || hadServiceID,
            chanID: chanID,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted(),
            pendingChannels: clientPending.keys.sorted()
        )
    }

    func handleInboundClose(chanID: Int) -> CloseSnapshot {
        let client = clientByChannel.removeValue(forKey: chanID)
        if let client {
            channelByClient.removeValue(forKey: client)
        }
        fragmentStates = fragmentStates.filter { $0.key.chanID != chanID }
        return CloseSnapshot(
            closed: client != nil,
            chanID: chanID,
            nextUdpID: nextUdpID,
            activeChannels: clientByChannel.keys.sorted()
        )
    }

    private func forgetClientOpenKey(chanID: Int) {
        let key = clientOpenKeyByChannel.removeValue(forKey: chanID)
        if let key, clientChannelByOpenKey[key] == chanID {
            clientChannelByOpenKey.removeValue(forKey: key)
        }
    }

    private func allocateUdpID() -> Int {
        let start = chanIDStart
        var channelID = nextUdpID
        if channelID < start || channelID > 65535 {
            channelID = start
        }
        let next = channelID + chanIDStride
        nextUdpID = next <= 65535 ? next : start
        return channelID
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
                    proto: .udp,
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
                proto: .udp,
                counter: nextCounter(chanID: chanID, mtype: .openChunk),
                mtype: .openChunk,
                body: chunk
            )
        }
    }

    private func buildDataFrames(chanID: Int, payload: Data) throws -> [Data]? {
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + payload.count <= sessionMaxAppPayload {
            return [
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .udp,
                    counter: nextCounter(chanID: chanID, mtype: .data),
                    mtype: .data,
                    body: payload
                )
            ]
        }

        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.udpFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, payload.count <= 0xFFFF else {
            return nil
        }
        let datagramID = nextServerFragmentDatagramID()
        var frames: [Data] = []
        for offset in stride(from: 0, to: payload.count, by: fragmentPayloadLimit) {
            let end = min(offset + fragmentPayloadLimit, payload.count)
            let part = payload.subdata(in: offset..<end)
            var body = Data()
            body.appendUInt32(datagramID)
            body.appendUInt16(UInt16(payload.count & 0xFFFF))
            body.appendUInt16(UInt16(offset & 0xFFFF))
            body.append(part)
            frames.append(
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .udp,
                    counter: nextCounter(chanID: chanID, mtype: .dataFrag),
                    mtype: .dataFrag,
                    body: body
                )
            )
        }
        return frames
    }

    private func nextServerFragmentDatagramID() -> UInt32 {
        var datagramID = nextFragmentDatagramID & 0xFFFFFFFF
        if datagramID == 0 {
            datagramID = 1
        }
        nextFragmentDatagramID = datagramID == 0xFFFFFFFF ? 1 : datagramID &+ 1
        return datagramID
    }

    private static func clientOpenKeyString(_ key: ClientOpenKey) -> String {
        return [
            String(key.peerID),
            String(key.chanID),
            String(key.serviceID),
            String(key.localProto),
            key.localBind,
            String(key.localPort),
            String(key.remoteProto),
            key.remoteHost,
            String(key.remotePort),
        ].joined(separator: ":")
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let bytes = [UInt8](data[offset..<(offset + 2)])
        return (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        let bytes = [UInt8](data[offset..<(offset + 4)])
        return
            (UInt32(bytes[0]) << 24) |
            (UInt32(bytes[1]) << 16) |
            (UInt32(bytes[2]) << 8) |
            UInt32(bytes[3])
    }
}