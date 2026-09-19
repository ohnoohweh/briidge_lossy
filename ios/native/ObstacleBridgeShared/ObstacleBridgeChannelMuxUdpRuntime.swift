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

    private let instanceID: UInt64
    private let connectionSeq: UInt32
    private let sessionMaxAppPayload: Int
    private let datagramCap: Int
    private let clientPendingCap: Int
    /// Common lifecycle state for ordinary local UDP service datagrams.
    /// Fragment framing and bounded reassembly belong to the portable packet
    /// model; this runtime retains only local socket ownership.
    private let serverSession: ObstacleBridgeChannelMuxSession
    /// Common state for remotely opened UDP services. The native dictionaries
    /// below are restricted to the local `NWConnection` and its pending
    /// datagrams; OPEN/DATA/CLOSE admission and counter progression belong to
    /// the portable session.
    private let clientSession: ObstacleBridgeChannelMuxSession
    private var nextFragmentDatagramID: UInt32
    private var channelByClient: [ClientKey: Int]
    private var clientByChannel: [Int: ClientKey]
    private var clientServiceIDByChannel: [Int: Int]
    private var clientOpenKeyByChannel: [Int: ClientOpenKey]
    private var clientChannelByOpenKey: [ClientOpenKey: Int]
    private var clientPending: [Int: [Data]]
    private var clientTransports: [Int: ClientTransportState]
    private let serverPacketReassembler: ObstacleBridgePacketReassembler
    private let clientPacketReassembler: ObstacleBridgePacketReassembler

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
        let normalizedChannelStride = max(1, chanIDStride)
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.datagramCap = datagramCap
        self.clientPendingCap = max(1, clientPendingCap)
        self.serverSession = ObstacleBridgeChannelMuxSession(
            maximumApplicationPayload: sessionMaxAppPayload,
            instanceID: instanceID,
            connectionSequence: connectionSeq,
            initialChannelID: UInt16(clamping: nextUdpID),
            channelStride: UInt16(clamping: normalizedChannelStride)
        )
        self.clientSession = ObstacleBridgeChannelMuxSession(
            maximumApplicationPayload: sessionMaxAppPayload
        )
        self.nextFragmentDatagramID = 1
        self.channelByClient = [:]
        self.clientByChannel = [:]
        self.clientServiceIDByChannel = [:]
        self.clientOpenKeyByChannel = [:]
        self.clientChannelByOpenKey = [:]
        self.clientPending = [:]
        self.clientTransports = [:]
        self.serverPacketReassembler = ObstacleBridgePacketReassembler(maximumPacketLength: datagramCap)
        self.clientPacketReassembler = ObstacleBridgePacketReassembler(maximumPacketLength: datagramCap)
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
        var frames: [Data] = []
        let chanID: Int
        if allocatedChannel {
            let outbound = try wireFrames(from: serverSession.acceptLocal(service: coreServiceSpec(spec)))
            guard let first = outbound.first else { return nil }
            chanID = first.chanID
            frames.append(contentsOf: outbound.map(\.wire))
            channelByClient[clientKey] = chanID
            clientByChannel[chanID] = clientKey
        } else {
            chanID = existingChanID!
        }

        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + payload.count <= sessionMaxAppPayload {
            frames.append(contentsOf: try wireFrames(from: serverSession.localData(channelID: UInt16(chanID), payload: payload)).map(\.wire))
        } else {
            guard let dataFrames = try buildServerFragmentFrames(chanID: chanID, payload: payload) else { return nil }
            frames.append(contentsOf: dataFrames)
        }

        return LocalServerDatagramSnapshot(
            chanID: chanID,
            allocatedChannel: allocatedChannel,
            frames: frames,
            nextUdpID: Int(serverSession.nextAvailableChannelID),
            nextCounter: Int(serverSession.nextOutboundCounter(channelID: UInt16(chanID)) ?? 0)
        )
    }

    func handleInboundServerData(chanID: Int, body: Data, counter: Int? = nil) -> InboundServerDatagramSnapshot {
        guard let client = clientByChannel[chanID], body.count <= datagramCap else {
            return InboundServerDatagramSnapshot(delivered: false, packet: nil, addrHost: nil, addrPort: nil)
        }
        guard let counter,
              let effects = try? serverSession.receive(.init(channelID: UInt16(chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue, counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: body)),
              case .writeLocal(_, let packet) = effects.first else {
            return InboundServerDatagramSnapshot(delivered: false, packet: nil, addrHost: nil, addrPort: nil)
        }
        return .init(delivered: true, packet: packet, addrHost: client.addrHost, addrPort: client.addrPort)
    }

    func handleInboundServerFragment(chanID: Int, payload: Data, counter: Int? = nil) -> InboundServerFragmentSnapshot {
        let empty = InboundServerFragmentSnapshot(
            delivered: false,
            packet: nil,
            addrHost: nil,
            addrPort: nil,
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        guard clientByChannel[chanID] != nil,
              let counter,
              let effects = try? serverSession.receive(.init(
                channelID: UInt16(clamping: chanID),
                protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
                counter: UInt16(clamping: counter),
                messageType: ObstacleBridgeChannelMuxSessionMessageType.dataFragment.rawValue,
                body: payload
              )), case .writeLocalFragment(_, let admittedPayload) = effects.first else {
            return empty
        }
        guard let fragment = try? ObstacleBridgePacketFragment(wire: admittedPayload),
              Int(fragment.totalLength) <= datagramCap,
              let coreChannelID = UInt16(exactly: chanID) else { return empty }
        switch serverPacketReassembler.consume(channelID: coreChannelID, wire: admittedPayload) {
        case .pending:
            return .init(
                delivered: false, packet: nil, addrHost: nil, addrPort: nil,
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength),
                receivedBytes: serverPacketReassembler.receivedBytes(channelID: coreChannelID, datagramID: fragment.datagramID)
            )
        case .complete(let assembled):
            guard let client = clientByChannel[chanID] else { return empty }
            return .init(
                delivered: true, packet: assembled, addrHost: client.addrHost, addrPort: client.addrPort,
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength), receivedBytes: assembled.count
            )
        case .rejected:
            return .init(
                delivered: false, packet: nil, addrHost: nil, addrPort: nil,
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength), receivedBytes: 0
            )
        }
    }

    func handleInboundClientOpen(chanID: Int, payload: Data, counter: Int = 0, peerID: Int? = nil) -> InboundClientOpenSnapshot {
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
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue,
            body: payload
        )), case .connectLocal(_, let admittedService) = effects.first,
           let parsed = ObstacleBridgeChannelMuxCodec.serviceSpec(admittedService) else {
            return empty
        }

        clientServiceIDByChannel[chanID] = parsed.svcID
        guard parsed.lProto.lowercased() == "udp", parsed.rProto.lowercased() == "udp" else {
            return InboundClientOpenSnapshot(
                accepted: false,
                serviceID: parsed.svcID,
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
            serviceID: parsed.svcID,
            localProto: ObstacleBridgeChannelMuxCodec.Proto.udp.rawValue,
            localBind: parsed.lBind,
            localPort: parsed.lPort,
            remoteProto: ObstacleBridgeChannelMuxCodec.Proto.udp.rawValue,
            remoteHost: parsed.rHost,
            remotePort: parsed.rPort
        )

        var replacedChannelID: Int?
        if let existingChanID = clientChannelByOpenKey[openKey], existingChanID != chanID {
            if clientTransports[existingChanID] != nil {
                return InboundClientOpenSnapshot(
                    accepted: false,
                    serviceID: parsed.svcID,
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
            serviceID: parsed.svcID,
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

    func handleInboundClientData(chanID: Int, body: Data, counter: Int = 1) -> InboundClientDataSnapshot {
        guard body.count <= datagramCap else {
            return InboundClientDataSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: []
            )
        }
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue,
            body: body
        )), case .writeLocal(_, let admittedBody) = effects.first else {
            return InboundClientDataSnapshot(
                buffered: false,
                dropped: true,
                sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                sentPackets: []
            )
        }
        return deliverAdmittedClientData(chanID: chanID, body: admittedBody)
    }

    private func deliverAdmittedClientData(chanID: Int, body: Data) -> InboundClientDataSnapshot {
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

    func handleInboundClientFragment(chanID: Int, payload: Data, counter: Int = 1) -> InboundClientFragmentSnapshot {
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
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.dataFragment.rawValue,
            body: payload
        )), case .writeLocalFragment(_, let admittedPayload) = effects.first else {
            return empty
        }
        guard let fragment = try? ObstacleBridgePacketFragment(wire: admittedPayload),
              Int(fragment.totalLength) <= datagramCap,
              let coreChannelID = UInt16(exactly: chanID) else { return empty }
        switch clientPacketReassembler.consume(channelID: coreChannelID, wire: admittedPayload) {
        case .pending:
            return .init(
                buffered: false, dropped: false, sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0, sentPackets: [],
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength),
                receivedBytes: clientPacketReassembler.receivedBytes(channelID: coreChannelID, datagramID: fragment.datagramID)
            )
        case .complete(let assembled):
            let delivered = deliverAdmittedClientData(chanID: chanID, body: assembled)
            return .init(
                buffered: delivered.buffered, dropped: delivered.dropped, sentImmediately: delivered.sentImmediately,
                pendingCount: delivered.pendingCount, sentPackets: delivered.sentPackets,
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength), receivedBytes: assembled.count
            )
        case .rejected:
            return .init(
                buffered: false, dropped: true, sentImmediately: false,
                pendingCount: clientPending[chanID]?.count ?? 0, sentPackets: [],
                datagramID: Int(fragment.datagramID), totalLen: Int(fragment.totalLength), receivedBytes: 0
            )
        }
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
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + payload.count <= sessionMaxAppPayload {
            let frames = try wireFrames(from: clientSession.localData(channelID: UInt16(clamping: chanID), payload: payload)).map(\.wire)
            guard !frames.isEmpty else { return nil }
            return LocalClientDatagramSnapshot(
                frames: frames,
                nextCounter: Int(clientSession.nextOutboundCounter(channelID: UInt16(clamping: chanID)) ?? 0),
                nextFragmentDatagramID: Int(nextFragmentDatagramID)
            )
        }
        guard let frames = try buildClientFragmentFrames(chanID: chanID, payload: payload) else { return nil }
        return LocalClientDatagramSnapshot(
            frames: frames,
            nextCounter: Int(clientSession.nextOutboundCounter(channelID: UInt16(clamping: chanID)) ?? 0),
            nextFragmentDatagramID: Int(nextFragmentDatagramID)
        )
    }

    func handleInboundClientClose(chanID: Int, counter: Int = 2) -> ClientCloseSnapshot {
        guard (try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue,
            body: Data()
        ))) != nil else {
            return ClientCloseSnapshot(
                closed: false,
                chanID: chanID,
                openChannels: clientOpenKeyByChannel.keys.sorted(),
                connectedChannels: clientTransports.keys.sorted(),
                pendingChannels: clientPending.keys.sorted()
            )
        }
        let hadOpen = clientOpenKeyByChannel[chanID] != nil
        let hadTransport = clientTransports.removeValue(forKey: chanID) != nil
        let hadPending = clientPending.removeValue(forKey: chanID) != nil
        let hadServiceID = clientServiceIDByChannel.removeValue(forKey: chanID) != nil
        forgetClientOpenKey(chanID: chanID)
        if let coreChannelID = UInt16(exactly: chanID) {
            clientPacketReassembler.withdraw(channelID: coreChannelID)
        }
        return ClientCloseSnapshot(
            closed: hadOpen || hadTransport || hadPending || hadServiceID,
            chanID: chanID,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted(),
            pendingChannels: clientPending.keys.sorted()
        )
    }

    func handleInboundClose(chanID: Int, counter: Int? = nil) -> CloseSnapshot {
        guard let counter,
              (try? serverSession.receive(.init(channelID: UInt16(chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue, counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data()))) != nil else {
            return .init(closed: false, chanID: chanID, nextUdpID: Int(serverSession.nextAvailableChannelID), activeChannels: clientByChannel.keys.sorted())
        }
        let client = clientByChannel.removeValue(forKey: chanID)
        if let client {
            channelByClient.removeValue(forKey: client)
        }
        if let coreChannelID = UInt16(exactly: chanID) {
            serverPacketReassembler.withdraw(channelID: coreChannelID)
        }
        return CloseSnapshot(
            closed: client != nil,
            chanID: chanID,
            nextUdpID: Int(serverSession.nextAvailableChannelID),
            activeChannels: clientByChannel.keys.sorted()
        )
    }

    private func forgetClientOpenKey(chanID: Int) {
        let key = clientOpenKeyByChannel.removeValue(forKey: chanID)
        if let key, clientChannelByOpenKey[key] == chanID {
            clientChannelByOpenKey.removeValue(forKey: key)
        }
    }

    private func buildClientFragmentFrames(chanID: Int, payload: Data) throws -> [Data]? {
        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.udpFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, payload.count <= 0xFFFF else { return nil }
        let datagramID = nextServerFragmentDatagramID()
        return try ObstacleBridgePacketFragment.fragment(payload, datagramID: datagramID, maximumPayload: fragmentPayloadLimit)
            .flatMap { try wireFrames(from: clientSession.localDataFragment(channelID: UInt16(clamping: chanID), payload: $0.wire)).map(\.wire) }
    }

    private func buildServerFragmentFrames(chanID: Int, payload: Data) throws -> [Data]? {
        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.udpFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, payload.count <= 0xFFFF else { return nil }
        let datagramID = nextServerFragmentDatagramID()
        return try ObstacleBridgePacketFragment.fragment(payload, datagramID: datagramID, maximumPayload: fragmentPayloadLimit)
            .flatMap { try wireFrames(from: serverSession.localDataFragment(channelID: UInt16(clamping: chanID), payload: $0.wire)).map(\.wire) }
    }

    private func nextServerFragmentDatagramID() -> UInt32 {
        var datagramID = nextFragmentDatagramID & 0xFFFFFFFF
        if datagramID == 0 {
            datagramID = 1
        }
        nextFragmentDatagramID = datagramID == 0xFFFFFFFF ? 1 : datagramID &+ 1
        return datagramID
    }

    private struct SessionWireFrame {
        let chanID: Int
        let wire: Data
    }

    private func coreServiceSpec(_ value: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> ObstacleBridgeServiceSpec {
        let proto: (String) -> UInt8? = { name in
            switch name.lowercased() {
            case "udp": return ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue
            case "tcp": return ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue
            default: return nil
            }
        }
        guard let listenProtocol = proto(value.lProto), let targetProtocol = proto(value.rProto) else {
            fatalError("unsupported UDP service protocol")
        }
        return .init(
            serviceID: UInt16(clamping: value.svcID), name: value.name,
            listenProtocol: listenProtocol, listenHost: value.lBind,
            listenPort: UInt16(clamping: value.lPort), targetProtocol: targetProtocol,
            targetHost: value.rHost, targetPort: UInt16(clamping: value.rPort),
            lifecycleHooks: value.lifecycleHooks.map(coreJSONValue),
            options: value.options.map(coreJSONValue)
        )
    }

    private func coreJSONValue(_ value: [String: ObstacleBridgeChannelMuxCodec.JSONValue]) -> [String: ObstacleBridgeJSONValue] {
        value.mapValues(coreJSONValue)
    }

    private func coreJSONValue(_ value: ObstacleBridgeChannelMuxCodec.JSONValue) -> ObstacleBridgeJSONValue {
        switch value {
        case .object(let object): return .object(coreJSONValue(object))
        case .array(let values): return .array(values.map(coreJSONValue))
        case .string(let value): return .string(value)
        case .integer(let value): return .integer(value)
        case .double(let value): return .double(value)
        case .bool(let value): return .bool(value)
        case .null: return .null
        }
    }

    private func wireFrames(from effects: [ObstacleBridgeChannelMuxSessionEffect]) throws -> [SessionWireFrame] {
        try effects.compactMap { effect in
            guard case .outbound(let frame) = effect,
                  let proto = ObstacleBridgeChannelMuxCodec.Proto(rawValue: Int(frame.protocolType)),
                  let messageType = ObstacleBridgeChannelMuxCodec.MType(rawValue: Int(frame.messageType))
            else { return nil }
            return .init(
                chanID: Int(frame.channelID),
                wire: try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: Int(frame.channelID), proto: proto,
                    counter: Int(frame.counter), mtype: messageType, body: frame.body
                )
            )
        }
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

}
