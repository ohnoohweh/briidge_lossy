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

    private let sessionMaxAppPayload: Int
    /// The common portable state owner for locally accepted TCP services.
    /// Native dictionaries below retain only NWConnection bookkeeping and
    /// client-dial metadata.
    private let serverSession: ObstacleBridgeChannelMuxSession
    /// Common state for remotely opened TCP services. Native state below is
    /// limited to the destination connection and its pending OS writes.
    private let clientSession: ObstacleBridgeChannelMuxSession
    private var counters: [Int: Int]
    private var nextTcpID: Int
    private var clientServiceIDByChannel: [Int: Int]
    private var clientOpenKeyByChannel: [Int: ClientOpenKey]
    private var clientChannelByOpenKey: [ClientOpenKey: Int]
    private var clientPending: [Int: [Data]]
    private var clientTransports: [Int: ClientTransportState]
    private var serverActiveChannels: Set<Int>

    init(
        instanceID: UInt64 = 0,
        connectionSeq: UInt32 = 0,
        nextTcpID: Int = 1,
        sessionMaxAppPayload: Int = 65535
    ) {
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.serverSession = ObstacleBridgeChannelMuxSession(
            maximumApplicationPayload: sessionMaxAppPayload,
            instanceID: instanceID,
            connectionSequence: connectionSeq,
            initialChannelID: UInt16(clamping: nextTcpID)
        )
        self.clientSession = ObstacleBridgeChannelMuxSession(
            maximumApplicationPayload: sessionMaxAppPayload
        )
        self.counters = [:]
        self.nextTcpID = nextTcpID
        self.clientServiceIDByChannel = [:]
        self.clientOpenKeyByChannel = [:]
        self.clientChannelByOpenKey = [:]
        self.clientPending = [:]
        self.clientTransports = [:]
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
        let effects = try serverSession.acceptLocal(service: coreServiceSpec(spec))
        let outbound = try wireFrames(from: effects)
        guard let first = outbound.first else { return nil }
        let chanID = Int(first.chanID)
        serverActiveChannels.insert(chanID)
        nextTcpID = Int(serverSession.nextAvailableChannelID)
        return LocalServerAcceptSnapshot(
            chanID: chanID,
            frames: outbound.map(\.wire),
            nextTcpID: nextTcpID,
            nextCounter: Int(serverSession.nextOutboundCounter(channelID: UInt16(chanID)) ?? 0),
            activeChannels: serverActiveChannels.sorted()
        )
    }

    func handleLocalServerData(chanID: Int, payload: Data, overlayConnected: Bool) throws -> LocalServerDataSnapshot {
        guard overlayConnected, serverActiveChannels.contains(chanID) else {
            return LocalServerDataSnapshot(sent: false, frames: [], nextCounter: counters[chanID] ?? 0, activeChannels: serverActiveChannels.sorted())
        }
        let frames = try wireFrames(from: serverSession.localData(channelID: UInt16(chanID), payload: payload))
        guard !frames.isEmpty else {
            return LocalServerDataSnapshot(sent: false, frames: [], nextCounter: counters[chanID] ?? 0, activeChannels: serverActiveChannels.sorted())
        }
        return LocalServerDataSnapshot(
            sent: true,
            frames: frames.map(\.wire),
            nextCounter: Int(serverSession.nextOutboundCounter(channelID: UInt16(chanID)) ?? 0),
            activeChannels: serverActiveChannels.sorted()
        )
    }

    func handleInboundServerData(chanID: Int, body: Data, counter: Int? = nil) -> InboundServerDataSnapshot {
        guard serverActiveChannels.contains(chanID) else {
            return InboundServerDataSnapshot(delivered: false, writtenBuffers: [])
        }
        guard let counter, let effects = try? serverSession.receive(.init(channelID: UInt16(chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: UInt16(clamping: counter), messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: body)),
              case .writeLocal(_, let payload) = effects.first else {
            return InboundServerDataSnapshot(delivered: false, writtenBuffers: [])
        }
        return InboundServerDataSnapshot(delivered: true, writtenBuffers: [payload])
    }

    func handleLocalServerEOF(chanID: Int, overlayConnected: Bool) throws -> ServerCloseSnapshot {
        guard serverActiveChannels.contains(chanID) else {
            return ServerCloseSnapshot(closed: false, chanID: chanID, localConnectionClosed: false, frames: [], activeChannels: serverActiveChannels.sorted())
        }
        let frames = try wireFrames(from: serverSession.localEOF(channelID: UInt16(chanID)))
        serverActiveChannels.remove(chanID)
        return ServerCloseSnapshot(closed: true, chanID: chanID, localConnectionClosed: true, frames: overlayConnected ? frames.map(\.wire) : [], activeChannels: serverActiveChannels.sorted())
    }

    func handleInboundServerClose(chanID: Int, counter: Int? = nil) -> ServerCloseSnapshot {
        let accepted = counter.flatMap { value in
            try? serverSession.receive(.init(channelID: UInt16(chanID), protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: UInt16(clamping: value), messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data()))
        } != nil
        let hadChannel = accepted && serverActiveChannels.remove(chanID) != nil
        return ServerCloseSnapshot(closed: hadChannel, chanID: chanID, localConnectionClosed: hadChannel, frames: [], activeChannels: serverActiveChannels.sorted())
    }

    func handleInboundClientOpen(chanID: Int, payload: Data, counter: Int = 0, peerID: Int? = nil) -> InboundClientOpenSnapshot {
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue,
            body: payload
        )), case .connectLocal(_, let admittedService) = effects.first,
           admittedService.listenProtocol == ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue else {
            return InboundClientOpenSnapshot(
                accepted: false, serviceID: nil, openKey: nil,
                connectRequested: false, connected: false,
                pendingCount: clientPending[chanID]?.count ?? 0,
                openChannels: clientOpenKeyByChannel.keys.sorted(),
                connectedChannels: clientTransports.keys.sorted()
            )
        }
        return admittedClientOpen(chanID: chanID, service: admittedService, peerID: peerID)
    }

    func handleInboundClientOpenChunk(chanID: Int, payload: Data, counter: Int, peerID: Int? = nil) -> InboundClientOpenSnapshot? {
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.openChunk.rawValue,
            body: payload
        )), case .connectLocal(_, let admittedService) = effects.first,
           admittedService.listenProtocol == ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue else {
            return nil
        }
        return admittedClientOpen(chanID: chanID, service: admittedService, peerID: peerID)
    }

    func clientServiceSpec(chanID: Int) -> ObstacleBridgeChannelMuxCodec.ServiceSpec? {
        clientSession.service(channelID: UInt16(clamping: chanID)).flatMap(ObstacleBridgeChannelMuxCodec.serviceSpec)
    }

    private func admittedClientOpen(chanID: Int, service: ObstacleBridgeServiceSpec, peerID: Int?) -> InboundClientOpenSnapshot {
        guard let spec = ObstacleBridgeChannelMuxCodec.serviceSpec(service) else {
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

        clientServiceIDByChannel[chanID] = Int(service.serviceID)

        forgetClientOpenKey(chanID: chanID)
        let openKey = ClientOpenKey(
            peerID: peerID ?? 0,
            serviceID: spec.svcID,
            localProto: ObstacleBridgeChannelMuxCodec.Proto.tcp.rawValue,
            localBind: spec.lBind,
            localPort: spec.lPort,
            remoteProto: ObstacleBridgeChannelMuxCodec.Proto.tcp.rawValue,
            remoteHost: spec.rHost,
            remotePort: spec.rPort
        )
        clientOpenKeyByChannel[chanID] = openKey
        clientChannelByOpenKey[openKey] = chanID

        let connected = clientTransports[chanID] != nil
        return InboundClientOpenSnapshot(
            accepted: true,
            serviceID: spec.svcID,
            openKey: Self.clientOpenKeyString(openKey),
            connectRequested: !connected,
            connected: connected,
            pendingCount: clientPending[chanID]?.count ?? 0,
            openChannels: clientOpenKeyByChannel.keys.sorted(),
            connectedChannels: clientTransports.keys.sorted()
        )
    }

    func handleInboundClientData(chanID: Int, body: Data, counter: Int) -> InboundClientDataSnapshot {
        guard let effects = try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue,
            body: body
        )), case .writeLocal(_, let admittedPayload) = effects.first else {
            return InboundClientDataSnapshot(buffered: false, sentImmediately: false, pendingCount: clientPending[chanID]?.count ?? 0, writtenBuffers: [])
        }
        if clientTransports[chanID] != nil {
            return InboundClientDataSnapshot(
                buffered: false,
                sentImmediately: true,
                pendingCount: clientPending[chanID]?.count ?? 0,
                writtenBuffers: [admittedPayload]
            )
        }

        var queue = clientPending[chanID] ?? []
        queue.append(admittedPayload)
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
        let frames = try wireFrames(from: clientSession.localData(channelID: UInt16(chanID), payload: payload))
        return LocalClientDataSnapshot(
            frames: frames.map(\.wire),
            nextCounter: Int(clientSession.nextOutboundCounter(channelID: UInt16(chanID)) ?? 0)
        )
    }

    func handleLocalClientEOF(chanID: Int, overlayConnected: Bool) throws -> LocalClientCloseSnapshot {
        let hadOpen = clientOpenKeyByChannel[chanID] != nil
        let hadTransport = clientTransports.removeValue(forKey: chanID) != nil
        let hadPending = clientPending.removeValue(forKey: chanID) != nil
        let hadService = clientServiceIDByChannel.removeValue(forKey: chanID) != nil
        var frames: [Data] = []
        if hadOpen || hadTransport {
            let closingFrames = try wireFrames(from: clientSession.localEOF(channelID: UInt16(chanID))).map(\.wire)
            if overlayConnected {
                frames = closingFrames
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

    func handleInboundClientClose(chanID: Int, counter: Int) -> ClientCloseSnapshot {
        guard (try? clientSession.receive(.init(
            channelID: UInt16(clamping: chanID),
            protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue,
            counter: UInt16(clamping: counter),
            messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue,
            body: Data()
        ))) != nil else {
            return ClientCloseSnapshot(closed: false, chanID: chanID, openChannels: clientOpenKeyByChannel.keys.sorted(), connectedChannels: clientTransports.keys.sorted(), pendingChannels: clientPending.keys.sorted())
        }
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
            fatalError("unsupported TCP service protocol")
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
