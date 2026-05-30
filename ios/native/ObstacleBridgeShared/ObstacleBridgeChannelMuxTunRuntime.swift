import Foundation

final class ObstacleBridgeChannelMuxTunRuntime {
    private static let tunFragmentHeaderSize = 8

    struct LocalTunSendSnapshot {
        var chanID: Int
        var allocatedChannel: Bool
        var frames: [Data]
        var nextTunID: Int
        var nextCounter: Int
    }

    struct InboundTunOpenSnapshot {
        var accepted: Bool
        var chanID: Int
        var preferredChanID: Int?
        var remoteSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    }

    struct InboundTunOpenChunkSnapshot {
        var assembled: Bool
        var accepted: Bool
        var chanID: Int
        var preferredChanID: Int?
        var remoteSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    }

    struct InboundTunDataSnapshot {
        var delivered: Bool
        var packet: Data?
    }

    struct InboundTunFragmentSnapshot {
        var delivered: Bool
        var packet: Data?
        var datagramID: Int
        var totalLen: Int
        var receivedBytes: Int
    }

    struct CloseSnapshot {
        var closed: Bool
        var chanID: Int
        var preferredChanID: Int?
        var boundChanIDs: [Int]
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
    private let localSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec?
    private var nextTunID: Int
    private var nextFragmentDatagramID: UInt32
    private var controlChunkNextTxID: UInt32
    private var counters: [Int: Int]
    private var boundTunChanIDs: Set<Int>
    private var preferredTunChanID: Int?
    private var fragmentStates: [FragmentKey: FragmentState]
    private let controlChunkReassembler: ObstacleBridgeChannelMuxCodec.ControlChunkReassembler

    init(
        instanceID: UInt64,
        connectionSeq: UInt32,
        chanIDStart: Int = 1,
        chanIDStride: Int = 1,
        nextTunID: Int = 1,
        localSpec: ObstacleBridgeChannelMuxCodec.ServiceSpec? = nil,
        sessionMaxAppPayload: Int = 65535
    ) {
        self.instanceID = instanceID
        self.connectionSeq = connectionSeq
        self.chanIDStart = chanIDStart
        self.chanIDStride = max(1, chanIDStride)
        self.nextTunID = nextTunID
        self.sessionMaxAppPayload = sessionMaxAppPayload
        self.localSpec = localSpec
        self.nextFragmentDatagramID = 1
        self.controlChunkNextTxID = 1
        self.counters = [:]
        self.boundTunChanIDs = []
        self.preferredTunChanID = nil
        self.fragmentStates = [:]
        self.controlChunkReassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()
    }

    func handleLocalTunPacket(
        packet: Data,
        mtu: Int,
        existingChanID: Int? = nil,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        overlayConnected: Bool,
        acceptingEnabled: Bool
    ) throws -> LocalTunSendSnapshot? {
        guard overlayConnected, acceptingEnabled else {
            return nil
        }
        guard packet.count <= mtu else {
            return nil
        }

        var frames: [Data] = []
        let preferredChanID = existingChanID ?? preferredTunChanID
        let allocatedChannel = preferredChanID == nil
        let chanID = preferredChanID ?? allocateTunID()
        if allocatedChannel {
            guard let openFrames = try buildOpenFrames(chanID: chanID, spec: spec) else {
                return nil
            }
            frames.append(contentsOf: openFrames)
        }
        boundTunChanIDs.insert(chanID)
        if preferredTunChanID == nil {
            preferredTunChanID = chanID
        }

        guard let dataFrames = try buildDataFrames(chanID: chanID, packet: packet) else {
            return nil
        }
        frames.append(contentsOf: dataFrames)
        return LocalTunSendSnapshot(
            chanID: chanID,
            allocatedChannel: allocatedChannel,
            frames: frames,
            nextTunID: nextTunID,
            nextCounter: counters[chanID] ?? 0
        )
    }

    func handleInboundTunOpen(chanID: Int, payload: Data) -> InboundTunOpenSnapshot {
        guard
            let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload),
            parsed.spec.lProto == "tun",
            parsed.spec.rProto == "tun"
        else {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: preferredTunChanID,
                remoteSpec: nil
            )
        }
        if let localSpec,
           (parsed.spec.rHost != localSpec.lBind || parsed.spec.rPort != localSpec.lPort) {
            return InboundTunOpenSnapshot(
                accepted: false,
                chanID: chanID,
                preferredChanID: preferredTunChanID,
                remoteSpec: parsed.spec
            )
        }
        boundTunChanIDs.insert(chanID)
        if preferredTunChanID == nil {
            preferredTunChanID = chanID
        }
        return InboundTunOpenSnapshot(
            accepted: true,
            chanID: chanID,
            preferredChanID: preferredTunChanID,
            remoteSpec: parsed.spec
        )
    }

    func handleInboundTunOpenChunk(
        chanID: Int,
        payload: Data,
        peerID: Int? = nil
    ) -> InboundTunOpenChunkSnapshot {
        guard let assembled = controlChunkReassembler.consume(
            chanID: chanID,
            proto: .tun,
            mtype: .openChunk,
            payload: payload,
            peerID: peerID
        ) else {
            return InboundTunOpenChunkSnapshot(
                assembled: false,
                accepted: false,
                chanID: chanID,
                preferredChanID: preferredTunChanID,
                remoteSpec: nil
            )
        }
        let openSnapshot = handleInboundTunOpen(chanID: chanID, payload: assembled)
        return InboundTunOpenChunkSnapshot(
            assembled: true,
            accepted: openSnapshot.accepted,
            chanID: openSnapshot.chanID,
            preferredChanID: openSnapshot.preferredChanID,
            remoteSpec: openSnapshot.remoteSpec
        )
    }

    func handleInboundTunData(
        chanID: Int,
        body: Data,
        mtu: Int,
        boundChanID: Int? = nil
    ) -> InboundTunDataSnapshot {
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = boundTunChanIDs.contains(chanID)
        }
        guard isBound, body.count <= mtu else {
            return InboundTunDataSnapshot(delivered: false, packet: nil)
        }
        return InboundTunDataSnapshot(delivered: true, packet: body)
    }

    func handleInboundTunFragment(
        chanID: Int,
        payload: Data,
        mtu: Int,
        boundChanID: Int? = nil
    ) -> InboundTunFragmentSnapshot {
        let empty = InboundTunFragmentSnapshot(
            delivered: false,
            packet: nil,
            datagramID: 0,
            totalLen: 0,
            receivedBytes: 0
        )
        let isBound: Bool
        if let boundChanID {
            isBound = boundChanID == chanID
        } else {
            isBound = boundTunChanIDs.contains(chanID)
        }
        guard isBound else {
            return empty
        }
        guard payload.count >= Self.tunFragmentHeaderSize else {
            return empty
        }
        let datagramID = Self.readUInt32(payload, offset: 0)
        let totalLen = Int(Self.readUInt16(payload, offset: 4))
        let offset = Int(Self.readUInt16(payload, offset: 6))
        let chunk = payload.subdata(in: Self.tunFragmentHeaderSize..<payload.count)
        let key = FragmentKey(chanID: chanID, datagramID: Int(datagramID))
        guard totalLen > 0, totalLen <= mtu else {
            fragmentStates.removeValue(forKey: key)
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: 0
            )
        }
        guard offset <= totalLen, (offset + chunk.count) <= totalLen, !chunk.isEmpty else {
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: fragmentStates[key]?.receivedBytes ?? 0
            )
        }
        var state = fragmentStates[key] ?? FragmentState(totalLen: totalLen, parts: [:], receivedBytes: 0)
        if state.totalLen != totalLen {
            fragmentStates.removeValue(forKey: key)
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
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
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }
        var assembled = Data(count: totalLen)
        var cursor = 0
        for partOffset in state.parts.keys.sorted() {
            guard let part = state.parts[partOffset], partOffset == cursor else {
                return InboundTunFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            let nextCursor = partOffset + part.count
            guard nextCursor <= totalLen else {
                fragmentStates.removeValue(forKey: key)
                return InboundTunFragmentSnapshot(
                    delivered: false,
                    packet: nil,
                    datagramID: Int(datagramID),
                    totalLen: totalLen,
                    receivedBytes: state.receivedBytes
                )
            }
            assembled.replaceSubrange(partOffset..<nextCursor, with: part)
            cursor = nextCursor
        }
        guard cursor == totalLen else {
            return InboundTunFragmentSnapshot(
                delivered: false,
                packet: nil,
                datagramID: Int(datagramID),
                totalLen: totalLen,
                receivedBytes: state.receivedBytes
            )
        }
        fragmentStates.removeValue(forKey: key)
        let dataSnapshot = handleInboundTunData(chanID: chanID, body: assembled, mtu: mtu, boundChanID: boundChanID)
        return InboundTunFragmentSnapshot(
            delivered: dataSnapshot.delivered,
            packet: dataSnapshot.packet,
            datagramID: Int(datagramID),
            totalLen: totalLen,
            receivedBytes: state.receivedBytes
        )
    }

    func handleInboundTunClose(chanID: Int) -> CloseSnapshot {
        let closed = boundTunChanIDs.remove(chanID) != nil
        fragmentStates = fragmentStates.filter { $0.key.chanID != chanID }
        if preferredTunChanID == chanID {
            preferredTunChanID = boundTunChanIDs.sorted().first
        }
        return CloseSnapshot(
            closed: closed,
            chanID: chanID,
            preferredChanID: preferredTunChanID,
            boundChanIDs: boundTunChanIDs.sorted()
        )
    }

    private func allocateTunID() -> Int {
        let start = chanIDStart
        var channelID = nextTunID
        if channelID < start || channelID > 65535 {
            channelID = start
        }
        let next = channelID + chanIDStride
        nextTunID = next <= 65535 ? next : start
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
                    proto: .tun,
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
                proto: .tun,
                counter: nextCounter(chanID: chanID, mtype: .openChunk),
                mtype: .openChunk,
                body: chunk
            )
        }
    }

    private func buildDataFrames(chanID: Int, packet: Data) throws -> [Data]? {
        if ObstacleBridgeChannelMuxCodec.muxHeaderSize + packet.count <= sessionMaxAppPayload {
            return [
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tun,
                    counter: nextCounter(chanID: chanID, mtype: .data),
                    mtype: .data,
                    body: packet
                )
            ]
        }
        let fragmentPayloadLimit = max(0, sessionMaxAppPayload - ObstacleBridgeChannelMuxCodec.muxHeaderSize - Self.tunFragmentHeaderSize)
        guard fragmentPayloadLimit > 0, packet.count <= 0xFFFF else {
            return nil
        }
        let datagramID = nextTunFragmentDatagramID()
        var frames: [Data] = []
        for offset in stride(from: 0, to: packet.count, by: fragmentPayloadLimit) {
            let end = min(offset + fragmentPayloadLimit, packet.count)
            let part = packet.subdata(in: offset..<end)
            var body = Data()
            body.appendUInt32(datagramID)
            body.appendUInt16(UInt16(packet.count & 0xFFFF))
            body.appendUInt16(UInt16(offset & 0xFFFF))
            body.append(part)
            frames.append(
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: chanID,
                    proto: .tun,
                    counter: nextCounter(chanID: chanID, mtype: .dataFrag),
                    mtype: .dataFrag,
                    body: body
                )
            )
        }
        return frames
    }

    private func nextTunFragmentDatagramID() -> UInt32 {
        var datagramID = nextFragmentDatagramID & 0xFFFFFFFF
        if datagramID == 0 {
            datagramID = 1
        }
        nextFragmentDatagramID = datagramID == 0xFFFFFFFF ? 1 : datagramID &+ 1
        return datagramID
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