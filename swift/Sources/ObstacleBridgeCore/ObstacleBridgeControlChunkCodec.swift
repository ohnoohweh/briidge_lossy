import Foundation

public enum ObstacleBridgeControlChunkCodecError: Error, Equatable, Sendable {
    case payloadTooLarge
    case invalidMaximumPayload
}

/// Bounded representation of the ChannelMux `CKV1` control-chunk payload.
/// Transport adapters own frame delivery; this type owns only the wire format
/// and reassembly state shared by ChannelMux OPEN and service-catalog chunks.
public enum ObstacleBridgeControlChunkCodec {
    public static let headerSize = 12
    public static let defaultMaximumInflight = 512
    public static let defaultMaximumReassembledBytes = 16 * 1024 * 1024
    private static let magic = Data("CKV1".utf8)

    public static func nextTransactionID(current: UInt32) -> (transactionID: UInt32, next: UInt32) {
        let transactionID = current == 0 ? UInt32(1) : current
        return (transactionID, transactionID == .max ? UInt32(1) : transactionID &+ 1)
    }

    public static func chunk(transactionID: UInt32, maximumApplicationPayload: Int, payload: Data) throws -> [Data] {
        let chunkCapacity = maximumApplicationPayload - ObstacleBridgeChannelMuxCodec.headerSize - headerSize
        guard chunkCapacity > 0 else { throw ObstacleBridgeControlChunkCodecError.invalidMaximumPayload }
        let count = max(1, (payload.count + chunkCapacity - 1) / chunkCapacity)
        guard count <= Int(UInt16.max) else { throw ObstacleBridgeControlChunkCodecError.payloadTooLarge }

        return (0..<count).map { index in
            let start = index * chunkCapacity
            let end = min(start + chunkCapacity, payload.count)
            var writer = ObstacleBridgeBinaryWriter(capacity: headerSize + end - start)
            writer.append(magic)
            writer.append(transactionID)
            writer.append(UInt16(index))
            writer.append(UInt16(count))
            writer.append(payload.subdata(in: start..<end))
            return writer.encoded
        }
    }

    fileprivate static func decodeHeader(_ payload: Data) -> (transactionID: UInt32, index: Int, total: Int)? {
        guard payload.count >= headerSize else { return nil }
        do {
            var reader = ObstacleBridgeBinaryReader(payload)
            guard try reader.readData(count: 4) == magic else { return nil }
            let transactionID = try reader.readUInt32()
            let index = Int(try reader.readUInt16())
            let total = Int(try reader.readUInt16())
            guard total > 0, index < total else { return nil }
            return (transactionID, index, total)
        } catch { return nil }
    }
}

public final class ObstacleBridgeControlChunkReassembler {
    private struct Key: Hashable {
        let peerID: Int
        let channelID: UInt16
        let protocolType: UInt8
        let messageType: UInt8
        let transactionID: UInt32
    }
    private struct State {
        let total: Int
        var parts: [Int: Data]
        var receivedBytes: Int
        var updatedAt: TimeInterval
    }

    private let maximumInflight: Int
    private let maximumReassembledBytes: Int
    private let ttl: TimeInterval
    private var states: [Key: State] = [:]

    public init(maximumInflight: Int = ObstacleBridgeControlChunkCodec.defaultMaximumInflight, maximumReassembledBytes: Int = ObstacleBridgeControlChunkCodec.defaultMaximumReassembledBytes, ttl: TimeInterval = 20) {
        self.maximumInflight = max(1, maximumInflight)
        self.maximumReassembledBytes = max(1, maximumReassembledBytes)
        self.ttl = max(0, ttl)
    }

    public func consume(channelID: UInt16, protocolType: ObstacleBridgeChannelMuxProtocol, messageType: ObstacleBridgeChannelMuxMessageType, payload: Data, peerID: Int?, now: TimeInterval = Date().timeIntervalSince1970) -> Data? {
        guard let header = ObstacleBridgeControlChunkCodec.decodeHeader(payload) else { return nil }
        let key = Key(peerID: peerID ?? 0, channelID: channelID, protocolType: protocolType.rawValue, messageType: messageType.rawValue, transactionID: header.transactionID)
        let part = Data(payload.dropFirst(ObstacleBridgeControlChunkCodec.headerSize))
        var state = states[key]

        if state == nil {
            if states.count >= maximumInflight {
                prune(now: now)
                guard states.count < maximumInflight else { return nil }
            }
            state = State(total: header.total, parts: [:], receivedBytes: 0, updatedAt: now)
        } else if state?.total != header.total {
            states.removeValue(forKey: key)
            return nil
        }
        guard var next = state else { return nil }
        if next.parts[header.index] == nil {
            guard part.count <= maximumReassembledBytes - next.receivedBytes else {
                states.removeValue(forKey: key)
                return nil
            }
            next.parts[header.index] = part
            next.receivedBytes += part.count
        }
        next.updatedAt = now
        states[key] = next
        guard next.parts.count == next.total else { return nil }

        var assembled = Data(capacity: next.receivedBytes)
        for index in 0..<next.total {
            guard let part = next.parts[index] else { return nil }
            assembled.append(part)
        }
        states.removeValue(forKey: key)
        return assembled
    }

    public func prune(now: TimeInterval = Date().timeIntervalSince1970) {
        states = states.filter { now - $0.value.updatedAt < ttl }
    }
}
