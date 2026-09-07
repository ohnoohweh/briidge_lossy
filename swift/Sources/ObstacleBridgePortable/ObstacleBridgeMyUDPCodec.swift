import Foundation

public enum ObstacleBridgeMyUDPCodecError: Error, Equatable { case payloadTooLarge, invalidFrame }

public struct ObstacleBridgeMyUDPDataFrame: Equatable, Sendable {
    public let counter: UInt16
    public let payload: Data
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
}

public struct ObstacleBridgeMyUDPStreamChunk: Equatable, Sendable {
    public let counter: UInt16
    public let payload: Data
    public init(counter: UInt16, payload: Data) { self.counter = counter; self.payload = payload }
}

public struct ObstacleBridgeMyUDPWireFrame: Equatable, Sendable {
    public let type: UInt8
    public let payload: Data
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
    public init(type: UInt8, payload: Data, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) {
        self.type = type; self.payload = payload; self.transmittedNanoseconds = transmittedNanoseconds; self.echoedNanoseconds = echoedNanoseconds
    }
}

/// myudp v2 framing shared with Python. DATA batches carry a reliable byte
/// stream; upper-layer messages are length-prefixed records in that stream.
public enum ObstacleBridgeMyUDPCodec {
    public static let protocolHeaderSize = 19
    public static let maximumPayloadSize = 1425
    public static let maximumBatchPayloadSize = 1433
    public static let dataType: UInt8 = 1
    public static let controlType: UInt8 = 2
    public static let idleType: UInt8 = 0

    public static func encodeData(payload: Data, counter: UInt16, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        try encodeData(chunks: [.init(counter: counter, payload: payload)], transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeData(chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard !chunks.isEmpty, chunks.count <= 64 else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var batch = Data([1, UInt8(chunks.count)])
        for chunk in chunks {
            guard chunk.counter != 0, !chunk.payload.isEmpty, chunk.payload.count <= maximumPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
            append(UInt16(chunk.payload.count + 4), to: &batch)
            append(chunk.counter, to: &batch)
            append(UInt16(chunk.payload.count), to: &batch)
            batch.append(chunk.payload)
        }
        guard batch.count <= maximumBatchPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        return try encode(type: dataType, payload: batch, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeControl(lastInOrder: UInt16, highestReceived: UInt16, missing: [UInt16] = [], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard missing.count <= 64 else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var payload = Data()
        append(lastInOrder, to: &payload); append(highestReceived, to: &payload); append(UInt16(missing.count), to: &payload)
        for counter in missing { append(counter, to: &payload) }
        return try encode(type: controlType, payload: payload, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func decodeWire(_ wire: Data) throws -> ObstacleBridgeMyUDPWireFrame {
        guard wire.count >= protocolHeaderSize else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let bodyLength = Int(readUInt16(wire, 1))
        guard wire.count == protocolHeaderSize + bodyLength else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        return .init(type: wire[0], payload: Data(wire.dropFirst(protocolHeaderSize)), transmittedNanoseconds: readUInt64(wire, 3), echoedNanoseconds: readUInt64(wire, 11))
    }

    public static func decodeDataChunks(_ wire: Data) throws -> (chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) {
        let frame = try decodeWire(wire)
        guard frame.type == dataType, frame.payload.count >= 2, frame.payload[0] == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let count = Int(frame.payload[1])
        guard count > 0, count <= 64 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        var offset = 2
        var chunks: [ObstacleBridgeMyUDPStreamChunk] = []
        for _ in 0..<count {
            guard offset + 2 <= frame.payload.count else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            let recordLength = Int(readUInt16(frame.payload, offset)); offset += 2
            guard recordLength >= 5, offset + recordLength <= frame.payload.count else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            let counter = readUInt16(frame.payload, offset)
            let payloadLength = Int(readUInt16(frame.payload, offset + 2))
            guard counter != 0, payloadLength > 0, payloadLength <= maximumPayloadSize, recordLength == payloadLength + 4 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            chunks.append(.init(counter: counter, payload: Data(frame.payload[(offset + 4)..<(offset + recordLength)])))
            offset += recordLength
        }
        guard offset == frame.payload.count else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        return (chunks, frame.transmittedNanoseconds, frame.echoedNanoseconds)
    }

    /// Compatibility helper for callers that deliberately use a single DATA
    /// record. Production transport code uses `decodeDataChunks`.
    public static func decodeData(_ wire: Data) throws -> ObstacleBridgeMyUDPDataFrame {
        let decoded = try decodeDataChunks(wire)
        guard decoded.chunks.count == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let chunk = decoded.chunks[0]
        return .init(counter: chunk.counter, payload: chunk.payload, transmittedNanoseconds: decoded.transmittedNanoseconds, echoedNanoseconds: decoded.echoedNanoseconds)
    }

    private static func encode(type: UInt8, payload: Data, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) throws -> Data {
        guard payload.count <= maximumBatchPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var result = Data([type])
        append(UInt16(payload.count), to: &result); append(transmittedNanoseconds, to: &result); append(echoedNanoseconds, to: &result)
        result.append(payload)
        return result
    }

    private static func append(_ value: UInt16, to data: inout Data) { data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff)) }
    private static func append(_ value: UInt64, to data: inout Data) { for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) } }
    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16 { (UInt16(data[offset]) << 8) | UInt16(data[offset + 1]) }
    private static func readUInt64(_ data: Data, _ offset: Int) -> UInt64 { (0..<8).reduce(UInt64(0)) { ($0 << 8) | UInt64(data[offset + $1]) } }
}
