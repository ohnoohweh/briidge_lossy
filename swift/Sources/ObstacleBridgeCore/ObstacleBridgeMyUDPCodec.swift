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

public struct ObstacleBridgeMyUDPControlFrame: Equatable, Sendable {
    public let lastInOrder: UInt16
    public let highestReceived: UInt16
    public let missing: [UInt16]
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
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

    public static func encodeStreamRecord(_ payload: Data) throws -> Data {
        guard payload.count <= Int(UInt16.max) else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: payload.count + 4)
        writer.append(UInt32(payload.count)); writer.append(payload)
        return writer.encoded
    }

    public static func decodeStreamRecordLength(_ header: Data) throws -> Int {
        do {
            var reader = ObstacleBridgeBinaryReader(header)
            let length = Int(try reader.readUInt32())
            guard reader.isAtEnd, length <= Int(UInt16.max) else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return length
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func encodeData(payload: Data, counter: UInt16, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        try encodeData(chunks: [.init(counter: counter, payload: payload)], transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeData(chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard !chunks.isEmpty, chunks.count <= 64 else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var batch = ObstacleBridgeBinaryWriter(capacity: maximumBatchPayloadSize)
        batch.append(UInt8(1)); batch.append(UInt8(chunks.count))
        for chunk in chunks {
            guard chunk.counter != 0, !chunk.payload.isEmpty, chunk.payload.count <= maximumPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
            batch.append(UInt16(chunk.payload.count + 4)); batch.append(chunk.counter)
            batch.append(UInt16(chunk.payload.count)); batch.append(chunk.payload)
        }
        guard batch.encoded.count <= maximumBatchPayloadSize else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        return try encode(type: dataType, payload: batch.encoded, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func encodeControl(lastInOrder: UInt16, highestReceived: UInt16, missing: [UInt16] = [], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard missing.count <= 64 else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        var payload = ObstacleBridgeBinaryWriter(capacity: 6 + missing.count * 2)
        payload.append(lastInOrder); payload.append(highestReceived); payload.append(UInt16(missing.count))
        for counter in missing { payload.append(counter) }
        return try encode(type: controlType, payload: payload.encoded, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
    }

    public static func decodeControl(_ wire: Data) throws -> ObstacleBridgeMyUDPControlFrame {
        do {
            let frame = try decodeWire(wire)
            guard frame.type == controlType else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            var reader = ObstacleBridgeBinaryReader(frame.payload)
            let lastInOrder = try reader.readUInt16()
            let highestReceived = try reader.readUInt16()
            let count = Int(try reader.readUInt16())
            guard count <= 64 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            let missing = try (0..<count).map { _ in try reader.readUInt16() }
            guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return .init(lastInOrder: lastInOrder, highestReceived: highestReceived, missing: missing, transmittedNanoseconds: frame.transmittedNanoseconds, echoedNanoseconds: frame.echoedNanoseconds)
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func decodeWire(_ wire: Data) throws -> ObstacleBridgeMyUDPWireFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            let type = try reader.readUInt8(), bodyLength = Int(try reader.readUInt16())
            let transmittedNanoseconds = try reader.readUInt64(), echoedNanoseconds = try reader.readUInt64()
            let payload = try reader.readData(count: bodyLength)
            guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
            return .init(type: type, payload: payload, transmittedNanoseconds: transmittedNanoseconds, echoedNanoseconds: echoedNanoseconds)
        } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
    }

    public static func decodeDataChunks(_ wire: Data) throws -> (chunks: [ObstacleBridgeMyUDPStreamChunk], transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64) {
        let frame = try decodeWire(wire)
        guard frame.type == dataType, frame.payload.count >= 2, frame.payload[0] == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let count = Int(frame.payload[1])
        guard count > 0, count <= 64 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        var reader = ObstacleBridgeBinaryReader(Data(frame.payload.dropFirst(2)))
        var chunks: [ObstacleBridgeMyUDPStreamChunk] = []
        for _ in 0..<count {
            do {
                let recordLength = Int(try reader.readUInt16())
                guard recordLength >= 5 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
                let counter = try reader.readUInt16(), payloadLength = Int(try reader.readUInt16())
                guard counter != 0, payloadLength > 0, payloadLength <= maximumPayloadSize, recordLength == payloadLength + 4 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
                chunks.append(.init(counter: counter, payload: try reader.readData(count: payloadLength)))
            } catch { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        }
        guard reader.isAtEnd else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
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
        var writer = ObstacleBridgeBinaryWriter(capacity: protocolHeaderSize + payload.count)
        writer.append(type); writer.append(UInt16(payload.count)); writer.append(transmittedNanoseconds); writer.append(echoedNanoseconds); writer.append(payload)
        return writer.encoded
    }
}
