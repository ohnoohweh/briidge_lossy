import Foundation

public enum ObstacleBridgeUdpOverlayCodecError: Error {
    case payloadTooLarge
    case invalidField
}

public struct ObstacleBridgeUdpOverlayCodec {
    // Compatibility names for the Apple peer runtime. Values remain owned by
    // Core so queue budgeting cannot drift from the shared wire codec.
    public static let protocolHeaderSize = ObstacleBridgeMyUDPCodec.protocolHeaderSize
    public static let streamRecordHeaderSize = ObstacleBridgeMyUDPCodec.streamRecordHeaderSize
    public static let maxStreamRecordBytes = ObstacleBridgeMyUDPCodec.maximumStreamRecordSize
    public static let batchHeaderSize = ObstacleBridgeMyUDPCodec.batchHeaderSize
    public static let batchRecordLengthSize = ObstacleBridgeMyUDPCodec.batchRecordLengthSize
    public static let chunkHeaderSize = ObstacleBridgeMyUDPCodec.chunkHeaderSize
    public static let maxBatchRecords = ObstacleBridgeMyUDPCodec.maximumBatchRecords
    public static let maxBatchPayloadBytes = ObstacleBridgeMyUDPCodec.maximumBatchPayloadSize
    public static let maxChunkBytes = ObstacleBridgeMyUDPCodec.maximumPayloadSize
    public static let ptypeIdle = Int(ObstacleBridgeMyUDPCodec.idleType)
    public static let ptypeData = Int(ObstacleBridgeMyUDPCodec.dataType)
    public static let ptypeControl = Int(ObstacleBridgeMyUDPCodec.controlType)

    public struct ParsedProtocolFrame: Equatable {
        public let ptype: Int
        public let payload: Data
        public let txNS: UInt64
        public let echoNS: UInt64

        public init(ptype: Int, payload: Data, txNS: UInt64, echoNS: UInt64) {
            self.ptype = ptype
            self.payload = payload
            self.txNS = txNS
            self.echoNS = echoNS
        }
    }

    public struct StreamChunk: Equatable {
        public let counter: Int
        public let data: Data

        public init(counter: Int, data: Data) {
            self.counter = counter
            self.data = data
        }
    }

    public struct ControlPacket: Equatable {
        public let lastInOrderRX: Int
        public let highestRX: Int
        public let missed: [Int]
        public let raw: Data

        public init(lastInOrderRX: Int, highestRX: Int, missed: [Int], raw: Data) {
            self.lastInOrderRX = lastInOrderRX
            self.highestRX = highestRX
            self.missed = missed
            self.raw = raw
        }
    }

    public static func maxPayloadLength() -> Int {
        maxBatchPayloadBytes
    }

    public static func encodeStreamRecord(_ payload: Data) throws -> Data {
        do { return try ObstacleBridgeMyUDPCodec.encodeStreamRecord(payload) }
        catch { throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge }
    }

    public static func encodeDataBatch(_ chunks: [StreamChunk]) throws -> Data {
        guard !chunks.isEmpty, chunks.count <= maxBatchRecords else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        for chunk in chunks {
            guard (1...0xFFFF).contains(chunk.counter), !chunk.data.isEmpty, chunk.data.count <= maxChunkBytes else {
                throw ObstacleBridgeUdpOverlayCodecError.invalidField
            }
        }
        do {
            return try ObstacleBridgeMyUDPCodec.encodeDataBatchPayload(
                chunks.map { .init(counter: UInt16($0.counter), payload: $0.data) }
            )
        } catch {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
    }

    public static func decodeDataBatch(_ payload: Data) -> [StreamChunk]? {
        guard let decoded = try? ObstacleBridgeMyUDPCodec.decodeDataBatchPayload(payload) else { return nil }
        return decoded.map { .init(counter: Int($0.counter), data: $0.payload) }
    }

    public static func buildDataBatchFrame(
        chunks: [StreamChunk],
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        do {
            return try ObstacleBridgeMyUDPCodec.encodeWire(
                type: ObstacleBridgeMyUDPCodec.dataType,
                payload: encodeDataBatch(chunks),
                transmittedNanoseconds: txNS,
                echoedNanoseconds: echoNS
            )
        } catch {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
    }

    public static func controlMaxMissed() -> Int {
        ObstacleBridgeMyUDPCodec.maximumControlMissingCount
    }

    public static func buildProtocolFrame(
        ptype: Int,
        payload: Data,
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        guard (0...0xFF).contains(ptype) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        guard payload.count <= maxPayloadLength() else {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
        do {
            return try ObstacleBridgeMyUDPCodec.encodeWire(
                type: UInt8(ptype), payload: payload, transmittedNanoseconds: txNS, echoedNanoseconds: echoNS
            )
        } catch {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
    }

    public static func parseProtocolFrame(_ data: Data) -> ParsedProtocolFrame? {
        guard let frame = try? ObstacleBridgeMyUDPCodec.decodeWire(data) else { return nil }
        return ParsedProtocolFrame(
            ptype: Int(frame.type), payload: frame.payload,
            txNS: frame.transmittedNanoseconds, echoNS: frame.echoedNanoseconds
        )
    }

    public static func buildControlFrame(
        lastInOrderRX: Int,
        highestRX: Int,
        missed: [Int],
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        guard (0...0xFFFF).contains(lastInOrderRX), (0...0xFFFF).contains(highestRX) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        return try ObstacleBridgeMyUDPCodec.encodeControl(
            lastInOrder: UInt16(lastInOrderRX),
            highestReceived: UInt16(highestRX),
            missing: missed.prefix(controlMaxMissed()).map(UInt16.init(truncatingIfNeeded:)),
            transmittedNanoseconds: txNS,
            echoedNanoseconds: echoNS
        )
    }

    public static func parseControlFrame(_ raw: Data) -> ControlPacket? {
        guard let frame = try? ObstacleBridgeMyUDPCodec.decodeControl(raw) else {
            return nil
        }
        return ControlPacket(
            lastInOrderRX: Int(frame.lastInOrder),
            highestRX: Int(frame.highestReceived),
            missed: frame.missing.map(Int.init),
            raw: raw
        )
    }

}
