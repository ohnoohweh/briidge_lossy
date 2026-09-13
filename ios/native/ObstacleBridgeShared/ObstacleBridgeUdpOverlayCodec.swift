import Foundation

enum ObstacleBridgeUdpOverlayCodecError: Error {
    case payloadTooLarge
    case invalidField
}

struct ObstacleBridgeUdpOverlayCodec {
    static let maxFrameSize = 1500 - 48
    static let protocolHeaderSize = 19
    static let streamRecordHeaderSize = 4
    static let maxStreamRecordBytes = 0xFFFF
    static let maxBatchRecords = 64
    static let maxBatchPayloadBytes = 1433
    static let maxChunkBytes = 1425
    static let ptypeIdle = 0
    static let ptypeData = 1
    static let ptypeControl = 2

    struct ParsedProtocolFrame: Equatable {
        var ptype: Int
        var payload: Data
        var txNS: UInt64
        var echoNS: UInt64
    }

    struct StreamChunk: Equatable {
        var counter: Int
        var data: Data
    }

    struct ControlPacket: Equatable {
        var lastInOrderRX: Int
        var highestRX: Int
        var missed: [Int]
        var raw: Data
    }

    static func maxPayloadLength() -> Int {
        return max(0, maxFrameSize - protocolHeaderSize)
    }

    static func encodeStreamRecord(_ payload: Data) throws -> Data {
        do { return try ObstacleBridgeMyUDPCodec.encodeStreamRecord(payload) }
        catch { throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge }
    }

    static func encodeDataBatch(_ chunks: [StreamChunk]) throws -> Data {
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

    static func decodeDataBatch(_ payload: Data) -> [StreamChunk]? {
        guard let decoded = try? ObstacleBridgeMyUDPCodec.decodeDataBatchPayload(payload) else { return nil }
        return decoded.map { .init(counter: Int($0.counter), data: $0.payload) }
    }

    static func buildDataBatchFrame(
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

    static func controlMaxMissed() -> Int {
        ObstacleBridgeMyUDPCodec.maximumControlMissingCount
    }

    static func buildProtocolFrame(
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

    static func parseProtocolFrame(_ data: Data) -> ParsedProtocolFrame? {
        guard let frame = try? ObstacleBridgeMyUDPCodec.decodeWire(data) else { return nil }
        return ParsedProtocolFrame(
            ptype: Int(frame.type), payload: frame.payload,
            txNS: frame.transmittedNanoseconds, echoNS: frame.echoedNanoseconds
        )
    }

    static func buildControlFrame(
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

    static func parseControlFrame(_ raw: Data) -> ControlPacket? {
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
