import Foundation

enum ObstacleBridgeUdpOverlayCodecError: Error {
    case payloadTooLarge
    case invalidField
}

struct ObstacleBridgeUdpOverlayCodec {
    static let maxFrameSize = 1500 - 48
    static let protocolHeaderSize = 19
    static let controlFixedBase = 6
    static let streamRecordHeaderSize = 4
    static let maxStreamRecordBytes = 0xFFFF
    static let batchVersion = 1
    static let maxBatchRecords = 64
    static let batchHeaderSize = 2
    static let batchRecordLengthSize = 2
    static let chunkHeaderSize = 4
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
        guard payload.count <= maxStreamRecordBytes else {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
        var record = Data()
        let length = UInt32(payload.count)
        record.append(UInt8((length >> 24) & 0xFF))
        record.append(UInt8((length >> 16) & 0xFF))
        record.append(UInt8((length >> 8) & 0xFF))
        record.append(UInt8(length & 0xFF))
        record.append(payload)
        return record
    }

    static func encodeDataBatch(_ chunks: [StreamChunk]) throws -> Data {
        guard !chunks.isEmpty, chunks.count <= maxBatchRecords else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        var payload = Data([UInt8(batchVersion), UInt8(chunks.count)])
        for chunk in chunks {
            guard (1...0xFFFF).contains(chunk.counter), !chunk.data.isEmpty, chunk.data.count <= maxChunkBytes else {
                throw ObstacleBridgeUdpOverlayCodecError.invalidField
            }
            let recordLength = chunkHeaderSize + chunk.data.count
            payload.appendUInt16(UInt16(recordLength))
            payload.appendUInt16(UInt16(chunk.counter))
            payload.appendUInt16(UInt16(chunk.data.count))
            payload.append(chunk.data)
        }
        guard payload.count <= maxBatchPayloadBytes else {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
        return payload
    }

    static func decodeDataBatch(_ payload: Data) -> [StreamChunk]? {
        guard payload.count >= batchHeaderSize, payload.count <= maxBatchPayloadBytes else {
            return nil
        }
        let version = Int(payload[payload.startIndex])
        let count = Int(payload[payload.index(after: payload.startIndex)])
        guard version == batchVersion, (1...maxBatchRecords).contains(count) else {
            return nil
        }
        var offset = batchHeaderSize
        var chunks: [StreamChunk] = []
        chunks.reserveCapacity(count)
        for _ in 0..<count {
            guard let recordLength = readUInt16(from: payload, offset: &offset) else {
                return nil
            }
            let length = Int(recordLength)
            guard length >= chunkHeaderSize + 1, offset + length <= payload.count,
                  let counter = readUInt16(from: payload, offset: &offset),
                  let chunkLength = readUInt16(from: payload, offset: &offset) else {
                return nil
            }
            let dataLength = Int(chunkLength)
            guard (1...0xFFFF).contains(Int(counter)), (1...maxChunkBytes).contains(dataLength),
                  length == chunkHeaderSize + dataLength,
                  let data = readData(from: payload, offset: &offset, length: dataLength) else {
                return nil
            }
            chunks.append(StreamChunk(counter: Int(counter), data: data))
        }
        return offset == payload.count ? chunks : nil
    }

    static func buildDataBatchFrame(
        chunks: [StreamChunk],
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        try buildProtocolFrame(ptype: ptypeData, payload: encodeDataBatch(chunks), txNS: txNS, echoNS: echoNS)
    }

    static func controlMaxMissed() -> Int {
        return (maxPayloadLength() - controlFixedBase) / 2
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
        var frame = Data()
        frame.appendUInt8(UInt8(ptype))
        frame.appendUInt16(UInt16(payload.count))
        frame.appendUInt64(txNS)
        frame.appendUInt64(echoNS)
        frame.append(payload)
        return frame
    }

    static func parseProtocolFrame(_ data: Data) -> ParsedProtocolFrame? {
        guard data.count >= protocolHeaderSize else {
            return nil
        }
        var offset = 0
        guard
            let ptype = readUInt8(from: data, offset: &offset),
            let payloadLength = readUInt16(from: data, offset: &offset),
            let txNS = readUInt64(from: data, offset: &offset),
            let echoNS = readUInt64(from: data, offset: &offset),
            let payload = readData(from: data, offset: &offset, length: Int(payloadLength))
        else {
            return nil
        }
        return ParsedProtocolFrame(ptype: Int(ptype), payload: payload, txNS: txNS, echoNS: echoNS)
    }

    static func buildControlPayload(
        lastInOrderRX: Int,
        highestRX: Int,
        missed: [Int]
    ) throws -> Data {
        guard (0...0xFFFF).contains(lastInOrderRX), (0...0xFFFF).contains(highestRX) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        let clippedMissed = Array(missed.prefix(controlMaxMissed()))
        var payload = Data()
        payload.appendUInt16(UInt16(lastInOrderRX))
        payload.appendUInt16(UInt16(highestRX))
        payload.appendUInt16(UInt16(clippedMissed.count))
        for missedCounter in clippedMissed {
            payload.appendUInt16(UInt16(missedCounter & 0xFFFF))
        }
        return payload
    }

    static func parseControlPayload(_ payload: Data, raw: Data) -> ControlPacket? {
        guard payload.count >= controlFixedBase else {
            return nil
        }
        var offset = 0
        guard
            let lastInOrderRX = readUInt16(from: payload, offset: &offset),
            let highestRX = readUInt16(from: payload, offset: &offset),
            let missedCount = readUInt16(from: payload, offset: &offset)
        else {
            return nil
        }
        var missed: [Int] = []
        missed.reserveCapacity(Int(missedCount))
        for _ in 0..<missedCount {
            guard let counter = readUInt16(from: payload, offset: &offset) else {
                return nil
            }
            missed.append(Int(counter))
        }
        return ControlPacket(
            lastInOrderRX: Int(lastInOrderRX),
            highestRX: Int(highestRX),
            missed: missed,
            raw: raw
        )
    }

    static func buildControlFrame(
        lastInOrderRX: Int,
        highestRX: Int,
        missed: [Int],
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        let payload = try buildControlPayload(
            lastInOrderRX: lastInOrderRX,
            highestRX: highestRX,
            missed: missed
        )
        return try buildProtocolFrame(ptype: ptypeControl, payload: payload, txNS: txNS, echoNS: echoNS)
    }

    static func parseControlFrame(_ raw: Data) -> ControlPacket? {
        guard let frame = parseProtocolFrame(raw), frame.ptype == ptypeControl else {
            return nil
        }
        return parseControlPayload(frame.payload, raw: raw)
    }

    private static func readUInt8(from data: Data, offset: inout Int) -> UInt8? {
        guard offset + 1 <= data.count else {
            return nil
        }
        let index = data.index(data.startIndex, offsetBy: offset)
        let value = data[index]
        offset += 1
        return value
    }

    private static func readUInt16(from data: Data, offset: inout Int) -> UInt16? {
        guard offset + 2 <= data.count else {
            return nil
        }
        let start = data.index(data.startIndex, offsetBy: offset)
        let end = data.index(after: start)
        let value = (UInt16(data[start]) << 8) | UInt16(data[end])
        offset += 2
        return value
    }

    private static func readUInt32(from data: Data, offset: inout Int) -> UInt32? {
        guard offset + 4 <= data.count else {
            return nil
        }
        let start = data.index(data.startIndex, offsetBy: offset)
        let byte1 = data.index(after: start)
        let byte2 = data.index(after: byte1)
        let byte3 = data.index(after: byte2)
        let value = (UInt32(data[start]) << 24) | (UInt32(data[byte1]) << 16) |
            (UInt32(data[byte2]) << 8) | UInt32(data[byte3])
        offset += 4
        return value
    }

    private static func readUInt64(from data: Data, offset: inout Int) -> UInt64? {
        guard offset + 8 <= data.count else {
            return nil
        }
        var value: UInt64 = 0
        for index in 0..<8 {
            let dataIndex = data.index(data.startIndex, offsetBy: offset + index)
            value = (value << 8) | UInt64(data[dataIndex])
        }
        offset += 8
        return value
    }

    private static func readData(from data: Data, offset: inout Int, length: Int) -> Data? {
        guard offset + length <= data.count else {
            return nil
        }
        let start = data.index(data.startIndex, offsetBy: offset)
        let end = data.index(start, offsetBy: length)
        let payload = data.subdata(in: start..<end)
        offset += length
        return payload
    }
}
