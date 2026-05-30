import Foundation

enum ObstacleBridgeUdpOverlayCodecError: Error {
    case payloadTooLarge
    case invalidField
}

struct ObstacleBridgeUdpOverlayCodec {
    static let maxFrameSize = 1500 - 48
    static let protocolHeaderSize = 19
    static let dataPayloadFixed = 7
    static let controlFixedBase = 6
    static let ptypeIdle = 0
    static let ptypeData = 1
    static let ptypeControl = 2

    struct ParsedProtocolFrame: Equatable {
        var ptype: Int
        var payload: Data
        var txNS: UInt64
        var echoNS: UInt64
    }

    struct DataPacket: Equatable {
        var pktCounter: Int
        var frameType: Int
        var lenOrOffset: Int
        var chunkLen: Int
        var data: Data
        var raw: Data
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

    static func dataMaxChunk() -> Int {
        return maxPayloadLength() - dataPayloadFixed
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

    static func buildDataPayload(
        pktCounter: Int,
        frameType: Int,
        lenOrOffset: Int,
        data: Data
    ) throws -> Data {
        let isIdle = pktCounter == 0 && frameType == 1 && data.isEmpty
        guard isIdle || (1...0xFFFF).contains(pktCounter) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        guard (0...0xFFFF).contains(lenOrOffset) else {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        guard data.count <= dataMaxChunk() else {
            throw ObstacleBridgeUdpOverlayCodecError.payloadTooLarge
        }
        if data.isEmpty && frameType != 1 {
            throw ObstacleBridgeUdpOverlayCodecError.invalidField
        }
        var payload = Data()
        payload.appendUInt16(UInt16(pktCounter & 0xFFFF))
        payload.appendUInt8(UInt8(frameType & 0xFF))
        payload.appendUInt16(UInt16(lenOrOffset))
        payload.appendUInt16(UInt16(data.count))
        payload.append(data)
        return payload
    }

    static func parseDataPayload(_ payload: Data, raw: Data) -> DataPacket? {
        guard payload.count >= dataPayloadFixed else {
            return nil
        }
        var offset = 0
        guard
            let pktCounter = readUInt16(from: payload, offset: &offset),
            let frameType = readUInt8(from: payload, offset: &offset),
            let lenOrOffset = readUInt16(from: payload, offset: &offset),
            let chunkLen = readUInt16(from: payload, offset: &offset),
            let chunk = readData(from: payload, offset: &offset, length: Int(chunkLen))
        else {
            return nil
        }
        return DataPacket(
            pktCounter: Int(pktCounter),
            frameType: Int(frameType),
            lenOrOffset: Int(lenOrOffset),
            chunkLen: Int(chunkLen),
            data: chunk,
            raw: raw
        )
    }

    static func buildDataFrame(
        pktCounter: Int,
        frameType: Int,
        lenOrOffset: Int,
        data: Data,
        txNS: UInt64,
        echoNS: UInt64
    ) throws -> Data {
        let payload = try buildDataPayload(
            pktCounter: pktCounter,
            frameType: frameType,
            lenOrOffset: lenOrOffset,
            data: data
        )
        return try buildProtocolFrame(ptype: ptypeData, payload: payload, txNS: txNS, echoNS: echoNS)
    }

    static func parseDataFrame(_ raw: Data) -> DataPacket? {
        guard let frame = parseProtocolFrame(raw), frame.ptype == ptypeData else {
            return nil
        }
        return parseDataPayload(frame.payload, raw: raw)
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
        let value = data[offset]
        offset += 1
        return value
    }

    private static func readUInt16(from data: Data, offset: inout Int) -> UInt16? {
        guard offset + 2 <= data.count else {
            return nil
        }
        let value = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
        offset += 2
        return value
    }

    private static func readUInt64(from data: Data, offset: inout Int) -> UInt64? {
        guard offset + 8 <= data.count else {
            return nil
        }
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value << 8) | UInt64(data[offset + index])
        }
        offset += 8
        return value
    }

    private static func readData(from data: Data, offset: inout Int, length: Int) -> Data? {
        guard offset + length <= data.count else {
            return nil
        }
        let payload = data.subdata(in: offset..<(offset + length))
        offset += length
        return payload
    }
}