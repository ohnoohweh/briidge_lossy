import Foundation

public enum ObstacleBridgeMyUDPCodecError: Error, Equatable { case payloadTooLarge, invalidFrame }

public struct ObstacleBridgeMyUDPDataFrame: Equatable, Sendable {
    public let counter: UInt16
    public let payload: Data
    public let transmittedNanoseconds: UInt64
    public let echoedNanoseconds: UInt64
}

/// myudp v2 DATA framing shared with the Python reference: protocol header
/// (ptype, length, tx_ns, echo_ns), then a v1 one-record DATA batch.
public enum ObstacleBridgeMyUDPCodec {
    public static let protocolHeaderSize = 19
    public static let maximumPayloadSize = 1425

    public static func encodeData(payload: Data, counter: UInt16, transmittedNanoseconds: UInt64, echoedNanoseconds: UInt64 = 0) throws -> Data {
        guard !payload.isEmpty, payload.count <= maximumPayloadSize, counter != 0 else { throw ObstacleBridgeMyUDPCodecError.payloadTooLarge }
        let recordLength = payload.count + 4
        var batch = Data([1, 1])
        append(UInt16(recordLength), to: &batch)
        append(counter, to: &batch)
        append(UInt16(payload.count), to: &batch)
        batch.append(payload)
        var result = Data([1])
        append(UInt16(batch.count), to: &result)
        append(transmittedNanoseconds, to: &result)
        append(echoedNanoseconds, to: &result)
        result.append(batch)
        return result
    }

    public static func decodeData(_ wire: Data) throws -> ObstacleBridgeMyUDPDataFrame {
        guard wire.count >= protocolHeaderSize, wire[0] == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let bodyLength = Int(readUInt16(wire, 1))
        guard wire.count == protocolHeaderSize + bodyLength, bodyLength >= 8, wire[19] == 1, wire[20] == 1 else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        let recordLength = Int(readUInt16(wire, 21))
        let counter = readUInt16(wire, 23)
        let payloadLength = Int(readUInt16(wire, 25))
        guard counter != 0, recordLength == payloadLength + 4, payloadLength > 0, payloadLength <= maximumPayloadSize, wire.count == 27 + payloadLength else { throw ObstacleBridgeMyUDPCodecError.invalidFrame }
        return .init(counter: counter, payload: Data(wire.dropFirst(27)), transmittedNanoseconds: readUInt64(wire, 3), echoedNanoseconds: readUInt64(wire, 11))
    }

    private static func append(_ value: UInt16, to data: inout Data) { data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff)) }
    private static func append(_ value: UInt64, to data: inout Data) { for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) } }
    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16 { (UInt16(data[offset]) << 8) | UInt16(data[offset + 1]) }
    private static func readUInt64(_ data: Data, _ offset: Int) -> UInt64 { (0..<8).reduce(UInt64(0)) { ($0 << 8) | UInt64(data[offset + $1]) } }
}
