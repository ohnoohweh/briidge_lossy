import Foundation

public enum ObstacleBridgeSecureLinkFrameCodecError: Error, Equatable, Sendable { case invalidFrame }

/// Shared SecureLink v1 envelope. Client and server state machines consume the
/// same versioned header owner; adapters only carry the resulting bytes.
public struct ObstacleBridgeSecureLinkFrame: Equatable, Sendable {
    public let type: UInt8
    public let sessionID: UInt64
    public let counter: UInt64
    public let header: Data
    public let payload: Data
}

public enum ObstacleBridgeSecureLinkFrameCodec {
    public static let headerLength = 20

    public static func encode(type: UInt8, sessionID: UInt64, counter: UInt64, payload: Data, flags: UInt8 = 0) -> Data {
        header(type: type, sessionID: sessionID, counter: counter, flags: flags) + payload
    }

    public static func header(type: UInt8, sessionID: UInt64, counter: UInt64, flags: UInt8 = 0) -> Data {
        var writer = ObstacleBridgeBinaryWriter(capacity: headerLength)
        writer.append(UInt8(1)); writer.append(type); writer.append(flags); writer.append(UInt8(0))
        writer.append(sessionID); writer.append(counter)
        return writer.encoded
    }

    public static func decode(_ wire: Data) throws -> ObstacleBridgeSecureLinkFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            guard try reader.readUInt8() == 1 else { throw ObstacleBridgeSecureLinkFrameCodecError.invalidFrame }
            let type = try reader.readUInt8()
            _ = try reader.readUInt8(); _ = try reader.readUInt8()
            let sessionID = try reader.readUInt64(), counter = try reader.readUInt64()
            return .init(type: type, sessionID: sessionID, counter: counter, header: Data(wire.prefix(headerLength)), payload: try reader.readData(count: reader.remainingCount))
        } catch { throw ObstacleBridgeSecureLinkFrameCodecError.invalidFrame }
    }
}
