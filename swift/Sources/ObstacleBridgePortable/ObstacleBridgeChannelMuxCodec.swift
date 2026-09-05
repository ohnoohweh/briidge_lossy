import Foundation

public enum ObstacleBridgeChannelMuxProtocol: UInt8, Sendable { case udp = 0, tcp = 1, tun = 2 }
public enum ObstacleBridgeChannelMuxMessageType: UInt8, Sendable { case data = 0, open = 1, close = 2, remoteServicesSetV1 = 3, remoteServicesSetV2 = 4, dataFragment = 5, remoteServicesSetV2Chunk = 6, openChunk = 7 }

public struct ObstacleBridgeChannelMuxFrame: Equatable, Sendable {
    public let channelID: UInt16
    public let protocolType: ObstacleBridgeChannelMuxProtocol
    public let counter: UInt16
    public let messageType: ObstacleBridgeChannelMuxMessageType
    public let body: Data
}

public enum ObstacleBridgeChannelMuxCodecError: Error, Equatable { case invalidFrame, payloadTooLarge }

/// Portable representation of the existing ChannelMux header:
/// channel-id(2), protocol(1), counter(2), message-type(1), body-length(2).
public enum ObstacleBridgeChannelMuxCodec {
    public static let headerSize = 8

    public static func encode(channelID: UInt16, protocolType: ObstacleBridgeChannelMuxProtocol, counter: UInt16, messageType: ObstacleBridgeChannelMuxMessageType, body: Data) throws -> Data {
        guard body.count <= Int(UInt16.max) else { throw ObstacleBridgeChannelMuxCodecError.payloadTooLarge }
        var result = Data()
        append(channelID, to: &result)
        result.append(protocolType.rawValue)
        append(counter, to: &result)
        result.append(messageType.rawValue)
        append(UInt16(body.count), to: &result)
        result.append(body)
        return result
    }

    public static func decode(_ wire: Data) throws -> ObstacleBridgeChannelMuxFrame {
        guard wire.count >= headerSize else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
        let channelID = readUInt16(wire, 0)
        guard let protocolType = ObstacleBridgeChannelMuxProtocol(rawValue: wire[2]),
              let messageType = ObstacleBridgeChannelMuxMessageType(rawValue: wire[5]) else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
        let counter = readUInt16(wire, 3)
        let length = Int(readUInt16(wire, 6))
        guard wire.count == headerSize + length else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
        return .init(channelID: channelID, protocolType: protocolType, counter: counter, messageType: messageType, body: Data(wire.dropFirst(headerSize)))
    }

    private static func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
    }
    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16 { (UInt16(data[offset]) << 8) | UInt16(data[offset + 1]) }
}
