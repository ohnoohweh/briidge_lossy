import Foundation

public enum ObstacleBridgeChannelMuxProtocol: UInt8, Sendable { case udp = 0, tcp = 1, tun = 2 }
public enum ObstacleBridgeChannelMuxMessageType: UInt8, Sendable { case data = 0, open = 1, close = 2, remoteServicesSetV1 = 3, remoteServicesSetV2 = 4, dataFragment = 5, remoteServicesSetV2Chunk = 6, openChunk = 7 }

public struct ObstacleBridgeChannelMuxFrame: Equatable, Sendable {
    public let channelID: UInt16
    public let protocolType: ObstacleBridgeChannelMuxProtocol
    public let counter: UInt16
    public let messageType: ObstacleBridgeChannelMuxMessageType
    public let body: Data

    public init(channelID: UInt16, protocolType: ObstacleBridgeChannelMuxProtocol, counter: UInt16, messageType: ObstacleBridgeChannelMuxMessageType, body: Data) {
        self.channelID = channelID
        self.protocolType = protocolType
        self.counter = counter
        self.messageType = messageType
        self.body = body
    }
}

public enum ObstacleBridgeChannelMuxCodecError: Error, Equatable { case invalidFrame, payloadTooLarge }

/// Portable representation of the existing ChannelMux header:
/// channel-id(2), protocol(1), counter(2), message-type(1), body-length(2).
public enum ObstacleBridgeChannelMuxCodec {
    public static let headerSize = 8

    public static func encode(channelID: UInt16, protocolType: ObstacleBridgeChannelMuxProtocol, counter: UInt16, messageType: ObstacleBridgeChannelMuxMessageType, body: Data) throws -> Data {
        guard body.count <= Int(UInt16.max) else { throw ObstacleBridgeChannelMuxCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: headerSize + body.count)
        writer.append(channelID); writer.append(protocolType.rawValue); writer.append(counter)
        writer.append(messageType.rawValue); writer.append(UInt16(body.count)); writer.append(body)
        return writer.encoded
    }

    public static func decode(_ wire: Data) throws -> ObstacleBridgeChannelMuxFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            let channelID = try reader.readUInt16()
            guard let protocolType = ObstacleBridgeChannelMuxProtocol(rawValue: try reader.readUInt8()) else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
            let counter = try reader.readUInt16()
            guard let messageType = ObstacleBridgeChannelMuxMessageType(rawValue: try reader.readUInt8()) else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
            let body = try reader.readData(count: Int(try reader.readUInt16()))
            guard reader.isAtEnd else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
            return .init(channelID: channelID, protocolType: protocolType, counter: counter, messageType: messageType, body: body)
        } catch { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
    }
}
