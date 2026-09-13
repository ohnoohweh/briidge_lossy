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
    public static let headerSize = ObstacleBridgeChannelMuxFrameCodec.headerSize

    public static func encode(channelID: UInt16, protocolType: ObstacleBridgeChannelMuxProtocol, counter: UInt16, messageType: ObstacleBridgeChannelMuxMessageType, body: Data) throws -> Data {
        do {
            return try ObstacleBridgeChannelMuxFrameCodec.encode(
                channelID: channelID, protocolType: protocolType.rawValue,
                counter: counter, messageType: messageType.rawValue, body: body
            )
        } catch { throw ObstacleBridgeChannelMuxCodecError.payloadTooLarge }
    }

    public static func decode(_ wire: Data) throws -> ObstacleBridgeChannelMuxFrame {
        do {
            let frame = try ObstacleBridgeChannelMuxFrameCodec.decode(wire)
            guard let protocolType = ObstacleBridgeChannelMuxProtocol(rawValue: frame.protocolType),
                  let messageType = ObstacleBridgeChannelMuxMessageType(rawValue: frame.messageType)
            else { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
            return .init(channelID: frame.channelID, protocolType: protocolType, counter: frame.counter, messageType: messageType, body: frame.body)
        } catch { throw ObstacleBridgeChannelMuxCodecError.invalidFrame }
    }
}
