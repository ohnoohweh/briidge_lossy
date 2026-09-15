import Foundation

public struct ObstacleBridgeChannelMuxWireFrame: Equatable, Sendable {
    public let channelID: UInt16
    public let protocolType: UInt8
    public let counter: UInt16
    public let messageType: UInt8
    public let body: Data
}

public enum ObstacleBridgeChannelMuxFrameCodecError: Error, Equatable, Sendable { case invalidFrame, payloadTooLarge }

/// Raw ChannelMux header codec shared by the Core model and flat Apple builds.
public enum ObstacleBridgeChannelMuxFrameCodec {
    public static let headerSize = 8

    public static func encode(channelID: UInt16, protocolType: UInt8, counter: UInt16, messageType: UInt8, body: Data) throws -> Data {
        guard body.count <= Int(UInt16.max) else { throw ObstacleBridgeChannelMuxFrameCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: headerSize + body.count)
        writer.append(channelID); writer.append(protocolType); writer.append(counter)
        writer.append(messageType); writer.append(UInt16(body.count)); writer.append(body)
        return writer.encoded
    }

    public static func decode(_ wire: Data) throws -> ObstacleBridgeChannelMuxWireFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            let channelID = try reader.readUInt16()
            let protocolType = try reader.readUInt8()
            let counter = try reader.readUInt16()
            let messageType = try reader.readUInt8()
            let body = try reader.readData(count: Int(try reader.readUInt16()))
            guard reader.isAtEnd else { throw ObstacleBridgeChannelMuxFrameCodecError.invalidFrame }
            return .init(channelID: channelID, protocolType: protocolType, counter: counter, messageType: messageType, body: body)
        } catch { throw ObstacleBridgeChannelMuxFrameCodecError.invalidFrame }
    }
}
