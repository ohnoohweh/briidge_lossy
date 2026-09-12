import Foundation

public enum ObstacleBridgeOverlayFrameKind: UInt8, Sendable { case application = 0, ping = 1, pong = 2 }

public struct ObstacleBridgeOverlayFrame: Equatable, Sendable {
    public let kind: ObstacleBridgeOverlayFrameKind
    public let payload: Data

    public init(kind: ObstacleBridgeOverlayFrameKind, payload: Data) {
        self.kind = kind
        self.payload = payload
    }
}

public enum ObstacleBridgeOverlayFrameCodecError: Error, Equatable, Sendable {
    case invalidFrame
    case payloadTooLarge
}

/// Common TCP/WebSocket APP, PING, and PONG record codec. TCP adds a four-byte
/// body length; WebSocket carries the encoded body as its binary message.
public enum ObstacleBridgeOverlayFrameCodec {
    public static let maximumBodyLength = 1_048_576

    public static func encodeBody(_ frame: ObstacleBridgeOverlayFrame) throws -> Data {
        guard frame.payload.count < maximumBodyLength else { throw ObstacleBridgeOverlayFrameCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: frame.payload.count + 1)
        writer.append(frame.kind.rawValue)
        writer.append(frame.payload)
        return writer.encoded
    }

    public static func encodeTCP(_ frame: ObstacleBridgeOverlayFrame) throws -> Data {
        let body = try encodeBody(frame)
        guard body.count <= Int(UInt32.max) else { throw ObstacleBridgeOverlayFrameCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: body.count + 4)
        writer.append(UInt32(body.count))
        writer.append(body)
        return writer.encoded
    }

    public static func decodeBody(_ body: Data) throws -> ObstacleBridgeOverlayFrame {
        guard body.count <= maximumBodyLength, let rawKind = body.first, let kind = ObstacleBridgeOverlayFrameKind(rawValue: rawKind) else { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
        let payload = Data(body.dropFirst())
        if kind != .application, payload.count < 8 { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
        return .init(kind: kind, payload: payload)
    }

    public static func decodeTCP(_ wire: Data) throws -> ObstacleBridgeOverlayFrame {
        do {
            var reader = ObstacleBridgeBinaryReader(wire)
            let length = Int(try reader.readUInt32())
            guard length > 0, length <= maximumBodyLength else { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
            let body = try reader.readData(count: length)
            guard reader.isAtEnd else { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
            return try decodeBody(body)
        } catch let error as ObstacleBridgeOverlayFrameCodecError { throw error
        } catch { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
    }

    public static func pong(forPing ping: ObstacleBridgeOverlayFrame) throws -> ObstacleBridgeOverlayFrame {
        guard ping.kind == .ping, ping.payload.count >= 8 else { throw ObstacleBridgeOverlayFrameCodecError.invalidFrame }
        return .init(kind: .pong, payload: Data(ping.payload.prefix(8)))
    }
}
