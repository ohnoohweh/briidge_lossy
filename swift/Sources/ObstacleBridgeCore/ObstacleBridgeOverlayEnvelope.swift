import Foundation

/// Result of consuming a lower-transport overlay envelope.  It is deliberately
/// independent of TCP framing and WebSocket message APIs.
public enum ObstacleBridgeOverlayEnvelopeDecision: Equatable, Sendable {
    case application(Data)
    case reply(ObstacleBridgeOverlayFrame)
    case ignore
}

/// Portable APP/PING/PONG policy shared by stream and WebSocket adapters.
public enum ObstacleBridgeOverlayEnvelope {
    public static func consume(_ frame: ObstacleBridgeOverlayFrame) throws -> ObstacleBridgeOverlayEnvelopeDecision {
        switch frame.kind {
        case .application: .application(frame.payload)
        case .ping: .reply(try ObstacleBridgeOverlayFrameCodec.pong(forPing: frame))
        case .pong: .ignore
        }
    }

    public static func decodeTCP(_ wire: Data) throws -> ObstacleBridgeOverlayEnvelopeDecision {
        try consume(try ObstacleBridgeOverlayFrameCodec.decodeTCP(wire))
    }

    public static func encodeTCP(_ frame: ObstacleBridgeOverlayFrame) throws -> Data {
        try ObstacleBridgeOverlayFrameCodec.encodeTCP(frame)
    }

    public static func decodeWebSocket(
        _ payload: ObstacleBridgeWebSocketPayload,
        mode: ObstacleBridgeWebSocketPayloadMode
    ) throws -> ObstacleBridgeOverlayEnvelopeDecision {
        let body = try ObstacleBridgeWebSocketPayloadCodec.decode(payload, mode: mode)
        return try consume(try ObstacleBridgeOverlayFrameCodec.decodeBody(body))
    }

    public static func encodeWebSocket(
        _ frame: ObstacleBridgeOverlayFrame,
        mode: ObstacleBridgeWebSocketPayloadMode
    ) throws -> ObstacleBridgeWebSocketPayload {
        try ObstacleBridgeWebSocketPayloadCodec.encode(
            ObstacleBridgeOverlayFrameCodec.encodeBody(frame), mode: mode
        )
    }
}
