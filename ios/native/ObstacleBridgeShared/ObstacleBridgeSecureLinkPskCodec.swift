import Foundation

enum ObstacleBridgeSecureLinkPskCodecError: Error {
    case invalidJSON
}

struct ObstacleBridgeSecureLinkPskCodec {
    struct ParsedFrame: Equatable {
        var slType: Int
        var sessionID: UInt64
        var counter: UInt64
        var payload: Data
    }

    static func headerBytes(
        slType: Int,
        sessionID: UInt64,
        counter: UInt64,
        flags: UInt8 = 0
    ) -> Data {
        ObstacleBridgeSecureLinkFrameCodec.header(
            type: UInt8(slType & 0xFF), sessionID: sessionID, counter: counter, flags: flags
        )
    }

    static func buildFrame(
        slType: Int,
        sessionID: UInt64,
        counter: UInt64,
        payload: Data,
        flags: UInt8 = 0
    ) -> Data {
        ObstacleBridgeSecureLinkFrameCodec.encode(
            type: UInt8(slType & 0xFF), sessionID: sessionID, counter: counter, payload: payload, flags: flags
        )
    }

    static func parseFrame(_ payload: Data) -> ParsedFrame? {
        guard let frame = try? ObstacleBridgeSecureLinkFrameCodec.decode(payload) else { return nil }
        return ParsedFrame(
            slType: Int(frame.type), sessionID: frame.sessionID,
            counter: frame.counter, payload: frame.payload
        )
    }

    static func nonce(counter: UInt64) -> Data {
        var nonce = Data([0, 0, 0, 0])
        nonce.appendUInt64(counter)
        return nonce
    }

    static func buildJSONPayload(_ object: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw ObstacleBridgeSecureLinkPskCodecError.invalidJSON
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func parseJSONPayload(_ payload: Data) -> [String: Any]? {
        guard let parsed = try? JSONSerialization.jsonObject(with: payload, options: []) else {
            return nil
        }
        return parsed as? [String: Any]
    }

}
