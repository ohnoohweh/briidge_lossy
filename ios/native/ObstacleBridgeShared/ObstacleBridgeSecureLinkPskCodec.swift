import CryptoKit
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

    static func deriveKeys(
        psk: Data,
        sessionID: UInt64,
        clientNonce: Data,
        serverNonce: Data
    ) -> (Data, Data) {
        let material = hkdfSHA256(
            salt: Data(SHA256.hash(data: psk)),
            info: ObstacleBridgeSecureLinkPSKTranscript.keyDerivationInfo(
                sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
            ),
            keyMaterial: psk + clientNonce + serverNonce,
            length: 64
        )
        return (material.prefix(32), material.suffix(32))
    }

    static func serverProof(
        psk: Data,
        sessionID: UInt64,
        clientNonce: Data,
        serverNonce: Data
    ) -> Data {
        hmacSHA256(
            key: psk,
            message: ObstacleBridgeSecureLinkPSKTranscript.serverProofMessage(
                sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
            )
        )
    }

    static func clientRekeyCommitProof(
        psk: Data,
        sessionID: UInt64,
        clientNonce: Data,
        serverNonce: Data
    ) -> Data {
        hmacSHA256(
            key: psk,
            message: ObstacleBridgeSecureLinkPSKTranscript.clientRekeyCommitProofMessage(
                sessionID: sessionID, clientNonce: clientNonce, serverNonce: serverNonce
            )
        )
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

    private static func hkdfSHA256(salt: Data, info: Data, keyMaterial: Data, length: Int) -> Data {
        let normalizedSalt = salt.isEmpty ? Data(repeating: 0, count: 32) : salt
        let prk = hmacSHA256(key: normalizedSalt, message: keyMaterial)
        var okm = Data()
        var previous = Data()
        var counter: UInt8 = 1
        while okm.count < length {
            previous = hmacSHA256(key: prk, message: previous + info + Data([counter]))
            okm.append(previous)
            counter &+= 1
        }
        return Data(okm.prefix(length))
    }

    private static func hmacSHA256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

}
