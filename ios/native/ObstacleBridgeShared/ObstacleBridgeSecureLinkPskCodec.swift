import CryptoKit
import Foundation

enum ObstacleBridgeSecureLinkPskCodecError: Error {
    case invalidJSON
}

struct ObstacleBridgeSecureLinkPskCodec {
    private static let transcriptPrefix = Data("obstaclebridge-securelink-psk-v1|".utf8)
    private static let serverProofPrefix = Data("obstaclebridge-securelink-server-proof-v1|".utf8)
    private static let clientRekeyCommitProofPrefix = Data("obstaclebridge-securelink-client-rekey-commit-v1|".utf8)

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
        let transcript = transcriptPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        let salt = Data(SHA256.hash(data: psk))
        let material = hkdfSHA256(
            salt: salt,
            info: transcript,
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
        let message = serverProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: psk)
        )
        return Data(authenticationCode)
    }

    static func clientRekeyCommitProof(
        psk: Data,
        sessionID: UInt64,
        clientNonce: Data,
        serverNonce: Data
    ) -> Data {
        let message = clientRekeyCommitProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: psk)
        )
        return Data(authenticationCode)
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

    private static func hkdfSHA256(
        salt: Data,
        info: Data,
        keyMaterial: Data,
        length: Int
    ) -> Data {
        let digestLength = 32
        let normalizedSalt = salt.isEmpty ? Data(repeating: 0, count: digestLength) : salt
        let prk = hmacSHA256(key: normalizedSalt, message: keyMaterial)
        var okm = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while okm.count < length {
            var block = Data()
            block.append(previous)
            block.append(info)
            block.append(counter)
            previous = hmacSHA256(key: prk, message: block)
            okm.append(previous)
            counter = counter &+ 1
        }
        return okm.prefix(length)
    }

    private static func hmacSHA256(key: Data, message: Data) -> Data {
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: key)
        )
        return Data(authenticationCode)
    }

}

private extension UInt64 {
    var bigEndianData: Data {
        var data = Data()
        data.appendUInt64(self)
        return data
    }
}
