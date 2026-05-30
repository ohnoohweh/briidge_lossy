import CryptoKit
import Foundation

enum ObstacleBridgeSecureLinkPskCodecError: Error {
    case invalidJSON
}

struct ObstacleBridgeSecureLinkPskCodec {
    static let version = 1
    static let headerSize = 20
    private static let transcriptPrefix = Data("obstaclebridge-securelink-psk-v1|".utf8)

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
        var header = Data()
        header.appendUInt8(UInt8(version))
        header.appendUInt8(UInt8(slType & 0xFF))
        header.appendUInt8(flags)
        header.appendUInt8(0)
        header.appendUInt64(sessionID)
        header.appendUInt64(counter)
        return header
    }

    static func buildFrame(
        slType: Int,
        sessionID: UInt64,
        counter: UInt64,
        payload: Data,
        flags: UInt8 = 0
    ) -> Data {
        return headerBytes(slType: slType, sessionID: sessionID, counter: counter, flags: flags) + payload
    }

    static func parseFrame(_ payload: Data) -> ParsedFrame? {
        guard payload.count >= headerSize else {
            return nil
        }
        var offset = 0
        guard
            let frameVersion = readUInt8(from: payload, offset: &offset),
            let slType = readUInt8(from: payload, offset: &offset),
            readUInt8(from: payload, offset: &offset) != nil,
            readUInt8(from: payload, offset: &offset) != nil,
            let sessionID = readUInt64(from: payload, offset: &offset),
            let counter = readUInt64(from: payload, offset: &offset),
            Int(frameVersion) == version
        else {
            return nil
        }
        return ParsedFrame(
            slType: Int(slType),
            sessionID: sessionID,
            counter: counter,
            payload: payload.dropFirst(headerSize)
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

    private static func readUInt8(from data: Data, offset: inout Int) -> UInt8? {
        guard offset + 1 <= data.count else {
            return nil
        }
        let value = data[offset]
        offset += 1
        return value
    }

    private static func readUInt64(from data: Data, offset: inout Int) -> UInt64? {
        guard offset + 8 <= data.count else {
            return nil
        }
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value << 8) | UInt64(data[offset + index])
        }
        offset += 8
        return value
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        var data = Data()
        data.appendUInt64(self)
        return data
    }
}