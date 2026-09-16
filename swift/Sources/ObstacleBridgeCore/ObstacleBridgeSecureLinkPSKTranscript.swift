import Foundation

/// Canonical SecureLink v1 PSK transcript byte construction. Crypto backends
/// consume these bytes; protocol owners do not reconstruct prefixes locally.
public enum ObstacleBridgeSecureLinkPSKTranscript {
    private static let keyDerivationPrefix = Data("obstaclebridge-securelink-psk-v1|".utf8)
    private static let serverProofPrefix = Data("obstaclebridge-securelink-server-proof-v1|".utf8)
    private static let clientRekeyCommitProofPrefix = Data("obstaclebridge-securelink-client-rekey-commit-v1|".utf8)

    public static func keyDerivationInfo(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        keyDerivationPrefix + sessionID.bigEndianData + clientNonce + serverNonce
    }

    public static func serverProofMessage(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        serverProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
    }

    public static func clientRekeyCommitProofMessage(sessionID: UInt64, clientNonce: Data, serverNonce: Data) -> Data {
        clientRekeyCommitProofPrefix + sessionID.bigEndianData + clientNonce + serverNonce
    }
}

private extension UInt64 {
    var bigEndianData: Data {
        var value = bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}
