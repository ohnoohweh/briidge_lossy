import Foundation

/// Canonical SecureLink v1 PSK transcript byte construction. Crypto backends
/// consume these bytes; protocol owners do not reconstruct prefixes locally.
public enum ObstacleBridgeSecureLinkPSKTranscript {
    // Build the small transcript prefixes for each handshake rather than
    // retaining heap-backed Data in process-lifetime lazy statics. This keeps
    // the cryptographic transcript ownership scoped to its caller and lets
    // Linux LeakSanitizer verify a clean product exit.
    private static var keyDerivationPrefix: Data { Data("obstaclebridge-securelink-psk-v1|".utf8) }
    private static var serverProofPrefix: Data { Data("obstaclebridge-securelink-server-proof-v1|".utf8) }
    private static var clientRekeyCommitProofPrefix: Data { Data("obstaclebridge-securelink-client-rekey-commit-v1|".utf8) }

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
