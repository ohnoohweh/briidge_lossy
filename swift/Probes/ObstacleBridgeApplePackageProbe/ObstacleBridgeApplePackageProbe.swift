import Foundation
import ObstacleBridgeCore

/// Compiled by the macOS host lane and available to an unsigned iOS package
/// consumer. It proves that Apple callers import the canonical core module
/// rather than compiling a private copy of its protocol types.
public enum ObstacleBridgeApplePackageProbe {
    public static func endpoint(host: String, port: UInt16) -> ObstacleBridgeEndpoint {
        ObstacleBridgeEndpoint(host: host, port: port)
    }
}
