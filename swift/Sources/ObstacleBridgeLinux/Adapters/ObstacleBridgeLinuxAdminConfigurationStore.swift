import Foundation
import ObstacleBridgeCore

/// Linux owns persistence, while Core owns update shape/type validation.
public final class ObstacleBridgeLinuxAdminConfigurationStore: @unchecked Sendable {
    private let lock = NSLock()
    private let path: String?
    private var configuration: [String: Any]

    public init(configuration: [String: Any], path: String? = nil) {
        self.configuration = configuration; self.path = path
    }

    public func snapshot() -> [String: Any] { lock.lock(); defer { lock.unlock() }; return configuration }

    /// The persisted snapshot is intentionally encrypted. Callers that need
    /// effective runtime values (for example invite construction) receive a
    /// short-lived decrypted copy and must not persist that copy directly.
    public func runtimeSnapshot() throws -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        return try ObstacleBridgeLinuxConfigSecretCodec.decryptPayload(configuration)
    }

    /// The Admin Web client consumes Core's grouped schema together with a
    /// flattened configuration snapshot.  Keep the schema owned by Core so
    /// the Linux persistence adapter cannot drift from the Python UI contract.
    public static func schemaSnapshot() -> [String: Any] {
        ObstacleBridgeRuntimeConfigPort.schemaSnapshot()
    }

    public func apply(updates: [String: Any]) throws -> (configuration: [String: Any], normalizedKeys: [String]) {
        lock.lock(); defer { lock.unlock() }
        let runtimeConfiguration = try ObstacleBridgeLinuxConfigSecretCodec.decryptPayload(configuration)
        let result = try ObstacleBridgeAdminConfigUpdatePort.validatedNextConfiguration(
            currentRawConfig: configuration,
            currentRuntimeConfig: runtimeConfiguration,
            updates: updates,
            schema: Self.schema(),
            sections: Self.sections()
        )
        let persisted = try ObstacleBridgeLinuxConfigSecretCodec.encryptPayload(result.configuration)
        if let path {
            let data = try JSONSerialization.data(withJSONObject: persisted, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
        configuration = persisted
        return (persisted, result.normalizedKeys)
    }

    private static func sections() -> [String: String] {
        ObstacleBridgeRuntimeConfigPort.schemaSnapshot().reduce(into: [:]) { result, entry in
            for row in entry.value as? [[String: Any]] ?? [] {
                if let key = row["key"] as? String { result[key] = entry.key }
            }
        }
    }

    private static func schema() -> [String: [String: Any]] {
        ObstacleBridgeRuntimeConfigPort.schemaSnapshot().values.reduce(into: [:]) { result, value in
            for row in value as? [[String: Any]] ?? [] {
                if let key = row["key"] as? String { result[key] = row }
            }
        }
    }
}
