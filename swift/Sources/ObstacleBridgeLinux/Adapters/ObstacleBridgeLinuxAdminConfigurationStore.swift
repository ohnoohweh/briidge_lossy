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

    public func apply(updates: [String: Any]) throws -> (configuration: [String: Any], normalizedKeys: [String]) {
        lock.lock(); defer { lock.unlock() }
        let result = try ObstacleBridgeAdminConfigUpdatePort.validatedNextConfiguration(
            currentRawConfig: configuration,
            currentRuntimeConfig: configuration,
            updates: updates,
            schema: Self.schema(),
            sections: Self.sections()
        )
        if let path {
            let data = try JSONSerialization.data(withJSONObject: result.configuration, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
        configuration = result.configuration
        return result
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
