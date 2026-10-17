import Foundation

/// Python-compatible foreground launch selection for the Linux-native CLI.
/// The parsed options contain no runtime state; the executable owns loading
/// the configuration and starting the admitted resource owners.
public struct ObstacleBridgeLinuxForegroundOptions: Equatable, Sendable {
    public static let defaultConfigurationPath = "ObstacleBridge.cfg"

    public let configurationPath: String
    public let adminPort: Int
    public let holdSeconds: Int?

    public init(configurationPath: String, adminPort: Int = 0, holdSeconds: Int? = nil) {
        self.configurationPath = configurationPath
        self.adminPort = adminPort
        self.holdSeconds = holdSeconds
    }

    /// Accepts the primary `--config` form without an artificial `--run`
    /// verb, as well as the prior explicit runtime form for compatibility.
    public static func parse(_ values: [String]) -> ObstacleBridgeLinuxForegroundOptions? {
        if values.isEmpty { return .init(configurationPath: defaultConfigurationPath) }

        let configurationPath: String
        var index: Int
        if values.count >= 2, values[0] == "--config" {
            configurationPath = values[1]
            index = 2
        } else if values.count >= 3, values[0] == "--runtime-config", values[2] == "--run" {
            configurationPath = values[1]
            index = 3
        } else {
            return nil
        }
        guard !configurationPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }

        var adminPort = 0
        var holdSeconds: Int?
        while index < values.count {
            guard index + 1 < values.count else { return nil }
            switch values[index] {
            case "--admin-port":
                guard let parsed = Int(values[index + 1]), (0...65535).contains(parsed) else { return nil }
                adminPort = parsed
            case "--hold-sec":
                guard let parsed = Int(values[index + 1]), parsed >= 0 else { return nil }
                holdSeconds = parsed
            default:
                return nil
            }
            index += 2
        }
        return .init(configurationPath: configurationPath, adminPort: adminPort, holdSeconds: holdSeconds)
    }
}
