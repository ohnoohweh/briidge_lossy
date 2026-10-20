import Foundation
import ObstacleBridgeCore

/// Linux-native interpretation of the shared `admin_web` section.  A command
/// line port is an explicit operator override; otherwise the configuration is
/// authoritative, matching `python -m obstacle_bridge`.
public struct ObstacleBridgeLinuxAdminWebConfiguration: Equatable, Sendable {
    public let enabled: Bool
    public let bindHost: String
    public let port: Int
    public let staticDirectory: String

    public init(rawConfiguration: [String: Any], portOverride: Int = 0) {
        let section = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("admin_web", from: rawConfiguration)
        enabled = Self.bool(section["admin_web"]) ?? true
        bindHost = (section["admin_web_bind"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false ? (section["admin_web_bind"] as! String).trimmingCharacters(in: .whitespacesAndNewlines) : "127.0.0.1"
        let configuredPort = Self.integer(section["admin_web_port"]) ?? 18_080
        port = portOverride > 0 ? portOverride : configuredPort
        staticDirectory = (section["admin_web_dir"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false ? (section["admin_web_dir"] as! String).trimmingCharacters(in: .whitespacesAndNewlines) : "./admin_web"
    }

    private static func integer(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func bool(_ value: Any?) -> Bool? { value as? Bool ?? (value as? NSNumber)?.boolValue }
}
