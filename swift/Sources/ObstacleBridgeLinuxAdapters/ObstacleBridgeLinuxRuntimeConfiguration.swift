import Foundation

public enum ObstacleBridgeLinuxRuntimeConfigurationError: Error, Equatable, LocalizedError {
    case unreadableFile(String)
    case malformedJSON
    case missingValue(String)
    case invalidValue(String)
    case unavailableTransport(String)
    case unsupportedSecureLinkMode(String)
    case missingPSK
    case unsupportedWebSocketTLS

    public var errorDescription: String? {
        switch self {
        case .unreadableFile(let message), .missingValue(let message), .invalidValue(let message), .unavailableTransport(let message), .unsupportedSecureLinkMode(let message): return message
        case .malformedJSON: return "runtime config must be a JSON object"
        case .missingPSK: return "secure_link_mode=psk requires a non-empty secure_link_psk"
        case .unsupportedWebSocketTLS: return "Linux wss is unavailable until a TLS backend is qualified"
        }
    }
}

/// The Linux admission view of the existing sectioned runtime configuration.
/// It intentionally accepts only fields that the current Linux Swift runtime
/// owns; all other sections remain preserved by the source configuration and
/// are not silently interpreted by this early transport slice.
public struct ObstacleBridgeLinuxRuntimeConfiguration: Equatable, Sendable {
    public let transport: ObstacleBridgeLinuxTransport
    public let host: String
    public let peerCandidates: [String]
    public let port: Int
    public let webSocketPath: String
    public let secureLinkPSK: Data?

    public init(transport: ObstacleBridgeLinuxTransport, host: String, port: Int, webSocketPath: String = "/", secureLinkPSK: Data? = nil) {
        self.transport = transport
        self.peerCandidates = host.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        self.host = self.peerCandidates.first ?? host
        self.port = port
        self.webSocketPath = webSocketPath
        self.secureLinkPSK = secureLinkPSK
    }

    public static func load(path: String) throws -> ObstacleBridgeLinuxRuntimeConfiguration {
        do {
            return try parse(data: Data(contentsOf: URL(fileURLWithPath: path)))
        } catch let error as ObstacleBridgeLinuxRuntimeConfigurationError {
            throw error
        } catch {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unreadableFile("cannot read runtime config: \(error.localizedDescription)")
        }
    }

    public static func parse(data: Data) throws -> ObstacleBridgeLinuxRuntimeConfiguration {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.malformedJSON
        }
        let runner = root["runner"] as? [String: Any] ?? [:]
        guard let transportText = string(runner["overlay_transport"] ?? root["overlay_transport"]),
              let transport = ObstacleBridgeLinuxTransport(rawValue: transportText.lowercased()) else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires runner.overlay_transport")
        }
        guard transport.isAvailable else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(transport.unavailableReason ?? "Linux transport unavailable")
        }
        let sessionName: String
        let peerKey: String
        let portKey: String
        switch transport {
        case .tcp: (sessionName, peerKey, portKey) = ("tcp_session", "tcp_peer", "tcp_peer_port")
        case .ws: (sessionName, peerKey, portKey) = ("ws_session", "ws_peer", "ws_peer_port")
        case .myudp: (sessionName, peerKey, portKey) = ("udp_session", "udp_peer", "udp_peer_port")
        case .quic: throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(transport.unavailableReason ?? "Linux transport unavailable")
        }
        let session = root[sessionName] as? [String: Any] ?? [:]
        guard let host = string(session[peerKey]), !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires \(sessionName).\(peerKey)")
        }
        guard let port = integer(session[portKey]), (1...65535).contains(port) else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config requires \(sessionName).\(portKey) between 1 and 65535")
        }
        if transport == .ws, boolean(session["ws_tls"]) == true {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedWebSocketTLS
        }
        let secure = root["secure_link"] as? [String: Any] ?? [:]
        let secureMode = (string(secure["secure_link_mode"]) ?? "off").lowercased()
        let psk: Data?
        switch secureMode {
        case "off": psk = nil
        case "psk":
            guard let value = string(secure["secure_link_psk"]), !value.isEmpty else { throw ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK }
            psk = Data(value.utf8)
        default: throw ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedSecureLinkMode("Linux secure_link_mode=\(secureMode) is unavailable")
        }
        let candidates = host.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !candidates.isEmpty else { throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config requires at least one non-empty \(sessionName).\(peerKey)") }
        return .init(transport: transport, host: candidates.joined(separator: ","), port: port, webSocketPath: string(session["ws_path"]) ?? "/", secureLinkPSK: psk)
    }

    private static func string(_ value: Any?) -> String? { value as? String }
    private static func integer(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func boolean(_ value: Any?) -> Bool? { value as? Bool ?? (value as? NSNumber)?.boolValue }
}
