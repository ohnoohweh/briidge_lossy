import Foundation
import ObstacleBridgePortable

public enum ObstacleBridgeLinuxRuntimeConfigurationError: Error, Equatable, LocalizedError {
    case unreadableFile(String)
    case malformedJSON
    case missingValue(String)
    case invalidValue(String)
    case unavailableTransport(String)
    case unsupportedSecureLinkMode(String)
    case missingPSK
    case unsupportedWebSocketTLS
    case invalidService(String)

    public var errorDescription: String? {
        switch self {
        case .unreadableFile(let message), .missingValue(let message), .invalidValue(let message), .unavailableTransport(let message), .unsupportedSecureLinkMode(let message), .invalidService(let message): return message
        case .malformedJSON: return "runtime config must be a JSON object"
        case .missingPSK: return "secure_link_mode=psk requires a non-empty secure_link_psk"
        case .unsupportedWebSocketTLS: return "Linux wss is unavailable until a TLS backend is qualified"
        }
    }
}

public struct ObstacleBridgeLinuxServiceSpec: Equatable, Sendable {
    public let serviceID: UInt16
    public let name: String?
    public let listenProtocol: ObstacleBridgeChannelMuxProtocol
    public let listenHost: String
    public let listenPort: Int
    public let targetProtocol: ObstacleBridgeChannelMuxProtocol
    public let targetHost: String
    public let targetPort: Int
}

/// The Linux admission view of the existing sectioned runtime configuration.
/// It intentionally accepts only fields that the current Linux Swift runtime
/// owns; all other sections remain preserved by the source configuration and
/// are not silently interpreted by this early transport slice.
public struct ObstacleBridgeLinuxRuntimeConfiguration: Equatable, Sendable {
    public let transport: ObstacleBridgeLinuxTransport
    public let listenerMode: Bool
    public let host: String
    public let peerCandidates: [String]
    public let port: Int
    public let webSocketPath: String
    public let secureLinkPSK: Data?
    public let ownServices: [ObstacleBridgeLinuxServiceSpec]
    public let remoteServices: [ObstacleBridgeLinuxServiceSpec]

    public init(transport: ObstacleBridgeLinuxTransport, host: String, port: Int, listenerMode: Bool = false, webSocketPath: String = "/", secureLinkPSK: Data? = nil, ownServices: [ObstacleBridgeLinuxServiceSpec] = [], remoteServices: [ObstacleBridgeLinuxServiceSpec] = []) {
        self.transport = transport
        self.listenerMode = listenerMode
        self.peerCandidates = host.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        self.host = self.peerCandidates.first ?? host
        self.port = port
        self.webSocketPath = webSocketPath
        self.secureLinkPSK = secureLinkPSK
        self.ownServices = ownServices
        self.remoteServices = remoteServices
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
        if let tun = root["TUN_routing"] as? [String: Any],
           boolean(tun["enabled_on_startup"] ?? tun["enabled"]) == true {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift TUN is unavailable until LSW-005 delivers the /dev/net/tun adapter; no Python fallback is used")
        }
        if let proxy = root["proxy_provider"] as? [String: Any], boolean(proxy["enabled"]) == true {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift proxy mode is unavailable; run a supported Python deployment explicitly instead of expecting fallback")
        }
        if root["service_manager"] != nil || root["linux_package"] != nil || boolean(runner["service_mode"]) == true {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift package/service-manager mode is unavailable; run the foreground executable under an operator-owned supervisor")
        }
        let listenerMode = boolean(runner["listener_mode"]) == true
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
        if listenerMode && transport == .myudp {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux listener_mode currently admits TCP and cleartext WebSocket only; myudp listener ownership is not yet qualified")
        }
        let host = string(session[peerKey]) ?? (listenerMode ? "listener" : "")
        guard listenerMode || !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires \(sessionName).\(peerKey)")
        }
        let ownPortKey = transport == .ws ? "ws_own_port" : "tcp_own_port"
        let configuredPort = listenerMode ? integer(session[ownPortKey] ?? session[portKey]) : integer(session[portKey])
        guard let port = configuredPort, (1...65535).contains(port) else {
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
        return .init(
            transport: transport,
            host: candidates.joined(separator: ","),
            port: port,
            listenerMode: listenerMode,
            webSocketPath: string(session["ws_path"]) ?? "/",
            secureLinkPSK: psk,
            ownServices: try serviceSpecs(root, key: "own_servers"),
            remoteServices: try serviceSpecs(root, key: "remote_servers")
        )
    }

    private static func string(_ value: Any?) -> String? { value as? String }
    private static func integer(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func boolean(_ value: Any?) -> Bool? { value as? Bool ?? (value as? NSNumber)?.boolValue }

    private static func serviceSpecs(_ root: [String: Any], key: String) throws -> [ObstacleBridgeLinuxServiceSpec] {
        let mux = root["channel_mux"] as? [String: Any]
        guard let values = (mux?[key] ?? root[key]) as? [Any] else { return [] }
        return try values.enumerated().map { index, value in
            guard let row = value as? [String: Any],
                  let listen = row["listen"] as? [String: Any],
                  let target = row["target"] as? [String: Any],
                  let listenName = string(listen["protocol"]),
                  let targetName = string(target["protocol"]),
                  let listenProtocol = channelProtocol(listenName),
                  let targetProtocol = channelProtocol(targetName),
                  let listenHost = string(listen["bind"]),
                  let listenPort = integer(listen["port"]),
                  let targetHost = string(target["host"]),
                  let targetPort = integer(target["port"]),
                  (1...65535).contains(listenPort),
                  (1...65535).contains(targetPort),
                  listenProtocol == targetProtocol
            else { throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has invalid \(key) service at index \(index)") }
            return .init(serviceID: UInt16(index + 1), name: string(row["name"]), listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort)
        }
    }

    private static func channelProtocol(_ value: String) -> ObstacleBridgeChannelMuxProtocol? {
        switch value.lowercased() {
        case "udp": return .udp
        case "tcp": return .tcp
        default: return nil
        }
    }
}
