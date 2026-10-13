import Foundation
import ObstacleBridgeCore

public enum ObstacleBridgeLinuxRuntimeConfigurationError: Error, Equatable, LocalizedError {
    case unreadableFile(String)
    case malformedJSON
    case missingValue(String)
    case invalidValue(String)
    case unavailableTransport(String)
    case unsupportedSecureLinkMode(String)
    case unsupportedCompressionAlgorithm(String)
    case missingPSK
    case invalidService(String)

    public var errorDescription: String? {
        switch self {
        case .unreadableFile(let message), .missingValue(let message), .invalidValue(let message), .unavailableTransport(let message), .unsupportedSecureLinkMode(let message), .unsupportedCompressionAlgorithm(let message), .invalidService(let message): return message
        case .malformedJSON: return "runtime config must be a JSON object"
        case .missingPSK: return "secure_link_mode=psk requires a non-empty secure_link_psk"
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

    /// Internal representation used after a Core-owned catalog decoder or a
    /// bound Linux socket has already established the service values. Runtime
    /// configuration admission continues through `init(nativeSpec:)`, which
    /// invokes the portable `ObstacleBridgeNativeServiceSpec` validator.
    init(serviceID: UInt16, name: String?, listenProtocol: ObstacleBridgeChannelMuxProtocol, listenHost: String, listenPort: Int, targetProtocol: ObstacleBridgeChannelMuxProtocol, targetHost: String, targetPort: Int) {
        self.serviceID = serviceID
        self.name = name
        self.listenProtocol = listenProtocol
        self.listenHost = listenHost
        self.listenPort = listenPort
        self.targetProtocol = targetProtocol
        self.targetHost = targetHost
        self.targetPort = targetPort
    }

    init(nativeSpec: ObstacleBridgeNativeServiceSpec) throws {
        guard let serviceID = UInt16(exactly: nativeSpec.svcID),
              let listenProtocol = ObstacleBridgeLinuxRuntimeConfiguration.channelProtocol(nativeSpec.listenProtocol),
              let targetProtocol = ObstacleBridgeLinuxRuntimeConfiguration.channelProtocol(nativeSpec.targetProtocol)
        else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has unsupported service protocol or identifier")
        }
        self.serviceID = serviceID
        self.name = nativeSpec.name
        self.listenProtocol = listenProtocol
        self.listenHost = nativeSpec.listenBind
        self.listenPort = nativeSpec.listenPort
        self.targetProtocol = targetProtocol
        self.targetHost = nativeSpec.targetHost
        self.targetPort = nativeSpec.targetPort
    }
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
    public let webSocketPayloadMode: String
    public let webSocketTLS: Bool
    /// Optional PEM roots for a verified outbound WSS client.  A missing value
    /// selects the backend's system trust store rather than disabling checks.
    public let webSocketTrustRootsPath: String?
    /// PEM certificate and private key used only by a WSS listener.
    public let webSocketCertificatePath: String?
    public let webSocketPrivateKeyPath: String?
    public let webSocketProxy: ObstacleBridgeLinuxHTTPProxy
    public let quicALPN: String
    public let quicInsecure: Bool
    /// Optional PEM trust-root bundle for an outbound QUIC client. `nil`
    /// selects the platform trust store unless the explicit test bypass is set.
    public let quicTrustRootsPath: String?
    public let secureLinkPSK: Data?
    public let receiveIdleTimeoutMilliseconds: Int
    /// Outbound compression policy. Inbound compressed frames remain accepted
    /// so a listener can safely interoperate with a peer-selected policy.
    public let compressionPolicy: ObstacleBridgeMuxCompressionPolicy
    public let ownServices: [ObstacleBridgeLinuxServiceSpec]
    public let remoteServices: [ObstacleBridgeLinuxServiceSpec]

    public init(transport: ObstacleBridgeLinuxTransport, host: String, port: Int, listenerMode: Bool = false, webSocketPath: String = "/", webSocketPayloadMode: String = "binary", webSocketTLS: Bool = false, webSocketTrustRootsPath: String? = nil, webSocketCertificatePath: String? = nil, webSocketPrivateKeyPath: String? = nil, webSocketProxy: ObstacleBridgeLinuxHTTPProxy = .init(), quicALPN: String = "hq-29", quicInsecure: Bool = false, quicTrustRootsPath: String? = nil, secureLinkPSK: Data? = nil, receiveIdleTimeoutMilliseconds: Int = 5_000, compressionPolicy: ObstacleBridgeMuxCompressionPolicy = .init(enabled: false), ownServices: [ObstacleBridgeLinuxServiceSpec] = [], remoteServices: [ObstacleBridgeLinuxServiceSpec] = []) {
        self.transport = transport
        self.listenerMode = listenerMode
        self.peerCandidates = host.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        self.host = self.peerCandidates.first ?? host
        self.port = port
        self.webSocketPath = webSocketPath
        self.webSocketPayloadMode = webSocketPayloadMode
        self.webSocketTLS = webSocketTLS
        self.webSocketTrustRootsPath = webSocketTrustRootsPath
        self.webSocketCertificatePath = webSocketCertificatePath
        self.webSocketPrivateKeyPath = webSocketPrivateKeyPath
        self.webSocketProxy = webSocketProxy
        self.quicALPN = quicALPN
        self.quicInsecure = quicInsecure
        self.quicTrustRootsPath = quicTrustRootsPath
        self.secureLinkPSK = secureLinkPSK
        self.receiveIdleTimeoutMilliseconds = max(1, receiveIdleTimeoutMilliseconds)
        self.compressionPolicy = compressionPolicy
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
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift local proxy_provider mode is unavailable; outbound WebSocket proxy configuration remains supported")
        }
        let listenerMode = boolean(runner["listener_mode"]) == true
        guard let transportText = string(runner["overlay_transport"] ?? root["overlay_transport"]),
              let transport = ObstacleBridgeLinuxTransport(rawValue: transportText.lowercased()) else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires runner.overlay_transport")
        }
        guard transport.isAvailable else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport(transport.unavailableReason ?? "Linux transport unavailable")
        }
        if listenerMode, transport == .quic {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux QUIC listener mode is unavailable until LSW-005B.2 qualifies the backend's inbound-stream ownership")
        }
        let sessionName: String
        let peerKey: String
        let portKey: String
        switch transport {
        case .tcp: (sessionName, peerKey, portKey) = ("tcp_session", "tcp_peer", "tcp_peer_port")
        case .ws: (sessionName, peerKey, portKey) = ("ws_session", "ws_peer", "ws_peer_port")
        case .myudp: (sessionName, peerKey, portKey) = ("udp_session", "udp_peer", "udp_peer_port")
        case .quic: (sessionName, peerKey, portKey) = ("quic_session", "quic_peer", "quic_peer_port")
        }
        let session = root[sessionName] as? [String: Any] ?? [:]
        let host = string(session[peerKey]) ?? (listenerMode ? "listener" : "")
        guard listenerMode || !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("runtime config requires \(sessionName).\(peerKey)")
        }
        let ownPortKey: String
        switch transport {
        case .tcp: ownPortKey = "tcp_own_port"
        case .ws: ownPortKey = "ws_own_port"
        case .myudp: ownPortKey = "udp_own_port"
        case .quic: ownPortKey = "quic_own_port"
        }
        let configuredPort = listenerMode ? integer(session[ownPortKey] ?? session[portKey]) : integer(session[portKey])
        guard let port = configuredPort, (1...65535).contains(port) else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config requires \(sessionName).\(portKey) between 1 and 65535")
        }
        if transport == .ws { _ = try ObstacleBridgeWebSocketPayloadCodec.mode(string(session["ws_payload_mode"]) ?? "binary") }
        let wsTLS = boolean(session["ws_tls"]) ?? false
        let wsCertificate = string(session["ws_cert"])
        let wsPrivateKey = string(session["ws_key"])
        let wsProxyMode = ObstacleBridgeLinuxWebSocketProxyMode(rawValue: (string(session["ws_proxy_mode"]) ?? "env").lowercased())
        guard let wsProxyMode else { throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("ws_session.ws_proxy_mode must be off, env, or manual") }
        let wsProxy = ObstacleBridgeLinuxHTTPProxy(mode: wsProxyMode, host: string(session["ws_proxy_host"]) ?? "", port: integer(session["ws_proxy_port"]) ?? 8080)
        if listenerMode, transport == .ws, wsTLS,
           (wsCertificate?.isEmpty != false || wsPrivateKey?.isEmpty != false) {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.missingValue("WSS listener requires ws_session.ws_cert and ws_session.ws_key")
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
        let compressionAlgorithm = (string(root["compress_layer_algo"]) ?? "zlib").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard compressionAlgorithm == "zlib" else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedCompressionAlgorithm("Linux compress_layer_algo=\(compressionAlgorithm) is unavailable")
        }
        let compressionLevel = min(9, max(0, integer(root["compress_layer_level"]) ?? 3))
        let compressionMinimumBytes = max(0, integer(root["compress_layer_min_bytes"]) ?? 64)
        let compressionPolicy = ObstacleBridgeMuxCompressionPolicy(
            enabled: boolean(root["compress_layer"]) ?? false,
            level: compressionLevel,
            minimumBodyBytes: compressionMinimumBytes,
            allowedMessageTypes: compressionMessageTypes(string(root["compress_layer_types"]))
        )
        // Keep Linux admission on the portable layer-ordering policy. The
        // adapter owns only configuration spelling and its POSIX transports.
        do {
            _ = try ObstacleBridgeOverlayStackPlanner.planTransport(
                transport: transport.rawValue,
                peerHost: listenerMode ? nil : host,
                secureLinkEnabled: secureMode != "off",
                secureLinkModeRaw: secureMode,
                secureLinkPSK: psk.map { String(decoding: $0, as: UTF8.self) } ?? "",
                compressLayerEnabled: compressionPolicy.enabled,
                compressLayerAlgoRaw: compressionAlgorithm
            )
        } catch {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue(error.localizedDescription)
        }
        let receiveIdleTimeoutMilliseconds = max(1, integer(root["secure_link_receive_idle_timeout_ms"]) ?? 5_000)
        let candidates = host.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !candidates.isEmpty else { throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config requires at least one non-empty \(sessionName).\(peerKey)") }
        return .init(
            transport: transport,
            host: candidates.joined(separator: ","),
            port: port,
            listenerMode: listenerMode,
            webSocketPath: string(session["ws_path"]) ?? "/",
            webSocketPayloadMode: string(session["ws_payload_mode"]) ?? "binary",
            webSocketTLS: wsTLS,
            webSocketTrustRootsPath: string(session["ws_ca_cert"]),
            webSocketCertificatePath: wsCertificate,
            webSocketPrivateKeyPath: wsPrivateKey,
            webSocketProxy: wsProxy,
            quicALPN: string(session["quic_alpn"]) ?? "hq-29",
            quicInsecure: boolean(session["quic_insecure"]) ?? false,
            quicTrustRootsPath: string(session["quic_ca_cert"]),
            secureLinkPSK: psk,
            receiveIdleTimeoutMilliseconds: receiveIdleTimeoutMilliseconds,
            compressionPolicy: compressionPolicy,
            ownServices: try serviceSpecs(root, key: "own_servers"),
            remoteServices: try serviceSpecs(root, key: "remote_servers")
        )
    }

    private static func string(_ value: Any?) -> String? { value as? String }
    private static func integer(_ value: Any?) -> Int? { value as? Int ?? (value as? NSNumber)?.intValue }
    private static func boolean(_ value: Any?) -> Bool? { value as? Bool ?? (value as? NSNumber)?.boolValue }

    private static func compressionMessageTypes(_ raw: String?) -> Set<UInt8> {
        let names: [String: UInt8] = [
            "data": 0, "open": 1, "close": 2, "remote_services_set_v1": 3,
            "remote_services_set_v2": 4, "data_frag": 5,
            "remote_services_set_v2_chunk": 6, "open_chunk": 7,
        ]
        let parsed = Set((raw ?? "data,data_frag").split(separator: ",").compactMap {
            names[String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()]
        })
        return parsed.isEmpty ? [0, 5] : parsed
    }

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
            let nativeSpec = ObstacleBridgeNativeServiceSpec(
                svcID: index + 1,
                name: string(row["name"]),
                listenProtocol: listenName,
                listenBind: listenHost,
                listenPort: listenPort,
                targetProtocol: targetName,
                targetHost: targetHost,
                targetPort: targetPort
            )
            return try .init(nativeSpec: nativeSpec)
        }
    }

    fileprivate static func channelProtocol(_ value: String) -> ObstacleBridgeChannelMuxProtocol? {
        switch value.lowercased() {
        case "udp": return .udp
        case "tcp": return .tcp
        default: return nil
        }
    }
}
