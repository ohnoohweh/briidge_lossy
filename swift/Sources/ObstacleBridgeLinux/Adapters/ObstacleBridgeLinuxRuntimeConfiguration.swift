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
    /// Bounded ChannelMux application payload used by service owners. The
    /// default preserves wire compatibility; smaller values exercise Core's
    /// typed control and UDP-fragment effects without changing socket policy.
    public let channelMuxMaximumApplicationPayload: Int
    public let ownServices: [ObstacleBridgeLinuxServiceSpec]
    public let remoteServices: [ObstacleBridgeLinuxServiceSpec]
    /// Explicit helper-control endpoint. This is admitted independently from
    /// TUN startup: selecting it never opens `/dev/net/tun` in this runtime.
    public let tunHelperSocketPath: String?

    public init(transport: ObstacleBridgeLinuxTransport, host: String, port: Int, listenerMode: Bool = false, webSocketPath: String = "/", webSocketPayloadMode: String = "binary", webSocketTLS: Bool = false, webSocketTrustRootsPath: String? = nil, webSocketCertificatePath: String? = nil, webSocketPrivateKeyPath: String? = nil, webSocketProxy: ObstacleBridgeLinuxHTTPProxy = .init(), quicALPN: String = "hq-29", quicInsecure: Bool = false, quicTrustRootsPath: String? = nil, secureLinkPSK: Data? = nil, receiveIdleTimeoutMilliseconds: Int = 5_000, compressionPolicy: ObstacleBridgeMuxCompressionPolicy = .init(enabled: false), channelMuxMaximumApplicationPayload: Int = 65_535, ownServices: [ObstacleBridgeLinuxServiceSpec] = [], remoteServices: [ObstacleBridgeLinuxServiceSpec] = [], tunHelperSocketPath: String? = nil) {
        self.transport = transport
        self.listenerMode = listenerMode
        self.peerCandidates = ObstacleBridgePeerAddressPort.configuredPeerCandidates(host)
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
        self.channelMuxMaximumApplicationPayload = max(32, min(channelMuxMaximumApplicationPayload, 65_535))
        self.ownServices = ownServices
        self.remoteServices = remoteServices
        self.tunHelperSocketPath = tunHelperSocketPath?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false ? tunHelperSocketPath : nil
    }

    public func makeTunHelperAdapter(timeoutMilliseconds: Int = 2_000) throws -> ObstacleBridgeLinuxTunHelperAdapter? {
        guard let tunHelperSocketPath else { return nil }
        return try ObstacleBridgeLinuxTunHelperAdapter(socketPath: tunHelperSocketPath, timeoutMilliseconds: timeoutMilliseconds)
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

    /// Raw configuration is retained only for Core-owned, redacted Admin
    /// projections. Runtime admission still uses `parse(data:)` above.
    public static func rawConfiguration(path: String) throws -> [String: Any] {
        do {
            guard let root = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any] else {
                throw ObstacleBridgeLinuxRuntimeConfigurationError.malformedJSON
            }
            return root
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
        // Core owns grouped-versus-flat precedence and schema scalar coercion.
        // Linux contributes only JSON input and Linux-specific capability gates.
        let flat = ObstacleBridgeRuntimeConfigPort.flatten(root)
        let runner = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("runner", from: root)
        let tunExecution = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("tun_execution", from: root)
        let tunMode = (string(tunExecution["tun_execution_mode"]) ?? "inline").lowercased()
        guard tunMode == "inline" || tunMode == "helper" else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("tun_execution.tun_execution_mode must be inline or helper")
        }
        let tunHelperSocket = tunMode == "helper" ? string(tunExecution["tun_helper_socket"]) : nil
        let tunRouting = ObstacleBridgeRuntimeConfigPort.tunnelRouting(from: root)
        if let route = tunRouting.invalidRoute {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidValue("runtime config has invalid TUN route \(route)")
        }
        if tunRouting.enabledOnStartup {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift TUN is unavailable until LSW-005 delivers the /dev/net/tun adapter; no Python fallback is used")
        }
        let proxy = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("proxy_provider", from: root)
        if !proxy.isEmpty, boolean(proxy["proxy_provider_enabled"] ?? proxy["enabled"]) == true {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unavailableTransport("Linux Swift local proxy_provider mode is unavailable; outbound WebSocket proxy configuration remains supported")
        }
        let listenerMode = boolean(runner["listener_mode"]) == true
        guard let transportText = string(runner["overlay_transport"] ?? flat["overlay_transport"]),
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
        let session = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload(sessionName, from: root)
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
        let secure = ObstacleBridgeRuntimeConfigPort.groupedSectionPayload("secure_link", from: root)
        let secureMode = (string(secure["secure_link_mode"]) ?? "off").lowercased()
        let psk: Data?
        switch secureMode {
        case "off": psk = nil
        case "psk":
            guard let value = string(secure["secure_link_psk"]), !value.isEmpty else { throw ObstacleBridgeLinuxRuntimeConfigurationError.missingPSK }
            psk = Data(value.utf8)
        default: throw ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedSecureLinkMode("Linux secure_link_mode=\(secureMode) is unavailable")
        }
        let compressionAlgorithm = (string(flat["compress_layer_algo"]) ?? "zlib").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard compressionAlgorithm == "zlib" else {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.unsupportedCompressionAlgorithm("Linux compress_layer_algo=\(compressionAlgorithm) is unavailable")
        }
        let compressionLevel = min(9, max(0, integer(flat["compress_layer_level"]) ?? 3))
        let compressionMinimumBytes = max(0, integer(flat["compress_layer_min_bytes"]) ?? 64)
        let compressionPolicy = ObstacleBridgeMuxCompressionPolicy(
            enabled: boolean(flat["compress_layer"]) ?? false,
            level: compressionLevel,
            minimumBodyBytes: compressionMinimumBytes,
            allowedMessageTypes: compressionMessageTypes(string(flat["compress_layer_types"]))
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
        let receiveIdleTimeoutMilliseconds = max(1, integer(flat["secure_link_receive_idle_timeout_ms"]) ?? 5_000)
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
            remoteServices: try serviceSpecs(root, key: "remote_servers"),
            tunHelperSocketPath: tunHelperSocket
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
        let catalog = ObstacleBridgeRuntimeConfigPort.serviceCatalog(root, key: key)
        if let index = catalog.invalidIndex {
            throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has invalid \(key) service at index \(index)")
        }
        return try catalog.records.map { nativeSpec in
            guard nativeSpec.listenProtocol == nativeSpec.targetProtocol else {
                throw ObstacleBridgeLinuxRuntimeConfigurationError.invalidService("runtime config has unsupported service protocol or identifier")
            }
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
