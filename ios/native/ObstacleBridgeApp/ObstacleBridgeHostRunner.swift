import CryptoKit
import Darwin
import Foundation
import Network

private enum ObstacleBridgeHostRunnerError: Error, LocalizedError {
    case usage(String)
    case invalidArgument(String)
    case unreadableRuntimeConfig(String)
    case invalidRuntimeConfigRoot
    case invalidEncryptedConfigSecret(String)
    case invalidStatusPort(Int)

    var errorDescription: String? {
        switch self {
        case .usage(let detail):
            return detail
        case .invalidArgument(let detail):
            return detail
        case .unreadableRuntimeConfig(let path):
            return "Unable to read runtime config at \(path)"
        case .invalidRuntimeConfigRoot:
            return "Runtime config JSON must decode to an object"
        case .invalidEncryptedConfigSecret(let key):
            return "Invalid encrypted runtime config secret for key \(key)"
        case .invalidStatusPort(let port):
            return "Invalid status/admin port: \(port)"
        }
    }
}

private enum ObstacleBridgeConfigSecretCodec {
    private static let secretFields: Set<String> = ["admin_web_password", "secure_link_psk"]
    private static let prefix = "enc:v1:"
    private static let salt = Data("ObstacleBridge config secret v1".utf8)
    private static let info = Data("ObstacleBridge config field encryption".utf8)
    private static let aad = Data("ObstacleBridge cfg secret".utf8)

    static func decryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        guard let decoded = try transformSecrets(in: payload, transform: decryptSecret) as? [String: Any] else {
            return payload
        }
        return decoded
    }

    static func encryptPayload(_ payload: [String: Any]) throws -> [String: Any] {
        guard let encoded = try transformSecrets(in: payload, transform: encryptSecret) as? [String: Any] else {
            return payload
        }
        return encoded
    }

    private static func transformSecrets(in object: Any, transform: (String) throws -> String) throws -> Any {
        if let dict = object as? [String: Any] {
            var out: [String: Any] = [:]
            out.reserveCapacity(dict.count)
            for (key, value) in dict {
                if secretFields.contains(key), let stringValue = value as? String {
                    out[key] = stringValue.isEmpty ? "" : try transform(stringValue)
                } else {
                    out[key] = try transformSecrets(in: value, transform: transform)
                }
            }
            return out
        }
        if let list = object as? [Any] {
            return try list.map { try transformSecrets(in: $0, transform: transform) }
        }
        return object
    }

    private static func encryptSecret(_ value: String) throws -> String {
        let key = derivedKey()
        let nonceData = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealed = try ChaChaPoly.seal(Data(value.utf8), using: key, nonce: nonce, authenticating: aad)
        let combined = sealed.combined
        return prefix + urlSafeBase64Encode(combined)
    }

    private static func decryptSecret(_ value: String) throws -> String {
        guard value.hasPrefix(prefix) else {
            return value
        }
        let encoded = String(value.dropFirst(prefix.count))
        let combined = try urlSafeBase64Decode(encoded)
        let sealed = try ChaChaPoly.SealedBox(combined: combined)
        let plaintext = try ChaChaPoly.open(sealed, using: derivedKey(), authenticating: aad)
        guard let stringValue = String(data: plaintext, encoding: .utf8) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("failed to decode config secret")
        }
        return stringValue
    }

    private static func derivedKey() -> SymmetricKey {
        let seed = configSecretSeed()
        guard let derived = ObstacleBridgeNativeCrypto.hkdfSHA256Salt(
            salt as NSData,
            info: info as NSData,
            keyMaterial: seed as NSData,
            lengthValue: 32
        ) as Data? else {
            return SymmetricKey(data: seed)
        }
        return SymmetricKey(data: derived)
    }

    private static func configSecretSeed() -> Data {
        var hostname = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
        if gethostname(&hostname, hostname.count) == 0,
           let text = String(validatingUTF8: hostname),
           !text.isEmpty {
            return Data(text.utf8)
        }
        let fallback = ProcessInfo.processInfo.hostName
        if !fallback.isEmpty {
            return Data(fallback.utf8)
        }
        return Data("obstacle-bridge".utf8)
    }

    private static func urlSafeBase64Encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    private static func urlSafeBase64Decode(_ text: String) throws -> Data {
        var normalized = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: normalized) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("invalid base64 config secret")
        }
        return data
    }
}

private final class ObstacleBridgeConfigStore {
    let configPath: String
    let configRoot: String
    private(set) var groupedConfig: [String: Any]
    private(set) var runtimeConfig: [String: Any]

    init(configPath: String, groupedConfig: [String: Any], runtimeConfig: [String: Any]) {
        self.configPath = configPath
        self.groupedConfig = groupedConfig
        self.runtimeConfig = runtimeConfig

        let configURL = URL(fileURLWithPath: configPath)
        let parent = configURL.deletingLastPathComponent()
        if parent.lastPathComponent == "config" {
            self.configRoot = parent.deletingLastPathComponent().path
        } else {
            self.configRoot = parent.path
        }
    }

    func adminWebDirectory() -> String {
        if let explicit = ObstacleBridgeHostRunner.stringValue(from: runtimeConfig["admin_web_dir"]) {
            return explicit
        }
        return URL(fileURLWithPath: configRoot).appendingPathComponent("admin_web").path
    }

    func debugLogFilePath() -> String? {
        if let nested = groupedConfig["debug_logging"] as? [String: Any],
           let path = ObstacleBridgeHostRunner.stringValue(from: nested["log_file"]) {
            return path
        }
        return ObstacleBridgeHostRunner.stringValue(from: runtimeConfig["log_file"])
    }

    func updateConfigs(groupedConfig: [String: Any], runtimeConfig: [String: Any]) {
        self.groupedConfig = groupedConfig
        self.runtimeConfig = runtimeConfig
    }

    func schemaSnapshot() -> [String: Any] {
        let sections = [
            "admin_web": [
                schemaItem(key: "admin_web", description: "Enable admin web interface", defaultValue: true),
                schemaItem(key: "admin_web_auth_disable", description: "Disable username/password challenge for admin web access", defaultValue: false),
                schemaItem(key: "admin_web_bind", description: "Bind address for admin web interface", defaultValue: "127.0.0.1"),
                schemaItem(key: "admin_web_port", description: "Port for admin web interface", defaultValue: 18080),
                schemaItem(key: "admin_web_path", description: "Base path for admin web interface", defaultValue: "/"),
                schemaItem(key: "admin_web_dir", description: "Directory containing admin web files", defaultValue: "./admin_web"),
                schemaItem(key: "admin_web_name", description: "Optional instance name shown in the admin web title and headline", defaultValue: ""),
                schemaItem(key: "admin_web_landing_page_disable", description: "Disable the Admin Web landing/quick-start panel for advanced users.", defaultValue: false),
                schemaItem(key: "admin_web_security_advisor_disable", description: "Disable the Admin Web startup security advisor panel for advanced users.", defaultValue: false),
                schemaItem(key: "admin_web_security_advisor_startup_disable", description: "Do not auto-open the security advisor on first page load.", defaultValue: false),
                schemaItem(key: "admin_web_first_tab", description: "Initial Admin Web tab. Use status for an advanced/operator-focused default.", defaultValue: "home", choices: ["home", "status", "secure-link", "configuration", "logs", "misc"]),
                schemaItem(key: "admin_web_token", description: "Optional bearer token for admin restart endpoint", defaultValue: ""),
                schemaItem(key: "admin_web_username", description: "Username for admin web access when challenge-based authentication is enabled", defaultValue: ""),
                schemaItem(key: "admin_web_password", description: "Password for admin web access when challenge-based authentication is enabled", defaultValue: "", secret: true),
            ],
            "debug_logging": [
                schemaItem(key: "log", description: "Global log level", defaultValue: "DEBUG", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]),
                schemaItem(key: "file_level", description: "File log level", defaultValue: "DEBUG", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]),
                schemaItem(key: "console_level", description: "Console log level", defaultValue: "INFO", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]),
                schemaItem(key: "log_file", description: "Debug log file path", defaultValue: ""),
                schemaItem(key: "log_file_max_bytes", description: "Maximum size of each log file before rotation", defaultValue: 1_048_576),
                schemaItem(key: "log_file_backup_count", description: "Number of rotated log files to keep", defaultValue: 5),
            ],
            "runner": [
                schemaItem(
                    key: "overlay_transport",
                    description: "Overlay transport between peers: comma-separated list from myudp,tcp,quic,ws. Multiple transports are supported simultaneously for listening instances.",
                    defaultValue: "myudp"
                ),
                schemaItem(
                    key: "client_restart_if_disconnected",
                    description: "If configured as a peer client and the overlay stays disconnected for this many seconds, request runner restart. 0 disables.",
                    defaultValue: 0.0
                ),
                schemaItem(
                    key: "overlay_reconnect_retry_delay_ms",
                    description: "Delay in milliseconds between failed reconnect attempts for reconnect-capable client overlays.",
                    defaultValue: 30000
                ),
            ],
            "udp_session": [
                schemaItem(key: "udp_bind", description: "overlay bind address (IPv4 '0.0.0.0' or IPv6 '::')", defaultValue: "::"),
                schemaItem(key: "udp_own_port", description: "overlay own port", defaultValue: 4433),
                schemaItem(key: "udp_peer", description: "peer IP/FQDN, or comma-separated IPv4/IPv6 alternatives (IPv6 may be in [brackets])", defaultValue: NSNull()),
                schemaItem(key: "udp_peer_port", description: "peer overlay port", defaultValue: 4433),
                schemaItem(key: "udp_peer_resolve_family", description: "Peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]),
            ],
            "tcp_session": [
                schemaItem(key: "tcp_bind", description: "TCP overlay bind address", defaultValue: "::"),
                schemaItem(key: "tcp_own_port", description: "TCP overlay own port", defaultValue: 8081),
                schemaItem(key: "tcp_peer", description: "TCP peer IP/FQDN", defaultValue: NSNull()),
                schemaItem(key: "tcp_peer_port", description: "TCP peer overlay port", defaultValue: 8081),
                schemaItem(key: "tcp_peer_resolve_family", description: "TCP peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]),
                schemaItem(key: "tcp_bp_wbuf_threshold", description: "TCP backpressure write-buffer threshold", defaultValue: 128 * 1024),
            ],
            "ws_session": [
                schemaItem(key: "ws_peer", description: "Remote WebSocket peer host", defaultValue: "bridge.example.com"),
                schemaItem(key: "ws_peer_port", description: "Remote WebSocket peer port", defaultValue: 443),
                schemaItem(key: "ws_payload_mode", description: "WebSocket payload framing mode", defaultValue: "binary", choices: ["binary", "base64", "json-base64", "semi-text-shape"]),
                schemaItem(key: "ws_static_dir", description: "Directory containing static web assets", defaultValue: "./web"),
            ],
            "secure_link": [
                schemaItem(key: "secure_link", description: "Enable SecureLink", defaultValue: false),
                schemaItem(key: "secure_link_mode", description: "SecureLink mode", defaultValue: "off", choices: ["off", "psk", "cert"]),
                schemaItem(key: "secure_link_psk", description: "SecureLink PSK secret", defaultValue: "", secret: true),
            ],
            "compress_layer": [
                schemaItem(key: "compress_layer", description: "Enable transport compression", defaultValue: false),
                schemaItem(key: "compress_layer_algo", description: "Compression algorithm", defaultValue: "zlib"),
                schemaItem(key: "compress_layer_level", description: "Compression level", defaultValue: 3),
                schemaItem(key: "compress_layer_min_bytes", description: "Minimum payload size before compression", defaultValue: 64),
                schemaItem(key: "compress_layer_types", description: "Comma-separated message types eligible for compression", defaultValue: "data,data_frag"),
            ],
            "TUN_routing": [
                schemaItem(key: "tunnel_address", description: "IPv4 tunnel address for the local iOS/macOS tunnel endpoint.", defaultValue: "192.168.106.1"),
                schemaItem(key: "tunnel_prefix", description: "IPv4 tunnel prefix length.", defaultValue: 30),
                schemaItem(key: "tunnel_gateway", description: "IPv4 peer gateway address used by TUN hook helpers.", defaultValue: "192.168.106.2"),
                schemaItem(key: "included_routes", description: "IPv4 routes that should be included in the packet tunnel.", defaultValue: ["0.0.0.0/0"]),
                schemaItem(key: "excluded_routes", description: "IPv4 routes that should bypass the packet tunnel.", defaultValue: ["127.0.0.0/8"]),
                schemaItem(key: "tunnel_address6", description: "IPv6 tunnel address for the local iOS/macOS tunnel endpoint.", defaultValue: "fd20:106::1"),
                schemaItem(key: "tunnel_prefix6", description: "IPv6 tunnel prefix length.", defaultValue: 126),
                schemaItem(key: "tunnel_gateway6", description: "IPv6 peer gateway address used by TUN hook helpers.", defaultValue: "fd20:106::2"),
                schemaItem(key: "included_routes6", description: "IPv6 routes that should be included in the packet tunnel.", defaultValue: ["::/0"]),
                schemaItem(key: "excluded_routes6", description: "IPv6 routes that should bypass the packet tunnel.", defaultValue: ["::1/128"]),
                schemaItem(key: "dns_servers", description: "DNS servers advertised to the packet tunnel network settings.", defaultValue: ["1.1.1.1"]),
                schemaItem(key: "mtu", description: "MTU applied to the packet tunnel network settings.", defaultValue: 1600),
                schemaItem(key: "log_TUN_routing", description: "Log level for TUN routing helpers.", defaultValue: "CRITICAL"),
            ],
            "channel_mux": [
                schemaItem(
                    key: "own_servers",
                    description: "Service catalog for local listeners in client mode. Use structured service objects with listen/target fields.",
                    defaultValue: []
                ),
                schemaItem(
                    key: "remote_servers",
                    description: "Service catalog pushed to the connected peer in client mode. Use structured service objects with listen/target fields.",
                    defaultValue: []
                ),
            ],
        ]
        return sections
    }

    private func schemaItem(key: String, description: String, defaultValue: Any, choices: [Any]? = nil, secret: Bool = false) -> [String: Any] {
        var row: [String: Any] = [
            "key": key,
            "description": description,
            "default": defaultValue,
        ]
        if let choices {
            row["choices"] = choices
        }
        if secret {
            row["secret"] = true
        }
        return row
    }

    func schemaRow(forKey key: String) -> [String: Any]? {
        for rows in schemaSnapshot().values {
            guard let items = rows as? [[String: Any]] else {
                continue
            }
            for row in items where String(describing: row["key"] ?? "") == key {
                return row
            }
        }
        return nil
    }

    func sectionName(forKey key: String) -> String? {
        for (section, rows) in schemaSnapshot() {
            guard let items = rows as? [[String: Any]] else {
                continue
            }
            if items.contains(where: { String(describing: $0["key"] ?? "") == key }) {
                return section
            }
        }
        return nil
    }
}

private struct ObstacleBridgeNativeServiceSpec {
    let svcID: Int
    let name: String?
    let listenProtocol: String
    let listenBind: String
    let listenPort: Int
    let targetProtocol: String
    let targetHost: String
    let targetPort: Int

    init(sharedSpec: ObstacleBridgeRuntimeServiceSpec) {
        self.svcID = sharedSpec.svcID
        self.name = sharedSpec.name
        self.listenProtocol = sharedSpec.listenProtocol
        self.listenBind = sharedSpec.listenBind
        self.listenPort = sharedSpec.listenPort
        self.targetProtocol = sharedSpec.targetProtocol
        self.targetHost = sharedSpec.targetHost
        self.targetPort = sharedSpec.targetPort
    }

    func toChannelMuxServiceSpec() -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeChannelMuxCodec.ServiceSpec(
            svcID: svcID,
            lProto: listenProtocol,
            lBind: listenBind,
            lPort: listenPort,
            rProto: targetProtocol,
            rHost: targetHost,
            rPort: targetPort,
            name: name,
            lifecycleHooks: nil,
            options: nil
        )
    }
}

private final class ObstacleBridgeTCPProxyConnection {
    private let chanID: Int
    private let spec: ObstacleBridgeNativeServiceSpec
    private let listenerHost: String
    private let listenerPort: Int
    private let runtime: ObstacleBridgeChannelMuxTcpRuntime
    private let localConnection: NWConnection
    private let remoteConnection: NWConnection
    private let queue: DispatchQueue
    private let updateState: ([String: Any]) -> Void
    private let finish: (Int) -> Void

    private var localClosed = false
    private var remoteClosed = false
    private var state = "connecting"
    private var sourceHost: String?
    private var sourcePort: Int?
    private var stats: [String: Int] = [
        "rx_msgs": 0,
        "tx_msgs": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    ]

    init(
        chanID: Int,
        spec: ObstacleBridgeNativeServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        runtime: ObstacleBridgeChannelMuxTcpRuntime,
        localConnection: NWConnection,
        remoteConnection: NWConnection,
        queue: DispatchQueue,
        updateState: @escaping ([String: Any]) -> Void,
        finish: @escaping (Int) -> Void
    ) {
        self.chanID = chanID
        self.spec = spec
        self.listenerHost = listenerHost
        self.listenerPort = listenerPort
        self.runtime = runtime
        self.localConnection = localConnection
        self.remoteConnection = remoteConnection
        self.queue = queue
        self.updateState = updateState
        self.finish = finish
    }

    func start() {
        captureSourceEndpoint()
        localConnection.stateUpdateHandler = { [weak self] state in
            self?.handleLocalState(state)
        }
        remoteConnection.stateUpdateHandler = { [weak self] state in
            self?.handleRemoteState(state)
        }
        localConnection.start(queue: queue)
        remoteConnection.start(queue: queue)
        updateState(snapshot())
    }

    func stop() {
        localClosed = true
        remoteClosed = true
        localConnection.cancel()
        remoteConnection.cancel()
        state = "closed"
        updateState(snapshot())
        finish(chanID)
    }

    private func captureSourceEndpoint() {
        if case let .hostPort(host, port) = localConnection.endpoint {
            sourceHost = host.debugDescription
            sourcePort = Int(port.rawValue)
        }
    }

    private func handleLocalState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            receiveFromLocal()
        case .failed, .cancelled:
            closeLocal()
        default:
            break
        }
    }

    private func handleRemoteState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            self.state = "connected"
            updateState(snapshot())
            receiveFromRemote()
        case .failed, .cancelled:
            closeRemote()
        default:
            break
        }
    }

    private func receiveFromLocal() {
        localConnection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                _ = try? self.runtime.handleLocalServerData(chanID: self.chanID, payload: data, overlayConnected: true)
                self.stats["tx_msgs", default: 0] += 1
                self.stats["tx_bytes", default: 0] += data.count
                self.updateState(self.snapshot())
                self.remoteConnection.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                self.closeLocal()
                return
            }
            self.receiveFromLocal()
        }
    }

    private func receiveFromRemote() {
        remoteConnection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let inbound = self.runtime.handleInboundServerData(chanID: self.chanID, body: data)
                if inbound.delivered {
                    for buffer in inbound.writtenBuffers {
                        self.stats["rx_msgs", default: 0] += 1
                        self.stats["rx_bytes", default: 0] += buffer.count
                        self.localConnection.send(content: buffer, completion: .contentProcessed { _ in })
                    }
                    self.updateState(self.snapshot())
                }
            }
            if isComplete || error != nil {
                self.closeRemote()
                return
            }
            self.receiveFromRemote()
        }
    }

    private func closeLocal() {
        guard !localClosed else { return }
        localClosed = true
        _ = try? runtime.handleLocalServerEOF(chanID: chanID, overlayConnected: true)
        localConnection.cancel()
        maybeFinish()
    }

    private func closeRemote() {
        guard !remoteClosed else { return }
        remoteClosed = true
        _ = runtime.handleInboundServerClose(chanID: chanID)
        remoteConnection.cancel()
        maybeFinish()
    }

    private func maybeFinish() {
        if localClosed || remoteClosed {
            state = "closed"
            updateState(snapshot())
        }
        if localClosed && remoteClosed {
            finish(chanID)
        } else if localClosed {
            remoteConnection.cancel()
            remoteClosed = true
            finish(chanID)
        } else if remoteClosed {
            localConnection.cancel()
            localClosed = true
            finish(chanID)
        }
    }

    func snapshot() -> [String: Any] {
        [
            "protocol": "tcp",
            "role": "server",
            "state": state,
            "chan_id": chanID,
            "svc_id": spec.svcID,
            "service_name": spec.name ?? "",
            "source": endpointDict(host: sourceHost, port: sourcePort),
            "local": endpointDict(host: listenerHost, port: listenerPort),
            "local_port": listenerPort,
            "remote_destination": endpointDict(host: spec.targetHost, port: spec.targetPort),
            "stats": stats,
        ]
    }

    private func endpointDict(host: String?, port: Int?) -> Any {
        guard let host, let port else {
            return NSNull()
        }
        return ["host": host, "port": port]
    }
}

private final class ObstacleBridgeUDPProxyConnection {
    private let spec: ObstacleBridgeNativeServiceSpec
    private let listenerHost: String
    private let listenerPort: Int
    private let runtime: ObstacleBridgeChannelMuxUdpRuntime
    private let localConnection: NWConnection
    private let remoteConnection: NWConnection
    private let queue: DispatchQueue
    private let updateState: ([String: Any]?) -> Void
    private let finish: (Int?) -> Void

    private var chanID: Int?
    private var sourceHost: String?
    private var sourcePort: Int?
    private var closed = false
    private var stats: [String: Int] = [
        "rx_msgs": 0,
        "tx_msgs": 0,
        "rx_bytes": 0,
        "tx_bytes": 0,
    ]

    init(
        spec: ObstacleBridgeNativeServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        runtime: ObstacleBridgeChannelMuxUdpRuntime,
        localConnection: NWConnection,
        remoteConnection: NWConnection,
        queue: DispatchQueue,
        updateState: @escaping ([String: Any]?) -> Void,
        finish: @escaping (Int?) -> Void
    ) {
        self.spec = spec
        self.listenerHost = listenerHost
        self.listenerPort = listenerPort
        self.runtime = runtime
        self.localConnection = localConnection
        self.remoteConnection = remoteConnection
        self.queue = queue
        self.updateState = updateState
        self.finish = finish
    }

    func start() {
        captureSourceEndpoint()
        localConnection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state, isLocal: true)
        }
        remoteConnection.stateUpdateHandler = { [weak self] state in
            self?.handleState(state, isLocal: false)
        }
        localConnection.start(queue: queue)
        remoteConnection.start(queue: queue)
    }

    func stop() {
        guard !closed else { return }
        closed = true
        localConnection.cancel()
        remoteConnection.cancel()
        if let chanID {
            _ = runtime.handleInboundClose(chanID: chanID)
        }
        updateState(nil)
        finish(chanID)
    }

    private func captureSourceEndpoint() {
        if case let .hostPort(host, port) = localConnection.endpoint {
            sourceHost = host.debugDescription
            sourcePort = Int(port.rawValue)
        }
    }

    private func handleState(_ state: NWConnection.State, isLocal: Bool) {
        switch state {
        case .ready:
            if isLocal {
                receiveFromLocal()
            } else {
                receiveFromRemote()
            }
        case .failed, .cancelled:
            stop()
        default:
            break
        }
    }

    private func receiveFromLocal() {
        localConnection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let snapshot = try? self.runtime.handleLocalServerDatagram(
                    spec: self.spec.toChannelMuxServiceSpec(),
                    serviceKey: "svc-\(self.spec.svcID)",
                    payload: data,
                    addrHost: self.sourceHost ?? "127.0.0.1",
                    addrPort: self.sourcePort ?? 0,
                    overlayConnected: true,
                    acceptingEnabled: true
                )
                if let snapshot {
                    self.chanID = snapshot.chanID
                    self.stats["tx_msgs", default: 0] += 1
                    self.stats["tx_bytes", default: 0] += data.count
                    self.updateState(self.snapshot())
                    self.remoteConnection.send(content: data, completion: .contentProcessed { _ in })
                }
            }
            if error != nil || self.closed {
                self.stop()
                return
            }
            self.receiveFromLocal()
        }
    }

    private func receiveFromRemote() {
        remoteConnection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty, let chanID = self.chanID {
                let inbound = self.runtime.handleInboundServerData(chanID: chanID, body: data)
                if inbound.delivered, let packet = inbound.packet {
                    self.stats["rx_msgs", default: 0] += 1
                    self.stats["rx_bytes", default: 0] += packet.count
                    self.updateState(self.snapshot())
                    self.localConnection.send(content: packet, completion: .contentProcessed { _ in })
                }
            }
            if error != nil || self.closed {
                self.stop()
                return
            }
            self.receiveFromRemote()
        }
    }

    func snapshot() -> [String: Any]? {
        guard let chanID else {
            return nil
        }
        return [
            "protocol": "udp",
            "role": "server",
            "state": "connected",
            "chan_id": chanID,
            "svc_id": spec.svcID,
            "service_name": spec.name ?? "",
            "source": endpointDict(host: sourceHost, port: sourcePort),
            "local": endpointDict(host: listenerHost, port: listenerPort),
            "local_port": listenerPort,
            "remote_destination": endpointDict(host: spec.targetHost, port: spec.targetPort),
            "stats": stats,
        ]
    }

    private func endpointDict(host: String?, port: Int?) -> Any {
        guard let host, let port else {
            return NSNull()
        }
        return ["host": host, "port": port]
    }
}

final class ObstacleBridgeHostRunner {
    private static let authChallengeTTL: TimeInterval = 300
    private static let authSessionTTL: TimeInterval = 12 * 60 * 60
    private static let configChallengeTTL: TimeInterval = 90

    private let runtimeConfigPath: String
    private var runtimeConfigRaw: [String: Any]
    private var runtimeConfig: [String: Any]
    private let configStore: ObstacleBridgeConfigStore
    private var ownServerSpecs: [ObstacleBridgeNativeServiceSpec]
    private var remoteServerSpecs: [ObstacleBridgeNativeServiceSpec]
    private let bindHost: String
    private let statusPort: Int
    private var startedAt = Date()
    private let serviceStateQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.Services")
    private let authStateQueue = DispatchQueue(label: "ObstacleBridgeHostRunner.Auth")
    private var controlServer: ObstacleBridgeWebAdminServer?
    private var bootstrapState: [String: Any] = [:]
    private var restartCount = 0
    private var reconnectCount = 0
    private var shutdownRequestedAt: Date?
    private var sharedChannelMuxUdpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
    private var sharedChannelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime()
    private var udpServiceListeners: [Int: NWListener] = [:]
    private var udpConnectionStates: [Int: [String: Any]] = [:]
    private var udpConnectionObjects: [ObjectIdentifier: ObstacleBridgeUDPProxyConnection] = [:]
    private var tcpServiceListeners: [Int: NWListener] = [:]
    private var tcpConnectionStates: [Int: [String: Any]] = [:]
    private var tcpConnectionObjects: [Int: ObstacleBridgeTCPProxyConnection] = [:]
    private var sharedCompressLayerRuntime: ObstacleBridgeCompressLayerRuntime?
    private var sharedSecureLinkPskTransportAdapter: ObstacleBridgeSecureLinkPskTransportAdapter?
    private var sharedOverlayLayerTransportAdapter: ObstacleBridgeOverlayLayerTransportAdapter?
    private var sharedWebSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime?
    private var sharedTcpOverlayRuntime: ObstacleBridgeTcpOverlayRuntime?
    private var sharedTcpOverlayTransportOwner: ObstacleBridgeTcpOverlayTransportOwner?
    private var sharedUdpOverlayTransportOwner: ObstacleBridgeUdpOverlayTransportOwner?
    private var clientRestartWatchdog: DispatchSourceTimer?
    private var overlayDisconnectedAt: TimeInterval?
    private var authChallenges: [String: [String: Any]] = [:]
    private var configChallenges: [String: [String: Any]] = [:]
    private var authSessions: [String: TimeInterval] = [:]

    init(runtimeConfigPath: String, bindHostOverride: String?, statusPortOverride: Int?) throws {
        self.runtimeConfigPath = runtimeConfigPath
        let decoded = try Self.loadRuntimeConfigFromDisk(runtimeConfigPath: runtimeConfigPath)
        self.runtimeConfigRaw = decoded
        self.runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(decoded)
        self.configStore = ObstacleBridgeConfigStore(configPath: runtimeConfigPath, groupedConfig: decoded, runtimeConfig: runtimeConfig)
        self.ownServerSpecs = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        self.remoteServerSpecs = ObstacleBridgeRuntimeConfig.remoteServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        self.bindHost = bindHostOverride ?? (ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_bind"]) ?? "127.0.0.1")
        let configuredPort = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["admin_web_port"])
        self.statusPort = statusPortOverride ?? configuredPort ?? 18080
    }

    static func appScopedRootURL() throws -> URL {
#if os(macOS)
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Application Support/ObstacleBridge")
        }
        let root = base.appendingPathComponent("ObstacleBridge", isDirectory: true)
#else
        guard let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig("Documents")
        }
        let root = base
#endif
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    static func appScopedRuntimeConfigPath() throws -> String {
        return try appScopedRootURL()
            .appendingPathComponent("config", isDirectory: true)
            .appendingPathComponent("ObstacleBridge.cfg", isDirectory: false)
            .path
    }

    static func makeAppScopedRunner() throws -> ObstacleBridgeHostRunner {
        try ObstacleBridgeHostRunner(
            runtimeConfigPath: appScopedRuntimeConfigPath(),
            bindHostOverride: nil,
            statusPortOverride: nil
        )
    }

    static func makeRunner(cli: ObstacleBridgeHostRunnerCLI) throws -> ObstacleBridgeHostRunner {
        try ObstacleBridgeHostRunner(
            runtimeConfigPath: cli.runtimeConfigPath,
            bindHostOverride: cli.bindHost,
            statusPortOverride: cli.statusPort
        )
    }

    static func runMain(arguments: [String]) throws {
        let cli = try ObstacleBridgeHostRunnerCLI.parse(arguments)
        let runner = try makeRunner(cli: cli)
        try runner.start()
        defer { runner.stop() }
        if cli.holdSec > 0 {
            let deadline = Date().addingTimeInterval(cli.holdSec)
            while Date() < deadline {
                _ = RunLoop.current.run(mode: .default, before: min(deadline, Date().addingTimeInterval(0.1)))
            }
            return
        }
        dispatchMain()
    }

    private static func loadRuntimeConfigFromDisk(runtimeConfigPath: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: runtimeConfigPath)
        guard let data = try? Data(contentsOf: url) else {
            throw ObstacleBridgeHostRunnerError.unreadableRuntimeConfig(runtimeConfigPath)
        }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let rawDecoded = object as? [String: Any] else {
            throw ObstacleBridgeHostRunnerError.invalidRuntimeConfigRoot
        }
        do {
            return try ObstacleBridgeConfigSecretCodec.decryptPayload(rawDecoded)
        } catch let error as ObstacleBridgeHostRunnerError {
            throw error
        } catch {
            throw ObstacleBridgeHostRunnerError.invalidEncryptedConfigSecret("runtime_config")
        }
    }

    private func reloadRuntimeConfigFromDisk() throws {
        let decoded = try Self.loadRuntimeConfigFromDisk(runtimeConfigPath: runtimeConfigPath)
        runtimeConfigRaw = decoded
        runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(decoded)
        configStore.updateConfigs(groupedConfig: decoded, runtimeConfig: runtimeConfig)
        ownServerSpecs = ObstacleBridgeRuntimeConfig.ownServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
        remoteServerSpecs = ObstacleBridgeRuntimeConfig.remoteServerSpecs(from: runtimeConfig).map(ObstacleBridgeNativeServiceSpec.init)
    }

    private func reloadRuntimeStateForControlAction() throws {
        try reloadRuntimeConfigFromDisk()
        stopOwnServers()
        prepareSharedOverlayBootstrap()
        try startOwnServers()
        startSharedTCPOverlayTransportOwnerIfNeeded()
        try startSharedUDPOverlayTransportOwnerIfNeeded()
        startedAt = Date()
    }

    func start() throws {
        prepareSharedOverlayBootstrap()
        try startOwnServers()
        startSharedTCPOverlayTransportOwnerIfNeeded()
        try startSharedUDPOverlayTransportOwnerIfNeeded()
        let controlServer = try ObstacleBridgeWebAdminServer(
            bindHost: bindHost,
            port: statusPort,
            fallbackIndexTitle: "ObstacleBridge macOS Swift Host Runner",
            fallbackIndexSubtitle: "Swift-only bootstrap and status surface for host-side E2E harnessing.",
            statusProvider: { [weak self] in
                self?.snapshot() ?? [:]
            },
            apiProvider: { [weak self] method, path, headers, body in
                guard let self else {
                    return nil
                }
                let request = ObstacleBridgeAdminAPIRequest(method: method, path: path, headers: headers, body: body)
                return ObstacleBridgeAdminAPI.response(for: request, provider: self)
            },
            staticFileProvider: { [weak self] path in
                self?.staticFileResponse(path: path)
            },
            liveTopicProvider: { [weak self] topic in
                guard let self else {
                    return nil
                }
                return ObstacleBridgeAdminAPI.liveTopicPayload(topic: topic, provider: self)
            },
            authRequiredProvider: { [weak self] in
                self?.adminAuthRequired() ?? false
            },
            authenticatedProvider: { [weak self] headers in
                self?.adminIsAuthenticated(headers: headers) ?? false
            }
        )
        self.controlServer = controlServer
        controlServer.start()
        startClientRestartWatchdog()
    }

    func stop() {
        clientRestartWatchdog?.cancel()
        clientRestartWatchdog = nil
        sharedTcpOverlayTransportOwner?.stop()
        sharedTcpOverlayTransportOwner = nil
        sharedUdpOverlayTransportOwner?.stop()
        sharedUdpOverlayTransportOwner = nil
        stopOwnServers()
        controlServer?.stop()
        controlServer = nil
    }

    func snapshot() -> [String: Any] {
        let uptimeMS = Int(Date().timeIntervalSince(startedAt) * 1000)
        let uptimeSec = Int(Date().timeIntervalSince(startedAt))
        return [
            "ok": true,
            "mode": "swift_host_runner",
            "pid": ProcessInfo.processInfo.processIdentifier,
            "runtime_config_path": runtimeConfigPath,
            "runtime_config_keys": runtimeConfig.keys.sorted(),
            "admin_bind_host": bindHost,
            "admin_port": statusPort,
            "admin_url": "http://\(bindHost):\(statusPort)/",
            "uptime_ms": uptimeMS,
            "uptime_sec": uptimeSec,
            "bootstrap_state": bootstrapState,
            "admin_web_name": Self.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            "build": buildSummary(),
            "admin_ui": adminUIPayload(),
            "security_advisor": securityAdvisorPayload(),
            "control_actions": controlActionSnapshot(),
            "transport_runtime": transportRuntimeSnapshot(),
            "compress_layer": compressLayerSnapshot(peerID: nil) ?? NSNull(),
            "secure_link_material_generation": 0,
            "secure_link_last_reload_unix_ts": NSNull(),
            "secure_link_last_reload_scope": "",
            "secure_link_last_reload_result": "",
            "secure_link_last_reload_detail": "",
            "secure_link_peers_dropped_total": 0,
        ]
    }

    private func staticFileResponse(path: String) -> (contentType: String, body: Data)? {
        let cleanedPath = normalizeStaticPath(path)
        let adminWebDir = configStore.adminWebDirectory()
        let fileURL = URL(fileURLWithPath: adminWebDir).appendingPathComponent(cleanedPath)
        guard fileURL.path.hasPrefix(URL(fileURLWithPath: adminWebDir).path),
              let data = try? Data(contentsOf: fileURL) else {
            return nil
        }
        return (contentType(for: fileURL.pathExtension), data)
    }

    private func normalizeStaticPath(_ rawPath: String) -> String {
        let basePath = rawPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
        let candidate = basePath == "/" ? "index.html" : String(basePath.drop(while: { $0 == "/" }))
        let components = candidate.split(separator: "/").filter { $0 != "." && $0 != ".." }
        return components.isEmpty ? "index.html" : components.joined(separator: "/")
    }

    private func contentType(for pathExtension: String) -> String {
        switch pathExtension.lowercased() {
        case "html":
            return "text/html; charset=utf-8"
        case "js":
            return "application/javascript; charset=utf-8"
        case "css":
            return "text/css; charset=utf-8"
        case "json":
            return "application/json; charset=utf-8"
        case "svg":
            return "image/svg+xml"
        default:
            return "application/octet-stream"
        }
    }

    private func metaSnapshot() -> [String: Any] {
        let uptimeSec = Int(Date().timeIntervalSince(startedAt))
        return [
            "admin_web_name": Self.stringValue(from: runtimeConfig["admin_web_name"]) ?? "",
            "uptime_sec": uptimeSec,
            "build": buildSummary(),
            "runtime_dependencies": adminRuntimeDependenciesPayload(),
            "bootstrap_state": bootstrapState,
            "control_actions": controlActionSnapshot(),
            "transport_runtime": transportRuntimeSnapshot(),
            "compress_layer": compressLayerSnapshot(peerID: nil) ?? NSNull(),
        ]
    }

    private func peersSnapshot() -> [[String: Any]] {
        let connections = connectionsSnapshot()
        let counts = connections["counts"] as? [String: Any] ?? [:]
        let transport = bootstrapState["transport"] ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        let peerEndpoint = peerEndpointSnapshot()
        let transportRuntime = transportRuntimeSnapshot()
        let myudpRuntime = transportRuntime["myudp"] as? [String: Any] ?? [:]
        let protocolStats = myudpRuntime["protocol_stats"] as? [String: Any] ?? [:]
        let overlayConnected = overlayCurrentlyConnected() ?? false
        let stateText: String
        if overlayConnected {
            stateText = "connected"
        } else if bootstrapState["status"] as? String == "prepared" {
            stateText = "connecting"
        } else {
            stateText = "failed"
        }
        var peer: [String: Any] = [
            "id": 1,
            "transport": transport,
            "state": stateText,
            "listen": NSNull(),
            "peer": peerEndpoint,
            "decode_errors": 0,
            "inflight": protocolStats["buffered_frames"] ?? 0,
            "last_incoming_age_seconds": lastIncomingAgeSeconds(from: myudpRuntime),
            "rtt_est_ms": myudpRuntime["rtt_est_ms"] ?? NSNull(),
            "transmit_delay_est_ms": myudpRuntime["transmit_delay_est_ms"] ?? NSNull(),
            "traffic": [
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_bytes_per_sec": 0,
                "tx_bytes_per_sec": 0,
            ],
            "open_connections": [
                "udp": counts["udp"] ?? 0,
                "tcp": counts["tcp"] ?? 0,
                "tun": counts["tun"] ?? 0,
            ],
            "secure_link": secureLinkSnapshot(defaultState: stateText),
            "compress_layer": compressLayerSnapshot(peerID: 1) ?? [
                "enabled": Self.boolValue(from: runtimeConfig["compress_layer"]) ?? false,
                "algorithm": Self.stringValue(from: runtimeConfig["compress_layer_algo"]) ?? "",
                "compress_attempts_total": 0,
                "compress_applied_total": 0,
                "compress_input_bytes_total": 0,
                "compress_output_bytes_total": 0,
                "decompress_ok_total": 0,
                "decompress_fail_total": 0,
            ],
            "runtime": transportRuntime,
        ]
        if let myudp = bootstrapState["transport"] as? String, myudp == "myudp" {
            peer["myudp"] = [
                "buffered_frames": protocolStats["buffered_frames"] ?? 0,
                "first_pass": protocolStats["first_pass"] ?? 0,
                "repeated_once": protocolStats["repeated_once"] ?? 0,
                "repeated_multiple": protocolStats["repeated_multiple"] ?? 0,
                "confirmed_total": protocolStats["confirmed_total"] ?? 0,
            ]
        }
        return [peer]
    }

    private func lastIncomingAgeSeconds(from runtime: [String: Any]) -> Any {
        guard let lastRxWall = runtime["last_rx_wall_ns"] as? UInt64, lastRxWall > 0 else {
            return NSNull()
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now >= lastRxWall else {
            return NSNull()
        }
        return Double(now - lastRxWall) / 1_000_000_000.0
    }

    private func peerEndpointSnapshot() -> Any {
        let overlayTransport = Self.stringValue(from: bootstrapState["transport"]) ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        if overlayTransport == "myudp",
           let ownerSnapshot = serviceStateQueue.sync(execute: { sharedUdpOverlayTransportOwner?.transportSnapshot() }),
           let host = ownerSnapshot["overlay_peer_host"] as? String,
           !host.isEmpty {
            return ["host": host, "port": ownerSnapshot["overlay_peer_port"] ?? NSNull()]
        }
        let host = bootstrapState["peer_host"] ?? (Self.peerHost(for: overlayTransport, payload: runtimeConfig) ?? "")
        let port: Any
        switch overlayTransport {
        case "tcp":
            port = Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? NSNull()
        case "ws":
            port = Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? NSNull()
        case "quic":
            port = Self.intValue(from: runtimeConfig["quic_peer_port"]) ?? NSNull()
        default:
            port = Self.intValue(from: runtimeConfig["udp_peer_port"]) ?? NSNull()
        }
        if let hostString = host as? String, !hostString.isEmpty {
            return ["host": hostString, "port": port]
        }
        return NSNull()
    }

    private func transportRuntimeSnapshot() -> [String: Any] {
        let transport = Self.stringValue(from: bootstrapState["transport"]) ?? (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp")
        var snapshot: [String: Any] = [
            "kind": transport,
            "status": bootstrapState["status"] ?? "unknown",
        ]
        if let websocket = webSocketRuntimeSnapshot() {
            snapshot["websocket"] = websocket
        }
        if let tcp = tcpRuntimeSnapshot() {
            snapshot["tcp"] = tcp
        }
        if let udp = udpRuntimeSnapshot() {
            snapshot["myudp"] = udp
        }
        return snapshot
    }

    private func udpRuntimeSnapshot() -> [String: Any]? {
        serviceStateQueue.sync {
            sharedUdpOverlayTransportOwner?.transportSnapshot()
        }
    }

    private func webSocketRuntimeSnapshot() -> [String: Any]? {
        guard let runtime = sharedWebSocketOverlayRuntime else {
            return nil
        }
        let host = Self.stringValue(from: runtimeConfig["ws_peer"]) ?? ""
        let port = Self.intValue(from: runtimeConfig["ws_peer_port"]) ?? 0
        let useTLS = Self.boolValue(from: runtimeConfig["ws_tls"]) ?? false
        let path = Self.stringValue(from: runtimeConfig["ws_path"]) ?? "/"
        let subprotocol = Self.stringValue(from: runtimeConfig["ws_subprotocol"])
        let proxyMode = (Self.stringValue(from: runtimeConfig["ws_proxy_mode"]) ?? "off").lowercased()
        let proxyActive = proxyMode != "off"
        let socketConfig = runtime.socketConfigSnapshot(socketPresent: false, tcpUserTimeoutAvailable: true)
        let plan = runtime.buildConnectPlan(
            host: host,
            port: max(0, port),
            peerNameHost: host.isEmpty ? nil : host,
            peerNamePort: port > 0 ? port : nil,
            useTLS: useTLS,
            wsPath: path,
            wsSubprotocol: subprotocol,
            proxyActive: proxyActive
        )
        return [
            "payload_mode": bootstrapState["ws_payload_mode"] ?? (Self.stringValue(from: runtimeConfig["ws_payload_mode"]) ?? "binary"),
            "uri": plan.uri,
            "host": host,
            "port": port,
            "path": path,
            "subprotocol": subprotocol ?? NSNull(),
            "proxy_active": proxyActive,
            "proxy_mode": proxyMode,
            "preflight_required": plan.preflightRequired,
            "uses_proxy_socket": plan.usesProxySocket,
            "max_size": plan.maxSize,
            "compression_disabled": plan.compressionDisabled,
            "upgrade_headers": plan.upgradeHeaders,
            "keep_alive_enabled": socketConfig.keepAliveEnabled,
            "tcp_user_timeout_ms": socketConfig.tcpUserTimeoutMS ?? NSNull(),
        ]
    }

    private func tcpRuntimeSnapshot() -> [String: Any]? {
        guard let runtime = sharedTcpOverlayRuntime else {
            return nil
        }
        let threshold = Self.intValue(from: runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
        let socketConfig = runtime.socketConfigSnapshot(socketPresent: false)
        let backpressure = runtime.backpressureSnapshot(writeBufferSize: 0, threshold: threshold)
        var snapshot: [String: Any] = [
            "host": Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? NSNull(),
            "port": Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? NSNull(),
            "keep_alive_enabled": socketConfig.keepAliveEnabled,
            "backpressure_threshold": threshold,
            "backpressure_signaled": backpressure.signaled,
        ]
        if let ownerSnapshot = serviceStateQueue.sync(execute: { sharedTcpOverlayTransportOwner?.transportSnapshot() }) {
            for (key, value) in ownerSnapshot {
                snapshot[key] = value
            }
        }
        return snapshot
    }

    private func compressLayerSnapshot(peerID: Int?) -> [String: Any]? {
        guard let runtime = sharedCompressLayerRuntime else {
            return nil
        }
        let snapshot = runtime.statusSnapshot(peerID: peerID)
        return [
            "enabled": snapshot.enabled,
            "algorithm": snapshot.algorithm,
            "transport": snapshot.transport,
            "level": snapshot.level,
            "min_bytes": snapshot.minBytes,
            "compress_attempts_total": snapshot.compressAttemptsTotal,
            "compress_applied_total": snapshot.compressAppliedTotal,
            "compress_skipped_no_gain_total": snapshot.compressSkippedNoGainTotal,
            "compress_input_bytes_total": snapshot.compressInputBytesTotal,
            "compress_output_bytes_total": snapshot.compressOutputBytesTotal,
            "decompress_ok_total": snapshot.decompressOKTotal,
            "decompress_fail_total": snapshot.decompressFailTotal,
        ]
    }

    private func secureLinkSnapshot(defaultState: String) -> [String: Any] {
        let enabled = Self.boolValue(from: runtimeConfig["secure_link"]) ?? false
        let mode = Self.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off"
        guard enabled, let adapter = serviceStateQueue.sync(execute: { sharedSecureLinkPskTransportAdapter }) else {
            return [
                "enabled": enabled,
                "mode": mode,
                "state": defaultState,
                "authenticated": false,
                "session_id": NSNull(),
                "rekey_in_progress": false,
                "last_event": "bootstrap",
                "last_event_unix_ts": NSNull(),
                "last_authenticated_unix_ts": NSNull(),
                "connected_since_unix_ts": NSNull(),
                "authenticated_sessions_total": 0,
                "rekeys_completed_total": 0,
                "peer_subject_id": "",
                "peer_subject_name": "",
                "peer_roles": [],
                "peer_deployment_id": "",
                "peer_serial": "",
                "issuer_id": "",
                "trust_validation_state": "n/a",
                "trust_failure_reason": "",
                "trust_failure_detail": "",
                "active_material_generation": 0,
                "last_material_reload_unix_ts": NSNull(),
                "last_material_reload_scope": "",
                "last_material_reload_result": "",
                "last_material_reload_detail": "",
                "trust_enforced_unix_ts": NSNull(),
                "disconnect_reason": "",
                "disconnect_detail": "",
            ]
        }

        let snapshot = adapter.statusSnapshot()
        let state: String
        let lastEvent: String
        let disconnectReason: String
        if snapshot.authenticated {
            state = "authenticated"
            lastEvent = "authenticated"
            disconnectReason = ""
        } else if snapshot.authFailCode != 0 {
            state = "auth_failed"
            lastEvent = "auth_failed"
            disconnectReason = "auth_failed"
        } else if snapshot.sessionID != 0 {
            state = "handshaking"
            lastEvent = "handshake_started"
            disconnectReason = ""
        } else {
            state = defaultState
            lastEvent = "bootstrap"
            disconnectReason = ""
        }

        return [
            "enabled": true,
            "mode": mode,
            "state": state,
            "authenticated": snapshot.authenticated,
            "session_id": snapshot.sessionID == 0 ? NSNull() : snapshot.sessionID,
            "rekey_in_progress": false,
            "last_event": lastEvent,
            "last_event_unix_ts": NSNull(),
            "last_authenticated_unix_ts": snapshot.authenticated ? Int(Date().timeIntervalSince1970) : NSNull(),
            "connected_since_unix_ts": snapshot.sessionID == 0 ? NSNull() : Int(Date().timeIntervalSince1970),
            "authenticated_sessions_total": snapshot.authenticated ? 1 : 0,
            "rekeys_completed_total": 0,
            "peer_subject_id": "",
            "peer_subject_name": "",
            "peer_roles": [],
            "peer_deployment_id": "",
            "peer_serial": "",
            "issuer_id": "",
            "trust_validation_state": snapshot.authenticated ? "validated" : "n/a",
            "trust_failure_reason": snapshot.authFailCode == 0 ? "" : "psk_auth_failed",
            "trust_failure_detail": snapshot.authFailCode == 0 ? "" : "code=\(snapshot.authFailCode)",
            "active_material_generation": snapshot.sessionID == 0 ? 0 : 1,
            "last_material_reload_unix_ts": NSNull(),
            "last_material_reload_scope": "",
            "last_material_reload_result": "",
            "last_material_reload_detail": "",
            "trust_enforced_unix_ts": NSNull(),
            "disconnect_reason": disconnectReason,
            "disconnect_detail": snapshot.authFailCode == 0 ? "" : "code=\(snapshot.authFailCode)",
        ]
    }

    private func readLogLines(limit: Int) -> [String] {
        guard let path = configStore.debugLogFilePath(), !path.isEmpty,
              let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        return Array(lines.suffix(max(1, min(limit, 1000))))
    }

    private func buildSummary() -> [String: Any] {
        if let sidecar = loadBuildSummaryFromSidecar() {
            return sidecar
        }

        let env = ProcessInfo.processInfo.environment
        let commit = (env["OBSTACLEBRIDGE_BUILD_COMMIT"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let source = (env["OBSTACLEBRIDGE_BUILD_SOURCE"] ?? "environment").trimmingCharacters(in: .whitespacesAndNewlines)
        let diffSHA = (env["OBSTACLEBRIDGE_BUILD_DIFF_SHA"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let tainted = Self.boolValue(from: env["OBSTACLEBRIDGE_BUILD_DIRTY"]) ?? false
        if !commit.isEmpty {
            return [
                "commit": commit,
                "source": source.isEmpty ? "environment" : source,
                "repo_root": "",
                "tainted": tainted,
                "tracked_changes": 0,
                "untracked_changes": 0,
                "available": true,
                "diff_sha": diffSHA,
            ]
        }

        return [
            "commit": "unknown",
            "source": "swift_host_runner",
            "repo_root": "",
            "tainted": false,
            "tracked_changes": 0,
            "untracked_changes": 0,
            "available": false,
            "diff_sha": "",
        ]
    }

    private func loadBuildSummaryFromSidecar() -> [String: Any]? {
        let executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        let sidecarURL = executableURL
            .deletingLastPathComponent()
            .appendingPathComponent("\(executableURL.lastPathComponent).build-info.json")
        guard let data = try? Data(contentsOf: sidecarURL),
              let object = try? JSONSerialization.jsonObject(with: data),
              let payload = object as? [String: Any] else {
            return nil
        }
        let commit = Self.stringValue(from: payload["commit"] ?? payload["build_commit"]) ?? "unknown"
        let source = Self.stringValue(from: payload["source"] ?? payload["build_source"]) ?? "embedded"
        let diffSHA = Self.stringValue(from: payload["diff_sha"] ?? payload["build_diff_sha"]) ?? ""
        let repoRoot = Self.stringValue(from: payload["repo_root"]) ?? ""
        let available = Self.boolValue(from: payload["available"])
            ?? !(commit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || commit == "unknown")
        let tainted = Self.boolValue(from: payload["tainted"] ?? payload["build_dirty"]) ?? false
        let trackedChanges = Self.intValue(from: payload["tracked_changes"]) ?? 0
        let untrackedChanges = Self.intValue(from: payload["untracked_changes"]) ?? 0
        return [
            "commit": commit,
            "source": source,
            "repo_root": repoRoot,
            "tainted": tainted,
            "tracked_changes": trackedChanges,
            "untracked_changes": untrackedChanges,
            "available": available,
            "diff_sha": diffSHA,
        ]
    }

    private func startOwnServers() throws {
        sharedChannelMuxUdpRuntime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        sharedChannelMuxTcpRuntime = ObstacleBridgeChannelMuxTcpRuntime()
        for spec in ownServerSpecs where spec.listenProtocol == "udp" && spec.targetProtocol == "udp" {
            try startUDPService(spec)
        }
        for spec in ownServerSpecs where spec.listenProtocol == "tcp" && spec.targetProtocol == "tcp" {
            try startTCPService(spec)
        }
    }

    private func stopOwnServers() {
        serviceStateQueue.sync {
            for connection in tcpConnectionObjects.values {
                connection.stop()
            }
            tcpConnectionObjects.removeAll()
            tcpConnectionStates.removeAll()
            for connection in udpConnectionObjects.values {
                connection.stop()
            }
            udpConnectionObjects.removeAll()
            udpConnectionStates.removeAll()
            for listener in tcpServiceListeners.values {
                listener.cancel()
            }
            tcpServiceListeners.removeAll()
            for listener in udpServiceListeners.values {
                listener.cancel()
            }
            udpServiceListeners.removeAll()
        }
    }

    private func startUDPService(_ spec: ObstacleBridgeNativeServiceSpec) throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.listenPort)) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("invalid own_server udp listen port: \(spec.listenPort)")
        }
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.listenBind), port: port)
        let listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] connection in
            self?.acceptUDPConnection(connection, spec: spec)
        }
        listener.start(queue: serviceStateQueue)
        serviceStateQueue.sync {
            udpServiceListeners[spec.svcID] = listener
        }
    }

    private func acceptUDPConnection(_ connection: NWConnection, spec: ObstacleBridgeNativeServiceSpec) {
        if let owner = sharedTcpOverlayTransportOwner,
           (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "tcp" {
            if owner.acceptLocalUDPConnection(
                connection,
                spec: spec.toChannelMuxServiceSpec(),
                listenerHost: spec.listenBind,
                listenerPort: spec.listenPort,
                serviceKey: "svc-\(spec.svcID)"
            ) {
                return
            }
        }
        if let owner = sharedUdpOverlayTransportOwner,
           (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased() == "myudp" {
            if owner.acceptLocalUDPConnection(
                connection,
                spec: spec.toChannelMuxServiceSpec(),
                listenerHost: spec.listenBind,
                listenerPort: spec.listenPort,
                serviceKey: "svc-\(spec.svcID)"
            ) {
                return
            }
        }
        guard let remotePort = NWEndpoint.Port(rawValue: UInt16(spec.targetPort)) else {
            connection.cancel()
            return
        }
        let remote = NWConnection(host: NWEndpoint.Host(spec.targetHost), port: remotePort, using: .udp)
        var proxy: ObstacleBridgeUDPProxyConnection!
        proxy = ObstacleBridgeUDPProxyConnection(
            spec: spec,
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort,
            runtime: sharedChannelMuxUdpRuntime,
            localConnection: connection,
            remoteConnection: remote,
            queue: serviceStateQueue,
            updateState: { [weak self] state in
                self?.serviceStateQueue.async {
                    if let state, let chanID = state["chan_id"] as? Int {
                        self?.udpConnectionStates[chanID] = state
                    }
                }
            },
            finish: { [weak self] chanID in
                self?.serviceStateQueue.async {
                    if let chanID {
                        self?.udpConnectionStates.removeValue(forKey: chanID)
                    }
                    self?.udpConnectionObjects.removeValue(forKey: ObjectIdentifier(proxy))
                }
            }
        )
        serviceStateQueue.async {
            self.udpConnectionObjects[ObjectIdentifier(proxy)] = proxy
            proxy.start()
        }
    }

    private func startTCPService(_ spec: ObstacleBridgeNativeServiceSpec) throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(spec.listenPort)) else {
            throw ObstacleBridgeHostRunnerError.invalidArgument("invalid own_server tcp listen port: \(spec.listenPort)")
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(spec.listenBind), port: port)
        let listener = try NWListener(using: params)
        listener.newConnectionHandler = { [weak self] connection in
            self?.acceptTCPConnection(connection, spec: spec)
        }
        listener.start(queue: serviceStateQueue)
        serviceStateQueue.sync {
            tcpServiceListeners[spec.svcID] = listener
        }
    }

    private func acceptTCPConnection(_ connection: NWConnection, spec: ObstacleBridgeNativeServiceSpec) {
        if let owner = sharedTcpOverlayTransportOwner,
           (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "tcp" {
            if owner.acceptLocalTCPConnection(
                connection,
                spec: spec.toChannelMuxServiceSpec(),
                listenerHost: spec.listenBind,
                listenerPort: spec.listenPort
            ) {
                return
            }
        }
        if let owner = sharedUdpOverlayTransportOwner,
           (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased() == "myudp" {
            if owner.acceptLocalTCPConnection(
                connection,
                spec: spec.toChannelMuxServiceSpec(),
                listenerHost: spec.listenBind,
                listenerPort: spec.listenPort
            ) {
                return
            }
        }
        let acceptSnapshot = try? sharedChannelMuxTcpRuntime.handleAcceptedServerConnection(
            spec: spec.toChannelMuxServiceSpec(),
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let acceptSnapshot else {
            connection.cancel()
            return
        }
        let remotePort = NWEndpoint.Port(rawValue: UInt16(spec.targetPort)) ?? 0
        let remote = NWConnection(host: NWEndpoint.Host(spec.targetHost), port: remotePort, using: .tcp)
        let proxy = ObstacleBridgeTCPProxyConnection(
            chanID: acceptSnapshot.chanID,
            spec: spec,
            listenerHost: spec.listenBind,
            listenerPort: spec.listenPort,
            runtime: sharedChannelMuxTcpRuntime,
            localConnection: connection,
            remoteConnection: remote,
            queue: serviceStateQueue,
            updateState: { [weak self] state in
                self?.serviceStateQueue.async {
                    self?.tcpConnectionStates[acceptSnapshot.chanID] = state
                }
            },
            finish: { [weak self] (chanID: Int) in
                self?.serviceStateQueue.async {
                    self?.tcpConnectionStates.removeValue(forKey: chanID)
                    self?.tcpConnectionObjects.removeValue(forKey: chanID)
                }
            }
        )
        serviceStateQueue.async {
            self.tcpConnectionObjects[acceptSnapshot.chanID] = proxy
            self.tcpConnectionStates[acceptSnapshot.chanID] = proxy.snapshot()
            proxy.start()
        }
    }

    private func connectionsSnapshot() -> [String: Any] {
        serviceStateQueue.sync {
            let tcpOverlayRows = sharedTcpOverlayTransportOwner?.connectionRows()
            let udpOverlayRows = sharedUdpOverlayTransportOwner?.connectionRows()
            let tcpListeningRows = ownServerSpecs
                .filter { $0.listenProtocol == "tcp" && $0.targetProtocol == "tcp" }
                .map { spec in
                    [
                        "protocol": "tcp",
                        "role": "server",
                        "state": "listening",
                        "chan_id": NSNull(),
                        "svc_id": spec.svcID,
                        "service_name": spec.name ?? "",
                        "source": NSNull(),
                        "local": ["host": spec.listenBind, "port": spec.listenPort],
                        "local_port": spec.listenPort,
                        "remote_destination": ["host": spec.targetHost, "port": spec.targetPort],
                        "stats": ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0],
                    ] as [String: Any]
                }
            let udpListeningRows = ownServerSpecs
                .filter { $0.listenProtocol == "udp" && $0.targetProtocol == "udp" }
                .map { spec in
                    [
                        "protocol": "udp",
                        "role": "server",
                        "state": "listening",
                        "chan_id": NSNull(),
                        "svc_id": spec.svcID,
                        "service_name": spec.name ?? "",
                        "source": NSNull(),
                        "local": ["host": spec.listenBind, "port": spec.listenPort],
                        "local_port": spec.listenPort,
                        "remote_destination": ["host": spec.targetHost, "port": spec.targetPort],
                        "stats": ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0],
                    ] as [String: Any]
                }
            let udpConnectedRows = udpConnectionStates.values.map { $0 } + (tcpOverlayRows?.udp ?? []) + (udpOverlayRows?.udp ?? [])
            let tcpConnectedRows = tcpConnectionStates.values.map { $0 } + (tcpOverlayRows?.tcp ?? []) + (udpOverlayRows?.tcp ?? [])
            let udpRows = (udpConnectedRows + udpListeningRows).sorted { lhs, rhs in
                let leftListening = String(describing: lhs["state"] ?? "") == "listening"
                let rightListening = String(describing: rhs["state"] ?? "") == "listening"
                if leftListening != rightListening {
                    return !leftListening && rightListening
                }
                let leftChan = lhs["chan_id"] as? Int ?? -1
                let rightChan = rhs["chan_id"] as? Int ?? -1
                return leftChan < rightChan
            }
            let tcpRows = (tcpConnectedRows + tcpListeningRows).sorted { lhs, rhs in
                let leftListening = String(describing: lhs["state"] ?? "") == "listening"
                let rightListening = String(describing: rhs["state"] ?? "") == "listening"
                if leftListening != rightListening {
                    return !leftListening && rightListening
                }
                let leftChan = lhs["chan_id"] as? Int ?? -1
                let rightChan = rhs["chan_id"] as? Int ?? -1
                return leftChan < rightChan
            }
            return [
                "udp": udpRows,
                "tcp": tcpRows,
                "tun": [],
                "counts": [
                    "udp": udpConnectedRows.count,
                    "tcp": tcpConnectedRows.count,
                    "tun": 0,
                    "udp_listening": udpListeningRows.count,
                    "tcp_listening": tcpListeningRows.count,
                    "tun_listening": 0,
                ],
            ]
        }
    }

    private func controlActionSnapshot() -> [String: Any] {
        [
            "restart_supported": true,
            "reconnect_supported": true,
            "shutdown_supported": true,
            "restart_count": restartCount,
            "reconnect_count": reconnectCount,
            "shutdown_requested": shutdownRequestedAt != nil,
            "shutdown_requested_unix_ts": shutdownRequestedAt.map { Int($0.timeIntervalSince1970) } ?? NSNull(),
        ]
    }

    private func adminRuntimeDependenciesPayload() -> [String: Any] {
        [
            "ok": true,
            "missing": [],
            "install_hint": "",
        ]
    }

    private func adminUIPayload() -> [String: Any] {
        let bootstrapState = ObstacleBridgeRuntimeConfig.adminUIBootstrapState(from: runtimeConfig)
        return [
            "home_tab_enabled": true,
            "landing_page_enabled": false,
            "security_advisor_enabled": !(Self.boolValue(from: runtimeConfig["admin_web_security_advisor_disable"]) ?? false),
            "security_advisor_startup_enabled": !(Self.boolValue(from: runtimeConfig["admin_web_security_advisor_startup_disable"]) ?? false),
            "first_tab": Self.stringValue(from: runtimeConfig["admin_web_first_tab"]) ?? "home",
            "first_start_detected": bootstrapState.firstStartDetected,
            "config_file_state": bootstrapState.configFileState,
            "platform": "darwin",
            "runtime_dependencies": adminRuntimeDependenciesPayload(),
        ]
    }

    private func securityAdvisorPayload() -> [String: Any] {
        let enabled = !(Self.boolValue(from: runtimeConfig["admin_web_security_advisor_disable"]) ?? false)
        let bind = (Self.stringValue(from: runtimeConfig["admin_web_bind"]) ?? bindHost).trimmingCharacters(in: .whitespacesAndNewlines)
        let adminLocalOnly = Self.isLoopbackHost(bind)
        let secureMode = (Self.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let securePSK = Self.stringValue(from: runtimeConfig["secure_link_psk"]) ?? ""
        let authDisabled = Self.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false
        var findings: [[String: Any]] = []
        if enabled {
            if (Self.boolValue(from: runtimeConfig["admin_web"]) ?? false), authDisabled {
                let adminMessage = adminLocalOnly
                    ? "Admin Web password protection is recommended even on localhost-only setups. Enable admin authentication in the configuration unless you intentionally want friction-free local access."
                    : "Admin Web is reachable beyond localhost and admin authentication is disabled in the configuration. This should be treated as a warning. Enable admin authentication or bind Admin Web to localhost."
                findings.append([
                    "id": "admin_auth_disabled",
                    "severity": adminLocalOnly ? "recommended" : "warning",
                    "title": "Protect Admin Web",
                    "message": adminMessage,
                    "action_label": "Open Configuration",
                    "action_target": "configuration",
                ])
            }
            if ["", "off", "none"].contains(secureMode) {
                let message = adminLocalOnly
                    ? "SecureLink is currently disabled. That can be acceptable for localhost-only or lab-style setups, but enabling SecureLink is still recommended."
                    : "This node is not localhost-only and SecureLink is currently disabled. Running without SecureLink should be treated as a warning. Start with PSK for quick protection or move to certificates for deployment-grade trust."
                findings.append([
                    "id": "secure_link_disabled",
                    "severity": adminLocalOnly ? "recommended" : "warning",
                    "title": "Enable SecureLink",
                    "message": message,
                    "action_label": "Open Secure-Link",
                    "action_target": "secure-link",
                ])
            } else if secureMode == "psk" {
                if securePSK.trimmingCharacters(in: .whitespacesAndNewlines).count < 12 {
                    findings.append([
                        "id": "secure_link_psk_weak",
                        "severity": "recommended",
                        "title": "Strengthen PSK",
                        "message": "SecureLink PSK is enabled, but the configured secret looks short. Use a stronger shared secret for better protection.",
                        "action_label": "Open Configuration",
                        "action_target": "configuration",
                    ])
                }
                findings.append([
                    "id": "secure_link_cert_followup",
                    "severity": "informational",
                    "title": "Plan Certificate Trust",
                    "message": "PSK is a good quick-start protection mode. For longer-lived deployments, certificate-based SecureLink provides a stronger operational trust model.",
                    "action_label": "Open Secure-Link",
                    "action_target": "secure-link",
                ])
            }
        }
        let highest: String
        if findings.contains(where: { String(describing: $0["severity"] ?? "") == "critical" }) {
            highest = "critical"
        } else if findings.contains(where: { String(describing: $0["severity"] ?? "") == "warning" }) {
            highest = "warning"
        } else if findings.contains(where: { String(describing: $0["severity"] ?? "") == "recommended" }) {
            highest = "recommended"
        } else {
            highest = "informational"
        }
        let summary: String
        if !enabled {
            summary = "Security advisor disabled."
        } else if findings.isEmpty {
            summary = "Current settings look reasonably hardened for this first implementation slice."
        } else if highest == "critical" {
            summary = "Security advisor found settings that should be addressed before wider exposure."
        } else if highest == "warning" {
            summary = "Security advisor found warning-level hardening issues for this node."
        } else if highest == "recommended" {
            summary = "Security advisor found recommended hardening steps for this node."
        } else {
            summary = "Security advisor found optional follow-up improvements."
        }
        return [
            "enabled": enabled,
            "summary": summary,
            "highest_severity": highest,
            "findings": findings,
        ]
    }

    private func maskedRuntimeConfigSnapshot() -> [String: Any] {
        var payload = runtimeConfig
        if payload["overlay_transport"] == nil {
            payload["overlay_transport"] = "myudp"
        }
        if payload["client_restart_if_disconnected"] == nil {
            payload["client_restart_if_disconnected"] = 0.0
        }
        if payload["overlay_reconnect_retry_delay_ms"] == nil {
            payload["overlay_reconnect_retry_delay_ms"] = 30000
        }
        if payload["udp_bind"] == nil {
            payload["udp_bind"] = "::"
        }
        if payload["udp_own_port"] == nil {
            payload["udp_own_port"] = 4433
        }
        if payload["udp_peer"] == nil {
            payload["udp_peer"] = NSNull()
        }
        if payload["udp_peer_port"] == nil {
            payload["udp_peer_port"] = 4433
        }
        if payload["udp_peer_resolve_family"] == nil {
            payload["udp_peer_resolve_family"] = "prefer-ipv6"
        }
        if payload["tcp_bind"] == nil {
            payload["tcp_bind"] = "::"
        }
        if payload["tcp_own_port"] == nil {
            payload["tcp_own_port"] = 8081
        }
        if payload["tcp_peer"] == nil {
            payload["tcp_peer"] = NSNull()
        }
        if payload["tcp_peer_port"] == nil {
            payload["tcp_peer_port"] = 8081
        }
        if payload["tcp_peer_resolve_family"] == nil {
            payload["tcp_peer_resolve_family"] = "prefer-ipv6"
        }
        if payload["tcp_bp_wbuf_threshold"] == nil {
            payload["tcp_bp_wbuf_threshold"] = 128 * 1024
        }
        if payload["own_servers"] == nil {
            payload["own_servers"] = []
        }
        if payload["remote_servers"] == nil {
            payload["remote_servers"] = []
        }
        for key in ["admin_web_password", "secure_link_psk"] where payload[key] != nil {
            payload[key] = ""
        }
        return payload
    }

    private func adminAuthUsername() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_username"]) ?? ""
    }

    private func adminAuthPassword() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_password"]) ?? ""
    }

    private func pruneAuthState() {
        let now = Date().timeIntervalSince1970
        authChallenges = authChallenges.filter { _, item in
            (item["expires_at"] as? TimeInterval ?? 0) > now
        }
        configChallenges = configChallenges.filter { _, item in
            (item["expires_at"] as? TimeInterval ?? 0) > now
        }
        authSessions = authSessions.filter { _, expiresAt in
            expiresAt > now
        }
    }

    private func resetAuthState() {
        authChallenges.removeAll()
        configChallenges.removeAll()
        authSessions.removeAll()
    }

    private func parseCookieHeader(_ headers: [String: String]) -> [String: String] {
        let raw = headers["cookie"] ?? ""
        var cookies: [String: String] = [:]
        for part in raw.split(separator: ";") {
            let item = String(part).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !item.isEmpty, let equals = item.firstIndex(of: "=") else {
                continue
            }
            let key = String(item[..<equals]).trimmingCharacters(in: .whitespacesAndNewlines)
            let value = String(item[item.index(after: equals)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            cookies[key] = value
        }
        return cookies
    }

    private func sessionCookieName() -> String {
        let scope = [bindHost, String(statusPort), Self.stringValue(from: runtimeConfig["admin_web_path"]) ?? "/"].joined(separator: "|")
        let digest = SHA256.hash(data: Data(scope.utf8)).map { String(format: "%02x", $0) }.joined()
        return "admin_web_session_\(digest.prefix(12))"
    }

    private static func isLoopbackHost(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return false
        }
        let lowered = trimmed.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if lowered == "localhost" || lowered == "ip6-localhost" {
            return true
        }
        return lowered == "127.0.0.1" || lowered == "::1"
    }

    private func adminWebToken() -> String {
        Self.stringValue(from: runtimeConfig["admin_web_token"]) ?? ""
    }

    private func validateAdminWebToken(headers: [String: String]) -> ObstacleBridgeAdminAPIResponse? {
        let token = adminWebToken().trimmingCharacters(in: .whitespacesAndNewlines)
        if token.isEmpty {
            return nil
        }
        if (headers["authorization"] ?? "") == "Bearer \(token)" {
            return nil
        }
        return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 403 Forbidden", body: "Forbidden")
    }

    private func buildAuthProof(seed: String, username: String, password: String) -> String {
        SHA256.hash(data: Data("\(seed):\(username):\(password)".utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func canonicalConfigUpdateData(_ updates: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: updates, options: [.sortedKeys])
    }

    private func configUpdateDigest(_ updates: [String: Any]) throws -> String {
        let data = try canonicalConfigUpdateData(updates)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func issueConfigChallenge(updates: [String: Any]) throws -> [String: Any] {
        let challengeID = UUID().uuidString.lowercased()
        let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + challengeID
        let updatesDigest = try configUpdateDigest(updates)
        authStateQueue.sync {
            pruneAuthState()
            configChallenges[challengeID] = [
                "seed": seed,
                "updates_digest": updatesDigest,
                "expires_at": Date().timeIntervalSince1970 + Self.configChallengeTTL,
            ]
        }
        return [
            "challenge_id": challengeID,
            "seed": seed,
            "updates_digest": updatesDigest,
        ]
    }

    private func validateConfigChallenge(challengeID: String, proof: String, updates: [String: Any]) -> String? {
        authStateQueue.sync {
            pruneAuthState()
            guard let challenge = configChallenges.removeValue(forKey: challengeID) else {
                return "invalid or expired configuration change challenge"
            }
            let updatesDigest: String
            do {
                updatesDigest = try configUpdateDigest(updates)
            } catch {
                return "failed to digest configuration updates"
            }
            guard updatesDigest == String(describing: challenge["updates_digest"] ?? "") else {
                return "configuration update payload mismatch"
            }
            let expected = buildConfigProof(
                seed: String(describing: challenge["seed"] ?? ""),
                username: adminAuthUsername(),
                password: adminAuthPassword(),
                updatesDigest: updatesDigest
            )
            return proof == expected ? nil : "configuration change confirmation failed"
        }
    }

    private func buildConfigProof(seed: String, username: String, password: String, updatesDigest: String) -> String {
        SHA256.hash(data: Data("\(seed):\(username):\(password):\(updatesDigest)".utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func onboardingConnectionProfiles() -> [[String: Any]] {
        ObstacleBridgeOnboarding.connectionProfiles(runtimeConfig: runtimeConfig)
    }

    private func onboardingBlueprints() -> [[String: Any]] {
        []
    }

    private func sanitizeOnboardingServices(_ value: Any?) -> [[String: Any]] {
        ObstacleBridgeOnboarding.sanitizeServices(value)
    }

    private func onboardingTokenPayload(
        connection: [String: Any],
        ownServices: [[String: Any]],
        remoteServices: [[String: Any]],
        requestPayload: [String: Any] = [:]
    ) -> [String: Any] {
        ObstacleBridgeOnboarding.tokenPayload(
            runtimeConfig: ObstacleBridgeOnboarding.tokenRuntimeConfig(
                runtimeConfig: runtimeConfig,
                requestPayload: requestPayload
            ),
            connection: connection,
            ownServices: ownServices,
            remoteServices: remoteServices,
            encryptSecrets: ObstacleBridgeConfigSecretCodec.encryptPayload
        )
    }

    private func encodeOnboardingToken(_ payload: [String: Any]) throws -> String {
        try ObstacleBridgeOnboarding.encodeToken(payload)
    }

    private func decodeOnboardingToken(_ token: String) throws -> [String: Any] {
        try ObstacleBridgeOnboarding.decodeToken(token)
    }

    private func onboardingUpdates(from payload: [String: Any]) throws -> [String: Any] {
        try ObstacleBridgeOnboarding.updates(
            from: payload,
            decryptSecrets: ObstacleBridgeConfigSecretCodec.decryptPayload
        )
    }

    private func normalizedConfigUpdates(_ updates: [String: Any]) -> [String: Any] {
        var normalized = updates
        if (normalized["admin_web_auth_disable"] as? Bool) == true {
            normalized["admin_web_username"] = ""
            normalized["admin_web_password"] = ""
        } else if
            let password = normalized["admin_web_password"] as? String,
            password.isEmpty,
            (Self.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false),
            normalized["admin_web_auth_disable"] == nil
        {
            normalized["admin_web_username"] = ""
            normalized["admin_web_auth_disable"] = true
        }
        return normalized
    }

    private func persistConfigUpdates(_ updates: [String: Any]) throws {
        let grouped = ObstacleBridgeRuntimeConfig.looksGrouped(runtimeConfigRaw)
        var nextRaw = runtimeConfigRaw
        let normalized = normalizedConfigUpdates(updates)
        for (key, rawValue) in normalized {
            guard let schemaRow = configStore.schemaRow(forKey: key) else {
                throw ObstacleBridgeHostRunnerError.invalidArgument("unknown config key: \(key)")
            }
            let defaultValue = schemaRow["default"]
            let value: Any
            switch defaultValue {
            case is Bool:
                guard let boolValue = rawValue as? Bool else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("\(key) expects boolean")
                }
                value = boolValue
            case is Int:
                guard let intValue = rawValue as? Int else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("\(key) expects integer")
                }
                value = intValue
            case is Double:
                if let doubleValue = rawValue as? Double {
                    value = doubleValue
                } else if let intValue = rawValue as? Int {
                    value = Double(intValue)
                } else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("\(key) expects number")
                }
            case is String:
                guard let stringValue = rawValue as? String else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("\(key) expects string")
                }
                value = stringValue
            case is [Any]:
                guard let listValue = rawValue as? [Any] else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("\(key) expects list")
                }
                value = listValue
            default:
                value = rawValue
            }

            if grouped, let section = configStore.sectionName(forKey: key) {
                var block = (nextRaw[section] as? [String: Any]) ?? [:]
                block[key] = value
                nextRaw[section] = block
            } else {
                nextRaw[key] = value
            }
        }

        let persistedPayload = try ObstacleBridgeConfigSecretCodec.encryptPayload(nextRaw)
        let data = try JSONSerialization.data(withJSONObject: persistedPayload, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: runtimeConfigPath), options: [.atomic])
        runtimeConfigRaw = nextRaw
        runtimeConfig = ObstacleBridgeRuntimeConfig.flatten(nextRaw)
        configStore.updateConfigs(groupedConfig: nextRaw, runtimeConfig: runtimeConfig)
    }

    private func issueSessionHeaders() -> [(String, String)] {
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        authStateQueue.sync {
            pruneAuthState()
            authSessions[token] = Date().timeIntervalSince1970 + Self.authSessionTTL
        }
        return [("Set-Cookie", "\(sessionCookieName())=\(token); Path=/; HttpOnly; SameSite=Strict")]
    }

    private func requestRestart() -> [String: Any] {
        do {
            try reloadRuntimeStateForControlAction()
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
                "restart_requested": false,
                "control_actions": controlActionSnapshot(),
            ]
        }
        restartCount += 1
        return [
            "ok": true,
            "restart_requested": true,
            "restart_supported": true,
            "restart_delay_sec": 0,
            "restart_mode": "immediate",
            "restart_embedded": true,
            "control_actions": controlActionSnapshot(),
            "bootstrap_state": bootstrapState,
        ]
    }

    private func requestReconnect() -> [String: Any] {
        do {
            try reloadRuntimeStateForControlAction()
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
                "reconnect_requested": false,
                "control_actions": controlActionSnapshot(),
            ]
        }
        reconnectCount += 1
        return [
            "ok": true,
            "reconnect_requested": true,
            "reconnect_supported": true,
            "restart_embedded": true,
            "control_actions": controlActionSnapshot(),
            "bootstrap_state": bootstrapState,
        ]
    }

    private func requestShutdown() -> [String: Any] {
        shutdownRequestedAt = Date()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) {
            exit(0)
        }
        return [
            "ok": true,
            "shutdown_requested": true,
            "control_actions": controlActionSnapshot(),
        ]
    }

    private func prepareSharedOverlayBootstrap() {
        sharedTcpOverlayTransportOwner?.stop()
        sharedUdpOverlayTransportOwner?.stop()
        sharedCompressLayerRuntime = nil
        sharedSecureLinkPskTransportAdapter = nil
        sharedOverlayLayerTransportAdapter = nil
        sharedWebSocketOverlayRuntime = nil
        sharedTcpOverlayRuntime = nil
        sharedTcpOverlayTransportOwner = nil
        sharedUdpOverlayTransportOwner = nil
        bootstrapState = [:]

        do {
            let settings = try ObstacleBridgeOverlayBootstrapSettings(payload: runtimeConfig)
            var summary = settings.summary(runtimeConfigGrouped: ObstacleBridgeRuntimeConfig.looksGrouped(runtimeConfigRaw))

            if settings.compressWrapped {
                let allowedMTypes = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["compress_layer_types"]) ?? "data,data_frag"
                let level = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_level"]) ?? 3
                let minBytes = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_min_bytes"]) ?? 64
                sharedCompressLayerRuntime = ObstacleBridgeCompressLayerRuntime(
                    configuredEnabled: settings.compressEnabled,
                    algorithm: settings.compressAlgo,
                    transportName: settings.transport,
                    level: level,
                    minBytes: minBytes,
                    allowedMTypesRaw: allowedMTypes,
                    peerSelectedLevel: level,
                    peerSelectedMinBytes: minBytes,
                    peerSelectedAllowedMTypesRaw: allowedMTypes
                )
                summary["compress_runtime"] = "ready"
                summary["compress_layer_types"] = allowedMTypes
            }

            if settings.secureLinkMode == "psk" {
                sharedSecureLinkPskTransportAdapter = ObstacleBridgeSecureLinkPskTransportAdapter(
                    runtime: ObstacleBridgeSecureLinkPskRuntime(
                        clientMode: settings.peerHost != nil,
                        psk: settings.secureLinkPSK
                    )
                )
                summary["secure_link_runtime"] = "ready"
            }

            if sharedCompressLayerRuntime != nil || sharedSecureLinkPskTransportAdapter != nil {
                sharedOverlayLayerTransportAdapter = ObstacleBridgeOverlayLayerTransportAdapter(
                    compressRuntime: sharedCompressLayerRuntime,
                    secureLinkAdapter: sharedSecureLinkPskTransportAdapter
                )
            }

            if settings.transport == "ws" {
                let payloadMode = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["ws_payload_mode"]) ?? "binary"
                let maxSize = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["ws_max_size"]) ?? 65535
                let sendTimeout = ObstacleBridgeRuntimeConfig.doubleValue(from: runtimeConfig["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = ObstacleBridgeRuntimeConfig.doubleValue(from: runtimeConfig["ws_reconnect_grace"]) ?? 3.0
                sharedWebSocketOverlayRuntime = try ObstacleBridgeWebSocketOverlayRuntime(
                    payloadMode: payloadMode,
                    wsMaxSize: maxSize,
                    sendTimeoutS: sendTimeout,
                    tcpUserTimeoutMS: tcpUserTimeout,
                    reconnectGraceS: reconnectGrace
                )
                summary["websocket_runtime"] = "ready"
                summary["ws_payload_mode"] = payloadMode
            }

            if settings.transport == "tcp" {
                let threshold = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                sharedTcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                summary["tcp_runtime"] = "ready"
                summary["tcp_bp_wbuf_threshold"] = threshold
            }

            if settings.transport == "myudp" {
                summary["udp_runtime"] = "ready"
            }

            summary["admin_web_enabled"] = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["admin_web"]) ?? false
            summary["admin_web_bind"] = bindHost
            summary["admin_web_port"] = statusPort
            bootstrapState = summary
        } catch {
            bootstrapState = [
                "status": "failed",
                "overlay_transport": ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp",
                "error": error.localizedDescription,
                "admin_web_bind": bindHost,
                "admin_web_port": statusPort,
            ]
        }
    }

    static func stringValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfig.stringValue(from: value)
    }

    private static func intValue(from value: Any?) -> Int? {
        ObstacleBridgeRuntimeConfig.intValue(from: value)
    }

    private static func doubleValue(from value: Any?) -> Double? {
        ObstacleBridgeRuntimeConfig.doubleValue(from: value)
    }

    private static func boolValue(from value: Any?) -> Bool? {
        ObstacleBridgeRuntimeConfig.boolValue(from: value)
    }

    private static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        ObstacleBridgeRuntimeConfig.peerHost(for: transport, payload: payload)
    }

    private func startSharedTCPOverlayTransportOwnerIfNeeded() {
        guard let runtime = sharedTcpOverlayRuntime,
              (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "").lowercased() == "tcp"
        else {
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? ""
        let peerPort = Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? 0
        let bindHost = Self.stringValue(from: runtimeConfig["tcp_bind"]) ?? "0.0.0.0"
        let bindPort = Self.intValue(from: runtimeConfig["tcp_own_port"]) ?? 0
        guard (!peerHost.isEmpty && peerPort > 0) || bindPort > 0 else {
            return
        }
        let owner = ObstacleBridgeTcpOverlayTransportOwner(
            peerHost: peerHost,
            peerPort: peerPort,
            bindHost: bindHost,
            bindPort: bindPort,
            overlayRuntime: runtime,
            reconnectRetryDelayMS: Self.intValue(from: runtimeConfig["overlay_reconnect_retry_delay_ms"]) ?? 30000,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") })
        )
        sharedTcpOverlayTransportOwner = owner
        owner.start()
    }

    private func startSharedUDPOverlayTransportOwnerIfNeeded() throws {
        guard (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased() == "myudp" else {
            return
        }
        let bindHost = Self.stringValue(from: runtimeConfig["udp_bind"]) ?? "0.0.0.0"
        let bindPort = Self.intValue(from: runtimeConfig["udp_own_port"]) ?? 0
        guard bindPort >= 0 else {
            return
        }
        let peerHost = Self.stringValue(from: runtimeConfig["udp_peer"])
        let peerPort = Self.intValue(from: runtimeConfig["udp_peer_port"])
        let owner = ObstacleBridgeUdpOverlayTransportOwner(
            bindHost: bindHost,
            bindPort: bindPort,
            peerHost: peerHost,
            peerPort: peerPort,
            sessionMaxAppPayload: ObstacleBridgeRuntimeConfig.overlaySessionMaxAppPayload(from: runtimeConfig),
            overlayLayerTransportAdapter: sharedOverlayLayerTransportAdapter,
            startupMuxFrames: remoteServiceCatalogMuxFrames(),
            queue: serviceStateQueue,
            serviceNameByID: Dictionary(uniqueKeysWithValues: ownServerSpecs.map { ($0.svcID, $0.name ?? "") })
        )
        sharedUdpOverlayTransportOwner = owner
        try owner.start()
    }

    private func remoteServiceCatalogMuxFrames() -> [Data] {
        guard !remoteServerSpecs.isEmpty else {
            return []
        }
        do {
            let specs = remoteServerSpecs.map { $0.toChannelMuxServiceSpec() }
            let payload = try ObstacleBridgeChannelMuxCodec.encodeRemoteServicesSetV2(
                instanceID: 0,
                connectionSeq: 0,
                services: specs
            )
            if ObstacleBridgeChannelMuxCodec.muxHeaderSize + payload.count <= 65535 {
                return [
                    try ObstacleBridgeChannelMuxCodec.packMux(
                        chanID: 0,
                        proto: .udp,
                        counter: 0,
                        mtype: .remoteServicesSetV2,
                        body: payload
                    )
                ]
            }
            let tx = ObstacleBridgeChannelMuxCodec.nextControlChunkTxID(current: 1)
            let chunks = ObstacleBridgeChannelMuxCodec.chunkControlPayload(
                txID: tx.txID,
                maxAppPayload: 65535,
                payload: payload
            )
            return try chunks.enumerated().map { index, chunk in
                try ObstacleBridgeChannelMuxCodec.packMux(
                    chanID: 0,
                    proto: .udp,
                    counter: index & 0xFFFF,
                    mtype: .remoteServicesSetV2Chunk,
                    body: chunk
                )
            }
        } catch {
            return []
        }
    }

    private func hasConfiguredOverlayPeer() -> Bool {
        let transport = (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased()
        if transport == "tcp" {
            let peerHost = (Self.stringValue(from: runtimeConfig["tcp_peer"]) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let peerPort = Self.intValue(from: runtimeConfig["tcp_peer_port"]) ?? 0
            return !peerHost.isEmpty && peerPort > 0
        }
        if transport == "myudp" {
            let peerHost = (Self.stringValue(from: runtimeConfig["udp_peer"]) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let peerPort = Self.intValue(from: runtimeConfig["udp_peer_port"]) ?? 0
            return !peerHost.isEmpty && peerPort > 0
        }
        return false
    }

    private func overlayCurrentlyConnected() -> Bool? {
        let transport = (Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp").lowercased()
        if transport == "tcp" {
            return sharedTcpOverlayTransportOwner?.transportSnapshot()["overlay_connected"] as? Bool
        }
        if transport == "myudp" {
            return sharedUdpOverlayTransportOwner?.transportSnapshot()["overlay_connected"] as? Bool
        }
        return nil
    }

    private func startClientRestartWatchdog() {
        clientRestartWatchdog?.cancel()
        clientRestartWatchdog = nil
        overlayDisconnectedAt = nil

        let timer = DispatchSource.makeTimerSource(queue: serviceStateQueue)
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            let timeout = Self.doubleValue(from: self.runtimeConfig["client_restart_if_disconnected"]) ?? 0.0
            if timeout <= 0 || !self.hasConfiguredOverlayPeer() {
                self.overlayDisconnectedAt = nil
                return
            }
            guard let connected = self.overlayCurrentlyConnected() else {
                self.overlayDisconnectedAt = nil
                return
            }
            if connected {
                self.overlayDisconnectedAt = nil
                return
            }
            let now = Date().timeIntervalSince1970
            let disconnectedAt = self.overlayDisconnectedAt ?? now
            self.overlayDisconnectedAt = disconnectedAt
            if (now - disconnectedAt) < timeout {
                return
            }
            self.overlayDisconnectedAt = now
            _ = self.requestRestart()
        }
        clientRestartWatchdog = timer
        timer.resume()
    }
}

extension ObstacleBridgeHostRunner: ObstacleBridgeAdminAPIStateProvider {
    func adminStatusSnapshot() -> [String: Any] {
        snapshot()
    }

    func adminConnectionsSnapshot() -> [String: Any] {
        connectionsSnapshot()
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        peersSnapshot()
    }

    func adminMetaSnapshot() -> [String: Any] {
        metaSnapshot()
    }

    func adminConfigSnapshot() -> [String: Any] {
        [
            "config": maskedRuntimeConfigSnapshot(),
            "schema": configStore.schemaSnapshot(),
        ]
    }

    func adminOnboardingConnectionProfiles() -> [[String: Any]] {
        onboardingConnectionProfiles()
    }

    func adminOnboardingBlueprints() -> [[String: Any]] {
        onboardingBlueprints()
    }

    func adminOnboardingInviteGenerate(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard let body = request.body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let profiles = onboardingConnectionProfiles()
        let connectionID = (payload["connection_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let selectedConnection: [String: Any]?
        if profiles.count > 1 && connectionID.isEmpty {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "multiple connection profiles available; select connection_id",
                "profiles": profiles,
            ], statusLine: "HTTP/1.1 409 Conflict")
        }
        if !connectionID.isEmpty {
            selectedConnection = profiles.first { String(describing: $0["id"] ?? "") == connectionID }
            if selectedConnection == nil {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": "unknown connection_id: \(connectionID)",
                ], statusLine: "HTTP/1.1 400 Bad Request")
            }
        } else {
            selectedConnection = profiles.first
        }
        let own = sanitizeOnboardingServices(payload["own_servers"] ?? runtimeConfig["own_servers"])
        let remote = sanitizeOnboardingServices(payload["remote_servers"] ?? runtimeConfig["remote_servers"])
        let preview = onboardingTokenPayload(
            connection: selectedConnection ?? [:],
            ownServices: own,
            remoteServices: remote,
            requestPayload: payload
        )
        do {
            let token = try encodeOnboardingToken(preview)
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "invite_token": token,
                "preview": preview,
            ])
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "failed to encode invite token",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
    }

    func adminOnboardingInvitePreview(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard let body = request.body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let token = (payload["invite_token"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invite_token is required",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        do {
            let decoded = try decodeOnboardingToken(token)
            var preview = decoded
            if let psk = preview["secure_link_psk"] as? String, !psk.isEmpty {
                preview["secure_link_psk"] = "***hidden***"
                preview["secure_link_psk_present"] = true
            }
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "preview": preview,
                "suggested_updates": try onboardingUpdates(from: decoded),
            ])
        } catch let error as ObstacleBridgeHostRunnerError {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error.localizedDescription,
            ], statusLine: "HTTP/1.1 400 Bad Request")
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error.localizedDescription,
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
    }

    func adminConfigChallenge(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard let body = request.body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let updates = payload["updates"] as? [String: Any] ?? [:]
        guard adminAuthRequired() else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
            ])
        }
        guard adminIsAuthenticated(headers: request.headers) else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "authentication required",
            ], statusLine: "HTTP/1.1 401 Unauthorized")
        }
        do {
            let challenge = try issueConfigChallenge(updates: updates)
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": true,
                "challenge_id": challenge["challenge_id"] as? String ?? "",
                "seed": challenge["seed"] as? String ?? "",
                "updates_digest": challenge["updates_digest"] as? String ?? "",
            ])
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "failed to issue configuration change challenge",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
    }

    func adminAuthRequired() -> Bool {
        if Self.boolValue(from: runtimeConfig["admin_web_auth_disable"]) ?? false {
            return false
        }
        return !adminAuthUsername().isEmpty && !adminAuthPassword().isEmpty
    }

    func adminIsAuthenticated(headers: [String: String]) -> Bool {
        if !adminAuthRequired() {
            return true
        }
        return authStateQueue.sync {
            pruneAuthState()
            let token = parseCookieHeader(headers)[sessionCookieName()] ?? ""
            return !token.isEmpty && authSessions[token] != nil
        }
    }

    func adminAuthState(headers: [String: String]) -> [String: Any] {
        [
            "ok": true,
            "auth_required": adminAuthRequired(),
            "authenticated": adminIsAuthenticated(headers: headers),
            "username": adminAuthRequired() ? adminAuthUsername() : "",
        ]
    }

    func adminAuthChallenge(method: String) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "GET" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard adminAuthRequired() else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
            ])
        }
        return authStateQueue.sync {
            pruneAuthState()
            let challengeID = UUID().uuidString.lowercased()
            let seed = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() + challengeID
            authChallenges[challengeID] = [
                "seed": seed,
                "expires_at": Date().timeIntervalSince1970 + Self.authChallengeTTL,
            ]
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": true,
                "challenge_id": challengeID,
                "seed": seed,
                "algorithm": "sha256(seed:username:password)",
            ])
        }
    }

    func adminAuthLogin(method: String, body: Data?) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard adminAuthRequired() else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": true,
                "auth_required": false,
                "authenticated": true,
            ], headers: issueSessionHeaders())
        }
        guard let body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let challengeID = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let seed: String? = authStateQueue.sync {
            pruneAuthState()
            let item = authChallenges.removeValue(forKey: challengeID)
            return item?["seed"] as? String
        }
        guard let seed else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "invalid or expired challenge",
            ], statusLine: "HTTP/1.1 403 Forbidden")
        }
        let expected = buildAuthProof(seed: seed, username: adminAuthUsername(), password: adminAuthPassword())
        guard proof == expected else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "authenticated": false,
                "error": "authentication failed",
            ], statusLine: "HTTP/1.1 403 Forbidden")
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "authenticated": true,
        ], headers: issueSessionHeaders())
    }

    func adminAuthLogout(method: String, headers: [String: String]) -> ObstacleBridgeAdminAPIResponse {
        guard method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        let token = parseCookieHeader(headers)[sessionCookieName()] ?? ""
        if !token.isEmpty {
            _ = authStateQueue.sync {
                authSessions.removeValue(forKey: token)
            }
        }
        return ObstacleBridgeAdminAPI.jsonResponse([
            "ok": true,
            "authenticated": false,
        ], headers: [("Set-Cookie", "\(sessionCookieName())=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])
    }

    func adminUpdateConfig(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        guard let body = request.body,
              let object = try? JSONSerialization.jsonObject(with: body),
              let payload = object as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "invalid JSON body",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        guard let updates = payload["updates"] as? [String: Any] else {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "updates must be an object",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }
        let restartAfterSave = (payload["restart_after_save"] as? Bool) ?? false
        if adminAuthRequired() {
            let challengeID = (payload["challenge_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let proof = (payload["proof"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !challengeID.isEmpty, !proof.isEmpty else {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": "configuration change confirmation required",
                ], statusLine: "HTTP/1.1 428 Precondition Required")
            }
            if let error = validateConfigChallenge(challengeID: challengeID, proof: proof, updates: updates) {
                return ObstacleBridgeAdminAPI.jsonResponse([
                    "ok": false,
                    "error": error,
                ], statusLine: "HTTP/1.1 403 Forbidden")
            }
        }
        do {
            try persistConfigUpdates(updates)
        } catch let error as ObstacleBridgeHostRunnerError {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": error.localizedDescription,
            ], statusLine: "HTTP/1.1 400 Bad Request")
        } catch {
            return ObstacleBridgeAdminAPI.jsonResponse([
                "ok": false,
                "error": "failed to persist runtime config",
            ], statusLine: "HTTP/1.1 400 Bad Request")
        }

        if updates.keys.contains(where: { ["admin_web_auth_disable", "admin_web_username", "admin_web_password", "secure_link_psk"].contains($0) }) {
            authStateQueue.sync {
                resetAuthState()
            }
        }

        let payloadResponse: [String: Any] = [
            "ok": true,
            "config": maskedRuntimeConfigSnapshot(),
            "restart_requested": restartAfterSave,
            "restart_supported": true,
            "restart_mode": restartAfterSave ? "immediate" : "",
            "restart_delay_sec": 0,
            "restart_embedded": restartAfterSave,
        ]
        if restartAfterSave {
            _ = requestRestart()
        }
        return ObstacleBridgeAdminAPI.jsonResponse(payloadResponse)
    }

    func adminRequestRestart(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = validateAdminWebToken(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestRestart())
    }

    func adminRequestReconnect(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = validateAdminWebToken(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestReconnect())
    }

    func adminRequestShutdown(request: ObstacleBridgeAdminAPIRequest) -> ObstacleBridgeAdminAPIResponse {
        guard request.method.uppercased() == "POST" else {
            return ObstacleBridgeAdminAPI.plainTextResponse(statusLine: "HTTP/1.1 405 Method Not Allowed", body: "Method Not Allowed")
        }
        if let forbidden = validateAdminWebToken(headers: request.headers) {
            return forbidden
        }
        return ObstacleBridgeAdminAPI.jsonResponse(requestShutdown())
    }

    func adminLogLines(limit: Int) -> [String] {
        readLogLines(limit: limit)
    }

    func adminRequestRestart() -> [String: Any] {
        requestRestart()
    }

    func adminRequestReconnect() -> [String: Any] {
        requestReconnect()
    }

    func adminRequestShutdown() -> [String: Any] {
        requestShutdown()
    }
}

struct ObstacleBridgeHostRunnerCLI {
    static let defaultRuntimeConfigName = "ObstacleBridge.cfg"

    let runtimeConfigPath: String
    let bindHost: String?
    let statusPort: Int?
    let holdSec: Double

    static func parse(_ args: [String]) throws -> ObstacleBridgeHostRunnerCLI {
        var runtimeConfigPath: String?
        var bindHost: String?
        var statusPort: Int?
        var holdSec = 0.0
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--runtime-config":
                index += 1
                guard index < args.count else {
                    throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
                }
                runtimeConfigPath = args[index]
            case "--bind-host":
                index += 1
                guard index < args.count else {
                    throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
                }
                bindHost = args[index]
            case "--status-port":
                index += 1
                guard index < args.count, let port = Int(args[index]) else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("--status-port requires an integer")
                }
                statusPort = port
            case "--hold-sec":
                index += 1
                guard index < args.count, let seconds = Double(args[index]) else {
                    throw ObstacleBridgeHostRunnerError.invalidArgument("--hold-sec requires a number")
                }
                holdSec = max(0.0, seconds)
            case "--help", "-h":
                throw ObstacleBridgeHostRunnerError.usage(Self.usageText())
            default:
                throw ObstacleBridgeHostRunnerError.invalidArgument("Unknown argument: \(arg)")
            }
            index += 1
        }
        return ObstacleBridgeHostRunnerCLI(
            runtimeConfigPath: runtimeConfigPath ?? defaultRuntimeConfigPath(),
            bindHost: bindHost,
            statusPort: statusPort,
            holdSec: holdSec
        )
    }

    private static func defaultRuntimeConfigPath() -> String {
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(defaultRuntimeConfigName)
            .path
    }

    static func usageText() -> String {
        "Usage: ObstacleBridgeHostRunner [--runtime-config <path>] [--bind-host <host>] [--status-port <port>] [--hold-sec <seconds>]"
    }
}
