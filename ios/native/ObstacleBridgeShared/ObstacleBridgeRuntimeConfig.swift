import Foundation
import Darwin

struct ObstacleBridgeDerivedTunnelSettings {
    let tunnelAddress: String
    let tunnelPrefix: Int
    let includedRoutes: [String]
    let excludedRoutes: [String]
    let tunnelAddress6: String
    let tunnelPrefix6: Int
    let includedRoutes6: [String]
    let excludedRoutes6: [String]
    let dnsServers: [String]
    let mtu: Int

    func applying(_ override: ObstacleBridgeTunnelRoutingOverride) -> ObstacleBridgeDerivedTunnelSettings {
        ObstacleBridgeDerivedTunnelSettings(
            tunnelAddress: override.tunnelAddress ?? tunnelAddress,
            tunnelPrefix: override.tunnelPrefix ?? tunnelPrefix,
            includedRoutes: override.includedRoutes ?? includedRoutes,
            excludedRoutes: override.excludedRoutes ?? excludedRoutes,
            tunnelAddress6: override.tunnelAddress6 ?? tunnelAddress6,
            tunnelPrefix6: override.tunnelPrefix6 ?? tunnelPrefix6,
            includedRoutes6: override.includedRoutes6 ?? includedRoutes6,
            excludedRoutes6: override.excludedRoutes6 ?? excludedRoutes6,
            dnsServers: override.dnsServers ?? dnsServers,
            mtu: override.mtu ?? mtu
        )
    }
}

struct ObstacleBridgeTunnelRoutingOverride {
    let tunnelAddress: String?
    let tunnelPrefix: Int?
    let tunnelGateway: String?
    let includedRoutes: [String]?
    let excludedRoutes: [String]?
    let tunnelAddress6: String?
    let tunnelPrefix6: Int?
    let tunnelGateway6: String?
    let includedRoutes6: [String]?
    let excludedRoutes6: [String]?
    let dnsServers: [String]?
    let mtu: Int?
}

struct ObstacleBridgeRuntimeServiceSpec {
    let svcID: Int
    let name: String?
    let listenProtocol: String
    let listenBind: String
    let listenPort: Int
    let targetProtocol: String
    let targetHost: String
    let targetPort: Int
    let lifecycleHooks: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?
    let options: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?

    var listenIfname: String? {
        listenProtocol == "tun" ? listenBind : nil
    }

    var targetIfname: String? {
        targetProtocol == "tun" ? targetHost : nil
    }

    func mtu(fallback: Int) -> Int {
        if listenProtocol == "tun" {
            return listenPort
        }
        if targetProtocol == "tun" {
            return targetPort
        }
        return fallback
    }

    func listenerHookEnvBlocks() -> [[String: Any]] {
        guard let lifecycleHooks,
              case .object(let listenerContainer)? = lifecycleHooks["listener"]
        else {
            return []
        }
        var out: [[String: Any]] = []
        for event in ["on_created", "on_channel_connected", "on_stopped"] {
            guard case .object(let command)? = listenerContainer[event],
                  case .object(let env)? = command["env"]
            else {
                continue
            }
            out.append(Self.foundationObject(from: env))
        }
        return out
    }

    func derivedLocalTunnelSettings(
        defaultTunnelAddress6: String,
        defaultTunnelPrefix6: Int,
        defaultIncludedRoutes: [String],
        defaultExcludedRoutes: [String],
        defaultIncludedRoutes6: [String],
        defaultExcludedRoutes6: [String],
        defaultDNS: [String],
        fallbackMTU: Int
    ) -> ObstacleBridgeDerivedTunnelSettings? {
        for env in listenerHookEnvBlocks() {
            guard let tunAddr = env["TUN_ADDR"] as? String,
                  let (addr, prefix) = Self.parseCIDR(tunAddr, maxPrefix: 32)
            else {
                continue
            }
            let tunnelAddr6 = (env["TUN_ADDR6"] as? String).flatMap { Self.parseCIDR($0, maxPrefix: 128) }
            return ObstacleBridgeDerivedTunnelSettings(
                tunnelAddress: addr,
                tunnelPrefix: prefix,
                includedRoutes: defaultIncludedRoutes,
                excludedRoutes: defaultExcludedRoutes,
                tunnelAddress6: tunnelAddr6?.0 ?? defaultTunnelAddress6,
                tunnelPrefix6: tunnelAddr6?.1 ?? defaultTunnelPrefix6,
                includedRoutes6: tunnelAddr6 == nil ? [] : defaultIncludedRoutes6,
                excludedRoutes6: tunnelAddr6 == nil ? [] : defaultExcludedRoutes6,
                dnsServers: defaultDNS,
                mtu: mtu(fallback: fallbackMTU)
            )
        }
        return nil
    }

    func derivedRemoteTunnelSettings(
        defaultTunnelPrefix: Int,
        defaultTunnelPrefix6: Int,
        defaultIncludedRoutes: [String],
        defaultExcludedRoutes: [String],
        defaultIncludedRoutes6: [String],
        defaultExcludedRoutes6: [String],
        defaultDNS: [String],
        fallbackMTU: Int
    ) -> ObstacleBridgeDerivedTunnelSettings? {
        for env in listenerHookEnvBlocks() {
            guard let peerAddr = env["PEER_ADDR"] as? String,
                  !peerAddr.isEmpty
            else {
                continue
            }
            let prefix = Self.parseCIDR(env["TUN_ADDR"] as? String ?? "", maxPrefix: 32)?.1
                ?? Self.parseCIDR(env["TUN_SUBNET"] as? String ?? "", maxPrefix: 32)?.1
                ?? defaultTunnelPrefix
            let peerAddr6 = env["PEER_ADDR6"] as? String ?? ""
            let prefix6 = Self.parseCIDR(env["TUN_ADDR6"] as? String ?? "", maxPrefix: 128)?.1
                ?? Self.parseCIDR(env["TUN_SUBNET6"] as? String ?? "", maxPrefix: 128)?.1
                ?? defaultTunnelPrefix6
            return ObstacleBridgeDerivedTunnelSettings(
                tunnelAddress: peerAddr,
                tunnelPrefix: prefix,
                includedRoutes: defaultIncludedRoutes,
                excludedRoutes: defaultExcludedRoutes,
                tunnelAddress6: peerAddr6,
                tunnelPrefix6: prefix6,
                includedRoutes6: peerAddr6.isEmpty ? [] : defaultIncludedRoutes6,
                excludedRoutes6: peerAddr6.isEmpty ? [] : defaultExcludedRoutes6,
                dnsServers: defaultDNS,
                mtu: mtu(fallback: fallbackMTU)
            )
        }
        return nil
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
            lifecycleHooks: lifecycleHooks,
            options: options
        )
    }

    private static func foundationObject(from object: [String: ObstacleBridgeChannelMuxCodec.JSONValue]) -> [String: Any] {
        var result: [String: Any] = [:]
        for (key, value) in object {
            result[key] = foundationValue(from: value)
        }
        return result
    }

    private static func foundationValue(from value: ObstacleBridgeChannelMuxCodec.JSONValue) -> Any {
        switch value {
        case .object(let object):
            return foundationObject(from: object)
        case .array(let array):
            return array.map(foundationValue(from:))
        case .string(let string):
            return string
        case .integer(let integer):
            return Int(integer)
        case .double(let double):
            return double
        case .bool(let bool):
            return bool
        case .null:
            return NSNull()
        }
    }

    private static func parseCIDR(_ text: String, maxPrefix: Int) -> (String, Int)? {
        let parts = text.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0,
              prefix <= maxPrefix
        else {
            return nil
        }
        return (parts[0], prefix)
    }
}

struct ObstacleBridgeSwiftUDPPeerConfig {
    let runtimeMode: String
    let bindHost: String
    let overlayBindHost: String
    let bindPort: Int
    let peerHost: String
    let peerPort: Int
    let peerResolveFamily: String
    let mtu: Int
    let tunIfname: String
}

struct ObstacleBridgeOverlayBootstrapSettings {
    let overlayTransport: String
    let transports: [String]
    let transport: String
    let layersTopDown: [String]
    let compressWrapped: Bool
    let compressConfiguredEnabled: Bool
    let peerHost: String?
    let secureLinkMode: String?
    let secureLinkEnabled: Bool
    let secureLinkPSK: String
    let compressEnabled: Bool
    let compressAlgo: String

    init(payload: [String: Any]) throws {
        let overlayTransport = ObstacleBridgeRuntimeConfig.stringValue(from: payload["overlay_transport"]) ?? "myudp"
        let configuredPeers: [String: Bool] = [
            "myudp": ObstacleBridgeRuntimeConfig.stringValue(from: payload["udp_peer"]) != nil,
            "tcp": ObstacleBridgeRuntimeConfig.stringValue(from: payload["tcp_peer"]) != nil,
            "quic": ObstacleBridgeRuntimeConfig.stringValue(from: payload["quic_peer"]) != nil,
            "ws": ObstacleBridgeRuntimeConfig.stringValue(from: payload["ws_peer"]) != nil,
        ]
        let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
            raw: overlayTransport,
            hasConfiguredPeerByTransport: configuredPeers
        )
        let selectedTransport = transports.first ?? "myudp"
        let peerHost = ObstacleBridgeRuntimeConfig.peerHost(for: selectedTransport, payload: payload)
        let secureLinkEnabled = ObstacleBridgeRuntimeConfig.boolValue(from: payload["secure_link"]) ?? false
        let secureLinkModeRaw = ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_mode"]) ?? "off"
        let secureLinkPSK = ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_psk"]) ?? ""
        let compressEnabled = ObstacleBridgeRuntimeConfig.boolValue(from: payload["compress_layer"]) ?? false
        let compressAlgo = ObstacleBridgeRuntimeConfig.stringValue(from: payload["compress_layer_algo"]) ?? "zlib"
        let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
            transport: selectedTransport,
            peerHost: peerHost,
            secureLinkEnabled: secureLinkEnabled,
            secureLinkModeRaw: secureLinkModeRaw,
            secureLinkPSK: secureLinkPSK,
            compressLayerEnabled: compressEnabled,
            compressLayerAlgoRaw: compressAlgo
        )

        self.overlayTransport = overlayTransport
        self.transports = transports
        self.transport = plan.transport
        self.layersTopDown = plan.layersTopDown
        self.compressWrapped = plan.compressWrapped
        self.compressConfiguredEnabled = plan.compressConfiguredEnabled
        self.peerHost = plan.peerHost
        self.secureLinkMode = plan.secureLinkMode
        self.secureLinkEnabled = secureLinkEnabled
        self.secureLinkPSK = secureLinkPSK
        self.compressEnabled = compressEnabled
        self.compressAlgo = compressAlgo
    }

    func summary(runtimeConfigGrouped: Bool? = nil) -> [String: Any] {
        var summary: [String: Any] = [
            "status": "prepared",
            "transport": transport,
            "transports": transports,
            "layers_top_down": layersTopDown,
            "compress_wrapped": compressWrapped,
            "compress_configured_enabled": compressConfiguredEnabled,
        ]
        if let peerHost {
            summary["peer_host"] = peerHost
        }
        if let secureLinkMode {
            summary["secure_link_mode"] = secureLinkMode
        }
        if let runtimeConfigGrouped {
            summary["runtime_config_grouped"] = runtimeConfigGrouped
        }
        return summary
    }
}

struct ObstacleBridgeAdminUIBootstrapState {
    let firstStartDetected: Bool
    let configFileState: String
}

enum ObstacleBridgeRuntimeConfig {
    private static let knownGroupedSections = [
        "runner",
        "udp_session",
        "tcp_session",
        "ws_session",
        "secure_link",
        "compress_layer",
        "TUN_routing",
        "admin_web",
        "debug_logging",
    ]
    private static let secureLinkFrameHeaderSize = 20
    private static let secureLinkAEADTagSize = 16

    static func configSchemaSnapshot() -> [String: Any] {
        [
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
                schemaItem(key: "overlay_transport", description: "Overlay transport between peers: comma-separated list from myudp,tcp,quic,ws. Multiple transports are supported simultaneously for listening instances.", defaultValue: "myudp"),
                schemaItem(key: "client_restart_if_disconnected", description: "If configured as a peer client and the overlay stays disconnected for this many seconds, request runner restart. 0 disables.", defaultValue: 0.0),
                schemaItem(key: "overlay_reconnect_retry_delay_ms", description: "Delay in milliseconds between failed reconnect attempts for reconnect-capable client overlays.", defaultValue: 30000),
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
                schemaItem(key: "own_servers", description: "Service catalog for local listeners in client mode. Use structured service objects with listen/target fields.", defaultValue: []),
                schemaItem(key: "remote_servers", description: "Service catalog pushed to the connected peer in client mode. Use structured service objects with listen/target fields.", defaultValue: []),
            ],
        ]
    }

    static func schemaRow(forKey key: String) -> [String: Any]? {
        for rows in configSchemaSnapshot().values {
            guard let items = rows as? [[String: Any]] else {
                continue
            }
            for row in items where String(describing: row["key"] ?? "") == key {
                return row
            }
        }
        return nil
    }

    static func sectionName(forKey key: String) -> String? {
        for (section, rows) in configSchemaSnapshot() {
            guard let items = rows as? [[String: Any]] else {
                continue
            }
            if items.contains(where: { String(describing: $0["key"] ?? "") == key }) {
                return section
            }
        }
        return nil
    }

    static func groupedSectionPayload(_ sectionName: String, runtimeConfig: [String: Any]) -> [String: Any] {
        if let nested = runtimeConfig[sectionName] as? [String: Any] {
            return normalizedSectionPayload(sectionName, payload: nested)
        }
        guard let rows = configSchemaSnapshot()[sectionName] as? [[String: Any]] else {
            return [:]
        }
        var payload: [String: Any] = [:]
        for row in rows {
            let key = String(describing: row["key"] ?? "")
            guard !key.isEmpty, let value = runtimeConfig[key] else {
                continue
            }
            payload[key] = value
        }
        return normalizedSectionPayload(sectionName, payload: payload)
    }

    static func overlaySessionMaxAppPayload(from payload: [String: Any]) -> Int {
        let transport = (stringValue(from: payload["overlay_transport"]) ?? "myudp").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var limit = 65535
        if transport == "ws" {
            limit = max(1, intValue(from: payload["ws_max_size"]) ?? 65535)
        }
        let secureLinkEnabled = boolValue(from: payload["secure_link"]) ?? false
        let secureLinkMode = (stringValue(from: payload["secure_link_mode"]) ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if secureLinkEnabled, secureLinkMode != "off" {
            limit = max(0, limit - secureLinkFrameHeaderSize - secureLinkAEADTagSize)
        }
        return max(0, limit)
    }

    static func normalizedConfigUpdates(_ updates: [String: Any], currentRuntimeConfig: [String: Any]) -> [String: Any] {
        var normalized = updates
        for sectionName in knownGroupedSections + ["channel_mux", "iOS_TUN_connector"] {
            guard let payload = normalized[sectionName] as? [String: Any] else {
                continue
            }
            normalized.removeValue(forKey: sectionName)
            for (key, value) in normalizedSectionPayload(sectionName, payload: payload) {
                normalized[key] = value
            }
        }
        if (normalized["admin_web_auth_disable"] as? Bool) == true {
            normalized["admin_web_username"] = ""
            normalized["admin_web_password"] = ""
        } else if
            let password = normalized["admin_web_password"] as? String,
            password.isEmpty,
            (boolValue(from: currentRuntimeConfig["admin_web_auth_disable"]) ?? false),
            normalized["admin_web_auth_disable"] == nil
        {
            normalized["admin_web_username"] = ""
            normalized["admin_web_auth_disable"] = true
        }
        return normalized
    }

    static func maskedConfigSnapshot(_ runtimeConfig: [String: Any]) -> [String: Any] {
        var payload = runtimeConfig
        normalizeFlatPayloadForSchema(&payload)
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

    private static func normalizedSectionPayload(_ sectionName: String, payload: [String: Any]) -> [String: Any] {
        guard let rows = configSchemaSnapshot()[sectionName] as? [[String: Any]] else {
            return payload
        }
        var normalized = payload
        for row in rows {
            let key = String(describing: row["key"] ?? "")
            guard !key.isEmpty, let rawValue = normalized[key] else {
                continue
            }
            normalized[key] = normalizeValueForSchema(rawValue: rawValue, defaultValue: row["default"])
        }
        return normalized
    }

    private static func normalizeFlatPayloadForSchema(_ payload: inout [String: Any]) {
        for rowsValue in configSchemaSnapshot().values {
            guard let rows = rowsValue as? [[String: Any]] else {
                continue
            }
            for row in rows {
                let key = String(describing: row["key"] ?? "")
                guard !key.isEmpty, let rawValue = payload[key] else {
                    continue
                }
                payload[key] = normalizeValueForSchema(rawValue: rawValue, defaultValue: row["default"])
            }
        }
    }

    private static func normalizeValueForSchema(rawValue: Any, defaultValue: Any?) -> Any {
        switch defaultValue {
        case is String:
            if let string = firstStringValue(from: rawValue) {
                return string
            }
        case is Int:
            if let integer = intValue(from: rawValue) {
                return integer
            }
        case is Double:
            if let double = doubleValue(from: rawValue) {
                return double
            }
        case is Bool:
            if let bool = boolValue(from: rawValue) {
                return bool
            }
        default:
            break
        }
        return rawValue
    }

    private static func schemaItem(key: String, description: String, defaultValue: Any, choices: [Any]? = nil, secret: Bool = false) -> [String: Any] {
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

    static func flatten(_ payload: [String: Any]) -> [String: Any] {
        var merged: [String: Any] = [:]
        for section in knownGroupedSections {
            if let block = payload[section] as? [String: Any] {
                for (key, value) in block {
                    merged[key] = value
                }
            }
        }
        if let channelMux = payload["channel_mux"] as? [String: Any] {
            for (key, value) in channelMux {
                merged[key] = value
            }
            merged["channel_mux"] = channelMux
        }
        if let connector = payload["iOS_TUN_connector"] as? [String: Any] {
            merged["iOS_TUN_connector"] = connector
        }
        for (key, value) in payload where !(value is [String: Any]) {
            merged[key] = value
        }
        return merged
    }

    static func looksGrouped(_ payload: [String: Any]) -> Bool {
        payload.values.contains { $0 is [String: Any] }
    }

    static func tunnelRoutingOverride(from payload: [String: Any]) -> ObstacleBridgeTunnelRoutingOverride? {
        guard let override = payload["TUN_routing"] as? [String: Any] else {
            return nil
        }
        return ObstacleBridgeTunnelRoutingOverride(
            tunnelAddress: firstStringValue(from: override["tunnel_address"]),
            tunnelPrefix: intValue(from: override["tunnel_prefix"]),
            tunnelGateway: firstStringValue(from: override["tunnel_gateway"]),
            includedRoutes: override["included_routes"] as? [String],
            excludedRoutes: override["excluded_routes"] as? [String],
            tunnelAddress6: firstStringValue(from: override["tunnel_address6"]),
            tunnelPrefix6: intValue(from: override["tunnel_prefix6"]),
            tunnelGateway6: firstStringValue(from: override["tunnel_gateway6"]),
            includedRoutes6: override["included_routes6"] as? [String],
            excludedRoutes6: override["excluded_routes6"] as? [String],
            dnsServers: override["dns_servers"] as? [String],
            mtu: intValue(from: override["mtu"])
        )
    }

    private static func tunnelRoutingString(
        _ value: String?,
        default defaultValue: String
    ) -> String {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? defaultValue : trimmed
    }

    private static func tunnelRoutingInt(
        _ value: Int?,
        default defaultValue: Int
    ) -> Int {
        value ?? defaultValue
    }

    private static func tunnelHookRemoteEnv(from payload: [String: Any]) -> [String: String] {
        let override = tunnelRoutingOverride(from: payload)
        let tunnelAddress = tunnelRoutingString(override?.tunnelAddress, default: "192.168.106.1")
        let tunnelPrefix = tunnelRoutingInt(override?.tunnelPrefix, default: 30)
        let peerGateway4 = tunnelRoutingString(override?.tunnelGateway, default: "192.168.106.2")
        let tunnelAddress6 = tunnelRoutingString(override?.tunnelAddress6, default: "fd20:106::1")
        let tunnelPrefix6 = tunnelRoutingInt(override?.tunnelPrefix6, default: 126)
        let peerGateway6 = tunnelRoutingString(override?.tunnelGateway6, default: "fd20:106::2")
        var env: [String: String] = [
            "TUN_ADDR": "\(peerGateway4)/\(tunnelPrefix)",
            "PEER_ADDR": tunnelAddress,
            "TUN_SUBNET": "\(tunnelAddress)/\(tunnelPrefix)",
        ]
        if !tunnelAddress6.isEmpty {
            env["TUN_ADDR6"] = "\(peerGateway6)/\(tunnelPrefix6)"
            env["PEER_ADDR6"] = tunnelAddress6
            env["TUN_SUBNET6"] = "\(tunnelAddress6)/\(tunnelPrefix6)"
        }
        if let subnet4 = normalizedCIDR(address: tunnelAddress, prefix: tunnelPrefix) {
            env["TUN_SUBNET"] = subnet4
        }
        if let subnet6 = normalizedCIDR(address: tunnelAddress6, prefix: tunnelPrefix6) {
            env["TUN_SUBNET6"] = subnet6
        }
        return env
    }

    private static func normalizedCIDR(address: String, prefix: Int) -> String? {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if prefix >= 0 && prefix <= 32 {
            var addr = in_addr()
            guard trimmed.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else {
                return nil
            }
            let hostOrder = UInt32(bigEndian: addr.s_addr)
            let mask: UInt32 = prefix == 0 ? 0 : (UInt32.max << UInt32(32 - prefix))
            let network = hostOrder & mask
            var networkAddr = in_addr(s_addr: network.bigEndian)
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &networkAddr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return nil
            }
            return "\(String(cString: buffer))/\(prefix)"
        }
        if prefix >= 0 && prefix <= 128 {
            var addr6 = in6_addr()
            guard trimmed.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 else {
                return nil
            }
            var networkBytes = withUnsafeBytes(of: &addr6) { Array($0) }
            var remaining = prefix
            for index in networkBytes.indices {
                if remaining >= 8 {
                    remaining -= 8
                    continue
                }
                if remaining <= 0 {
                    networkBytes[index] = 0
                } else {
                    let shift = 8 - remaining
                    let mask = UInt8(truncatingIfNeeded: 0xFF << shift)
                    networkBytes[index] &= mask
                    remaining = 0
                }
            }
            var networkAddr6 = in6_addr()
            withUnsafeMutableBytes(of: &networkAddr6) { bytes in
                bytes.copyBytes(from: networkBytes)
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &networkAddr6, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return "\(String(cString: buffer))/\(prefix)"
        }
        return nil
    }

    private static func mergedListenerHookEnv(
        lifecycleHooks: [String: ObstacleBridgeChannelMuxCodec.JSONValue]?,
        envDefaults: [String: String]
    ) -> [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
        guard let lifecycleHooks,
              !envDefaults.isEmpty,
              case .object(let listenerHooks)? = lifecycleHooks["listener"]
        else {
            return lifecycleHooks
        }
        var changed = false
        var mergedLifecycleHooks = lifecycleHooks
        var mergedListenerHooks = listenerHooks
        for (event, commandValue) in listenerHooks {
            guard case .object(let commandObject) = commandValue else {
                continue
            }
            var mergedCommandObject = commandObject
            var mergedEnv = envDefaults.reduce(into: [String: ObstacleBridgeChannelMuxCodec.JSONValue]()) { partial, entry in
                partial[entry.key] = .string(entry.value)
            }
            if case .object(let existingEnv)? = commandObject["env"] {
                for (key, value) in existingEnv {
                    mergedEnv[key] = value
                }
            }
            let existingEnvObject: [String: ObstacleBridgeChannelMuxCodec.JSONValue]
            if case .object(let envObject)? = commandObject["env"] {
                existingEnvObject = envObject
            } else {
                existingEnvObject = [:]
            }
            if existingEnvObject != mergedEnv {
                mergedCommandObject["env"] = .object(mergedEnv)
                mergedListenerHooks[event] = .object(mergedCommandObject)
                changed = true
            }
        }
        if changed {
            mergedLifecycleHooks["listener"] = .object(mergedListenerHooks)
        }
        return changed ? mergedLifecycleHooks : lifecycleHooks
    }

    static func localTunServiceSpec(ifname: String, mtu: Int, svcID: Int = 0, name: String? = nil) -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
        ObstacleBridgeRuntimeServiceSpec(
            svcID: svcID,
            name: name,
            listenProtocol: "tun",
            listenBind: ifname,
            listenPort: mtu,
            targetProtocol: "tun",
            targetHost: ifname,
            targetPort: mtu,
            lifecycleHooks: nil,
            options: nil
        ).toChannelMuxServiceSpec()
    }

    static func remoteServiceCatalogMuxFrames(
        from payload: [String: Any],
        instanceID: UInt64 = 0,
        connectionSeq: UInt32 = 0
    ) -> [Data] {
        let remoteEnvDefaults = tunnelHookRemoteEnv(from: payload)
        let specs = remoteServerSpecs(from: payload, preserveInputIndices: true)
            .map { spec -> ObstacleBridgeRuntimeServiceSpec in
                guard spec.listenProtocol == "tun" else {
                    return spec
                }
                let mergedHooks = mergedListenerHookEnv(
                    lifecycleHooks: spec.lifecycleHooks,
                    envDefaults: remoteEnvDefaults
                )
                return ObstacleBridgeRuntimeServiceSpec(
                    svcID: spec.svcID,
                    name: spec.name,
                    listenProtocol: spec.listenProtocol,
                    listenBind: spec.listenBind,
                    listenPort: spec.listenPort,
                    targetProtocol: spec.targetProtocol,
                    targetHost: spec.targetHost,
                    targetPort: spec.targetPort,
                    lifecycleHooks: mergedHooks,
                    options: spec.options
                )
            }
            .map { $0.toChannelMuxServiceSpec() }
        guard !specs.isEmpty else {
            return []
        }
        do {
            let payload = try ObstacleBridgeChannelMuxCodec.encodeRemoteServicesSetV2(
                instanceID: instanceID,
                connectionSeq: connectionSeq,
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

    static func intValue(from value: Any?) -> Int? {
        if let number = value as? NSNumber {
            return number.intValue
        }
        if let value = value as? Int {
            return value
        }
        if let value = value as? String {
            return Int(value)
        }
        return nil
    }

    static func doubleValue(from value: Any?) -> Double? {
        if let number = value as? NSNumber {
            return number.doubleValue
        }
        if let value = value as? Double {
            return value
        }
        if let value = value as? Int {
            return Double(value)
        }
        if let value = value as? String {
            return Double(value)
        }
        return nil
    }

    static func boolValue(from value: Any?) -> Bool? {
        if let value = value as? Bool {
            return value
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        if let value = value as? String {
            switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "1", "true", "yes", "on":
                return true
            case "0", "false", "no", "off":
                return false
            default:
                return nil
            }
        }
        return nil
    }

    static func stringValue(from value: Any?) -> String? {
        guard let value else {
            return nil
        }
        if let string = value as? String {
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let number = value as? NSNumber {
            return number.stringValue
        }
        return nil
    }

    private static func firstStringValue(from value: Any?) -> String? {
        if let string = stringValue(from: value) {
            return string
        }
        if let values = value as? [String] {
            return values.compactMap { stringValue(from: $0) }.first
        }
        if let values = value as? [Any] {
            return values.compactMap { stringValue(from: $0) }.first
        }
        return nil
    }

    static func peerResolveFamilyValue(from value: Any?) -> String? {
        guard let raw = stringValue(from: value)?.lowercased() else {
            return nil
        }
        switch raw {
        case "prefer-ipv6", "ipv4", "ipv6":
            return raw
        default:
            return nil
        }
    }

    static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        switch transport {
        case "myudp":
            return stringValue(from: payload["udp_peer"])
        case "tcp":
            return stringValue(from: payload["tcp_peer"])
        case "quic":
            return stringValue(from: payload["quic_peer"])
        case "ws":
            return stringValue(from: payload["ws_peer"])
        default:
            return nil
        }
    }

    static func peerPort(for transport: String, payload: [String: Any]) -> Int? {
        switch transport {
        case "myudp":
            return intValue(from: payload["udp_peer_port"])
        case "tcp":
            return intValue(from: payload["tcp_peer_port"])
        case "quic":
            return intValue(from: payload["quic_peer_port"])
        case "ws":
            return intValue(from: payload["ws_peer_port"])
        default:
            return nil
        }
    }

    static func adminUIBootstrapState(from payload: [String: Any]) -> ObstacleBridgeAdminUIBootstrapState {
        let flattened = flatten(payload)
        let overlayTransport = stringValue(from: flattened["overlay_transport"]) ?? "myudp"
        let selectedTransport = overlayTransport
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .first(where: { !$0.isEmpty }) ?? "myudp"
        let peerConfigured: Bool
        if let host = peerHost(for: selectedTransport, payload: flattened),
           !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           let port = peerPort(for: selectedTransport, payload: flattened),
           port > 0 {
            peerConfigured = true
        } else {
            peerConfigured = false
        }
        let ownConfigured = !ownServerSpecs(from: payload).isEmpty
        let remoteConfigured = !remoteServerSpecs(from: payload).isEmpty
        let firstStartDetected = !peerConfigured && !ownConfigured && !remoteConfigured
        return ObstacleBridgeAdminUIBootstrapState(
            firstStartDetected: firstStartDetected,
            configFileState: firstStartDetected ? "empty" : "loaded"
        )
    }

    private static func isLegacySwiftUDPShimPeer(host: String?, port: Int?, bindPort: Int) -> Bool {
        guard let host = host?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !host.isEmpty,
              let port
        else {
            return false
        }
        guard host == "127.0.0.1" || host == "::1" || host == "localhost" else {
            return false
        }
        return port == 5556 || port == bindPort + 1
    }

    private static func normalizedPacketflowBindHost(_ host: Any?, connectorMode: String) -> String {
        let raw = stringValue(from: host)
        let normalized = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        guard connectorMode == "swift_udp" || connectorMode == "swift_simple_udp" else {
            return raw ?? "127.0.0.1"
        }
        if normalized.isEmpty || normalized == "0.0.0.0" || normalized == "::" || normalized == "*" || normalized == "localhost" {
            return "127.0.0.1"
        }
        return raw ?? "127.0.0.1"
    }

    static func packetflowConnectorSelection(from payload: [String: Any]) -> String? {
        guard let experiment = packetflowConnectorSection(from: payload) else {
            return nil
        }
        let connectorMode = (experiment["packetflow_connector"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return connectorMode.isEmpty ? nil : connectorMode
    }

    static func runtimeExecutionMode(from payload: [String: Any], supportsSwiftHostRunner: Bool) -> String {
        guard let connectorMode = packetflowConnectorSelection(from: payload) else {
            return "packet_tunnel"
        }
        if supportsSwiftHostRunner && connectorMode == "swift_host_runner" {
            return "swift_host_runner"
        }
        return "packet_tunnel"
    }

    static func packetflowConnectorMode(from payload: [String: Any]) -> String? {
        guard let connectorMode = packetflowConnectorSelection(from: payload) else {
            return nil
        }
        switch connectorMode {
        case "swift_udp", "swift_udp_peer":
            return "swift_udp"
        case "swift_simple_udp", "swift_simple_udp_peer", "simple_udp_peer":
            return "swift_simple_udp"
        default:
            return nil
        }
    }

    static func swiftUDPPeerConfig(from payload: [String: Any], defaultMTU: Int) -> ObstacleBridgeSwiftUDPPeerConfig? {
        guard let experiment = packetflowConnectorSection(from: payload) else {
            return nil
        }
        guard let connectorMode = packetflowConnectorMode(from: payload) else {
            return nil
        }
        let bindHost = normalizedPacketflowBindHost(experiment["bind_host"], connectorMode: connectorMode)
        let overlayBindHost: String
        let configuredOverlayBind = stringValue(from: payload["udp_bind"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        if connectorMode == "swift_udp" {
            if let configuredOverlayBind, !configuredOverlayBind.isEmpty {
                overlayBindHost = configuredOverlayBind
            } else {
                overlayBindHost = "::"
            }
        } else {
            overlayBindHost = bindHost
        }
        let bindPort = intValue(from: experiment["bind_port"]) ?? 5555
        let overlayTransport = stringValue(from: payload["overlay_transport"]) ?? "myudp"
        let selectedTransport = overlayTransport
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .first(where: { !$0.isEmpty }) ?? "myudp"
        let explicitPeerHostRaw = stringValue(from: experiment["peer_host"])
        let explicitPeerHost = explicitPeerHostRaw?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
            ? explicitPeerHostRaw?.trimmingCharacters(in: .whitespacesAndNewlines)
            : nil
        let explicitPeerPortRaw = intValue(from: experiment["peer_port"])
        let explicitPeerPort = (explicitPeerPortRaw ?? 0) > 0 ? explicitPeerPortRaw : nil
        let useOverlayPeerFallback =
            connectorMode == "swift_udp"
            && isLegacySwiftUDPShimPeer(host: explicitPeerHost, port: explicitPeerPort, bindPort: bindPort)
        let peerHost = (useOverlayPeerFallback ? nil : explicitPeerHost)
            ?? (connectorMode == "swift_udp" ? peerHost(for: selectedTransport, payload: payload) : nil)
        guard let peerHost else {
            return nil
        }
        let peerPort = (useOverlayPeerFallback ? nil : explicitPeerPort)
            ?? (connectorMode == "swift_udp" ? (peerPort(for: selectedTransport, payload: payload) ?? 0) : 0)
        guard peerPort > 0 else {
            return nil
        }
        let peerResolveFamily = peerResolveFamilyValue(from: experiment["udp_peer_resolve_family"]) ?? "prefer-ipv6"
        let mtu = intValue(from: experiment["mtu"]) ?? defaultMTU
        let tunIfname = stringValue(from: experiment["ifname"]) ?? "ios-utun"
        return ObstacleBridgeSwiftUDPPeerConfig(
            runtimeMode: connectorMode,
            bindHost: bindHost,
            overlayBindHost: overlayBindHost,
            bindPort: bindPort > 0 ? bindPort : peerPort,
            peerHost: peerHost,
            peerPort: peerPort,
            peerResolveFamily: peerResolveFamily,
            mtu: mtu,
            tunIfname: tunIfname
        )
    }

    static func ownServerSpecs(from payload: [String: Any], preserveInputIndices: Bool = false) -> [ObstacleBridgeRuntimeServiceSpec] {
        serviceSpecs(from: payload, key: "own_servers", preserveInputIndices: preserveInputIndices)
    }

    static func remoteServerSpecs(from payload: [String: Any], preserveInputIndices: Bool = false) -> [ObstacleBridgeRuntimeServiceSpec] {
        serviceSpecs(from: payload, key: "remote_servers", preserveInputIndices: preserveInputIndices)
    }

    static func localTCPServiceSpecs(from payload: [String: Any]) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        ownServerSpecs(from: payload, preserveInputIndices: true)
            .filter { $0.listenProtocol == "tcp" && $0.targetProtocol == "tcp" }
            .map { $0.toChannelMuxServiceSpec() }
    }

    private static func serviceSpecs(
        from payload: [String: Any],
        key: String,
        preserveInputIndices: Bool
    ) -> [ObstacleBridgeRuntimeServiceSpec] {
        guard let rawSpecs = serviceArray(from: payload, key: key) else {
            return []
        }
        var specs: [ObstacleBridgeRuntimeServiceSpec] = []
        var nextDenseID = 1
        for (index, item) in rawSpecs.enumerated() {
            let svcID = preserveInputIndices ? (index + 1) : nextDenseID
            guard let spec = parseOwnServerSpec(item, svcID: svcID) else {
                continue
            }
            specs.append(spec)
            if !preserveInputIndices {
                nextDenseID += 1
            }
        }
        return specs
    }

    private static func packetflowConnectorSection(from payload: [String: Any]) -> [String: Any]? {
        payload["iOS_TUN_connector"] as? [String: Any]
    }

    private static func serviceArray(from payload: [String: Any], key: String) -> [Any]? {
        if let channelMux = payload["channel_mux"] as? [String: Any],
           let specs = channelMux[key] as? [Any] {
            return specs
        }
        return payload[key] as? [Any]
    }

    private static func parseOwnServerSpec(_ item: Any, svcID: Int) -> ObstacleBridgeRuntimeServiceSpec? {
        guard let dictionary = item as? [String: Any],
              let listen = dictionary["listen"] as? [String: Any],
              let target = dictionary["target"] as? [String: Any],
              let listenProtocol = stringValue(from: listen["protocol"]),
              let targetProtocol = stringValue(from: target["protocol"]) else {
            return nil
        }
        guard listenProtocol == "tcp" || listenProtocol == "udp" || listenProtocol == "tun" else {
            return nil
        }
        guard targetProtocol == "tcp" || targetProtocol == "udp" || targetProtocol == "tun" else {
            return nil
        }

        let listenBind: String?
        let listenPort: Int?
        if listenProtocol == "tun" {
            listenBind = stringValue(from: listen["ifname"])
            listenPort = intValue(from: listen["mtu"])
        } else {
            listenBind = stringValue(from: listen["bind"])
            listenPort = intValue(from: listen["port"])
        }

        let targetHost: String?
        let targetPort: Int?
        if targetProtocol == "tun" {
            targetHost = stringValue(from: target["ifname"])
            targetPort = intValue(from: target["mtu"])
        } else {
            targetHost = stringValue(from: target["host"])
            targetPort = intValue(from: target["port"])
        }

        guard let listenBind,
              let listenPort,
              let targetHost,
              let targetPort else {
            return nil
        }
        return ObstacleBridgeRuntimeServiceSpec(
            svcID: svcID,
            name: stringValue(from: dictionary["name"]),
            listenProtocol: listenProtocol,
            listenBind: listenBind,
            listenPort: listenPort,
            targetProtocol: targetProtocol,
            targetHost: targetHost,
            targetPort: targetPort,
            lifecycleHooks: jsonDictionary(from: dictionary["lifecycle_hooks"]),
            options: jsonDictionary(from: dictionary["options"])
        )
    }

    private static func jsonDictionary(from value: Any?) -> [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
        guard let value,
              let json = ObstacleBridgeChannelMuxCodec.jsonValue(from: value),
              case .object(let object) = json
        else {
            return nil
        }
        return object
    }
}
