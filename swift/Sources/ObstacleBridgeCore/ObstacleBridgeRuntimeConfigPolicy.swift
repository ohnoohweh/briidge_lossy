import Foundation

/// Portable scalar and overlay-limit policy shared by platform configuration adapters.
enum ObstacleBridgeRuntimeConfigPolicy {
    static let knownGroupedSections = [
        "runner", "udp_session", "tcp_session", "quic_session", "ws_session",
        "secure_link", "compress_layer", "tun_execution", "TUN_routing",
        "admin_web", "debug_logging", "telemetry_client", "channel_mux",
        "iOS_TUN_connector", "proxy_provider",
    ]
    static let proxyProviderCompatibilityAliasKeys = ["enabled", "bind", "http_port", "socks5_port", "protocols", "auth", "egress", "policy"]
    static let tunExecutionCompatibilityAliasKeys = ["mode", "helper_backend", "helper_socket", "helper_apply_network", "helper_log_level"]
    static func schemaItem(key: String, description: String, defaultValue: Any, choices: [Any]? = nil, secret: Bool = false) -> [String: Any] {
        var row: [String: Any] = ["key": key, "description": description, "default": defaultValue]
        if let choices { row["choices"] = choices }
        if secret { row["secret"] = true }
        return row
    }
    static func applyCompatibilityAliases(to payload: inout [String: Any]) {
        if payload["udp_peer_resolve_family"] == nil, let value = payload["peer_resolve_family"] { payload["udp_peer_resolve_family"] = value }
        for (alias, canonical) in ["enabled": "proxy_provider_enabled", "bind": "proxy_provider_bind", "http_port": "proxy_provider_http_port", "socks5_port": "proxy_provider_socks5_port", "protocols": "proxy_provider_protocols", "auth": "proxy_provider_auth", "egress": "proxy_provider_egress", "policy": "proxy_provider_policy"] where payload[canonical] == nil { if let value = payload[alias] { payload[canonical] = value } }
        for (alias, canonical) in ["mode": "tun_execution_mode", "helper_backend": "tun_helper_backend", "helper_socket": "tun_helper_socket", "helper_apply_network": "tun_helper_apply_network", "helper_log_level": "tun_helper_log_level"] where payload[canonical] == nil { if let value = payload[alias] { payload[canonical] = value } }
    }

    static func defaultTelemetryConfig() -> [String: Any] {
        [
            "telemetry_enabled": false,
            "telemetry_endpoint": "https://127.0.0.1:18443/v1/telemetry/batches",
            "telemetry_spool_directory": "/var/lib/obstaclebridge/telemetry-client",
        ]
    }

    static func configSchemaSnapshot() -> [String: Any] {
        [
            "admin_web": [schemaItem(key: "admin_web", description: "Enable admin web interface", defaultValue: true), schemaItem(key: "admin_web_auth_disable", description: "Disable username/password challenge for admin web access", defaultValue: false), schemaItem(key: "admin_web_bind", description: "Bind address for admin web interface", defaultValue: "127.0.0.1"), schemaItem(key: "admin_web_port", description: "Port for admin web interface", defaultValue: 18080), schemaItem(key: "admin_web_path", description: "Base path for admin web interface", defaultValue: "/"), schemaItem(key: "admin_web_dir", description: "Directory containing admin web files", defaultValue: "./admin_web"), schemaItem(key: "admin_web_name", description: "Optional instance name shown in the admin web title and headline", defaultValue: ""), schemaItem(key: "admin_web_landing_page_disable", description: "Disable the Admin Web landing/quick-start panel for advanced users.", defaultValue: false), schemaItem(key: "admin_web_security_advisor_disable", description: "Disable the Admin Web startup security advisor panel for advanced users.", defaultValue: false), schemaItem(key: "admin_web_security_advisor_startup_disable", description: "Do not auto-open the security advisor on first page load.", defaultValue: false), schemaItem(key: "admin_web_first_tab", description: "Initial Admin Web tab. Use status for an advanced/operator-focused default.", defaultValue: "home", choices: ["home", "status", "secure-link", "configuration", "logs", "misc"]), schemaItem(key: "admin_web_token", description: "Optional bearer token for admin restart endpoint", defaultValue: ""), schemaItem(key: "admin_web_username", description: "Username for admin web access when challenge-based authentication is enabled", defaultValue: ""), schemaItem(key: "admin_web_password", description: "Password for admin web access when challenge-based authentication is enabled", defaultValue: "", secret: true)],
            "debug_logging": [schemaItem(key: "log", description: "Global log level", defaultValue: "DEBUG", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]), schemaItem(key: "file_level", description: "File log level", defaultValue: "DEBUG", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]), schemaItem(key: "console_level", description: "Console log level", defaultValue: "INFO", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]), schemaItem(key: "log_file", description: "Debug log file path", defaultValue: ""), schemaItem(key: "log_file_max_bytes", description: "Maximum size of each log file before rotation", defaultValue: 1_048_576), schemaItem(key: "log_file_backup_count", description: "Number of rotated log files to keep", defaultValue: 5)],
            "telemetry_client": [schemaItem(key: "telemetry_enabled", description: "Enable bounded HTTPS telemetry upload outside the bridge and packet paths.", defaultValue: false), schemaItem(key: "telemetry_endpoint", description: "HTTPS collector endpoint for telemetry batches.", defaultValue: "https://127.0.0.1:18443/v1/telemetry/batches"), schemaItem(key: "telemetry_spool_directory", description: "Telemetry spool directory. Packet Tunnel telemetry uses its app-group container.", defaultValue: "/var/lib/obstaclebridge/telemetry-client")],
            "runner": [schemaItem(key: "overlay_transport", description: "Overlay transport between peers: comma-separated list from myudp,tcp,quic,ws. Multiple transports are supported simultaneously for listening instances.", defaultValue: "myudp"), schemaItem(key: "client_restart_if_disconnected", description: "If configured as a peer client and the overlay stays disconnected for this many seconds, request runner restart. 0 disables.", defaultValue: 0.0), schemaItem(key: "overlay_reconnect_retry_delay_ms", description: "Delay in milliseconds between failed reconnect attempts for reconnect-capable client overlays.", defaultValue: 30000)],
            "udp_session": [schemaItem(key: "udp_bind", description: "overlay bind address (IPv4 '0.0.0.0' or IPv6 '::')", defaultValue: "::"), schemaItem(key: "udp_own_port", description: "overlay own port", defaultValue: 4433), schemaItem(key: "udp_peer", description: "peer IP/FQDN, or comma-separated IPv4/IPv6 alternatives (IPv6 may be in [brackets])", defaultValue: NSNull()), schemaItem(key: "udp_peer_port", description: "peer overlay port", defaultValue: 4433), schemaItem(key: "udp_peer_resolve_family", description: "Peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]), schemaItem(key: "max_inflight", description: "Maximum myUDP DATA frames allowed in flight before excess frames are queued.", defaultValue: 200)],
            "tcp_session": [schemaItem(key: "tcp_bind", description: "TCP overlay bind address", defaultValue: "::"), schemaItem(key: "tcp_own_port", description: "TCP overlay own port", defaultValue: 8081), schemaItem(key: "tcp_peer", description: "TCP peer IP/FQDN", defaultValue: NSNull()), schemaItem(key: "tcp_peer_port", description: "TCP peer overlay port", defaultValue: 8081), schemaItem(key: "tcp_peer_resolve_family", description: "TCP peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]), schemaItem(key: "tcp_bp_wbuf_threshold", description: "TCP backpressure write-buffer threshold", defaultValue: 128 * 1024)],
            "quic_session": [schemaItem(key: "quic_bind", description: "QUIC overlay bind address", defaultValue: "::"), schemaItem(key: "quic_own_port", description: "QUIC overlay own port", defaultValue: 443), schemaItem(key: "quic_peer", description: "QUIC peer IP/FQDN", defaultValue: NSNull()), schemaItem(key: "quic_peer_port", description: "QUIC peer overlay port", defaultValue: 443), schemaItem(key: "quic_peer_resolve_family", description: "QUIC peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]), schemaItem(key: "quic_alpn", description: "QUIC ALPN identifier", defaultValue: "hq-29"), schemaItem(key: "quic_insecure", description: "Disable QUIC certificate verification for local/lab peers", defaultValue: false), schemaItem(key: "quic_max_size", description: "Maximum QUIC app payload size", defaultValue: 65535)],
            "ws_session": [schemaItem(key: "ws_bind", description: "WebSocket overlay bind address", defaultValue: "::"), schemaItem(key: "ws_own_port", description: "WebSocket overlay own port", defaultValue: 8080), schemaItem(key: "ws_peer", description: "Remote WebSocket peer host", defaultValue: "bridge.example.com"), schemaItem(key: "ws_peer_addresses", description: "Optional ordered IPv4/IPv6 literal connection addresses; ws_peer remains the HTTP and TLS server name.", defaultValue: []), schemaItem(key: "ws_peer_port", description: "Remote WebSocket peer port", defaultValue: 8080), schemaItem(key: "ws_path", description: "WebSocket HTTP path", defaultValue: "/"), schemaItem(key: "ws_payload_mode", description: "WebSocket payload framing mode", defaultValue: "binary", choices: ["binary", "base64", "json-base64", "semi-text-shape"]), schemaItem(key: "ws_peer_resolve_family", description: "WebSocket peer name resolution policy: prefer IPv6 then IPv4, IPv4 only, or IPv6 only.", defaultValue: "prefer-ipv6", choices: ["prefer-ipv6", "ipv4", "ipv6"]), schemaItem(key: "ws_proxy_auth", description: "WebSocket client proxy authentication mode.", defaultValue: "none", choices: ["none", "basic", "negotiate"]), schemaItem(key: "ws_proxy_host", description: "Manual WebSocket proxy host.", defaultValue: ""), schemaItem(key: "ws_proxy_mode", description: "WebSocket client proxy mode.", defaultValue: "env", choices: ["off", "env", "manual", "system"]), schemaItem(key: "ws_proxy_port", description: "Manual WebSocket proxy port.", defaultValue: 8080), schemaItem(key: "ws_reconnect_grace", description: "Seconds to wait before reporting DISCONNECTED after WebSocket transport loss.", defaultValue: 3.0), schemaItem(key: "ws_send_timeout", description: "Seconds to wait for a WebSocket frame send before forcing reconnect.", defaultValue: 3.0), schemaItem(key: "ws_static_dir", description: "Directory containing static web assets", defaultValue: "./web"), schemaItem(key: "ws_subprotocol", description: "Optional WebSocket subprotocol.", defaultValue: NSNull()), schemaItem(key: "ws_tcp_user_timeout_ms", description: "TCP_USER_TIMEOUT in milliseconds for WebSocket sockets.", defaultValue: 10000), schemaItem(key: "ws_tls", description: "Use TLS (wss://) for the WebSocket overlay.", defaultValue: false), schemaItem(key: "ws_max_size", description: "Maximum WebSocket message size accepted or sent.", defaultValue: 65535)],
            "secure_link": [schemaItem(key: "secure_link", description: "Enable SecureLink", defaultValue: false), schemaItem(key: "secure_link_mode", description: "SecureLink mode", defaultValue: "off", choices: ["off", "psk", "cert"]), schemaItem(key: "secure_link_psk", description: "SecureLink PSK secret", defaultValue: "", secret: true), schemaItem(key: "secure_link_rekey_after_frames", description: "Automatically rekey PSK sessions after this many protected data frames. 0 disables frame-triggered rekey.", defaultValue: 0), schemaItem(key: "secure_link_rekey_after_seconds", description: "Automatically rekey PSK sessions after this many authenticated seconds. 0 disables time-triggered rekey.", defaultValue: 0.0), schemaItem(key: "secure_link_retry_backoff_initial_ms", description: "Initial SecureLink client retry backoff after authentication failure, in milliseconds.", defaultValue: 1000), schemaItem(key: "secure_link_retry_backoff_max_ms", description: "Maximum SecureLink client retry backoff after repeated authentication failures, in milliseconds.", defaultValue: 5000)],
            "compress_layer": [schemaItem(key: "compress_layer", description: "Enable transport compression", defaultValue: false), schemaItem(key: "compress_layer_algo", description: "Compression algorithm", defaultValue: "zlib"), schemaItem(key: "compress_layer_level", description: "Compression level", defaultValue: 3), schemaItem(key: "compress_layer_min_bytes", description: "Minimum payload size before compression", defaultValue: 64), schemaItem(key: "compress_layer_types", description: "Comma-separated message types eligible for compression", defaultValue: "data,data_frag")],
            "iOS_TUN_connector": [schemaItem(key: "packetflow_connector", description: "Packet Tunnel connector implementation. swift_udp is the native iOS provider path; swift_host_runner is the macOS Swift host path.", defaultValue: "", choices: ["", "udp", "direct", "simple_udp_peer", "swift_udp", "swift_udp_peer", "swift_host_runner"]), schemaItem(key: "bind_host", description: "Local PacketFlow/helper connector bind address. This is not an overlay transport bind address.", defaultValue: "127.0.0.1"), schemaItem(key: "bind_port", description: "Local PacketFlow/helper connector port. This is not the MyUDP source port.", defaultValue: 5555), schemaItem(key: "peer_host", description: "Local PacketFlow/helper connector peer address. Native Swift overlay peers use the selected transport configuration.", defaultValue: ""), schemaItem(key: "peer_port", description: "Local PacketFlow/helper connector peer port. Native Swift overlay peers use the selected transport configuration.", defaultValue: 0), schemaItem(key: "ifname", description: "Logical packet-tunnel interface name used by the connector.", defaultValue: "ios-utun"), schemaItem(key: "mtu", description: "PacketFlow/helper connector MTU.", defaultValue: 1280)],
            "tun_execution": [schemaItem(key: "tun_execution_mode", description: "Desktop local TUN execution topology: inline current-process ownership or helper-backed ownership.", defaultValue: "inline", choices: ["inline", "helper"]), schemaItem(key: "tun_helper_backend", description: "Helper backend identifier for helper mode. Values include linux-native, linux-python, and darwin-native.", defaultValue: "linux-native"), schemaItem(key: "tun_helper_socket", description: "Optional explicit local IPC socket path for helper mode.", defaultValue: ""), schemaItem(key: "tun_helper_apply_network", description: "Whether the helper should own privileged address/route/DNS/firewall apply-remove work.", defaultValue: true), schemaItem(key: "tun_helper_log_level", description: "Log level for the TUN helper control path.", defaultValue: "INFO", choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"])],
            "TUN_routing": [schemaItem(key: "tunnel_address", description: "IPv4 tunnel address for the local iOS/macOS tunnel endpoint.", defaultValue: "192.168.106.1"), schemaItem(key: "tunnel_prefix", description: "IPv4 tunnel prefix length.", defaultValue: 30), schemaItem(key: "tunnel_gateway", description: "IPv4 peer gateway address used by TUN hook helpers.", defaultValue: "192.168.106.2"), schemaItem(key: "included_routes", description: "IPv4 routes that should be included in the packet tunnel.", defaultValue: ["0.0.0.0/0"]), schemaItem(key: "excluded_routes", description: "IPv4 routes that should bypass the packet tunnel.", defaultValue: ["127.0.0.0/8"]), schemaItem(key: "tunnel_address6", description: "IPv6 tunnel address for the local iOS/macOS tunnel endpoint.", defaultValue: "fd20:106::1"), schemaItem(key: "tunnel_prefix6", description: "IPv6 tunnel prefix length.", defaultValue: 126), schemaItem(key: "tunnel_gateway6", description: "IPv6 peer gateway address used by TUN hook helpers.", defaultValue: "fd20:106::2"), schemaItem(key: "included_routes6", description: "IPv6 routes that should be included in the packet tunnel.", defaultValue: ["::/0"]), schemaItem(key: "excluded_routes6", description: "IPv6 routes that should bypass the packet tunnel.", defaultValue: ["::1/128"]), schemaItem(key: "dns_servers", description: "DNS servers advertised to the packet tunnel network settings.", defaultValue: ["1.1.1.1"]), schemaItem(key: "mtu", description: "MTU applied to the packet tunnel network settings.", defaultValue: 1600), schemaItem(key: "log_TUN_routing", description: "Log level for TUN routing helpers.", defaultValue: "CRITICAL"), schemaItem(key: "shared_tun_disable_outgoing_normalization", description: "Disable shared-TUN local packet source normalization as a diagnostic isolation switch.", defaultValue: false), schemaItem(key: "shared_tun_disable_inflow_filter", description: "Disable shared-TUN inbound ownership/source filtering as a diagnostic isolation switch.", defaultValue: false), schemaItem(key: "shared_tun_disable_outflow_filter", description: "Disable shared-TUN outbound route and relay filtering as a diagnostic isolation switch.", defaultValue: false), schemaItem(key: "shared_tun_disable_scoped_throttle", description: "Disable shared-TUN scoped inflow throttling as a diagnostic isolation switch.", defaultValue: false)],
            "channel_mux": [schemaItem(key: "own_servers", description: "Service catalog for local listeners in client mode. Use structured service objects with listen/target fields.", defaultValue: []), schemaItem(key: "remote_servers", description: "Service catalog pushed to the connected peer in client mode. Use structured service objects with listen/target fields.", defaultValue: []), schemaItem(key: "mux_tcp_bp_threshold", description: "Mux TCP write-buffer threshold in bytes before drain is triggered.", defaultValue: 1), schemaItem(key: "mux_tcp_bp_latency_ms", description: "Mux TCP latency threshold before pending writers are drained.", defaultValue: 300), schemaItem(key: "mux_tcp_bp_poll_interval_ms", description: "Mux TCP polling interval for time-based backpressure.", defaultValue: 50), schemaItem(key: "channelmux_transport_delay_threshold_ms", description: "Estimated transport-delay threshold before ChannelMux sheds local traffic and arms sustained-delay rotation.", defaultValue: 5000), schemaItem(key: "channelmux_transport_delay_rotation_delay_ms", description: "Continuous estimated-delay duration before ChannelMux requests a connection rotation.", defaultValue: 30000)],
            "proxy_provider": [schemaItem(key: "proxy_provider_enabled", description: "Enable the explicit HTTP CONNECT and SOCKS5 proxy provider.", defaultValue: false), schemaItem(key: "proxy_provider_bind", description: "Local bind address for the proxy listeners.", defaultValue: "127.0.0.1"), schemaItem(key: "proxy_provider_http_port", description: "Local HTTP/CONNECT proxy listener port.", defaultValue: 13881), schemaItem(key: "proxy_provider_socks5_port", description: "Local SOCKS5 CONNECT proxy listener port.", defaultValue: 13882), schemaItem(key: "proxy_provider_protocols", description: "Enabled proxy protocol families.", defaultValue: ["http-connect", "socks5-connect"]), schemaItem(key: "proxy_provider_auth", description: "Proxy authentication object. Use mode token/basic/password with username and token/password.", defaultValue: ["mode": "none", "username": "", "token": ""]), schemaItem(key: "proxy_provider_egress", description: "Proxy egress policy object for outbound connection behavior.", defaultValue: ["mode": "system", "address_families": ["ipv4", "ipv6"]]), schemaItem(key: "proxy_provider_policy", description: "Proxy destination policy object.", defaultValue: ["allow_private_destinations": false, "blocked_host_patterns": []]), schemaItem(key: "log_proxy_provider", description: "Proxy provider log level override.", defaultValue: NSNull(), choices: ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"])]
        ]
    }

    static func intValue(from value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let value = value as? Int { return value }
        if let value = value as? String { return Int(value) }
        return nil
    }

    static func doubleValue(from value: Any?) -> Double? {
        if let number = value as? NSNumber { return number.doubleValue }
        if let value = value as? Double { return value }
        if let value = value as? Int { return Double(value) }
        if let value = value as? String { return Double(value) }
        return nil
    }

    static func boolValue(from value: Any?) -> Bool? {
        if let value = value as? Bool { return value }
        if let number = value as? NSNumber { return number.boolValue }
        guard let value = value as? String else { return nil }
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: return nil
        }
    }

    static func stringValue(from value: Any?) -> String? {
        guard let value else { return nil }
        if let string = value as? String {
            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        return (value as? NSNumber)?.stringValue
    }

    static func firstStringValue(from value: Any?) -> String? {
        if let string = stringValue(from: value) { return string }
        if let values = value as? [Any] {
            return values.compactMap { stringValue(from: $0) }.first
        }
        return nil
    }

    static func optionalStringValueAllowEmpty(from value: Any?) -> String? {
        guard let value else { return nil }
        if let string = value as? String { return string.trimmingCharacters(in: .whitespacesAndNewlines) }
        return (value as? NSNumber)?.stringValue
    }

    static func overlaySessionMaxAppPayload(from payload: [String: Any]) -> Int {
        let transport = (stringValue(from: payload["overlay_transport"]) ?? "myudp").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var limit = transport == "ws" ? max(1, intValue(from: payload["ws_max_size"]) ?? 65535) : 65535
        let secureLinkEnabled = boolValue(from: payload["secure_link"]) ?? false
        let secureLinkMode = (stringValue(from: payload["secure_link_mode"]) ?? "off").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if secureLinkEnabled, secureLinkMode != "off" { limit = max(0, limit - 20 - 16) }
        return max(0, limit)
    }

    static func overlayMaxInflight(from payload: [String: Any]) -> Int {
        min(32767, max(1, intValue(from: payload["max_inflight"]) ?? 200))
    }

    static func peerResolveFamilyValue(from value: Any?) -> String? {
        guard let raw = stringValue(from: value)?.lowercased() else { return nil }
        return ["prefer-ipv6", "ipv4", "ipv6"].contains(raw) ? raw : nil
    }

    static func looksGrouped(_ payload: [String: Any]) -> Bool {
        payload.values.contains { value in
            value is [String: Any] || Mirror(reflecting: value).displayStyle == .dictionary
        }
    }

    static func wsPeerAddresses(from value: Any?) -> [String] {
        let values = (value as? [Any]) ?? (value.map { [$0] } ?? [])
        var addresses: [String] = []
        for value in values {
            guard let rendered = stringValue(from: value) else { continue }
            for token in rendered.replacingOccurrences(of: ";", with: ",").split(separator: ",", omittingEmptySubsequences: false) {
                let trimmed = String(token).trimmingCharacters(in: .whitespacesAndNewlines)
                let address = trimmed.hasPrefix("[") && trimmed.hasSuffix("]") ? String(trimmed.dropFirst().dropLast()) : trimmed
                if !address.isEmpty, !addresses.contains(address) { addresses.append(address) }
            }
        }
        return addresses
    }

    static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        let keys = ["myudp": "udp_peer", "tcp": "tcp_peer", "quic": "quic_peer", "ws": "ws_peer"]
        return keys[transport].flatMap { stringValue(from: payload[$0]) }
    }

    static func peerPort(for transport: String, payload: [String: Any]) -> Int? {
        let keys = ["myudp": "udp_peer_port", "tcp": "tcp_peer_port", "quic": "quic_peer_port", "ws": "ws_peer_port"]
        return keys[transport].flatMap { intValue(from: payload[$0]) }
    }

    static func overlayPeerExcludedRoutes(from flatPayload: [String: Any]) -> (ipv4: [String], ipv6: [String]) {
        let transport = (stringValue(from: flatPayload["overlay_transport"]) ?? "myudp")
            .split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .first(where: { !$0.isEmpty }) ?? "myudp"
        guard let host = peerHost(for: transport, payload: flatPayload),
              let port = peerPort(for: transport, payload: flatPayload), port > 0 else { return ([], []) }
        let resolveFamily = resolveFamily(for: transport, payload: flatPayload)
        let bindHost = bindHost(for: transport, payload: flatPayload)
        let wsAddresses = transport == "ws" ? wsPeerAddresses(from: flatPayload["ws_peer_addresses"]) : []
        let candidates = wsAddresses.isEmpty ? splitConfiguredPeerHosts(host) : wsAddresses
        var ipv4: [String] = []; var ipv6: [String] = []
        for host in candidates {
            guard let route = ObstacleBridgePacketTunnelRoutePolicy.hostRouteCIDR(host) else { continue }
            if route.isIPv6 {
                if resolveFamily != "ipv4" { ipv6.append(route.route) }
            } else if resolveFamily != "ipv6" {
                ipv4.append(route.route)
                if resolveFamily != "ipv4", bindHost == "::", let mapped = ObstacleBridgePacketTunnelRoutePolicy.ipv4MappedIPv6RouteCIDR(host) { ipv6.append(mapped) }
            }
        }
        return (dedupeRoutes(ipv4), dedupeRoutes(ipv6))
    }

    static func effectiveExcludedRoutes(from flatPayload: [String: Any], baseIPv4: [String], baseIPv6: [String]) -> (ipv4: [String], ipv6: [String]) {
        let peerRoutes = overlayPeerExcludedRoutes(from: flatPayload)
        return (dedupeRoutes(baseIPv4 + peerRoutes.ipv4), dedupeRoutes(baseIPv6 + peerRoutes.ipv6))
    }

    static func enforceAdminAuthenticationUpdate(
        _ updates: inout [String: Any], currentAuthDisabled: Bool
    ) {
        if (updates["admin_web_auth_disable"] as? Bool) == true {
            updates["admin_web_username"] = ""
            updates["admin_web_password"] = ""
        } else if let password = updates["admin_web_password"] as? String,
                  password.isEmpty,
                  currentAuthDisabled,
                  updates["admin_web_auth_disable"] == nil {
            updates["admin_web_username"] = ""
            updates["admin_web_auth_disable"] = true
        }
    }

    private static func bindHost(for transport: String, payload: [String: Any]) -> String {
        let keys = ["myudp": "udp_bind", "tcp": "tcp_bind", "quic": "quic_bind", "ws": "ws_bind"]
        return keys[transport].flatMap { stringValue(from: payload[$0]) } ?? "::"
    }

    private static func resolveFamily(for transport: String, payload: [String: Any]) -> String {
        let keys = ["myudp": "udp_peer_resolve_family", "tcp": "tcp_peer_resolve_family", "quic": "quic_peer_resolve_family", "ws": "ws_peer_resolve_family"]
        return keys[transport].flatMap { peerResolveFamilyValue(from: payload[$0]) } ?? "prefer-ipv6"
    }

    private static func splitConfiguredPeerHosts(_ host: String) -> [String] {
        host.replacingOccurrences(of: ";", with: ",").split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    private static func dedupeRoutes(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.compactMap { value in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && seen.insert(trimmed).inserted ? trimmed : nil
        }
    }
}
