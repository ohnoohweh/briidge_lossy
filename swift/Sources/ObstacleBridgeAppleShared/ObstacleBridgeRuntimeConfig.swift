import Foundation
import Darwin

enum ObstacleBridgeAppleRuntimeMetricsSampler {
    static func recordProcessCPU() {
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else { return }
        func ns(_ value: timeval) -> UInt64 { UInt64(max(0, value.tv_sec)) * 1_000_000_000 + UInt64(max(0, value.tv_usec)) * 1_000 }
        ObstacleBridgeRuntimeMetrics.shared.recordCPUSample(processCPUNS: ns(usage.ru_utime) &+ ns(usage.ru_stime))
    }
}

enum ObstacleBridgeRuntimeConfig {
    /// Version shared by desktop hosts when handing runtime configuration to an isolated worker.
    static let isolatedWorkerProtocolVersion = 1
    /// The iOS packet-flow bridge is the only Apple runtime with this FIFO, but
    /// its status schema and capacity are shared so WebAdmin payload consumers
    /// do not need a platform-private vocabulary.
    static let packetFlowFIFOQueueCapacity = 2048
    // Packaged-host qualification may provide an isolated runtime config
    // without changing either platform's durable app-scoped configuration.
    // The macOS primary app and host runner consume this shared vocabulary;
    // iOS deliberately has no process-environment override at runtime.
    static let appRuntimeConfigOverrideEnvironmentKey = "OBSTACLEBRIDGE_APP_RUNTIME_CONFIG"


    static func defaultTelemetryConfig() -> [String: Any] {
        ObstacleBridgeRuntimeConfigPolicy.defaultTelemetryConfig()
    }

    static func configSchemaSnapshot() -> [String: Any] {
        ObstacleBridgeRuntimeConfigPolicy.configSchemaSnapshot()
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
        ObstacleBridgeRuntimeConfigPolicy.overlaySessionMaxAppPayload(from: payload)
    }

    static func overlayMaxInflight(from payload: [String: Any]) -> Int {
        ObstacleBridgeRuntimeConfigPolicy.overlayMaxInflight(from: payload)
    }

    static func normalizedConfigUpdates(_ updates: [String: Any], currentRuntimeConfig: [String: Any]) -> [String: Any] {
        var normalized = updates
        for sectionName in ObstacleBridgeRuntimeConfigPolicy.knownGroupedSections + ["channel_mux", "iOS_TUN_connector"] {
            guard let payload = normalized[sectionName] as? [String: Any] else {
                continue
            }
            normalized.removeValue(forKey: sectionName)
            for (key, value) in normalizedSectionPayload(sectionName, payload: payload) {
                normalized[key] = value
            }
        }
        applyCompatibilityAliases(to: &normalized)
        ObstacleBridgeRuntimeConfigPolicy.enforceAdminAuthenticationUpdate(
            &normalized,
            currentAuthDisabled: boolValue(from: currentRuntimeConfig["admin_web_auth_disable"]) ?? false
        )
        return normalized
    }

    static func maskedConfigSnapshot(_ runtimeConfig: [String: Any]) -> [String: Any] {
        var payload = runtimeConfig
        normalizeFlatPayloadForSchema(&payload)
        // The admin configuration form posts every visible telemetry-client
        // field. Return schema-typed defaults for unset values so a
        // read-modify-save cycle never submits a null where the schema
        // requires an empty string.
        for (key, defaultValue) in defaultTelemetryConfig()
            where payload[key] == nil || payload[key] is NSNull {
            payload[key] = defaultValue
        }
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
        if payload["proxy_provider_enabled"] == nil {
            payload["proxy_provider_enabled"] = false
        }
        if payload["proxy_provider_bind"] == nil {
            payload["proxy_provider_bind"] = "127.0.0.1"
        }
        if payload["proxy_provider_http_port"] == nil {
            payload["proxy_provider_http_port"] = 13881
        }
        if payload["proxy_provider_socks5_port"] == nil {
            payload["proxy_provider_socks5_port"] = 13882
        }
        if payload["proxy_provider_protocols"] == nil {
            payload["proxy_provider_protocols"] = ["http-connect", "socks5-connect"]
        }
        if payload["proxy_provider_auth"] == nil {
            payload["proxy_provider_auth"] = [
                "mode": "none",
                "username": "",
                "token": "",
            ]
        }
        if payload["proxy_provider_egress"] == nil {
            payload["proxy_provider_egress"] = [
                "mode": "system",
                "address_families": ["ipv4", "ipv6"],
            ]
        }
        if payload["proxy_provider_policy"] == nil {
            payload["proxy_provider_policy"] = [
                "allow_private_destinations": false,
                "blocked_host_patterns": [],
            ]
        }
        if payload["log_proxy_provider"] == nil {
            payload["log_proxy_provider"] = NSNull()
        }
        if payload["quic_bind"] == nil {
            payload["quic_bind"] = "::"
        }
        if payload["quic_own_port"] == nil {
            payload["quic_own_port"] = 443
        }
        if payload["quic_peer"] == nil {
            payload["quic_peer"] = NSNull()
        }
        if payload["quic_peer_port"] == nil {
            payload["quic_peer_port"] = 443
        }
        if payload["quic_peer_resolve_family"] == nil {
            payload["quic_peer_resolve_family"] = "prefer-ipv6"
        }
        if payload["ws_bind"] == nil {
            payload["ws_bind"] = "::"
        }
        if payload["ws_own_port"] == nil {
            payload["ws_own_port"] = 8080
        }
        if payload["ws_peer"] == nil {
            payload["ws_peer"] = NSNull()
        }
        if payload["ws_peer_addresses"] == nil {
            payload["ws_peer_addresses"] = []
        }
        if payload["ws_peer_port"] == nil {
            payload["ws_peer_port"] = 8080
        }
        if payload["ws_path"] == nil {
            payload["ws_path"] = "/"
        }
        if payload["ws_peer_resolve_family"] == nil {
            payload["ws_peer_resolve_family"] = "prefer-ipv6"
        }
        if payload["secure_link"] == nil {
            payload["secure_link"] = false
        }
        if payload["secure_link_mode"] == nil {
            payload["secure_link_mode"] = "off"
        }
        if payload["secure_link_psk"] == nil {
            payload["secure_link_psk"] = ""
        }
        if payload["secure_link_rekey_after_frames"] == nil {
            payload["secure_link_rekey_after_frames"] = 0
        }
        if payload["secure_link_rekey_after_seconds"] == nil {
            payload["secure_link_rekey_after_seconds"] = 0.0
        }
        if payload["secure_link_retry_backoff_initial_ms"] == nil {
            payload["secure_link_retry_backoff_initial_ms"] = 1000
        }
        if payload["secure_link_retry_backoff_max_ms"] == nil {
            payload["secure_link_retry_backoff_max_ms"] = 5000
        }
        if payload["compress_layer"] == nil {
            payload["compress_layer"] = false
        }
        if payload["compress_layer_algo"] == nil {
            payload["compress_layer_algo"] = "zlib"
        }
        if payload["compress_layer_level"] == nil {
            payload["compress_layer_level"] = 3
        }
        if payload["compress_layer_min_bytes"] == nil {
            payload["compress_layer_min_bytes"] = 64
        }
        if payload["compress_layer_types"] == nil {
            payload["compress_layer_types"] = "data,data_frag"
        }
        for key in [
            "admin_web_password",
            "secure_link_psk",
        ] where payload[key] != nil {
            payload[key] = ""
        }
        return payload
    }

    private static func normalizedSectionPayload(_ sectionName: String, payload: [String: Any]) -> [String: Any] {
        guard let rows = configSchemaSnapshot()[sectionName] as? [[String: Any]] else {
            return payload
        }
        var normalized = payload
        if sectionName == "proxy_provider" {
            applyCompatibilityAliases(to: &normalized)
            for alias in ObstacleBridgeRuntimeConfigPolicy.proxyProviderCompatibilityAliasKeys {
                normalized.removeValue(forKey: alias)
            }
        } else if sectionName == "tun_execution" {
            applyCompatibilityAliases(to: &normalized)
            for alias in ObstacleBridgeRuntimeConfigPolicy.tunExecutionCompatibilityAliasKeys {
                normalized.removeValue(forKey: alias)
            }
        }
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
        applyCompatibilityAliases(to: &payload)
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

    private static func applyCompatibilityAliases(to payload: inout [String: Any]) {
        ObstacleBridgeRuntimeConfigPolicy.applyCompatibilityAliases(to: &payload)
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
        ObstacleBridgeRuntimeConfigPolicy.schemaItem(key: key, description: description, defaultValue: defaultValue, choices: choices, secret: secret)
    }

    static func flatten(_ payload: [String: Any]) -> [String: Any] {
        var merged: [String: Any] = [:]
        for section in ObstacleBridgeRuntimeConfigPolicy.knownGroupedSections {
            let block = groupedSectionPayload(section, runtimeConfig: payload)
            for (key, value) in block {
                merged[key] = value
            }
        }
        for (key, value) in payload where !(value is [String: Any]) {
            if merged[key] == nil {
                merged[key] = value
            }
        }
        applyCompatibilityAliases(to: &merged)
        return merged
    }

    static func looksGrouped(_ payload: [String: Any]) -> Bool {
        ObstacleBridgeRuntimeConfigPolicy.looksGrouped(payload)
    }

    static func tunnelRoutingOverride(from payload: [String: Any]) -> ObstacleBridgeTunnelRoutingOverride? {
        let override: [String: Any]
        if let grouped = payload["TUN_routing"] as? [String: Any] {
            override = grouped
        } else {
            var flattened: [String: Any] = [:]
            let keys = [
                "tunnel_address",
                "tunnel_prefix",
                "tunnel_gateway",
                "included_routes",
                "excluded_routes",
                "tunnel_address6",
                "tunnel_prefix6",
                "tunnel_gateway6",
                "included_routes6",
                "excluded_routes6",
                "dns_servers",
                "mtu",
                "enabled_on_startup",
                "enable_tcpmss",
                "enable_tun_tcpdump",
                "tun_tcpdump_pcap_path",
                "shared_tun_disable_outgoing_normalization",
                "shared_tun_disable_inflow_filter",
                "shared_tun_disable_outflow_filter",
                "shared_tun_disable_scoped_throttle",
            ]
            for key in keys {
                if let value = payload[key] {
                    flattened[key] = value
                }
            }
            guard !flattened.isEmpty else {
                return nil
            }
            override = flattened
        }
        return ObstacleBridgeTunnelRoutingOverride(
            tunnelAddress: firstStringValue(from: override["tunnel_address"]),
            tunnelPrefix: intValue(from: override["tunnel_prefix"]),
            tunnelGateway: optionalStringValueAllowEmpty(from: override["tunnel_gateway"]),
            includedRoutes: override["included_routes"] as? [String],
            excludedRoutes: override["excluded_routes"] as? [String],
            tunnelAddress6: firstStringValue(from: override["tunnel_address6"]),
            tunnelPrefix6: intValue(from: override["tunnel_prefix6"]),
            tunnelGateway6: optionalStringValueAllowEmpty(from: override["tunnel_gateway6"]),
            includedRoutes6: override["included_routes6"] as? [String],
            excludedRoutes6: override["excluded_routes6"] as? [String],
            dnsServers: override["dns_servers"] as? [String],
            mtu: intValue(from: override["mtu"]),
            enabledOnStartup: boolValue(from: override["enabled_on_startup"]),
            enableTCPMSS: boolValue(from: override["enable_tcpmss"]),
            enableTunTcpdump: boolValue(from: override["enable_tun_tcpdump"]),
            tunTcpdumpPcapPath: optionalStringValueAllowEmpty(from: override["tun_tcpdump_pcap_path"]),
            sharedTunDisableOutgoingNormalization: boolValue(from: override["shared_tun_disable_outgoing_normalization"]),
            sharedTunDisableInflowFilter: boolValue(from: override["shared_tun_disable_inflow_filter"]),
            sharedTunDisableOutflowFilter: boolValue(from: override["shared_tun_disable_outflow_filter"]),
            sharedTunDisableScopedThrottle: boolValue(from: override["shared_tun_disable_scoped_throttle"])
        )
    }

    private static func tunnelRoutingString(
        _ value: String?,
        default defaultValue: String,
        allowEmpty: Bool = false
    ) -> String {
        guard let value else {
            return defaultValue
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return allowEmpty ? "" : defaultValue
        }
        return trimmed
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
        let peerGateway4 = tunnelRoutingString(override?.tunnelGateway, default: "192.168.106.2", allowEmpty: true)
        let tunnelAddress6 = tunnelRoutingString(override?.tunnelAddress6, default: "fd20:106::1")
        let tunnelPrefix6 = tunnelRoutingInt(override?.tunnelPrefix6, default: 126)
        let peerGateway6 = tunnelRoutingString(override?.tunnelGateway6, default: "fd20:106::2", allowEmpty: true)
        let mtu = tunnelRoutingInt(override?.mtu, default: 1600)
        var env: [String: String] = [
            "MTU": String(mtu),
            "ENABLE_TCPMSS": (override?.enableTCPMSS ?? false) ? "1" : "0",
            "ENABLE_TUN_TCPDUMP": (override?.enableTunTcpdump ?? false) ? "1" : "0",
            "TUN_SUBNET": "\(tunnelAddress)/\(tunnelPrefix)",
        ]
        if let pcapPath = override?.tunTcpdumpPcapPath, !pcapPath.isEmpty {
            env["TCPDUMP_PCAP_PATH"] = pcapPath
        }
        if !peerGateway4.isEmpty {
            env["TUN_ADDR"] = "\(peerGateway4)/\(tunnelPrefix)"
            env["PEER_ADDR"] = tunnelAddress
        }
        if !tunnelAddress6.isEmpty {
            env["TUN_SUBNET6"] = "\(tunnelAddress6)/\(tunnelPrefix6)"
        }
        if !peerGateway6.isEmpty, !tunnelAddress6.isEmpty {
            env["TUN_ADDR6"] = "\(peerGateway6)/\(tunnelPrefix6)"
            env["PEER_ADDR6"] = tunnelAddress6
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
        ObstacleBridgeRuntimeConfigPolicy.intValue(from: value)
    }

    /// The portable private-worker record vocabulary uses Python logging's
    /// non-negative numeric threshold. Hosts that do not own desktop workers
    /// can still validate configuration without creating a process boundary.
    static func privateWorkerLogLevel(from value: Any?, fallback: Int = 30) -> Int {
        guard let level = intValue(from: value), level >= 0 else { return fallback }
        return level
    }

    static func doubleValue(from value: Any?) -> Double? {
        ObstacleBridgeRuntimeConfigPolicy.doubleValue(from: value)
    }

    static func boolValue(from value: Any?) -> Bool? {
        ObstacleBridgeRuntimeConfigPolicy.boolValue(from: value)
    }

    static func stringValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfigPolicy.stringValue(from: value)
    }

    private static func firstStringValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfigPolicy.firstStringValue(from: value)
    }

    static func peerResolveFamilyValue(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfigPolicy.peerResolveFamilyValue(from: value)
    }

    static func wsPeerAddresses(from value: Any?) -> [String] {
        ObstacleBridgeRuntimeConfigPolicy.wsPeerAddresses(from: value)
    }

    static func peerHost(for transport: String, payload: [String: Any]) -> String? {
        ObstacleBridgeRuntimeConfigPolicy.peerHost(for: transport, payload: payload)
    }

    static func peerPort(for transport: String, payload: [String: Any]) -> Int? {
        ObstacleBridgeRuntimeConfigPolicy.peerPort(for: transport, payload: payload)
    }

    static func overlayPeerExcludedRoutes(from payload: [String: Any]) -> (ipv4: [String], ipv6: [String]) {
        ObstacleBridgeRuntimeConfigPolicy.overlayPeerExcludedRoutes(from: flatten(payload))
    }

    static func effectiveExcludedRoutes(from payload: [String: Any], baseIPv4: [String], baseIPv6: [String]) -> (ipv4: [String], ipv6: [String]) {
        ObstacleBridgeRuntimeConfigPolicy.effectiveExcludedRoutes(
            from: flatten(payload), baseIPv4: baseIPv4, baseIPv6: baseIPv6
        )
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
        return ObstacleBridgeAdminWebSupport.bootstrapState(
            peerConfigured: peerConfigured,
            ownServicesConfigured: ownConfigured,
            remoteServicesConfigured: remoteConfigured
        )
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
        // `iOS_TUN_connector` describes the local Packet Tunnel/helper
        // boundary. Native Swift UDP gets its remote overlay endpoint only
        // from the selected transport's configuration.
        let peerHost = connectorMode == "swift_udp"
            ? peerHost(for: selectedTransport, payload: payload)
            : nil
        guard let peerHost else {
            return nil
        }
        let peerPort = connectorMode == "swift_udp"
            ? (peerPort(for: selectedTransport, payload: payload) ?? 0)
            : 0
        guard peerPort > 0 else {
            return nil
        }
        let peerResolveFamily: String
        switch selectedTransport {
        case "tcp":
            peerResolveFamily = peerResolveFamilyValue(from: payload["tcp_peer_resolve_family"]) ?? "prefer-ipv6"
        case "quic":
            peerResolveFamily = peerResolveFamilyValue(from: payload["quic_peer_resolve_family"]) ?? "prefer-ipv6"
        default:
            peerResolveFamily = peerResolveFamilyValue(from: payload["udp_peer_resolve_family"]) ?? "prefer-ipv6"
        }
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

    static func localUDPServiceSpecs(from payload: [String: Any]) -> [ObstacleBridgeChannelMuxCodec.ServiceSpec] {
        ownServerSpecs(from: payload, preserveInputIndices: true)
            .filter { $0.listenProtocol == "udp" && $0.targetProtocol == "udp" }
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
        let defaultTunMTU = tunnelRoutingOverride(from: payload)?.mtu ?? 1600
        var specs: [ObstacleBridgeRuntimeServiceSpec] = []
        var nextDenseID = 1
        for (index, item) in rawSpecs.enumerated() {
            let svcID = preserveInputIndices ? (index + 1) : nextDenseID
            guard let spec = parseOwnServerSpec(item, svcID: svcID, defaultTunMTU: defaultTunMTU) else {
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
        if let section = payload["iOS_TUN_connector"] as? [String: Any] {
            return section
        }
        let flat = flatten(payload)
        let transport = stringValue(from: flat["overlay_transport"]) ?? ""
        guard !transport.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        return [
            "packetflow_connector": "swift_udp",
            "bind_host": "127.0.0.1",
            "bind_port": 5555,
            "peer_host": "",
            "peer_port": 0,
            "ifname": "ios-utun",
            "mtu": intValue(from: flat["mtu"]) ?? 1600,
        ]
    }

    private static func serviceArray(from payload: [String: Any], key: String) -> [Any]? {
        if let channelMux = payload["channel_mux"] as? [String: Any],
           let specs = channelMux[key] as? [Any] {
            return specs
        }
        return payload[key] as? [Any]
    }

    private static func parseOwnServerSpec(_ item: Any, svcID: Int) -> ObstacleBridgeRuntimeServiceSpec? {
        return parseOwnServerSpec(item, svcID: svcID, defaultTunMTU: 1600)
    }

    private static func parseOwnServerSpec(_ item: Any, svcID: Int, defaultTunMTU: Int) -> ObstacleBridgeRuntimeServiceSpec? {
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
            listenPort = intValue(from: listen["mtu"]) ?? defaultTunMTU
        } else {
            listenBind = stringValue(from: listen["bind"])
            listenPort = intValue(from: listen["port"])
        }

        let targetHost: String?
        let targetPort: Int?
        if targetProtocol == "tun" {
            targetHost = stringValue(from: target["ifname"])
            targetPort = intValue(from: target["mtu"]) ?? defaultTunMTU
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

    private static func optionalStringValueAllowEmpty(from value: Any?) -> String? {
        ObstacleBridgeRuntimeConfigPolicy.optionalStringValueAllowEmpty(from: value)
    }
}

extension ObstacleBridgeRuntimeConfig {
    static func adminConfigPolicy() -> ObstacleBridgeAdminConfigSupport.ConfigurationPolicy {
        ObstacleBridgeAdminConfigSupport.ConfigurationPolicy(
            normalizedUpdates: { normalizedConfigUpdates($0, currentRuntimeConfig: $1) },
            looksGrouped: looksGrouped,
            schemaRow: schemaRow(forKey:),
            sectionName: sectionName(forKey:)
        )
    }
}
