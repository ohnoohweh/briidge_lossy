import Foundation

enum ObstacleBridgeOnboarding {
    static func tokenRuntimeConfig(runtimeConfig: [String: Any], requestPayload: [String: Any]) -> [String: Any] {
        var effective = runtimeConfig
        let adminWebName = (requestPayload["admin_web_name"] as? String ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if !adminWebName.isEmpty {
            effective["admin_web_name"] = adminWebName
        }
        return effective
    }

    static func normalizedOverlayTransports(runtimeConfig: [String: Any]) -> [String] {
        let raw = runtimeConfig["overlay_transport"]
        let candidates: [String]
        if let string = raw as? String {
            candidates = string.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        } else if let list = raw as? [Any] {
            candidates = list.map { String(describing: $0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        } else {
            candidates = []
        }
        var out: [String] = []
        for item in candidates where ["udp", "myudp", "tcp", "quic", "ws"].contains(item) {
            let normalized = item == "udp" ? "myudp" : item
            if !out.contains(normalized) {
                out.append(normalized)
            }
        }
        return out.isEmpty ? ["myudp"] : out
    }

    static func connectionProfiles(runtimeConfig: [String: Any]) -> [[String: Any]] {
        let secureMode = (ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        var profiles: [[String: Any]] = []
        for transport in normalizedOverlayTransports(runtimeConfig: runtimeConfig) {
            let prefix = transport == "myudp" ? "udp" : transport
            let bind = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["\(prefix)_bind"]) ?? ""
            let ownPort = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["\(prefix)_own_port"])
            let peerHost = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["\(prefix)_peer"]) ?? ""
            let peerPort = ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["\(prefix)_peer_port"])
            let role = peerHost.isEmpty ? "server" : "client"
            let endpointHost = role == "client" ? peerHost : bind
            let endpointPort = role == "client" ? peerPort : ownPort
            var profile: [String: Any] = [
                "id": "cfg:\(transport):\(profiles.count)",
                "source": "config",
                "transport": transport,
                "role": role,
                "endpoint_host": endpointHost,
                "endpoint_port": endpointPort ?? NSNull(),
                "listen_bind": bind,
                "listen_port": ownPort ?? NSNull(),
                "peer_host": peerHost,
                "peer_port": peerPort ?? NSNull(),
                "secure_link_mode": secureMode,
                "label": role == "client"
                    ? "\(transport.uppercased()) peer \(peerHost):\(peerPort ?? 0)"
                    : "\(transport.uppercased()) listen \(bind):\(ownPort ?? 0)",
            ]
            if transport == "ws" {
                profile["ws_path"] = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["ws_path"]) ?? "/"
                profile["ws_tls"] = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["ws_tls"]) ?? false
            }
            profiles.append(profile)
        }
        return profiles
    }

    static func sanitizeServices(_ value: Any?) -> [[String: Any]] {
        guard let items = value as? [Any] else {
            return []
        }
        var out: [[String: Any]] = []
        for item in items {
            guard let dict = item as? [String: Any],
                  let listen = dict["listen"] as? [String: Any],
                  let target = dict["target"] as? [String: Any] else {
                continue
            }
            let listenProto = (ObstacleBridgeRuntimeConfig.stringValue(from: listen["protocol"]) ?? "").lowercased()
            let targetProto = (ObstacleBridgeRuntimeConfig.stringValue(from: target["protocol"]) ?? "").lowercased()
            guard ["udp", "tcp", "tun"].contains(listenProto),
                  ["udp", "tcp", "tun"].contains(targetProto) else {
                continue
            }
            var spec: [String: Any] = [
                "listen": ["protocol": listenProto],
                "target": ["protocol": targetProto],
            ]
            if let name = ObstacleBridgeRuntimeConfig.stringValue(from: dict["name"]), !name.isEmpty {
                spec["name"] = name
            }
            if listenProto == "tun" {
                if let ifname = ObstacleBridgeRuntimeConfig.stringValue(from: listen["ifname"]), !ifname.isEmpty {
                    var branch = spec["listen"] as? [String: Any] ?? [:]
                    branch["ifname"] = ifname
                    if let mtu = ObstacleBridgeRuntimeConfig.intValue(from: listen["mtu"]), (1...65535).contains(mtu) {
                        branch["mtu"] = mtu
                    }
                    spec["listen"] = branch
                }
            } else if let bind = ObstacleBridgeRuntimeConfig.stringValue(from: listen["bind"]),
                      let port = ObstacleBridgeRuntimeConfig.intValue(from: listen["port"]),
                      !bind.isEmpty,
                      (1...65535).contains(port) {
                var branch = spec["listen"] as? [String: Any] ?? [:]
                branch["bind"] = bind
                branch["port"] = port
                spec["listen"] = branch
            }
            if targetProto == "tun" {
                if let ifname = ObstacleBridgeRuntimeConfig.stringValue(from: target["ifname"]), !ifname.isEmpty {
                    var branch = spec["target"] as? [String: Any] ?? [:]
                    branch["ifname"] = ifname
                    if let mtu = ObstacleBridgeRuntimeConfig.intValue(from: target["mtu"]), (1...65535).contains(mtu) {
                        branch["mtu"] = mtu
                    }
                    spec["target"] = branch
                }
            } else if let host = ObstacleBridgeRuntimeConfig.stringValue(from: target["host"]),
                      let port = ObstacleBridgeRuntimeConfig.intValue(from: target["port"]),
                      !host.isEmpty,
                      (1...65535).contains(port) {
                var branch = spec["target"] as? [String: Any] ?? [:]
                branch["host"] = host
                branch["port"] = port
                spec["target"] = branch
            }
            if let hooks = dict["lifecycle_hooks"] as? [String: Any] {
                spec["lifecycle_hooks"] = hooks
            }
            if let options = dict["options"] as? [String: Any] {
                spec["options"] = options
            }
            out.append(spec)
        }
        return out
    }

    static func tokenPayload(
        runtimeConfig: [String: Any],
        connection: [String: Any],
        ownServices: [[String: Any]],
        remoteServices: [[String: Any]],
        encryptSecrets: ([String: Any]) throws -> [String: Any]
    ) -> [String: Any] {
        let secureMode = (ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let plainPSK = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["secure_link_psk"]) ?? ""
        let adminWebName = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["admin_web_name"]) ?? ""
        let tunRouting = ObstacleBridgeRuntimeConfig.groupedSectionPayload("TUN_routing", runtimeConfig: runtimeConfig)
        return [
            "version": 1,
            "generated_unix_ts": Int(Date().timeIntervalSince1970),
            "generated_by": adminWebName,
            "admin_web_name": adminWebName,
            "connection": connection,
            "secure_link_mode": ["off", "none", "psk", "cert"].contains(secureMode) ? secureMode : "off",
            "secure_link_psk": plainPSK,
            "secure_link_required": ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["secure_link_require"]) ?? false,
            "compress_layer": ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["compress_layer"]) ?? true,
            "compress_layer_algo": ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["compress_layer_algo"]) ?? "zlib",
            "compress_layer_level": ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_level"]) ?? 3,
            "compress_layer_min_bytes": ObstacleBridgeRuntimeConfig.intValue(from: runtimeConfig["compress_layer_min_bytes"]) ?? 64,
            "compress_layer_types": ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["compress_layer_types"]) ?? "data,data_frag",
            "TUN_routing": tunRouting,
            "admin_auth_recommended": true,
            "own_servers": ownServices,
            "remote_servers": remoteServices,
        ]
    }

    static func encodeToken(_ payload: [String: Any]) throws -> String {
        let raw = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        return "ob1." + urlSafeBase64Encode(raw)
    }

    static func decodeToken(_ token: String) throws -> [String: Any] {
        var text = token.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("ob1.") {
            text.removeFirst(4)
        }
        guard !text.isEmpty else {
            throw NSError(domain: "ObstacleBridgeOnboarding", code: 1, userInfo: [NSLocalizedDescriptionKey: "invite token is empty"])
        }
        let raw = try urlSafeBase64Decode(text)
        guard let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
            throw NSError(domain: "ObstacleBridgeOnboarding", code: 2, userInfo: [NSLocalizedDescriptionKey: "invite token payload must be a JSON object"])
        }
        return object
    }

    static func updates(
        from payload: [String: Any],
        decryptSecrets: ([String: Any]) throws -> [String: Any]
    ) throws -> [String: Any] {
        guard let connection = payload["connection"] as? [String: Any] else {
            return [:]
        }
        var updates: [String: Any] = [:]
        var transport = (ObstacleBridgeRuntimeConfig.stringValue(from: connection["transport"]) ?? "").lowercased()
        if transport == "udp" {
            transport = "myudp"
        }
        let host = ObstacleBridgeRuntimeConfig.stringValue(from: connection["endpoint_host"]) ?? ""
        let port = ObstacleBridgeRuntimeConfig.intValue(from: connection["endpoint_port"])
        if ["myudp", "tcp", "quic", "ws"].contains(transport), !host.isEmpty {
            let prefix = transport == "myudp" ? "udp" : transport
            updates["overlay_transport"] = transport
            updates["\(prefix)_peer"] = host
            if let port, (1...65535).contains(port) {
                updates["\(prefix)_peer_port"] = port
            }
        }
        let secureMode = (ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_mode"]) ?? "").lowercased()
        if ["off", "none", "psk", "cert"].contains(secureMode) {
            updates["secure_link_mode"] = ["off", "none"].contains(secureMode) ? "off" : secureMode
            updates["secure_link"] = !["off", "none"].contains(secureMode)
        }
        if let adminWebName = ObstacleBridgeRuntimeConfig.stringValue(from: payload["admin_web_name"]), !adminWebName.isEmpty {
            updates["admin_web_name"] = adminWebName
        }
        if payload["compress_layer"] != nil {
            updates["compress_layer"] = ObstacleBridgeRuntimeConfig.boolValue(from: payload["compress_layer"]) ?? false
        }
        for key in ["compress_layer_algo", "compress_layer_level", "compress_layer_min_bytes", "compress_layer_types"] {
            if let value = payload[key] {
                updates[key] = value
            }
        }
        if let tunRouting = payload["TUN_routing"] as? [String: Any], !tunRouting.isEmpty {
            updates["TUN_routing"] = tunRouting
        }
        if let tokenPSK = ObstacleBridgeRuntimeConfig.stringValue(from: payload["secure_link_psk"]), !tokenPSK.isEmpty {
            var plainPSK = tokenPSK
            do {
                if let decryptedPSK = try decryptSecrets(["secure_link_psk": tokenPSK])["secure_link_psk"] as? String,
                   !decryptedPSK.isEmpty {
                    plainPSK = decryptedPSK
                }
            } catch {
                if tokenPSK.hasPrefix("enc:v1:") {
                    throw NSError(
                        domain: "ObstacleBridgeOnboarding",
                        code: 4,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "invite token carries a legacy encrypted secure_link_psk that cannot be decrypted on this device; generate a fresh invite token"
                        ]
                    )
                }
            }
            if !plainPSK.isEmpty {
                updates["secure_link_psk"] = plainPSK
            }
        }
        let own = sanitizeServices(payload["own_servers"])
        let remote = sanitizeServices(payload["remote_servers"])
        if !own.isEmpty {
            updates["own_servers"] = own
        }
        if !remote.isEmpty {
            updates["remote_servers"] = remote
        }
        return updates
    }

    private static func urlSafeBase64Encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
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
            throw NSError(domain: "ObstacleBridgeOnboarding", code: 3, userInfo: [NSLocalizedDescriptionKey: "invite token is not valid base64url"])
        }
        return data
    }
}
