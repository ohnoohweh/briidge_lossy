import Foundation

/// Public projection port for platform-owned Admin HTTP surfaces. Core owns
/// the payload shape and hardening advice; adapters own request I/O.
public enum ObstacleBridgeAdminWebPort {
    public static func uiPayload(runtimeConfig: [String: Any], platform: String) -> [String: Any] {
        ObstacleBridgeAdminWebSupport.adminUIPayload(
            runtimeConfig: runtimeConfig,
            platform: platform,
            runtimeDependencies: ObstacleBridgeAdminWebSupport.adminRuntimeDependenciesPayload()
        )
    }

    public static func securityAdvisorPayload(runtimeConfig: [String: Any], bindHostFallback: String) -> [String: Any] {
        ObstacleBridgeAdminWebSupport.securityAdvisorPayload(
            runtimeConfig: runtimeConfig,
            bindHostFallback: bindHostFallback
        )
    }
}

struct ObstacleBridgeAdminUIBootstrapState {
    let firstStartDetected: Bool
    let configFileState: String
}

enum ObstacleBridgeAdminWebSupport {
    static func bootstrapState(
        peerConfigured: Bool,
        ownServicesConfigured: Bool,
        remoteServicesConfigured: Bool
    ) -> ObstacleBridgeAdminUIBootstrapState {
        let firstStartDetected = !peerConfigured && !ownServicesConfigured && !remoteServicesConfigured
        return ObstacleBridgeAdminUIBootstrapState(
            firstStartDetected: firstStartDetected,
            configFileState: firstStartDetected ? "empty" : "loaded"
        )
    }
    static func staticFileResponse(baseDirectoryURL: URL, path: String) -> (contentType: String, body: Data)? {
        let cleanedPath = normalizeStaticPath(path)
        let fileURL = baseDirectoryURL.appendingPathComponent(cleanedPath, isDirectory: false)
        guard fileURL.path.hasPrefix(baseDirectoryURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            return nil
        }
        return (contentType(for: fileURL.pathExtension), data)
    }

    static func normalizeStaticPath(_ rawPath: String) -> String {
        let basePath = rawPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
        let candidate = basePath == "/" ? "index.html" : String(basePath.drop(while: { $0 == "/" }))
        let components = candidate.split(separator: "/").filter { $0 != "." && $0 != ".." }
        return components.isEmpty ? "index.html" : components.joined(separator: "/")
    }

    static func contentType(for pathExtension: String) -> String {
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

    static func adminRuntimeDependenciesPayload() -> [String: Any] {
        [
            "ok": true,
            "missing": [],
            "install_hint": "",
        ]
    }

    static func adminUIPayload(
        runtimeConfig: [String: Any],
        platform: String,
        runtimeDependencies: [String: Any]
    ) -> [String: Any] {
        let bootstrapState = adminUIBootstrapState(from: runtimeConfig)
        return [
            "home_tab_enabled": true,
            "landing_page_enabled": false,
            "security_advisor_enabled": !(boolValue(value(for: "admin_web_security_advisor_disable", in: runtimeConfig)) ?? false),
            "security_advisor_startup_enabled": !(boolValue(value(for: "admin_web_security_advisor_startup_disable", in: runtimeConfig)) ?? false),
            "first_tab": stringValue(value(for: "admin_web_first_tab", in: runtimeConfig)) ?? "home",
            "first_start_detected": bootstrapState.firstStartDetected,
            "config_file_state": bootstrapState.configFileState,
            "platform": platform,
            "runtime_dependencies": runtimeDependencies,
        ]
    }

    static func securityAdvisorPayload(
        runtimeConfig: [String: Any],
        bindHostFallback: String
    ) -> [String: Any] {
        let enabled = !(boolValue(value(for: "admin_web_security_advisor_disable", in: runtimeConfig)) ?? false)
        let bind = (stringValue(value(for: "admin_web_bind", in: runtimeConfig)) ?? bindHostFallback)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let adminLocalOnly = isLoopbackHost(bind)
        let secureMode = (stringValue(value(for: "secure_link_mode", in: runtimeConfig)) ?? "off")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let securePSK = stringValue(value(for: "secure_link_psk", in: runtimeConfig)) ?? ""
        let authDisabled = boolValue(value(for: "admin_web_auth_disable", in: runtimeConfig)) ?? false
        var findings: [[String: Any]] = []
        if enabled {
            if (boolValue(value(for: "admin_web", in: runtimeConfig)) ?? false), authDisabled {
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

    static func isLoopbackHost(_ value: String) -> Bool {
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

    private static func value(for key: String, in payload: [String: Any]) -> Any? {
        if let direct = payload[key], !(direct is [String: Any]) {
            return direct
        }
        if let section = payload[key] as? [String: Any], let nested = section[key] {
            return nested
        }
        for value in payload.values {
            if let nested = value as? [String: Any], let match = self.value(for: key, in: nested) {
                return match
            }
        }
        return nil
    }

    private static func boolValue(_ value: Any?) -> Bool? {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        guard let value = value as? String else { return nil }
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: return nil
        }
    }

    private static func intValue(_ value: Any?) -> Int? {
        if let value = value as? NSNumber { return value.intValue }
        if let value = value as? Int { return value }
        if let value = value as? String { return Int(value) }
        return nil
    }

    private static func stringValue(_ value: Any?) -> String? {
        guard let value else { return nil }
        if let value = value as? String {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        if let value = value as? NSNumber { return value.stringValue }
        return nil
    }

    private static func adminUIBootstrapState(from runtimeConfig: [String: Any]) -> ObstacleBridgeAdminUIBootstrapState {
        let transportText = stringValue(value(for: "overlay_transport", in: runtimeConfig)) ?? "myudp"
        let transport = transportText.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.first(where: { !$0.isEmpty }) ?? "myudp"
        let prefix = transport == "myudp" ? "udp" : transport
        let peerConfigured = !(stringValue(value(for: "\(prefix)_peer", in: runtimeConfig)) ?? "").isEmpty
            && (intValue(value(for: "\(prefix)_peer_port", in: runtimeConfig)) ?? 0) > 0
        let ownConfigured = !(value(for: "own_servers", in: runtimeConfig) as? [Any] ?? []).isEmpty
        let remoteConfigured = !(value(for: "remote_servers", in: runtimeConfig) as? [Any] ?? []).isEmpty
        return bootstrapState(
            peerConfigured: peerConfigured,
            ownServicesConfigured: ownConfigured,
            remoteServicesConfigured: remoteConfigured
        )
    }
}
