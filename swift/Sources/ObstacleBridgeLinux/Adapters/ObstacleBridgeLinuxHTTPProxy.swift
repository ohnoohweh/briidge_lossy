import Foundation

/// Outbound WebSocket proxy policy. This is deliberately client-only and is
/// shared by clear WS and WSS setup before either WebSocket upgrade begins.
public enum ObstacleBridgeLinuxWebSocketProxyMode: String, Equatable, Sendable {
    case off, env, manual
}

public struct ObstacleBridgeLinuxHTTPProxy: Equatable, Sendable {
    public let mode: ObstacleBridgeLinuxWebSocketProxyMode
    public let host: String
    public let port: Int

    public init(mode: ObstacleBridgeLinuxWebSocketProxyMode = .env, host: String = "", port: Int = 8080) {
        self.mode = mode; self.host = host.trimmingCharacters(in: .whitespacesAndNewlines); self.port = port
    }

    func endpoint(targetHost: String, secure: Bool, environment: [String: String] = ProcessInfo.processInfo.environment) throws -> (String, Int)? {
        switch mode {
        case .off: return nil
        case .manual:
            guard !host.isEmpty, (1...65535).contains(port) else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
            return try parse(host, defaultPort: port)
        case .env:
            if bypasses(targetHost, noProxy: environment["NO_PROXY"] ?? environment["no_proxy"] ?? "") { return nil }
            let value = secure
                ? (environment["HTTPS_PROXY"] ?? environment["https_proxy"] ?? environment["HTTP_PROXY"] ?? environment["http_proxy"])
                : (environment["HTTP_PROXY"] ?? environment["http_proxy"])
            guard let value, !value.isEmpty else { return nil }
            return try parse(value, defaultPort: 8080)
        }
    }

    func basicAuthorization(targetHost: String, secure: Bool, environment: [String: String] = ProcessInfo.processInfo.environment) -> String? {
        let value: String?
        switch mode {
        case .off: return nil
        case .manual: value = host
        case .env:
            guard !bypasses(targetHost, noProxy: environment["NO_PROXY"] ?? environment["no_proxy"] ?? "") else { return nil }
            value = secure ? (environment["HTTPS_PROXY"] ?? environment["https_proxy"] ?? environment["HTTP_PROXY"] ?? environment["http_proxy"]) : (environment["HTTP_PROXY"] ?? environment["http_proxy"])
        }
        guard let value, value.contains("@") else { return nil }
        let candidate = value.contains("://") ? value : "http://\(value)"
        guard let components = URLComponents(string: candidate), let user = components.user else { return nil }
        let password = components.password ?? ""
        return "Basic " + Data("\(user):\(password)".utf8).base64EncodedString()
    }

    private func bypasses(_ target: String, noProxy: String) -> Bool {
        let host = target.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        // A local overlay peer is never an environment-proxy destination.
        // Manual proxy mode remains an explicit opt-in for test/deployment
        // topologies that deliberately tunnel loopback traffic.
        if host == "localhost" || host == "127.0.0.1" || host == "::1" { return true }
        return noProxy.split(separator: ",").contains { raw in
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if value == "*" { return true }
            let name = value.split(separator: ":", maxSplits: 1).first.map(String.init) ?? value
            return host == name || host.hasSuffix("." + name.trimmingCharacters(in: CharacterSet(charactersIn: ".")))
        }
    }

    private func parse(_ raw: String, defaultPort: Int) throws -> (String, Int) {
        let candidate = raw.contains("://") ? raw : "http://\(raw)"
        guard let components = URLComponents(string: candidate),
              components.scheme?.lowercased() == "http",
              let host = components.host, !host.isEmpty else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
        let port = components.port ?? defaultPort
        guard (1...65535).contains(port) else { throw ObstacleBridgeLinuxOverlayTransportError.invalidEndpoint }
        return (host, port)
    }
}
