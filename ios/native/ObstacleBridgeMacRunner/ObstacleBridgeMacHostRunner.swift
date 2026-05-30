import Foundation
import Network

private enum ObstacleBridgeMacHostRunnerError: Error, LocalizedError {
    case usage(String)
    case invalidArgument(String)
    case unreadableRuntimeConfig(String)
    case invalidRuntimeConfigRoot
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
        case .invalidStatusPort(let port):
            return "Invalid status/admin port: \(port)"
        }
    }
}

private final class ObstacleBridgeHTTPControlServer {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "ObstacleBridgeMacHostRunner.HTTP")
    private let statusProvider: () -> [String: Any]

    init(bindHost: String, port: Int, statusProvider: @escaping () -> [String: Any]) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw ObstacleBridgeMacHostRunnerError.invalidStatusPort(port)
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let host = bindHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty {
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: nwPort)
        }
        self.listener = try NWListener(using: parameters)
        self.statusProvider = statusProvider
        listener.stateUpdateHandler = { state in
            switch state {
            case .failed(let error):
                fputs("ObstacleBridgeMacHostRunner listener failed: \(error.localizedDescription)\n", stderr)
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.handle(connection)
        }
    }

    func start() {
        listener.start(queue: queue)
    }

    func stop() {
        listener.cancel()
    }

    private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, _, _ in
            guard let self else {
                connection.cancel()
                return
            }
            let request = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let path = Self.requestPath(from: request)
            let response = self.response(for: path)
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }

    private static func requestPath(from request: String) -> String {
        guard let line = request.split(separator: "\n", maxSplits: 1).first else {
            return "/"
        }
        let parts = line.split(separator: " ")
        guard parts.count >= 2 else {
            return "/"
        }
        return String(parts[1])
    }

    private func response(for path: String) -> Data {
        let snapshot = statusProvider()
        if path == "/api/status" || path == "/status" || path == "/healthz" {
            return Self.httpResponse(
                statusLine: "HTTP/1.1 200 OK",
                contentType: "application/json; charset=utf-8",
                body: Self.jsonBody(snapshot)
            )
        }
        if path == "/api/bootstrap" {
            let body = Self.jsonBody(snapshot["bootstrap_state"] ?? [:])
            return Self.httpResponse(
                statusLine: "HTTP/1.1 200 OK",
                contentType: "application/json; charset=utf-8",
                body: body
            )
        }
        let html = Self.htmlIndex(snapshot: snapshot)
        return Self.httpResponse(
            statusLine: "HTTP/1.1 200 OK",
            contentType: "text/html; charset=utf-8",
            body: Data(html.utf8)
        )
    }

    private static func jsonBody(_ value: Any) -> Data {
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) {
            return data
        }
        let fallback: [String: Any] = [
            "ok": false,
            "error": "snapshot was not a valid JSON object",
        ]
        return (try? JSONSerialization.data(withJSONObject: fallback, options: [.prettyPrinted, .sortedKeys])) ?? Data("{}".utf8)
    }

    private static func httpResponse(statusLine: String, contentType: String, body: Data) -> Data {
        var header = "\(statusLine)\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Content-Length: \(body.count)\r\n"
        header += "Connection: close\r\n"
        header += "Cache-Control: no-store\r\n\r\n"
        var response = Data(header.utf8)
        response.append(body)
        return response
    }

    private static func htmlIndex(snapshot: [String: Any]) -> String {
        let jsonData = jsonBody(snapshot)
        let jsonText = String(data: jsonData, encoding: .utf8) ?? "{}"
        return """
        <!doctype html>
        <html lang=\"en\">
        <head>
          <meta charset=\"utf-8\">
          <title>ObstacleBridge macOS Swift Host Runner</title>
          <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
          <style>
            :root { color-scheme: light; }
            body { margin: 0; font-family: Menlo, Monaco, monospace; background: #f3efe7; color: #1e2a2f; }
            main { max-width: 960px; margin: 0 auto; padding: 32px 20px 48px; }
            h1 { margin: 0 0 8px; font-size: 28px; }
            p { margin: 0 0 16px; }
            .card { background: #fffaf3; border: 1px solid #d9ccb8; border-radius: 16px; padding: 20px; box-shadow: 0 10px 30px rgba(30, 42, 47, 0.08); }
            pre { overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
            a { color: #005f73; }
          </style>
        </head>
        <body>
          <main>
            <h1>ObstacleBridge macOS Swift Host Runner</h1>
            <p>Swift-only bootstrap and status surface for host-side E2E harnessing.</p>
            <div class=\"card\">
              <p><a href=\"/api/status\">/api/status</a> | <a href=\"/api/bootstrap\">/api/bootstrap</a></p>
              <pre>\(Self.escapeHTML(jsonText))</pre>
            </div>
          </main>
        </body>
        </html>
        """
    }

    private static func escapeHTML(_ text: String) -> String {
        var output = text
        let replacements = [
            ("&", "&amp;"),
            ("<", "&lt;"),
            (">", "&gt;"),
        ]
        for (needle, replacement) in replacements {
            output = output.replacingOccurrences(of: needle, with: replacement)
        }
        return output
    }
}

private final class ObstacleBridgeMacHostRunner {
    private let runtimeConfigPath: String
    private let runtimeConfigRaw: [String: Any]
    private let runtimeConfig: [String: Any]
    private let bindHost: String
    private let statusPort: Int
    private let startedAt = Date()
    private var controlServer: ObstacleBridgeHTTPControlServer?
    private var bootstrapState: [String: Any] = [:]
    private var sharedCompressLayerRuntime: ObstacleBridgeCompressLayerRuntime?
    private var sharedWebSocketOverlayRuntime: ObstacleBridgeWebSocketOverlayRuntime?
    private var sharedTcpOverlayRuntime: ObstacleBridgeTcpOverlayRuntime?

    init(runtimeConfigPath: String, bindHostOverride: String?, statusPortOverride: Int?) throws {
        self.runtimeConfigPath = runtimeConfigPath
        let url = URL(fileURLWithPath: runtimeConfigPath)
        guard let data = try? Data(contentsOf: url) else {
            throw ObstacleBridgeMacHostRunnerError.unreadableRuntimeConfig(runtimeConfigPath)
        }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let decoded = object as? [String: Any] else {
            throw ObstacleBridgeMacHostRunnerError.invalidRuntimeConfigRoot
        }
        self.runtimeConfigRaw = decoded
        self.runtimeConfig = Self.flattenRuntimeConfig(decoded)
        self.bindHost = bindHostOverride ?? (Self.stringValue(from: runtimeConfig["admin_web_bind"]) ?? "127.0.0.1")
        let configuredPort = Self.intValue(from: runtimeConfig["admin_web_port"])
        self.statusPort = statusPortOverride ?? configuredPort ?? 18080
    }

    func start() throws {
        prepareSharedOverlayBootstrap()
        let controlServer = try ObstacleBridgeHTTPControlServer(bindHost: bindHost, port: statusPort) { [weak self] in
            self?.snapshot() ?? [:]
        }
        self.controlServer = controlServer
        controlServer.start()
    }

    func stop() {
        controlServer?.stop()
        controlServer = nil
    }

    func snapshot() -> [String: Any] {
        let uptimeMS = Int(Date().timeIntervalSince(startedAt) * 1000)
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
            "bootstrap_state": bootstrapState,
        ]
    }

    private func prepareSharedOverlayBootstrap() {
        sharedCompressLayerRuntime = nil
        sharedWebSocketOverlayRuntime = nil
        sharedTcpOverlayRuntime = nil
        bootstrapState = [:]

        let overlayTransport = Self.stringValue(from: runtimeConfig["overlay_transport"]) ?? "myudp"
        let configuredPeers: [String: Bool] = [
            "myudp": Self.stringValue(from: runtimeConfig["udp_peer"]) != nil,
            "tcp": Self.stringValue(from: runtimeConfig["tcp_peer"]) != nil,
            "quic": Self.stringValue(from: runtimeConfig["quic_peer"]) != nil,
            "ws": Self.stringValue(from: runtimeConfig["ws_peer"]) != nil,
        ]

        do {
            let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
                raw: overlayTransport,
                hasConfiguredPeerByTransport: configuredPeers
            )
            let selectedTransport = transports.first ?? "myudp"
            let peerHost = Self.peerHost(for: selectedTransport, payload: runtimeConfig)
            let secureLinkEnabled = Self.boolValue(from: runtimeConfig["secure_link"]) ?? false
            let secureLinkMode = Self.stringValue(from: runtimeConfig["secure_link_mode"]) ?? "off"
            let secureLinkPSK = Self.stringValue(from: runtimeConfig["secure_link_psk"]) ?? ""
            let compressEnabled = Self.boolValue(from: runtimeConfig["compress_layer"]) ?? false
            let compressAlgo = Self.stringValue(from: runtimeConfig["compress_layer_algo"]) ?? "zlib"
            let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
                transport: selectedTransport,
                peerHost: peerHost,
                secureLinkEnabled: secureLinkEnabled,
                secureLinkModeRaw: secureLinkMode,
                secureLinkPSK: secureLinkPSK,
                compressLayerEnabled: compressEnabled,
                compressLayerAlgoRaw: compressAlgo
            )

            var summary: [String: Any] = [
                "status": "prepared",
                "transport": plan.transport,
                "transports": transports,
                "layers_top_down": plan.layersTopDown,
                "compress_wrapped": plan.compressWrapped,
                "compress_configured_enabled": plan.compressConfiguredEnabled,
                "runtime_config_grouped": Self.runtimeConfigLooksGrouped(runtimeConfigRaw),
            ]
            if let peerHost = plan.peerHost {
                summary["peer_host"] = peerHost
            }
            if let secureLinkMode = plan.secureLinkMode {
                summary["secure_link_mode"] = secureLinkMode
            }

            if plan.compressWrapped {
                let allowedMTypes = Self.stringValue(from: runtimeConfig["compress_layer_types"]) ?? "data,data_frag"
                let level = Self.intValue(from: runtimeConfig["compress_layer_level"]) ?? 3
                let minBytes = Self.intValue(from: runtimeConfig["compress_layer_min_bytes"]) ?? 64
                sharedCompressLayerRuntime = ObstacleBridgeCompressLayerRuntime(
                    configuredEnabled: compressEnabled,
                    algorithm: compressAlgo,
                    transportName: plan.transport,
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

            if plan.transport == "ws" {
                let payloadMode = Self.stringValue(from: runtimeConfig["ws_payload_mode"]) ?? "binary"
                let maxSize = Self.intValue(from: runtimeConfig["ws_max_size"]) ?? 65535
                let sendTimeout = Self.doubleValue(from: runtimeConfig["ws_send_timeout"]) ?? 3.0
                let tcpUserTimeout = Self.intValue(from: runtimeConfig["ws_tcp_user_timeout_ms"]) ?? 10000
                let reconnectGrace = Self.doubleValue(from: runtimeConfig["ws_reconnect_grace"]) ?? 3.0
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

            if plan.transport == "tcp" {
                let threshold = Self.intValue(from: runtimeConfig["tcp_bp_wbuf_threshold"]) ?? 128 * 1024
                sharedTcpOverlayRuntime = ObstacleBridgeTcpOverlayRuntime(wbufThreshold: threshold)
                summary["tcp_runtime"] = "ready"
                summary["tcp_bp_wbuf_threshold"] = threshold
            }

            summary["admin_web_enabled"] = Self.boolValue(from: runtimeConfig["admin_web"]) ?? false
            summary["admin_web_bind"] = bindHost
            summary["admin_web_port"] = statusPort
            bootstrapState = summary
        } catch {
            bootstrapState = [
                "status": "failed",
                "overlay_transport": overlayTransport,
                "error": error.localizedDescription,
                "admin_web_bind": bindHost,
                "admin_web_port": statusPort,
            ]
        }
    }

    private static func flattenRuntimeConfig(_ payload: [String: Any]) -> [String: Any] {
        var merged: [String: Any] = [:]
        let knownSections = [
            "runner",
            "udp_session",
            "tcp_session",
            "ws_session",
            "secure_link",
            "compress_layer",
            "admin_web",
            "debug_logging",
        ]
        for section in knownSections {
            if let block = payload[section] as? [String: Any] {
                for (key, value) in block {
                    merged[key] = value
                }
            }
        }
        if let channelMux = payload["channel_mux"] as? [String: Any] {
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

    private static func runtimeConfigLooksGrouped(_ payload: [String: Any]) -> Bool {
        payload.values.contains { $0 is [String: Any] }
    }

    private static func intValue(from value: Any?) -> Int? {
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

    private static func doubleValue(from value: Any?) -> Double? {
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

    private static func boolValue(from value: Any?) -> Bool? {
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

    private static func stringValue(from value: Any?) -> String? {
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

    private static func peerHost(for transport: String, payload: [String: Any]) -> String? {
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
}

private struct ObstacleBridgeMacHostRunnerCLI {
    let runtimeConfigPath: String
    let bindHost: String?
    let statusPort: Int?
    let holdSec: Double

    static func parse(_ args: [String]) throws -> ObstacleBridgeMacHostRunnerCLI {
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
                    throw ObstacleBridgeMacHostRunnerError.usage(Self.usageText())
                }
                runtimeConfigPath = args[index]
            case "--bind-host":
                index += 1
                guard index < args.count else {
                    throw ObstacleBridgeMacHostRunnerError.usage(Self.usageText())
                }
                bindHost = args[index]
            case "--status-port":
                index += 1
                guard index < args.count, let port = Int(args[index]) else {
                    throw ObstacleBridgeMacHostRunnerError.invalidArgument("--status-port requires an integer")
                }
                statusPort = port
            case "--hold-sec":
                index += 1
                guard index < args.count, let seconds = Double(args[index]) else {
                    throw ObstacleBridgeMacHostRunnerError.invalidArgument("--hold-sec requires a number")
                }
                holdSec = max(0.0, seconds)
            case "--help", "-h":
                throw ObstacleBridgeMacHostRunnerError.usage(Self.usageText())
            default:
                throw ObstacleBridgeMacHostRunnerError.invalidArgument("Unknown argument: \(arg)")
            }
            index += 1
        }
        guard let runtimeConfigPath else {
            throw ObstacleBridgeMacHostRunnerError.usage(Self.usageText())
        }
        return ObstacleBridgeMacHostRunnerCLI(
            runtimeConfigPath: runtimeConfigPath,
            bindHost: bindHost,
            statusPort: statusPort,
            holdSec: holdSec
        )
    }

    static func usageText() -> String {
        "Usage: ObstacleBridgeMacHostRunner --runtime-config <path> [--bind-host <host>] [--status-port <port>] [--hold-sec <seconds>]"
    }
}

@main
struct ObstacleBridgeMacHostRunnerMain {
    static func main() {
        do {
            let cli = try ObstacleBridgeMacHostRunnerCLI.parse(Array(CommandLine.arguments.dropFirst()))
            let runner = try ObstacleBridgeMacHostRunner(
                runtimeConfigPath: cli.runtimeConfigPath,
                bindHostOverride: cli.bindHost,
                statusPortOverride: cli.statusPort
            )
            try runner.start()
            let snapshot = runner.snapshot()
            if let data = try? JSONSerialization.data(withJSONObject: snapshot, options: [.sortedKeys]),
               let text = String(data: data, encoding: .utf8) {
                print(text)
                fflush(stdout)
            }
            if cli.holdSec > 0 {
                let deadline = Date().addingTimeInterval(cli.holdSec)
                while Date() < deadline {
                    _ = RunLoop.current.run(mode: .default, before: min(deadline, Date().addingTimeInterval(0.1)))
                }
            } else {
                dispatchMain()
            }
            runner.stop()
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }
}