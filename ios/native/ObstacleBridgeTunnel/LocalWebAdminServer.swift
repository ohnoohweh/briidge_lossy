import Foundation
import Network

final class LocalWebAdminServer {
    private let configuration: TunnelProviderConfiguration
    private let statusProvider: () -> TunnelStatus
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "ObstacleBridge.LocalWebAdminServer")
    private var logLines: [String] = []

    var url: String? {
        guard isEnabled else { return nil }
        return "http://127.0.0.1:\(port)/"
    }

    private var isEnabled: Bool {
        boolValue(configuration.obstacleBridgeConfig["admin_web"], defaultValue: true)
    }

    private var port: UInt16 {
        uint16Value(configuration.obstacleBridgeConfig["admin_web_port"], defaultValue: 18080)
    }

    init(configuration: TunnelProviderConfiguration, statusProvider: @escaping () -> TunnelStatus) {
        self.configuration = configuration
        self.statusProvider = statusProvider
    }

    func start() throws {
        guard isEnabled else {
            appendLog("extension WebAdmin disabled by config")
            return
        }
        let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port) ?? 18080)
        listener.newConnectionHandler = { [weak self] connection in
            self?.handle(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            self?.queue.async {
                self?.appendLog("extension WebAdmin state: \(state)")
            }
        }
        self.listener = listener
        listener.start(queue: queue)
        appendLog("extension WebAdmin listening on \(url ?? "")")
    }

    func stop() {
        listener?.cancel()
        listener = nil
        appendLog("extension WebAdmin stopped")
    }

    private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        receiveRequest(connection)
    }

    private func receiveRequest(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    self.appendLog("extension WebAdmin receive error: \(error.localizedDescription)")
                    connection.cancel()
                    return
                }
                let request = String(data: data ?? Data(), encoding: .utf8) ?? ""
                let response = self.response(for: request)
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
    }

    private func response(for request: String) -> Data {
        let firstLine = request.split(separator: "\r\n", maxSplits: 1).first.map(String.init) ?? ""
        let parts = firstLine.split(separator: " ", maxSplits: 2).map(String.init)
        let method = parts.indices.contains(0) ? parts[0] : "GET"
        let path = parts.indices.contains(1) ? parts[1] : "/"
        appendLog("extension WebAdmin \(method) \(path)")

        if method == "GET" && (path == "/" || path == "/index.html") {
            return http(
                status: "200 OK",
                contentType: "text/html; charset=utf-8",
                body: Data(extensionIndexHTML.utf8)
            )
        }
        if method == "GET" && path == "/api/config" {
            return jsonResponse([
                "ok": true,
                "source": "packet-tunnel-extension",
                "config": sanitizedConfig(),
            ])
        }
        if method == "GET" && path == "/api/status" {
            return jsonResponse([
                "ok": true,
                "source": "packet-tunnel-extension",
                "status": statusDictionary(statusProvider()),
            ])
        }
        if method == "GET" && path == "/api/logs" {
            return jsonResponse([
                "ok": true,
                "source": "packet-tunnel-extension",
                "logs": logLines,
            ])
        }
        if method == "POST" && path == "/api/restart" {
            return jsonResponse([
                "ok": true,
                "source": "packet-tunnel-extension",
                "restart_supported": false,
                "detail": "Packet tunnel restart is owned by NEPacketTunnelProviderManager",
            ])
        }
        if method == "POST" && path == "/api/config" {
            return jsonResponse([
                "ok": false,
                "source": "packet-tunnel-extension",
                "error": "configuration writes must be saved by the containing app and reloaded by restarting the VPN tunnel",
            ], status: "409 Conflict")
        }
        return jsonResponse(["ok": false, "error": "not found"], status: "404 Not Found")
    }

    private func jsonResponse(_ object: Any, status: String = "200 OK") -> Data {
        let body: Data
        if JSONSerialization.isValidJSONObject(object),
           let encoded = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) {
            body = encoded
        } else {
            body = Data(#"{"ok":false,"error":"json encoding failed"}"#.utf8)
        }
        return http(status: status, contentType: "application/json; charset=utf-8", body: body)
    }

    private func http(status: String, contentType: String, body: Data) -> Data {
        var head = ""
        head += "HTTP/1.1 \(status)\r\n"
        head += "Content-Type: \(contentType)\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Connection: close\r\n"
        head += "Cache-Control: no-store\r\n"
        head += "\r\n"
        return Data(head.utf8) + body
    }

    private func sanitizedConfig() -> [String: Any] {
        var output = configuration.obstacleBridgeConfig
        if output["secure_link_psk"] != nil {
            output["secure_link_psk"] = "***hidden***"
            output["secure_link_psk_present"] = true
        }
        if output["admin_web_password"] != nil {
            output["admin_web_password"] = "***hidden***"
            output["admin_web_password_present"] = true
        }
        output["runtime_owner"] = "packet-tunnel-extension"
        output["runtime_layers"] = configuration.runtimeLayers
        return output
    }

    private func statusDictionary(_ status: TunnelStatus) -> [String: Any] {
        [
            "state": status.state.rawValue,
            "packets_from_system": status.packetsFromSystem,
            "packets_to_system": status.packetsToSystem,
            "bytes_from_system": status.bytesFromSystem,
            "bytes_to_system": status.bytesToSystem,
            "runtime_owner": status.runtimeOwner,
            "runtime_layers": status.runtimeLayers,
            "webadmin_url": status.webAdminURL as Any,
            "webadmin_running": status.webAdminRunning,
            "last_error": status.lastError as Any,
        ]
    }

    private func appendLog(_ line: String) {
        let row = "\(Date()) \(line)"
        logLines.append(row)
        if logLines.count > 200 {
            logLines.removeFirst(logLines.count - 200)
        }
        NSLog("%@", row)
    }

    private func boolValue(_ value: Any?, defaultValue: Bool) -> Bool {
        if let bool = value as? Bool {
            return bool
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        if let text = value as? String {
            return !["0", "false", "no", "off"].contains(text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
        }
        return defaultValue
    }

    private func uint16Value(_ value: Any?, defaultValue: UInt16) -> UInt16 {
        if let number = value as? NSNumber, let port = UInt16(exactly: number.intValue) {
            return port
        }
        if let int = value as? Int, let port = UInt16(exactly: int) {
            return port
        }
        if let text = value as? String, let int = Int(text), let port = UInt16(exactly: int) {
            return port
        }
        return defaultValue
    }

    private var extensionIndexHTML: String {
        """
        <!doctype html>
        <html>
        <head><meta charset="utf-8"><title>ObstacleBridge Extension</title></head>
        <body>
        <h1>ObstacleBridge Packet Tunnel</h1>
        <pre id="status">Loading...</pre>
        <script>
        async function refresh() {
          const [status, config] = await Promise.all([
            fetch('/api/status').then(r => r.json()),
            fetch('/api/config').then(r => r.json())
          ]);
          document.getElementById('status').textContent = JSON.stringify({status, config}, null, 2);
        }
        refresh();
        setInterval(refresh, 2000);
        </script>
        </body>
        </html>
        """
    }
}
