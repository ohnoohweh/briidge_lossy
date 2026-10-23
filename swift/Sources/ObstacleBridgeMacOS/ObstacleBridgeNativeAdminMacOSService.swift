import Foundation

/// macOS-owned first IPC-1A2 slice. It deliberately exposes only status and
/// status live-topic reads through the bounded parent RPC; API/auth/session
/// parity remains the subsequent A2 work.
enum ObstacleBridgeNativeAdminMacOSService {
    static func run(controlFD: Int32, lifetimeFD: Int32, logFD: Int32?, generation: Int) throws {
        try ObstacleBridgeNativeAdminWorker.run(
            controlFD: controlFD,
            lifetimeFD: lifetimeFD,
            logFD: logFD,
            generation: generation,
            serviceFactory: makeService
        )
    }

    private static func makeService(arguments: [String: Any], parentRPC: ObstacleBridgeNativeAdminWorker.ParentRPC) throws -> ObstacleBridgeNativeAdminWorker.Service {
        let bindHost = (arguments["admin_web_bind"] as? String) ?? "127.0.0.1"
        let requestedPort = (arguments["admin_web_port"] as? NSNumber)?.intValue ?? 0
        func status() -> [String: Any] {
            (try? parentRPC.call(method: "get_status_snapshot")) as? [String: Any] ?? ["state": "unavailable"]
        }
        let server = try ObstacleBridgeWebAdminServer(
            bindHost: bindHost,
            port: requestedPort,
            fallbackIndexTitle: "ObstacleBridge native Admin child",
            fallbackIndexSubtitle: "Native Admin status is served through inherited parent RPC.",
            statusProvider: status,
            apiProvider: { method, path, _, _ in
                guard method.uppercased() == "GET", path == "/api/status" else { return nil }
                return ObstacleBridgeAdminAPIResponse(
                    statusLine: "HTTP/1.1 200 OK",
                    contentType: "application/json; charset=utf-8",
                    body: ObstacleBridgeWebAdminServer.jsonBody(status()),
                    headers: []
                )
            },
            staticFileProvider: { _ in nil },
            liveTopicProvider: { topic in topic == "status" ? status() : nil }
        )
        let port = try server.startAndWait()
        return .init(port: port, stop: { server.stop() })
    }
}
