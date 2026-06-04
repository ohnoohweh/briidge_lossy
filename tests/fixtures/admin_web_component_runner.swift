import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum AdminWebComponentRunnerError: Error {
    case invalidRequest
    case invalidAction
}

private func jsonObject(_ value: Any) throws -> [String: Any] {
    guard let object = value as? [String: Any] else {
        throw AdminWebComponentRunnerError.invalidRequest
    }
    return object
}

private func jsonData(_ value: Any) throws -> Data {
    if JSONSerialization.isValidJSONObject(value) {
        return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }
    if value is NSNull {
        return Data("null".utf8)
    }
    throw AdminWebComponentRunnerError.invalidRequest
}

private func bodyData(from object: [String: Any]) throws -> Data? {
    if let bodyBase64 = object["body_base64"] as? String {
        return Data(base64Encoded: bodyBase64)
    }
    if let bodyUTF8 = object["body_utf8"] as? String {
        return Data(bodyUTF8.utf8)
    }
    if let bodyJSON = object["body_json"] {
        return try jsonData(bodyJSON)
    }
    return nil
}

private final class StubProvider: ObstacleBridgeAdminAPIStateProvider {
    private let status: [String: Any]
    private let connections: [String: Any]
    private let tunRouting: [String: Any]
    private let peers: [[String: Any]]
    private let meta: [String: Any]

    init(
        status: [String: Any],
        connections: [String: Any],
        tunRouting: [String: Any],
        peers: [[String: Any]],
        meta: [String: Any]
    ) {
        self.status = status
        self.connections = connections
        self.tunRouting = tunRouting
        self.peers = peers
        self.meta = meta
    }

    func adminStatusSnapshot() -> [String: Any] {
        status
    }

    func adminConnectionsSnapshot() -> [String: Any] {
        connections
    }

    func adminTunRoutingSnapshot() -> [String: Any] {
        tunRouting
    }

    func adminPeersSnapshot() -> [[String: Any]] {
        peers
    }

    func adminMetaSnapshot() -> [String: Any] {
        meta
    }
}

private func provider(from request: [String: Any]) -> StubProvider {
    let status = request["status_snapshot"] as? [String: Any] ?? [:]
    let connections = request["connections_snapshot"] as? [String: Any] ?? ObstacleBridgeAdminAPI.emptyConnectionsSnapshot()
    let tunRouting = request["tun_routing_snapshot"] as? [String: Any] ?? ObstacleBridgeAdminAPI.emptyTunRoutingSnapshot()
    let peers = request["peers_snapshot"] as? [[String: Any]] ?? []
    let meta = request["meta_snapshot"] as? [String: Any] ?? [:]
    return StubProvider(
        status: status,
        connections: connections,
        tunRouting: tunRouting,
        peers: peers,
        meta: meta
    )
}

private func run(_ request: [String: Any]) throws -> [String: Any] {
    guard let action = request["action"] as? String else {
        throw AdminWebComponentRunnerError.invalidRequest
    }
    switch action {
    case "admin_ui_payload":
        let runtimeConfig = request["runtime_config"] as? [String: Any] ?? [:]
        let platform = request["platform"] as? String ?? "ios"
        let runtimeDependencies = request["runtime_dependencies"] as? [String: Any]
            ?? ObstacleBridgeAdminWebSupport.adminRuntimeDependenciesPayload()
        return [
            "payload": ObstacleBridgeAdminWebSupport.adminUIPayload(
                runtimeConfig: runtimeConfig,
                platform: platform,
                runtimeDependencies: runtimeDependencies
            ),
        ]
    case "security_advisor_payload":
        let runtimeConfig = request["runtime_config"] as? [String: Any] ?? [:]
        let bindHostFallback = request["bind_host_fallback"] as? String ?? "127.0.0.1"
        return [
            "payload": ObstacleBridgeAdminWebSupport.securityAdvisorPayload(
                runtimeConfig: runtimeConfig,
                bindHostFallback: bindHostFallback
            ),
        ]
    case "derive_tun_routing_snapshot":
        let connections = request["connections_snapshot"] as? [String: Any] ?? ObstacleBridgeAdminAPI.emptyConnectionsSnapshot()
        return ["payload": ObstacleBridgeAdminAPI.tunRoutingSnapshot(fromConnections: connections)]
    case "admin_api_request":
        guard let requestObject = request["request"] else {
            throw AdminWebComponentRunnerError.invalidRequest
        }
        let object = try jsonObject(requestObject)
        guard let path = object["path"] as? String else {
            throw AdminWebComponentRunnerError.invalidRequest
        }
        let apiRequest = ObstacleBridgeAdminAPIRequest(
            method: (object["method"] as? String) ?? "GET",
            path: path,
            headers: object["headers"] as? [String: String] ?? [:],
            body: try bodyData(from: object)
        )
        return ObstacleBridgeAdminAPI.appMessageResponse(
            for: apiRequest,
            provider: provider(from: request)
        )
    case "admin_api_live_topic_payload":
        guard let topic = request["topic"] as? String else {
            throw AdminWebComponentRunnerError.invalidRequest
        }
        return [
            "payload": ObstacleBridgeAdminAPI.liveTopicPayload(
                topic: topic,
                provider: provider(from: request)
            ) ?? NSNull(),
        ]
    default:
        throw AdminWebComponentRunnerError.invalidAction
    }
}

@main
struct AdminWebComponentRunnerMain {
    static func main() throws {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        do {
            let root = try JSONSerialization.jsonObject(with: input, options: [])
            let request = try jsonObject(root)
            let result = try run(request)
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        } catch {
            let payload: [String: Any] = [
                "ok": false,
                "error": String(describing: error),
            ]
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
            exit(1)
        }
    }
}
