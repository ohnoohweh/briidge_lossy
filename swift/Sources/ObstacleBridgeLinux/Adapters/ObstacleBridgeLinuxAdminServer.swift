import Dispatch
import Foundation
import Crypto
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

public enum ObstacleBridgeLinuxAdminServerError: Error, Equatable, LocalizedError {
    case invalidBindHost
    case socketFailure(Int32)
    case bindFailure(Int32)
    case listenFailure(Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidBindHost: return "Linux Admin server currently requires an IPv4 bind address"
        case .socketFailure(let code), .bindFailure(let code), .listenFailure(let code): return "POSIX Admin server failure errno=\(code)"
        }
    }
}

/// Minimal Linux-native Admin HTTP surface. It owns no transport state and
/// reads only the runtime's redacted status projection.
public final class ObstacleBridgeLinuxAdminServer: @unchecked Sendable {
    private let statusProvider: () -> ObstacleBridgeLinuxRuntimeStatus
    private let peersProvider: () -> [(identity: String, snapshot: ObstacleBridgeLinuxPeerSnapshot)]
    private let runtimeHealthProvider: () -> (count: Int, previousClean: Bool?)
    private let runtimeHealthRecordsProvider: () -> [ObstacleBridgeRuntimeHealthRecord]
    private let resourceHealthProvider: () -> [String: Any]
    private let adminConfigurationProvider: () -> [String: Any]
    private let staticDirectory: URL?
    private let configurationStore: ObstacleBridgeLinuxAdminConfigurationStore?
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.admin")
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    public private(set) var port: Int = 0

    public init(runtime: ObstacleBridgeLinuxConfiguredRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil) {
        self.statusProvider = { runtime.status() }
        self.peersProvider = { [("configured-peer", runtime.status().peer)] }
        self.runtimeHealthProvider = { (0, nil) }
        self.runtimeHealthRecordsProvider = { [] }
        self.resourceHealthProvider = { [:] }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.staticDirectory = staticDirectory
    }

    public init(liveRuntime: ObstacleBridgeLinuxLiveRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil) {
        self.statusProvider = { liveRuntime.status() }
        self.peersProvider = { [("configured-peer", liveRuntime.status().peer)] }
        self.runtimeHealthProvider = { liveRuntime.runtimeHealthMetadataForAdmin() }
        self.runtimeHealthRecordsProvider = { liveRuntime.runtimeHealthRecentRecordsForAdmin() }
        self.resourceHealthProvider = { liveRuntime.resourceHealthForAdmin() }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.staticDirectory = staticDirectory
    }

    public init(myudpListenerRuntime: ObstacleBridgeLinuxMyUDPListenerRuntime, adminConfiguration: [String: Any] = [:], configurationStore: ObstacleBridgeLinuxAdminConfigurationStore? = nil, staticDirectory: URL? = nil) {
        self.statusProvider = { myudpListenerRuntime.status() }
        self.peersProvider = {
            myudpListenerRuntime.peers().map { ($0.identity, $0.snapshot) }
        }
        self.runtimeHealthProvider = { (0, nil) }
        self.runtimeHealthRecordsProvider = { [] }
        self.resourceHealthProvider = { [:] }
        self.configurationStore = configurationStore; self.adminConfigurationProvider = { configurationStore?.snapshot() ?? adminConfiguration }
        self.staticDirectory = staticDirectory
    }

    public func start(bindHost: String = "127.0.0.1", port requestedPort: Int = 0) throws {
        guard listener < 0 else { return }
        guard let address = ipv4Address(bindHost), (0...65535).contains(requestedPort) else { throw ObstacleBridgeLinuxAdminServerError.invalidBindHost }
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw ObstacleBridgeLinuxAdminServerError.socketFailure(errno) }
        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, $0, socklen_t(MemoryLayout<Int32>.size)) }
        var socketAddress = sockaddr_in()
        socketAddress.sin_family = sa_family_t(AF_INET)
        socketAddress.sin_port = in_port_t(UInt16(requestedPort).bigEndian)
        socketAddress.sin_addr = address
        let bindResult = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bindResult == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.bindFailure(code) }
        guard listen(fd, 16) == 0 else { let code = errno; _ = close(fd); throw ObstacleBridgeLinuxAdminServerError.listenFailure(code) }
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &actual) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
        self.listener = fd
        self.port = Int(UInt16(bigEndian: actual.sin_port))
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        self.source = source
        source.setEventHandler { [weak self] in self?.acceptReadyClient() }
        source.setCancelHandler { _ = close(fd) }
        source.resume()
    }

    public func stop() {
        source?.cancel()
        source = nil
        listener = -1
        port = 0
    }

    private func acceptReadyClient() {
        guard listener >= 0 else { return }
        let client = accept(listener, nil, nil)
        guard client >= 0 else { return }
        DispatchQueue.global().async { [weak self] in self?.serve(client) }
    }

    private func serve(_ client: Int32) {
        defer { _ = close(client) }
        var request = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while request.count < 16 * 1024 {
            let received = read(client, &buffer, buffer.count)
            guard received > 0 else { return }
            request.append(buffer, count: Int(received))
            if request.range(of: Data("\r\n\r\n".utf8)) != nil { break }
        }
        guard let headerEnd = request.range(of: Data("\r\n\r\n".utf8)) else { return }
        let headerData = request[..<headerEnd.lowerBound]
        let headerText = String(data: headerData, encoding: .utf8) ?? ""
        let contentLength = headerText.split(separator: "\r\n").dropFirst().compactMap { line -> Int? in
            let parts = line.split(separator: ":", maxSplits: 1)
            return parts.count == 2 && parts[0].lowercased() == "content-length" ? Int(parts[1].trimmingCharacters(in: .whitespaces)) : nil
        }.first ?? 0
        guard (0...65_536).contains(contentLength) else { return }
        let bodyStart = headerEnd.upperBound
        while request.count - bodyStart < contentLength {
            let received = read(client, &buffer, buffer.count); guard received > 0 else { return }; request.append(buffer, count: Int(received))
        }
        let body = Data(request[bodyStart..<(bodyStart + contentLength)])
        let requestLine = headerText.split(separator: "\r\n", maxSplits: 1).first ?? ""
        let parts = requestLine.split(separator: " ")
        let method = parts.first.map(String.init) ?? ""
        let target = parts.dropFirst().first.map(String.init) ?? ""
        let path = target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? target
        if path == "/api/live", method == "GET", headerText.lowercased().contains("upgrade: websocket") {
            serveLiveWebSocket(client, target: target, headerText: headerText)
            return
        }
        let response: ObstacleBridgeAdminLinuxResponse
        if method != "GET" && !(method == "POST" && ["/api/config", "/api/onboarding/invite", "/api/onboarding/preview"].contains(path)) {
            response = .init(statusCode: 405, body: Data("{\"error\":\"method not allowed\"}".utf8))
        } else { switch path {
        case "/", "/index.html":
            response = staticResponse(path) ?? .init(statusCode: 200, body: Data(adminDashboard.utf8), contentType: "text/html; charset=utf-8")
        case "/api/status": response = ObstacleBridgeAdminAPI.linuxJSONResponse(statusPayload()) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/peers": response = ObstacleBridgeAdminAPI.linuxJSONResponse(peersPayload()) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/live":
            let requestedTopic = target.split(separator: "?", maxSplits: 1).dropFirst().first?
                .split(separator: "&").first(where: { $0.hasPrefix("topic=") })?
                .dropFirst("topic=".count).description ?? ""
            let topic = ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(requestedTopic) ?? ""
            response = ObstacleBridgeAdminLiveTopicPort.payload(topic: topic, status: statusPayload(), peers: peersPayload())
                .flatMap { ObstacleBridgeAdminAPI.linuxJSONResponse($0) } ?? .init(statusCode: 404, body: Data("{}".utf8))
        case "/api/config":
            if method == "GET" {
                response = ObstacleBridgeAdminAPI.linuxJSONResponse(["config": ObstacleBridgeRuntimeConfigPort.redactedConfiguration(adminConfigurationProvider())]) ?? .init(statusCode: 500, body: Data("{}".utf8))
            } else if let updates = (try? JSONSerialization.jsonObject(with: body) as? [String: Any])?["updates"] as? [String: Any], let configurationStore {
                do { let saved = try configurationStore.apply(updates: updates); response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": true, "updated_keys": saved.normalizedKeys, "config": ObstacleBridgeRuntimeConfigPort.redactedConfiguration(saved.configuration)]) ?? .init(statusCode: 500, body: Data("{}".utf8)) }
                catch { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": error.localizedDescription], statusCode: 400) ?? .init(statusCode: 500, body: Data("{}".utf8)) }
            } else { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["ok": false, "error": "invalid JSON body or configuration writes unavailable"], statusCode: 400) ?? .init(statusCode: 500, body: Data("{}".utf8)) }
        case "/api/onboarding/invite":
            response = ObstacleBridgeAdminOnboardingPort.generate(body: body, runtimeConfig: adminConfigurationProvider())
        case "/api/onboarding/preview":
            response = ObstacleBridgeAdminOnboardingPort.preview(body: body)
        case "/api/admin-ui":
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(ObstacleBridgeAdminWebPort.uiPayload(runtimeConfig: adminConfigurationProvider(), platform: "linux-swift")) ?? .init(statusCode: 500, body: Data("{}".utf8))
        case "/api/security-advisor":
            response = ObstacleBridgeAdminAPI.linuxJSONResponse(ObstacleBridgeAdminWebPort.securityAdvisorPayload(runtimeConfig: adminConfigurationProvider(), bindHostFallback: "127.0.0.1")) ?? .init(statusCode: 500, body: Data("{}".utf8))
        default:
            if method == "GET", let staticAsset = staticResponse(path) { response = staticAsset }
            else { response = ObstacleBridgeAdminAPI.linuxJSONResponse(["error": "not found"], statusCode: 404) ?? .init(statusCode: 404, body: Data("{}".utf8)) }
        } }
        let statusText = response.statusCode == 200 ? "200 OK" : response.statusCode == 400 ? "400 Bad Request" : response.statusCode == 404 ? "404 Not Found" : response.statusCode == 405 ? "405 Method Not Allowed" : response.statusCode == 409 ? "409 Conflict" : "500 Internal Server Error"
        let header = "HTTP/1.1 \(statusText)\r\nContent-Type: \(response.contentType)\r\nContent-Length: \(response.body.count)\r\nConnection: close\r\n\r\n"
        var wire = Data(header.utf8); wire.append(response.body)
        _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
    }

    private var adminDashboard: String {
        """
        <!doctype html><html><head><meta charset="utf-8"><title>ObstacleBridge Linux</title><style>body{font-family:system-ui;margin:2rem;max-width:72rem}pre{background:#111;color:#ddd;padding:1rem;overflow:auto}a{margin-right:1rem}</style></head><body><h1>ObstacleBridge Linux</h1><p>Native runtime Admin dashboard.</p><p><a href="/api/status">Status JSON</a><a href="/api/peers">Peers JSON</a><a href="/api/config">Redacted config</a></p><pre id="status">Loading…</pre><script>const view=document.getElementById('status');async function refresh(){try{view.textContent=JSON.stringify(await (await fetch('/api/status')).json(),null,2)}catch(e){view.textContent='Admin status unavailable: '+e}}refresh();setInterval(refresh,1000)</script></body></html>
        """
    }

    private func staticResponse(_ requestPath: String) -> ObstacleBridgeAdminLinuxResponse? {
        guard let base = resolvedStaticDirectory() else { return nil }
        let relative = (requestPath.isEmpty || requestPath == "/") ? "index.html" : String(requestPath.drop(while: { $0 == "/" }))
        guard !relative.contains("..") else { return .init(statusCode: 404, body: Data("not found".utf8), contentType: "text/plain; charset=utf-8") }
        let file = base.appendingPathComponent(relative).standardizedFileURL
        guard file.path.hasPrefix(base.standardizedFileURL.path + "/"), let body = try? Data(contentsOf: file) else { return nil }
        let contentType: String
        switch file.pathExtension.lowercased() {
        case "html": contentType = "text/html; charset=utf-8"
        case "css": contentType = "text/css; charset=utf-8"
        case "js": contentType = "application/javascript; charset=utf-8"
        case "json": contentType = "application/json; charset=utf-8"
        case "svg": contentType = "image/svg+xml"
        case "png": contentType = "image/png"
        default: contentType = "application/octet-stream"
        }
        return .init(statusCode: 200, body: body, contentType: contentType)
    }

    private func resolvedStaticDirectory() -> URL? {
        let manager = FileManager.default
        let candidates = [staticDirectory, URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("admin_web"), CommandLine.arguments.first.map { URL(fileURLWithPath: $0).deletingLastPathComponent().appendingPathComponent("admin_web") }].compactMap { $0 }
        return candidates.first { manager.fileExists(atPath: $0.appendingPathComponent("index.html").path) }
    }

    /// A reconnectable, snapshot-first WebSocket subscription. The Linux
    /// socket owner intentionally keeps protocol framing local while Core
    /// decides topic admission and payload shape.
    private func serveLiveWebSocket(_ client: Int32, target: String, headerText: String) {
        guard let key = headerText.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("sec-websocket-key:") })?
            .split(separator: ":", maxSplits: 1).dropFirst().first?.trimmingCharacters(in: .whitespaces),
              let requested = target.split(separator: "?", maxSplits: 1).dropFirst().first?
                .split(separator: "&").first(where: { $0.hasPrefix("topic=") })?
                .dropFirst("topic=".count).description,
              let topic = ObstacleBridgeAdminLiveTopicPolicyPort.normalizedTopic(requested)
        else {
            let wire = Data("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".utf8)
            _ = wire.withUnsafeBytes { write(client, $0.baseAddress, wire.count) }
            return
        }
        let accept = Data(Insecure.SHA1.hash(data: Data("\(key)258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString()
        let handshake = Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n".utf8)
        _ = handshake.withUnsafeBytes { write(client, $0.baseAddress, handshake.count) }
        while let payload = ObstacleBridgeAdminLiveTopicPort.payload(topic: topic, status: statusPayload(), peers: peersPayload()),
              let body = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) {
            var frame = Data([0x81])
            if body.count < 126 { frame.append(UInt8(body.count)) }
            else if body.count <= Int(UInt16.max) { frame.append(126); var length = UInt16(body.count).bigEndian; frame.append(Data(bytes: &length, count: 2)) }
            else { return }
            frame.append(body)
            let sent = frame.withUnsafeBytes { write(client, $0.baseAddress, frame.count) }
            guard sent == frame.count else { return }
            usleep(250_000)
        }
    }

    private func statusPayload() -> [String: Any] {
        let status = statusProvider()
        let health = runtimeHealthProvider()
        let healthRecords = runtimeHealthRecordsProvider().compactMap { record -> [String: Any]? in
            guard let data = try? JSONEncoder().encode(record) else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        let transportRuntime = ObstacleBridgeAdminSnapshotSupport.transportRuntimeEnvelope(
            kind: status.transport,
            status: status.state,
            extra: ["app_ready": status.appReady, "failure_reason": status.failureReason as Any]
        )
        let payload: [String: Any] = [
            "platform": "linux-swift",
            "overlay_transport": status.transport,
            "transport_state": status.state,
            "app_ready": status.appReady,
            "failure_reason": status.failureReason as Any,
            "transport_runtime": transportRuntime,
            "runtime_health_record_count": health.count,
            "previous_runtime_lifetime_ended_cleanly": health.previousClean as Any,
            "runtime_health_recent_records": healthRecords,
            "resource_health": resourceHealthProvider(),
            "operator_capabilities": operatorCapabilities(),
            "connection_layers": [
                ["name": "transport", "state": status.state, "connected": status.state == "connected"],
                ["name": "secure_link", "state": status.secureLinkState, "authenticated": status.secureLinkState == "authenticated"],
            ],
            "channel_mux": [
                "tcp_open": status.activeTCPChannels,
                "udp_open": status.activeUDPChannels,
                "queued_frames": status.queuedServiceFrames,
                "dropped_frames": status.droppedServiceFrames,
                "malformed_frames": status.malformedServiceFrames,
                "service_failures": status.serviceFailures,
                "tcp_opened_total": status.openedTCPChannels,
                "udp_opened_total": status.openedUDPChannels,
            ],
            "receive_loop": [
                "state": status.receiveLoopState,
                "connection_epoch": status.receiveEpoch,
                "received_frames": status.receivedFrames,
                "dropped_frames": status.droppedReceiveFrames,
                "queue_depth": status.receiveQueueDepth,
                "failure_reason": status.receiveFailureReason as Any,
            ],
            "peer": peerPayload(status.peer),
        ]
        return payload
    }

    /// Host facts and actionable guidance for the Linux resource boundaries.
    /// This exposes neither configured endpoints nor credentials.
    private func operatorCapabilities() -> [String: Any] {
        let manager = FileManager.default
        let tunPresent = manager.fileExists(atPath: "/dev/net/tun")
        let effectiveCapabilities = (try? String(contentsOfFile: "/proc/self/status", encoding: .utf8))?
            .split(separator: "\n").first(where: { $0.hasPrefix("CapEff:") })?
            .split(separator: "\t").last.flatMap { UInt64($0, radix: 16) } ?? 0
        let netAdmin = effectiveCapabilities & (UInt64(1) << 12) != 0
        let ipAvailable = ["/usr/sbin/ip", "/sbin/ip"].contains { manager.isExecutableFile(atPath: $0) }
        let resolvectlAvailable = ["/usr/bin/resolvectl", "/bin/resolvectl"].contains { manager.isExecutableFile(atPath: $0) }
        let firewallAvailable = ["/usr/sbin/iptables", "/sbin/iptables"].contains { manager.isExecutableFile(atPath: $0) }
        var guidance: [String] = []
        if !tunPresent { guidance.append("/dev/net/tun is unavailable") }
        if !netAdmin { guidance.append("grant CAP_NET_ADMIN to the helper process or launch it through an authorized supervisor") }
        if !ipAvailable { guidance.append("install iproute2 for address and route policy") }
        if !resolvectlAvailable { guidance.append("install systemd-resolved/resolvectl before configuring helper-owned DNS") }
        return [
            "tun_device_present": tunPresent, "net_admin_effective": netAdmin,
            "ip_available": ipAvailable, "resolvectl_available": resolvectlAvailable,
            "iptables_available": firewallAvailable, "privileged_tun_ready": tunPresent && netAdmin && ipAvailable,
            "guidance": guidance,
        ]
    }

    private func peersPayload() -> [[String: Any]] {
        let status = statusProvider()
        return peersProvider().map { row in
            var peer = peerPayload(row.snapshot, identity: row.identity)
            peer["configured_candidates"] = status.configuredCandidates
            peer["active_host"] = status.activeHost as Any
            peer["port"] = status.port
            peer["failure_reason"] = status.failureReason as Any
            return peer
        }
    }

    /// Serialize the one Core/adapter-derived peer projection. Do not read
    /// configuration secrets or construct protocol counters in this HTTP
    /// adapter: all SecureLink fields arrive through `status.peer`.
    private func peerPayload(_ peer: ObstacleBridgeLinuxPeerSnapshot, identity: String = "configured-peer") -> [String: Any] {
        [
            "peer_id": identity,
            "transport": peer.transport,
            "state": peer.lifecycleState,
            "connection_epoch": peer.connectionEpoch,
            "app_ready": peer.ready,
            "secure_link": [
                "state": peer.secureLinkState,
                "authenticated": peer.authenticated,
                "session_id": peer.sessionID ?? NSNull(),
                "pending_rekey_session_id": peer.pendingRekeySessionID ?? NSNull(),
                "application_sending_blocked": peer.applicationSendingBlocked,
                "attempts": peer.attempts,
                "next_retry_milliseconds": peer.nextRetryMilliseconds ?? NSNull(),
                "protected_tx_counter": peer.protectedTxCounter,
                "protected_rx_counter": peer.protectedRxCounter,
                "protected_frames_sent_total": peer.protectedFramesSentTotal,
                "protected_frames_received_total": peer.protectedFramesReceivedTotal,
                "authenticated_generations_total": peer.authenticatedGenerationsTotal,
                "rekeys_completed_total": peer.rekeysCompletedTotal,
            ],
            "compression_layer": [
                "enabled": peer.compression.enabled,
                "algorithm": peer.compression.algorithm,
                "level": peer.compression.level,
                "min_bytes": peer.compression.minimumBodyBytes,
                "compress_attempts_total": peer.compression.compressAttemptsTotal,
                "compress_applied_total": peer.compression.compressAppliedTotal,
                "compress_skipped_no_gain_total": peer.compression.compressSkippedNoGainTotal,
                "compress_input_bytes_total": peer.compression.compressInputBytesTotal,
                "compress_output_bytes_total": peer.compression.compressOutputBytesTotal,
                "compressed_frames_sent_total": peer.compression.compressedFramesSentTotal,
                "compressed_frames_received_total": peer.compression.compressedFramesReceivedTotal,
                "compressed_input_bytes_sent_total": peer.compression.compressedInputBytesSentTotal,
                "compressed_output_bytes_sent_total": peer.compression.compressedOutputBytesSentTotal,
                "compressed_input_bytes_received_total": peer.compression.compressedInputBytesReceivedTotal,
                "compressed_output_bytes_received_total": peer.compression.compressedOutputBytesReceivedTotal,
                "uncompressed_frames_sent_total": peer.compression.uncompressedFramesSentTotal,
                "uncompressed_frames_received_total": peer.compression.uncompressedFramesReceivedTotal,
                "uncompressed_bytes_sent_total": peer.compression.uncompressedBytesSentTotal,
                "uncompressed_bytes_received_total": peer.compression.uncompressedBytesReceivedTotal,
                "rejected_frames_total": peer.compression.rejectedFramesTotal,
                "rejected_bytes_total": peer.compression.rejectedBytesTotal,
            ],
        ]
    }

    private func json(_ object: Any) -> Data { (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8) }

    private func ipv4Address(_ host: String) -> in_addr? {
        var address = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &address) == 1 ? address : nil }
    }

    deinit { stop() }
}
