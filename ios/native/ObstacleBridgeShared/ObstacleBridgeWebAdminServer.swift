import CryptoKit
import Foundation
import Network

enum ObstacleBridgeWebAdminServerError: Error, LocalizedError {
    case invalidPort(Int)

    var errorDescription: String? {
        switch self {
        case .invalidPort(let port):
            return "Invalid web admin port: \(port)"
        }
    }
}

final class ObstacleBridgeWebAdminServer {
    typealias APIProvider = (String, String, [String: String], Data?) -> ObstacleBridgeAdminAPIResponse?
    typealias StaticFileProvider = (String) -> (contentType: String, body: Data)?
    typealias LiveTopicProvider = (String) -> Any?

    private struct HTTPRequest {
        let method: String
        let path: String
        let headers: [String: String]
        let body: Data?
    }

    private struct WebSocketFrame {
        let opcode: UInt8
        let payload: Data
        let final: Bool
        let consumed: Int
    }

    private static let liveTopics = ["status", "connections", "peers", "tun_routing", "meta"]
    private static let liveWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    private let listener: NWListener
    private let queue = DispatchQueue(label: "ObstacleBridgeWebAdminServer")
    private let statusProvider: () -> [String: Any]
    private let apiProvider: APIProvider
    private let staticFileProvider: StaticFileProvider
    private let liveTopicProvider: LiveTopicProvider
    private let authRequiredProvider: () -> Bool
    private let authenticatedProvider: ([String: String]) -> Bool
    private let fallbackIndexTitle: String
    private let fallbackIndexSubtitle: String
    private var liveSessions: [ObjectIdentifier: LiveSession] = [:]

    init(
        bindHost: String,
        port: Int,
        fallbackIndexTitle: String,
        fallbackIndexSubtitle: String,
        statusProvider: @escaping () -> [String: Any],
        apiProvider: @escaping APIProvider,
        staticFileProvider: @escaping StaticFileProvider,
        liveTopicProvider: @escaping LiveTopicProvider,
        authRequiredProvider: @escaping () -> Bool = { false },
        authenticatedProvider: @escaping ([String: String]) -> Bool = { _ in true }
    ) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw ObstacleBridgeWebAdminServerError.invalidPort(port)
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        if let host = Self.normalizedListenerHost(bindHost) {
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: nwPort)
        }
        self.listener = try NWListener(using: parameters)
        self.statusProvider = statusProvider
        self.apiProvider = apiProvider
        self.staticFileProvider = staticFileProvider
        self.liveTopicProvider = liveTopicProvider
        self.authRequiredProvider = authRequiredProvider
        self.authenticatedProvider = authenticatedProvider
        self.fallbackIndexTitle = fallbackIndexTitle
        self.fallbackIndexSubtitle = fallbackIndexSubtitle
        listener.stateUpdateHandler = { state in
            switch state {
            case .failed(let error):
                fputs("ObstacleBridgeWebAdminServer listener failed: \(error.localizedDescription)\n", stderr)
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.handle(connection)
        }
    }

    private static func normalizedListenerHost(_ bindHost: String) -> String? {
        let host = bindHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.isEmpty || host == "*" || host == "0.0.0.0" || host == "::" || host == "[::]" {
            return nil
        }
        if host == "localhost" {
            return "127.0.0.1"
        }
        return bindHost.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func start() {
        listener.start(queue: queue)
    }

    func stop() {
        listener.cancel()
        for session in liveSessions.values {
            session.stop()
        }
        liveSessions.removeAll()
    }

    func broadcastLiveTopic(_ topic: String, payload: Any) {
        guard Self.liveTopics.contains(topic) else {
            return
        }
        for session in liveSessions.values {
            session.push(topic: topic, payload: payload)
        }
    }

    static func jsonBody(_ value: Any) -> Data {
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

    private func handle(_ connection: NWConnection) {
        connection.start(queue: queue)
        receiveHTTPRequest(connection, buffer: Data())
    }

    private func receiveHTTPRequest(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }
            var nextBuffer = buffer
            if let data, !data.isEmpty {
                nextBuffer.append(data)
            }
            if let request = Self.parseHTTPRequest(from: nextBuffer) {
                self.handleRequest(request, connection: connection)
                return
            }
            if isComplete || error != nil {
                connection.cancel()
                return
            }
            self.receiveHTTPRequest(connection, buffer: nextBuffer)
        }
    }

    private func handleRequest(_ request: HTTPRequest, connection: NWConnection) {
        if request.path.hasPrefix("/api/"),
           Self.authExemptPaths.contains(request.path) == false,
           authRequiredProvider(),
           authenticatedProvider(request.headers) == false {
            let response = Self.httpResponse(
                statusLine: "HTTP/1.1 401 Unauthorized",
                contentType: "application/json; charset=utf-8",
                body: Self.jsonBody(["ok": false, "authenticated": false, "error": "authentication required"])
            )
            connection.send(content: response, completion: .contentProcessed { _ in
                connection.cancel()
            })
            return
        }
        if request.path == "/api/live", Self.isWebSocketUpgrade(headers: request.headers) {
            let session = LiveSession(
                connection: connection,
                queue: queue,
                topicProvider: liveTopicProvider,
                intervalProvider: Self.liveTopicInterval,
                onClose: { [weak self] session in
                    self?.liveSessions.removeValue(forKey: ObjectIdentifier(session))
                }
            )
            liveSessions[ObjectIdentifier(session)] = session
            session.start(headers: request.headers)
            return
        }
        let response = response(for: request)
        connection.send(content: response, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func response(for request: HTTPRequest) -> Data {
        let snapshot = statusProvider()
        if request.path == "/api/status" || request.path == "/status" || request.path == "/healthz" {
            return Self.httpResponse(
                statusLine: "HTTP/1.1 200 OK",
                contentType: "application/json; charset=utf-8",
                body: Self.jsonBody(snapshot)
            )
        }
        if request.path == "/api/bootstrap" {
            return Self.httpResponse(
                statusLine: "HTTP/1.1 200 OK",
                contentType: "application/json; charset=utf-8",
                body: Self.jsonBody(snapshot["bootstrap_state"] ?? [:])
            )
        }
        if request.path.hasPrefix("/api/") {
            if let result = apiProvider(request.method, request.path, request.headers, request.body) {
                return Self.httpResponse(statusLine: result.statusLine, contentType: result.contentType, body: result.body, headers: result.headers)
            }
            return Self.httpResponse(
                statusLine: "HTTP/1.1 404 Not Found",
                contentType: "application/json; charset=utf-8",
                body: Self.jsonBody(["ok": false, "error": "not found", "path": request.path])
            )
        }
        if let staticFile = staticFileProvider(request.path) {
            return Self.httpResponse(
                statusLine: "HTTP/1.1 200 OK",
                contentType: staticFile.contentType,
                body: staticFile.body
            )
        }
        let html = Self.htmlIndex(
            title: fallbackIndexTitle,
            subtitle: fallbackIndexSubtitle,
            snapshot: snapshot
        )
        return Self.httpResponse(
            statusLine: "HTTP/1.1 200 OK",
            contentType: "text/html; charset=utf-8",
            body: Data(html.utf8)
        )
    }

    private static func parseHTTPRequest(from data: Data) -> HTTPRequest? {
        let separator = Data("\r\n\r\n".utf8)
        guard let headerRange = data.range(of: separator) else {
            return nil
        }
        let headerData = data.subdata(in: 0..<headerRange.lowerBound)
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            return nil
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            return nil
        }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else {
            return nil
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let key = line[..<colon].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
            headers[key] = value
        }
        let contentLength = Int(headers["content-length"] ?? "") ?? 0
        let bodyStart = headerRange.upperBound
        guard data.count >= bodyStart + contentLength else {
            return nil
        }
        let body = contentLength > 0 ? data.subdata(in: bodyStart..<(bodyStart + contentLength)) : nil
        return HTTPRequest(
            method: String(parts[0]).uppercased(),
            path: String(parts[1]),
            headers: headers,
            body: body
        )
    }

    private static func isWebSocketUpgrade(headers: [String: String]) -> Bool {
        let upgrade = headers["upgrade"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        let connection = headers["connection"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return upgrade == "websocket" && connection.contains("upgrade")
    }

    private static func liveTopicInterval(_ topic: String) -> TimeInterval {
        switch topic {
        case "meta":
            return 5.0
        case "status", "connections", "peers", "tun_routing":
            return 1.0
        default:
            return 1.0
        }
    }

    static func liveTopicsForControlMessage(
        subscribe: Any?,
        activeTabs: [Any]?,
        currentTopics: Set<String>? = nil
    ) -> Set<String> {
        var topics = currentTopics ?? Set(liveTopics)
        let requested = parseLiveTopics(subscribe)
        if !requested.isEmpty {
            topics = requested
        }
        if let activeTabs, !activeTabs.isEmpty {
            var nextTopics: Set<String> = ["status"]
            let tabs = Set(activeTabs.compactMap { item in
                let text = String(describing: item).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                return text.isEmpty ? nil : text
            })
            if tabs.contains("status") {
                nextTopics.formUnion(["connections", "peers"])
            }
            if tabs.contains("tun-routing") {
                nextTopics.insert("tun_routing")
            }
            if tabs.contains("misc") {
                nextTopics.insert("meta")
            }
            topics = nextTopics
        }
        return topics
    }

    static func parseLiveTopics(_ value: Any?) -> Set<String> {
        if let value = value as? String {
            let topic = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return liveTopics.contains(topic) ? [topic] : []
        }
        if let sequence = value as? [Any] {
            var topics: Set<String> = []
            for item in sequence {
                let topic = String(describing: item).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if liveTopics.contains(topic) {
                    topics.insert(topic)
                }
            }
            return topics
        }
        return []
    }

    private static let authExemptPaths: Set<String> = [
        "/api/auth/state",
        "/api/auth/challenge",
        "/api/auth/login",
        "/api/auth/logout",
    ]

    private static func httpResponse(statusLine: String, contentType: String, body: Data, headers: [(String, String)] = []) -> Data {
        var header = "\(statusLine)\r\n"
        header += "Content-Type: \(contentType)\r\n"
        header += "Content-Length: \(body.count)\r\n"
        for (key, value) in headers {
            header += "\(key): \(value)\r\n"
        }
        header += "Connection: close\r\n"
        header += "Cache-Control: no-store\r\n\r\n"
        var response = Data(header.utf8)
        response.append(body)
        return response
    }

    private static func htmlIndex(title: String, subtitle: String, snapshot: [String: Any]) -> String {
        let jsonText = String(data: jsonBody(snapshot), encoding: .utf8) ?? "{}"
        return """
        <!doctype html>
        <html lang=\"en\">
        <head>
          <meta charset=\"utf-8\">
          <title>\(escapeHTML(title))</title>
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
            <h1>\(escapeHTML(title))</h1>
            <p>\(escapeHTML(subtitle))</p>
            <div class=\"card\">
              <p><a href=\"/api/status\">/api/status</a> | <a href=\"/api/bootstrap\">/api/bootstrap</a> | <a href=\"/api/live\">/api/live</a></p>
              <pre>\(escapeHTML(jsonText))</pre>
            </div>
          </main>
        </body>
        </html>
        """
    }

    private static func escapeHTML(_ text: String) -> String {
        var output = text
        for (needle, replacement) in [("&", "&amp;"), ("<", "&lt;"), (">", "&gt;")] {
            output = output.replacingOccurrences(of: needle, with: replacement)
        }
        return output
    }

    private final class LiveSession {
        private let connection: NWConnection
        private let queue: DispatchQueue
        private let topicProvider: LiveTopicProvider
        private let intervalProvider: (String) -> TimeInterval
        private let onClose: (LiveSession) -> Void
        private var topics = Set(ObstacleBridgeWebAdminServer.liveTopics)
        private var nextDue: [String: TimeInterval] = [:]
        private var receiveBuffer = Data()
        private var timer: DispatchSourceTimer?
        private var closed = false

        init(
            connection: NWConnection,
            queue: DispatchQueue,
            topicProvider: @escaping LiveTopicProvider,
            intervalProvider: @escaping (String) -> TimeInterval,
            onClose: @escaping (LiveSession) -> Void
        ) {
            self.connection = connection
            self.queue = queue
            self.topicProvider = topicProvider
            self.intervalProvider = intervalProvider
            self.onClose = onClose
        }

        func start(headers: [String: String]) {
            let key = headers["sec-websocket-key"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let version = headers["sec-websocket-version"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !key.isEmpty, version == "13" else {
                connection.send(
                    content: ObstacleBridgeWebAdminServer.httpResponse(
                        statusLine: "HTTP/1.1 400 Bad Request",
                        contentType: "text/plain; charset=utf-8",
                        body: Data("Bad WebSocket Request".utf8)
                    ),
                    completion: .contentProcessed { _ in
                        self.stop()
                    }
                )
                return
            }
            let acceptSeed = Data((key + ObstacleBridgeWebAdminServer.liveWebSocketGUID).utf8)
            let accept = Data(Insecure.SHA1.hash(data: acceptSeed)).base64EncodedString()
            let responseText =
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: \(accept)\r\n\r\n"
            let response = Data(responseText.utf8)
            connection.send(content: response, completion: .contentProcessed { [weak self] _ in
                guard let self else { return }
                let intervals = Dictionary(uniqueKeysWithValues: ObstacleBridgeWebAdminServer.liveTopics.map { ($0, self.intervalProvider($0)) })
                self.sendJSON([
                    "type": "hello",
                    "topics": Array(self.topics).sorted(),
                    "intervals_sec": intervals,
                ])
                let now = ProcessInfo.processInfo.systemUptime
                for topic in ObstacleBridgeWebAdminServer.liveTopics {
                    self.sendTopic(topic, now: now)
                }
                self.startTimer()
                self.receiveLoop()
            })
        }

        func push(topic: String, payload: Any) {
            guard !closed, topics.contains(topic) else {
                return
            }
            sendJSON(["type": topic, "data": payload])
            nextDue[topic] = ProcessInfo.processInfo.systemUptime + intervalProvider(topic)
        }

        func stop() {
            guard !closed else { return }
            closed = true
            timer?.cancel()
            timer = nil
            connection.cancel()
            onClose(self)
        }

        private func startTimer() {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 0.25, repeating: 0.25)
            timer.setEventHandler { [weak self] in
                self?.flushDueTopics()
            }
            self.timer = timer
            timer.resume()
        }

        private func receiveLoop() {
            guard !closed else { return }
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
                guard let self else { return }
                if let data, !data.isEmpty {
                    self.receiveBuffer.append(data)
                    self.processFrames()
                }
                if isComplete || error != nil || self.closed {
                    self.stop()
                    return
                }
                self.receiveLoop()
            }
        }

        private func processFrames() {
            while let frame = Self.parseFrame(from: receiveBuffer) {
                receiveBuffer.removeSubrange(0..<frame.consumed)
                handle(frame: frame)
                if closed {
                    return
                }
            }
        }

        private func handle(frame: WebSocketFrame) {
            guard frame.final else {
                stop()
                return
            }
            switch frame.opcode {
            case 0x1:
                guard let text = String(data: frame.payload, encoding: .utf8) else {
                    return
                }
                handleTextMessage(text)
            case 0x8:
                sendFrame(opcode: 0x8, payload: Data())
                stop()
            case 0x9:
                sendFrame(opcode: 0xA, payload: frame.payload)
            case 0xA:
                break
            default:
                break
            }
        }

        private func handleTextMessage(_ text: String) {
            guard let data = text.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                return
            }
            topics = ObstacleBridgeWebAdminServer.liveTopicsForControlMessage(
                subscribe: object["subscribe"],
                activeTabs: object["active_tabs"] as? [Any],
                currentTopics: topics
            )
            let requestTopics = ObstacleBridgeWebAdminServer.parseLiveTopics(object["request"])
            let now = ProcessInfo.processInfo.systemUptime
            for topic in requestTopics.sorted() {
                sendTopic(topic, now: now)
            }
        }

        private func flushDueTopics() {
            let now = ProcessInfo.processInfo.systemUptime
            for topic in topics.sorted() {
                if now >= (nextDue[topic] ?? 0) {
                    sendTopic(topic, now: now)
                }
            }
        }

        private func sendTopic(_ topic: String, now: TimeInterval) {
            guard let payload = topicProvider(topic) else {
                nextDue[topic] = now + intervalProvider(topic)
                return
            }
            sendJSON(["type": topic, "data": payload])
            nextDue[topic] = now + intervalProvider(topic)
        }

        private func sendJSON(_ value: Any) {
            let data = ObstacleBridgeWebAdminServer.jsonBody(value)
            sendFrame(opcode: 0x1, payload: data)
        }

        private func sendFrame(opcode: UInt8, payload: Data) {
            guard !closed else { return }
            var frame = Data([0x80 | opcode])
            if payload.count < 126 {
                frame.append(UInt8(payload.count))
            } else if payload.count <= 0xFFFF {
                frame.append(126)
                frame.append(UInt8((payload.count >> 8) & 0xFF))
                frame.append(UInt8(payload.count & 0xFF))
            } else {
                frame.append(127)
                let length = UInt64(payload.count)
                for shift in stride(from: 56, through: 0, by: -8) {
                    frame.append(UInt8((length >> UInt64(shift)) & 0xFF))
                }
            }
            frame.append(payload)
            connection.send(content: frame, completion: .contentProcessed { [weak self] _ in
                guard let self else { return }
                if self.closed {
                    self.connection.cancel()
                }
            })
        }
        private static func parseFrame(from data: Data) -> WebSocketFrame? {
            guard data.count >= 2 else {
                return nil
            }
            let b1 = data[data.startIndex]
            let b2 = data[data.startIndex + 1]
            let final = (b1 & 0x80) != 0
            let opcode = b1 & 0x0F
            let masked = (b2 & 0x80) != 0
            var index = 2
            var payloadLength = Int(b2 & 0x7F)
            if payloadLength == 126 {
                guard data.count >= index + 2 else { return nil }
                payloadLength = (Int(data[data.startIndex + index]) << 8) | Int(data[data.startIndex + index + 1])
                index += 2
            } else if payloadLength == 127 {
                guard data.count >= index + 8 else { return nil }
                var length: UInt64 = 0
                for offset in 0..<8 {
                    length = (length << 8) | UInt64(data[data.startIndex + index + offset])
                }
                guard length <= UInt64(Int.max) else { return nil }
                payloadLength = Int(length)
                index += 8
            }
            var mask: [UInt8] = []
            if masked {
                guard data.count >= index + 4 else { return nil }
                mask = Array(data[(data.startIndex + index)..<(data.startIndex + index + 4)])
                index += 4
            }
            guard data.count >= index + payloadLength else {
                return nil
            }
            var payload = Data(data[(data.startIndex + index)..<(data.startIndex + index + payloadLength)])
            if masked {
                var bytes = Array(payload)
                for offset in bytes.indices {
                    bytes[offset] ^= mask[offset % 4]
                }
                payload = Data(bytes)
            }
            return WebSocketFrame(opcode: opcode, payload: payload, final: final, consumed: index + payloadLength)
        }
    }
}
