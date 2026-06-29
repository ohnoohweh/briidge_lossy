import Foundation
import Network

enum ObstacleBridgeProxyServerError: Error, LocalizedError {
    case invalidPort(Int)

    var errorDescription: String? {
        switch self {
        case .invalidPort(let port):
            return "Invalid proxy server port: \(port)"
        }
    }
}

final class ObstacleBridgeProxyServer {
    struct Credentials {
        let username: String
        let password: String
    }

    struct Configuration {
        let bindHost: String
        let port: Int
        let credentials: Credentials?
        let allowHTTP: Bool
        let allowSOCKS5: Bool
        let maxHeaderBytes: Int

        init(
            bindHost: String = "127.0.0.1",
            port: Int,
            credentials: Credentials? = nil,
            allowHTTP: Bool = true,
            allowSOCKS5: Bool = true,
            maxHeaderBytes: Int = 64 * 1024
        ) {
            self.bindHost = bindHost
            self.port = port
            self.credentials = credentials
            self.allowHTTP = allowHTTP
            self.allowSOCKS5 = allowSOCKS5
            self.maxHeaderBytes = max(4096, maxHeaderBytes)
        }
    }

    private struct ProxySnapshot {
        var acceptedConnections = 0
        var activeConnections = 0
        var completedConnections = 0
        var failedConnections = 0
        var rxBytes = 0
        var txBytes = 0
        var lastError = ""

        func dictionary() -> [String: Any] {
            [
                "accepted_connections": acceptedConnections,
                "active_connections": activeConnections,
                "completed_connections": completedConnections,
                "failed_connections": failedConnections,
                "rx_bytes": rxBytes,
                "tx_bytes": txBytes,
                "last_error": lastError,
            ]
        }
    }

    private let configuration: Configuration
    private let listener: NWListener
    private let queue = DispatchQueue(label: "ObstacleBridgeProxyServer")
    private var sessions: [ObjectIdentifier: ProxySession] = [:]
    private var snapshotState = ProxySnapshot()

    init(configuration: Configuration) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(configuration.port)) else {
            throw ObstacleBridgeProxyServerError.invalidPort(configuration.port)
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        if let host = Self.normalizedListenerHost(configuration.bindHost) {
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: nwPort)
        }
        self.configuration = configuration
        self.listener = try NWListener(using: parameters)
        listener.stateUpdateHandler = { state in
            switch state {
            case .failed(let error):
                fputs("ObstacleBridgeProxyServer listener failed: \(error.localizedDescription)\n", stderr)
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
        for session in sessions.values {
            session.stop()
        }
        sessions.removeAll()
        snapshotState.activeConnections = 0
    }

    func snapshot() -> [String: Any] {
        var result = snapshotState.dictionary()
        result["bind_host"] = configuration.bindHost
        result["port"] = configuration.port
        result["http_enabled"] = configuration.allowHTTP
        result["socks5_enabled"] = configuration.allowSOCKS5
        result["auth_required"] = configuration.credentials != nil
        return result
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

    private func handle(_ connection: NWConnection) {
        let session = ProxySession(
            inbound: connection,
            configuration: configuration,
            queue: queue,
            onBytes: { [weak self] rxBytes, txBytes in
                self?.snapshotState.rxBytes += rxBytes
                self?.snapshotState.txBytes += txBytes
            },
            onClose: { [weak self] session, error in
                guard let self else { return }
                self.sessions.removeValue(forKey: ObjectIdentifier(session))
                self.snapshotState.activeConnections = max(0, self.snapshotState.activeConnections - 1)
                if let error, !error.isEmpty {
                    self.snapshotState.failedConnections += 1
                    self.snapshotState.lastError = error
                } else {
                    self.snapshotState.completedConnections += 1
                }
            }
        )
        sessions[ObjectIdentifier(session)] = session
        snapshotState.acceptedConnections += 1
        snapshotState.activeConnections += 1
        session.start()
    }
}

private final class ProxySession {
    private struct HTTPRequestHead {
        let method: String
        let target: String
        let version: String
        let headers: [String: String]
        let headerLength: Int
        let rawHeader: Data
    }

    private let inbound: NWConnection
    private let configuration: ObstacleBridgeProxyServer.Configuration
    private let queue: DispatchQueue
    private let onBytes: (Int, Int) -> Void
    private let onClose: (ProxySession, String?) -> Void

    private var outbound: NWConnection?
    private var closed = false
    private var inboundReady = false
    private var outboundReady = false

    init(
        inbound: NWConnection,
        configuration: ObstacleBridgeProxyServer.Configuration,
        queue: DispatchQueue,
        onBytes: @escaping (Int, Int) -> Void,
        onClose: @escaping (ProxySession, String?) -> Void
    ) {
        self.inbound = inbound
        self.configuration = configuration
        self.queue = queue
        self.onBytes = onBytes
        self.onClose = onClose
    }

    func start() {
        inbound.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.inboundReady = true
                self?.receiveInitial(buffer: Data())
            case .failed(let error):
                self?.finish(error: error.localizedDescription)
            case .cancelled:
                self?.finish(error: nil)
            default:
                break
            }
        }
        inbound.start(queue: queue)
    }

    func stop() {
        finish(error: nil)
    }

    private func receiveInitial(buffer: Data) {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                self.finish(error: error.localizedDescription)
                return
            }
            var nextBuffer = buffer
            if let data, !data.isEmpty {
                nextBuffer.append(data)
            }
            guard !nextBuffer.isEmpty else {
                if isComplete { self.finish(error: nil) }
                else { self.receiveInitial(buffer: nextBuffer) }
                return
            }
            if nextBuffer.first == 0x05 {
                guard self.configuration.allowSOCKS5 else {
                    self.finish(error: "socks5 disabled")
                    return
                }
                self.handleSOCKS5Greeting(buffer: nextBuffer)
                return
            }
            guard self.configuration.allowHTTP else {
                self.finish(error: "http proxy disabled")
                return
            }
            if let request = Self.parseHTTPRequestHead(nextBuffer) {
                self.handleHTTPRequest(request, buffer: nextBuffer)
                return
            }
            if nextBuffer.count > self.configuration.maxHeaderBytes {
                self.sendHTTPError(status: "431 Request Header Fields Too Large", message: "request header too large")
                return
            }
            if isComplete {
                self.finish(error: "incomplete request")
                return
            }
            self.receiveInitial(buffer: nextBuffer)
        }
    }

    private func handleHTTPRequest(_ request: HTTPRequestHead, buffer: Data) {
        guard authorized(headers: request.headers) else {
            let body = Data("proxy authentication required\n".utf8)
            var response = Data()
            response.append(Data("HTTP/1.1 407 Proxy Authentication Required\r\n".utf8))
            response.append(Data("Proxy-Authenticate: Basic realm=\"ObstacleBridge\"\r\n".utf8))
            response.append(Data("Content-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8))
            response.append(body)
            inbound.send(content: response, completion: .contentProcessed { [weak self] _ in self?.finish(error: "proxy authentication required") })
            return
        }
        if request.method.uppercased() == "CONNECT" {
            guard let destination = Self.parseAuthority(request.target, defaultPort: 443) else {
                sendHTTPError(status: "400 Bad Request", message: "invalid CONNECT authority")
                return
            }
            connectOutbound(host: destination.host, port: destination.port) { [weak self] success in
                guard let self else { return }
                guard success else { return }
                let response = Data("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ObstacleBridge\r\n\r\n".utf8)
                self.inbound.send(content: response, completion: .contentProcessed { [weak self] error in
                    guard let self else { return }
                    if let error {
                        self.finish(error: error.localizedDescription)
                        return
                    }
                    let remainder = Self.remainder(buffer: buffer, after: request.headerLength)
                    self.startTunnel(pendingInboundData: remainder)
                })
            }
            return
        }
        guard let url = URL(string: request.target), let host = url.host else {
            sendHTTPError(status: "400 Bad Request", message: "absolute-form HTTP target required")
            return
        }
        let port = url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)
        connectOutbound(host: host, port: port) { [weak self] success in
            guard let self else { return }
            guard success else { return }
            var forwarded = Self.rewriteHTTPRequestForOriginServer(request, originalBuffer: buffer)
            let remainder = Self.remainder(buffer: buffer, after: request.headerLength)
            forwarded.append(remainder)
            self.outbound?.send(content: forwarded, completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                if let error {
                    self.finish(error: error.localizedDescription)
                    return
                }
                self.onBytes(forwarded.count, 0)
                self.startTunnel(pendingInboundData: Data())
            })
        }
    }

    private func handleSOCKS5Greeting(buffer: Data) {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 2 else {
            receiveSOCKS5Greeting(buffer: buffer)
            return
        }
        let methodCount = Int(bytes[1])
        guard bytes.count >= 2 + methodCount else {
            receiveSOCKS5Greeting(buffer: buffer)
            return
        }
        let methods = Array(bytes[2..<(2 + methodCount)])
        let authRequired = configuration.credentials != nil
        let selectedMethod: UInt8
        if authRequired, methods.contains(0x02) {
            selectedMethod = 0x02
        } else if !authRequired, methods.contains(0x00) {
            selectedMethod = 0x00
        } else {
            inbound.send(content: Data([0x05, 0xff]), completion: .contentProcessed { [weak self] _ in
                self?.finish(error: "no acceptable socks5 auth method")
            })
            return
        }
        let consumed = 2 + methodCount
        let remainder = Self.remainder(buffer: buffer, after: consumed)
        inbound.send(content: Data([0x05, selectedMethod]), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.finish(error: error.localizedDescription)
                return
            }
            if selectedMethod == 0x02 {
                self.handleSOCKS5UserPassword(buffer: remainder)
            } else {
                self.handleSOCKS5Request(buffer: remainder)
            }
        })
    }

    private func receiveSOCKS5Greeting(buffer: Data) {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.finish(error: error.localizedDescription)
                return
            }
            var nextBuffer = buffer
            if let data { nextBuffer.append(data) }
            self.handleSOCKS5Greeting(buffer: nextBuffer)
        }
    }

    private func handleSOCKS5UserPassword(buffer: Data) {
        let bytes = [UInt8](buffer)
        guard bytes.count >= 2 else {
            receiveSOCKS5UserPassword(buffer: buffer)
            return
        }
        let usernameLength = Int(bytes[1])
        guard bytes.count >= 2 + usernameLength + 1 else {
            receiveSOCKS5UserPassword(buffer: buffer)
            return
        }
        let passwordLengthIndex = 2 + usernameLength
        let passwordLength = Int(bytes[passwordLengthIndex])
        guard bytes.count >= passwordLengthIndex + 1 + passwordLength else {
            receiveSOCKS5UserPassword(buffer: buffer)
            return
        }
        let usernameBytes = bytes[2..<(2 + usernameLength)]
        let passwordStart = passwordLengthIndex + 1
        let passwordBytes = bytes[passwordStart..<(passwordStart + passwordLength)]
        let username = String(bytes: usernameBytes, encoding: .utf8) ?? ""
        let password = String(bytes: passwordBytes, encoding: .utf8) ?? ""
        let authorized = username == configuration.credentials?.username && password == configuration.credentials?.password
        let consumed = passwordStart + passwordLength
        let remainder = Self.remainder(buffer: buffer, after: consumed)
        inbound.send(content: Data([0x01, authorized ? 0x00 : 0x01]), completion: .contentProcessed { [weak self] _ in
            guard let self else { return }
            if authorized {
                self.handleSOCKS5Request(buffer: remainder)
            } else {
                self.finish(error: "socks5 authentication failed")
            }
        })
    }

    private func receiveSOCKS5UserPassword(buffer: Data) {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.finish(error: error.localizedDescription)
                return
            }
            var nextBuffer = buffer
            if let data { nextBuffer.append(data) }
            self.handleSOCKS5UserPassword(buffer: nextBuffer)
        }
    }

    private func handleSOCKS5Request(buffer: Data) {
        guard let parsed = Self.parseSOCKS5ConnectRequest(buffer) else {
            receiveSOCKS5Request(buffer: buffer)
            return
        }
        guard parsed.command == 0x01 else {
            sendSOCKS5Reply(status: 0x07)
            finish(error: "unsupported socks5 command")
            return
        }
        connectOutbound(host: parsed.host, port: parsed.port) { [weak self] success in
            guard let self else { return }
            guard success else { return }
            self.sendSOCKS5Reply(status: 0x00) { [weak self] in
                self?.startTunnel(pendingInboundData: Self.remainder(buffer: buffer, after: parsed.consumed))
            }
        }
    }

    private func receiveSOCKS5Request(buffer: Data) {
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.finish(error: error.localizedDescription)
                return
            }
            var nextBuffer = buffer
            if let data { nextBuffer.append(data) }
            self.handleSOCKS5Request(buffer: nextBuffer)
        }
    }

    private func connectOutbound(host: String, port: Int, completion: @escaping (Bool) -> Void) {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            sendHTTPError(status: "400 Bad Request", message: "invalid destination port")
            completion(false)
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        outbound = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if !self.outboundReady {
                    self.outboundReady = true
                    completion(true)
                }
            case .failed(let error):
                self.finish(error: error.localizedDescription)
                completion(false)
            case .cancelled:
                self.finish(error: nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func startTunnel(pendingInboundData: Data) {
        if !pendingInboundData.isEmpty {
            outbound?.send(content: pendingInboundData, completion: .contentProcessed { _ in })
            onBytes(pendingInboundData.count, 0)
        }
        receiveInboundForTunnel()
        receiveOutboundForTunnel()
    }

    private func receiveInboundForTunnel() {
        guard !closed else { return }
        inbound.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.onBytes(data.count, 0)
                self.outbound?.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                self.finish(error: error?.localizedDescription)
                return
            }
            self.receiveInboundForTunnel()
        }
    }

    private func receiveOutboundForTunnel() {
        guard !closed, let outbound else { return }
        outbound.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.onBytes(0, data.count)
                self.inbound.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                self.finish(error: error?.localizedDescription)
                return
            }
            self.receiveOutboundForTunnel()
        }
    }

    private func sendHTTPError(status: String, message: String) {
        let body = Data("\(message)\n".utf8)
        var response = Data("HTTP/1.1 \(status)\r\n".utf8)
        response.append(Data("Content-Type: text/plain; charset=utf-8\r\n".utf8))
        response.append(Data("Content-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8))
        response.append(body)
        inbound.send(content: response, completion: .contentProcessed { [weak self] _ in self?.finish(error: message) })
    }

    private func sendSOCKS5Reply(status: UInt8, completion: (() -> Void)? = nil) {
        let response = Data([0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        inbound.send(content: response, completion: .contentProcessed { [weak self] error in
            if let error {
                self?.finish(error: error.localizedDescription)
                return
            }
            completion?()
        })
    }

    private func authorized(headers: [String: String]) -> Bool {
        guard let credentials = configuration.credentials else {
            return true
        }
        guard let raw = headers["proxy-authorization"] else {
            return false
        }
        let prefix = "basic "
        let lower = raw.lowercased()
        guard lower.hasPrefix(prefix) else {
            return false
        }
        let encoded = String(raw.dropFirst(prefix.count)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: encoded), let decoded = String(data: data, encoding: .utf8) else {
            return false
        }
        return decoded == "\(credentials.username):\(credentials.password)"
    }

    private func finish(error: String?) {
        guard !closed else { return }
        closed = true
        inbound.cancel()
        outbound?.cancel()
        onClose(self, error)
    }

    private static func parseHTTPRequestHead(_ data: Data) -> HTTPRequestHead? {
        guard let marker = data.range(of: Data("\r\n\r\n".utf8)) else {
            return nil
        }
        let headerLength = marker.upperBound
        let rawHeader = data[..<headerLength]
        guard let headerText = String(data: rawHeader, encoding: .isoLatin1) else {
            return nil
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            return nil
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            return nil
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }
        return HTTPRequestHead(method: parts[0], target: parts[1], version: parts[2], headers: headers, headerLength: headerLength, rawHeader: Data(rawHeader))
    }

    private static func rewriteHTTPRequestForOriginServer(_ request: HTTPRequestHead, originalBuffer: Data) -> Data {
        let url = URL(string: request.target)
        let originPath: String
        if let url {
            let path = url.path.isEmpty ? "/" : url.path
            originPath = url.query.map { "\(path)?\($0)" } ?? path
        } else {
            originPath = request.target
        }
        var lines: [String] = ["\(request.method) \(originPath) \(request.version)"]
        if let headerText = String(data: request.rawHeader, encoding: .isoLatin1) {
            for line in headerText.components(separatedBy: "\r\n").dropFirst() where !line.isEmpty {
                let lower = line.lowercased()
                if lower.hasPrefix("proxy-authorization:") || lower.hasPrefix("proxy-connection:") {
                    continue
                }
                lines.append(line)
            }
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    private static func parseAuthority(_ raw: String, defaultPort: Int) -> (host: String, port: Int)? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { return nil }
            let host = String(value[value.index(after: value.startIndex)..<end])
            let remainder = value[value.index(after: end)...]
            let port = remainder.hasPrefix(":") ? Int(remainder.dropFirst()) ?? defaultPort : defaultPort
            return (host, port)
        }
        if let colon = value.lastIndex(of: ":"), value[value.index(after: colon)...].allSatisfy({ $0.isNumber }) {
            return (String(value[..<colon]), Int(value[value.index(after: colon)...]) ?? defaultPort)
        }
        return (value, defaultPort)
    }

    private static func parseSOCKS5ConnectRequest(_ data: Data) -> (command: UInt8, host: String, port: Int, consumed: Int)? {
        let bytes = [UInt8](data)
        guard bytes.count >= 4, bytes[0] == 0x05 else {
            return nil
        }
        let command = bytes[1]
        let addressType = bytes[3]
        var cursor = 4
        let host: String
        switch addressType {
        case 0x01:
            guard bytes.count >= cursor + 4 + 2 else { return nil }
            host = bytes[cursor..<(cursor + 4)].map(String.init).joined(separator: ".")
            cursor += 4
        case 0x03:
            guard bytes.count >= cursor + 1 else { return nil }
            let length = Int(bytes[cursor])
            cursor += 1
            guard bytes.count >= cursor + length + 2 else { return nil }
            host = String(bytes: bytes[cursor..<(cursor + length)], encoding: .utf8) ?? ""
            cursor += length
        case 0x04:
            guard bytes.count >= cursor + 16 + 2 else { return nil }
            var segments: [String] = []
            var segmentIndex = 0
            while segmentIndex < 8 {
                let high = UInt16(bytes[cursor + segmentIndex * 2]) << 8
                let low = UInt16(bytes[cursor + segmentIndex * 2 + 1])
                segments.append(String(high | low, radix: 16))
                segmentIndex += 1
            }
            host = segments.joined(separator: ":")
            cursor += 16
        default:
            return nil
        }
        let port = Int(UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1]))
        cursor += 2
        guard !host.isEmpty, port > 0 else {
            return nil
        }
        return (command, host, port, cursor)
    }

    private static func remainder(buffer: Data, after consumed: Int) -> Data {
        guard consumed < buffer.count else {
            return Data()
        }
        return Data(buffer[consumed..<buffer.count])
    }
}