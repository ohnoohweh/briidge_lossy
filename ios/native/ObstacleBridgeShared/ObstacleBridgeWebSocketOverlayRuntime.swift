import Foundation

enum ObstacleBridgeWebSocketOverlayRuntimeError: Error, LocalizedError {
    case httpPreflightFailed(String)
    case invalidPayload(String)

    var errorDescription: String? {
        switch self {
        case .httpPreflightFailed(let detail):
            return detail
        case .invalidPayload(let detail):
            return detail
        }
    }
}

final class ObstacleBridgeWebSocketOverlayRuntime {
    enum InboundFrame {
        case app(Data)
        case ping(txNS: UInt64, echoNS: UInt64)
        case pong(echoTxNS: UInt64)
    }

    struct ConnectPlan {
        var uri: String
        var host: String?
        var port: Int?
        var serverHostname: String?
        var subprotocols: [String]?
        var maxSize: Int
        var compressionDisabled: Bool
        var preflightRequired: Bool
        var upgradeHeaders: [String: String]
        var usesProxySocket: Bool
    }

    struct SendSnapshot {
        var txBytes: Int
        var peerTxNotifications: [Int]
        var sentPayloadKinds: [String]
        var sentPayloadValues: [String]
        var closeCalls: Int
        var earlyBufBytes: Int
    }

    struct SocketConfigSnapshot {
        var keepAliveEnabled: Bool
        var tcpUserTimeoutMS: Int?
    }

    struct DisconnectSnapshot {
        var overlayConnected: Bool
        var disconnectScheduled: Bool
    }

    struct HTTPPreflightSnapshot {
        var request: String
        var statusCode: Int
        var bodyBytes: Int
    }

    struct ListenerPeerSnapshot {
        var payloadMode: String
        var decodedHex: String?
        var sentPayloadKind: String
        var sentPayloadValue: String
    }

    private let payloadMode: String
    private let corePayloadMode: ObstacleBridgeWebSocketPayloadMode
    private let frameMaxSize: Int
    private let sendTimeoutS: Double
    private let tcpUserTimeoutMS: Int
    private let reconnectGraceS: Double
    private var earlyBuf: [Data] = []
    private var earlyBufBytes = 0
    private var txBytes = 0
    private var disconnectScheduled = false
    private var overlayConnected = false

    var configuredPayloadMode: String { payloadMode }

    init(
        payloadMode: String,
        wsMaxSize: Int = 65535,
        sendTimeoutS: Double = 3.0,
        tcpUserTimeoutMS: Int = 10000,
        reconnectGraceS: Double = 3.0
    ) throws {
        self.payloadMode = payloadMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        self.corePayloadMode = try ObstacleBridgeWebSocketPayloadCodec.mode(self.payloadMode)
        self.frameMaxSize = ObstacleBridgeWebSocketPayloadCodec.maximumEncodedSize(wsMaxSize, mode: self.corePayloadMode)
        self.sendTimeoutS = max(0.0, sendTimeoutS)
        self.tcpUserTimeoutMS = max(0, tcpUserTimeoutMS)
        self.reconnectGraceS = max(0.0, reconnectGraceS)
    }

    func buildConnectPlan(
        host: String,
        port: Int,
        peerNameHost: String?,
        peerNamePort: Int?,
        useTLS: Bool,
        wsPath: String,
        wsSubprotocol: String?,
        proxyActive: Bool,
        headerKeyAvailable: Bool = true
    ) -> ConnectPlan {
        var uriHost = normalizeHost(peerNameHost ?? host)
        if uriHost.contains(":") {
            uriHost = "[\(uriHost)]"
        }
        let uriPort = peerNamePort ?? port
        let uri = "\(useTLS ? "wss" : "ws")://\(uriHost):\(uriPort)\(wsPath)"
        var directHost: String?
        var directPort: Int?
        var serverHostname: String?
        let preflightRequired = !proxyActive
        if proxyActive {
            if useTLS {
                serverHostname = normalizeHost(peerNameHost ?? host)
            }
        } else if let peerNameHost, normalizeHost(peerNameHost) != host || uriPort != port {
            directHost = host
            directPort = port
            if useTLS {
                serverHostname = peerNameHost
            }
        }
        let headers = headerKeyAvailable ? ["X-ObstacleBridge-WS-Payload-Mode": payloadMode] : [:]
        let subprotocols = wsSubprotocol.flatMap { $0.isEmpty ? nil : [$0] }
        return ConnectPlan(
            uri: uri,
            host: directHost,
            port: directPort,
            serverHostname: serverHostname,
            subprotocols: subprotocols,
            maxSize: frameMaxSize,
            compressionDisabled: true,
            preflightRequired: preflightRequired,
            upgradeHeaders: headers,
            usesProxySocket: proxyActive
        )
    }

    func bufferEarly(_ wire: Data) {
        earlyBuf.append(wire)
        earlyBufBytes += wire.count
    }

    func flushEarly(sendWillTimeout: Bool = false) throws -> SendSnapshot {
        let pending = earlyBuf
        earlyBuf.removeAll()
        earlyBufBytes = 0
        return try sendWires(pending, sendWillTimeout: sendWillTimeout)
    }

    func sendImmediate(_ wire: Data, sendWillTimeout: Bool = false) throws -> SendSnapshot {
        return try sendWires([wire], sendWillTimeout: sendWillTimeout)
    }

    private func sendWires(_ wires: [Data], sendWillTimeout: Bool) throws -> SendSnapshot {
        var peerTx: [Int] = []
        var payloadKinds: [String] = []
        var payloadValues: [String] = []
        var closeCalls = 0
        for wire in wires {
            if sendWillTimeout && sendTimeoutS > 0 {
                closeCalls += 1
                continue
            }
            let encoded = try ObstacleBridgeWebSocketPayloadCodec.encode(wire, mode: corePayloadMode)
            if case .binary(let data) = encoded {
                payloadKinds.append("binary")
                payloadValues.append(hexFromData(data))
            } else if case .text(let text) = encoded {
                payloadKinds.append("text")
                payloadValues.append(text)
            }
            txBytes += wire.count
            peerTx.append(wire.count)
        }
        return SendSnapshot(
            txBytes: txBytes,
            peerTxNotifications: peerTx,
            sentPayloadKinds: payloadKinds,
            sentPayloadValues: payloadValues,
            closeCalls: closeCalls,
            earlyBufBytes: earlyBufBytes
        )
    }

    func encodeClientWire(_ wire: Data) throws -> URLSessionWebSocketTask.Message {
        let overlayWire = try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .application, payload: wire))
        let encoded = try ObstacleBridgeWebSocketPayloadCodec.encode(overlayWire, mode: corePayloadMode)
        if case .binary(let data) = encoded {
            return .data(data)
        }
        if case .text(let text) = encoded { return .string(text) }
        throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket codec did not produce a payload")
    }

    func encodeClientPong(echoTxNS: UInt64) throws -> URLSessionWebSocketTask.Message {
        let overlayWire = try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .pong, payload: ObstacleBridgeOverlayFrameCodec.pongPayload(echoTxNS: echoTxNS)))
        let encoded = try ObstacleBridgeWebSocketPayloadCodec.encode(overlayWire, mode: corePayloadMode)
        if case .binary(let data) = encoded {
            return .data(data)
        }
        if case .text(let text) = encoded { return .string(text) }
        throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket codec did not produce a payload")
    }

    func encodeClientPing(txNS: UInt64, echoNS: UInt64) throws -> URLSessionWebSocketTask.Message {
        let overlayWire = try ObstacleBridgeOverlayFrameCodec.encodeBody(.init(kind: .ping, payload: ObstacleBridgeOverlayFrameCodec.pingPayload(txNS: txNS, echoNS: echoNS)))
        let encoded = try ObstacleBridgeWebSocketPayloadCodec.encode(overlayWire, mode: corePayloadMode)
        if case .binary(let data) = encoded {
            return .data(data)
        }
        if case .text(let text) = encoded { return .string(text) }
        throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket codec did not produce a payload")
    }

    func decodeClientMessage(_ message: URLSessionWebSocketTask.Message) throws -> Data {
        switch try decodeClientFrame(message) {
        case .app(let payload):
            return payload
        case .ping:
            throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket ping control frame is not app payload")
        case .pong:
            throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket pong control frame is not app payload")
        }
    }

    func decodeClientFrame(_ message: URLSessionWebSocketTask.Message) throws -> InboundFrame {
        let decodedWire: Data
        switch message {
        case .data(let data):
            decodedWire = try ObstacleBridgeWebSocketPayloadCodec.decode(.binary(data), mode: corePayloadMode)
        case .string(let text):
            decodedWire = try ObstacleBridgeWebSocketPayloadCodec.decode(.text(text), mode: corePayloadMode)
        @unknown default:
            return .app(Data())
        }
        return try decodeWireFrame(decodedWire)
    }

    func socketConfigSnapshot(socketPresent: Bool, tcpUserTimeoutAvailable: Bool) -> SocketConfigSnapshot {
        guard socketPresent else {
            return SocketConfigSnapshot(keepAliveEnabled: false, tcpUserTimeoutMS: nil)
        }
        let timeout = (tcpUserTimeoutMS > 0 && tcpUserTimeoutAvailable) ? tcpUserTimeoutMS : nil
        return SocketConfigSnapshot(keepAliveEnabled: true, tcpUserTimeoutMS: timeout)
    }

    func scheduleOverlayDisconnect(runFlag: Bool, initiallyConnected: Bool) -> DisconnectSnapshot {
        overlayConnected = initiallyConnected
        guard !disconnectScheduled, runFlag else {
            return DisconnectSnapshot(overlayConnected: overlayConnected, disconnectScheduled: disconnectScheduled)
        }
        if reconnectGraceS <= 0 {
            overlayConnected = false
            return DisconnectSnapshot(overlayConnected: overlayConnected, disconnectScheduled: false)
        }
        disconnectScheduled = true
        return DisconnectSnapshot(overlayConnected: overlayConnected, disconnectScheduled: true)
    }

    func handleAcceptCancellingDisconnect() -> DisconnectSnapshot {
        disconnectScheduled = false
        overlayConnected = true
        return DisconnectSnapshot(overlayConnected: true, disconnectScheduled: false)
    }

    func fireDisconnectTimer(wsPresent: Bool) -> DisconnectSnapshot {
        if disconnectScheduled && !wsPresent {
            overlayConnected = false
        }
        disconnectScheduled = false
        return DisconnectSnapshot(overlayConnected: overlayConnected, disconnectScheduled: false)
    }

    func buildHTTPPreflightRequest(hostHeader: String) -> String {
        return "GET / HTTP/1.1\r\nHost: \(hostHeader)\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml\r\nUser-Agent: ObstacleBridge-ws-preflight/1.0\r\n\r\n"
    }

    func validateHTTPPreflight(
        hostHeader: String,
        statusLine: String,
        headers: [String: String],
        body: Data
    ) throws -> HTTPPreflightSnapshot {
        let parts = statusLine.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", maxSplits: 2)
        let statusCode = parts.count >= 2 ? Int(parts[1]) ?? 0 : 0
        if let contentLengthText = headers["content-length"], let contentLength = Int(contentLengthText), body.count != contentLength {
            throw ObstacleBridgeWebSocketOverlayRuntimeError.httpPreflightFailed(
                "incomplete HTTP body \(body.count)/\(contentLength) for status \(statusCode)"
            )
        }
        if statusCode != 200 {
            throw ObstacleBridgeWebSocketOverlayRuntimeError.httpPreflightFailed("unexpected HTTP status \(statusCode)")
        }
        return HTTPPreflightSnapshot(
            request: buildHTTPPreflightRequest(hostHeader: hostHeader),
            statusCode: statusCode,
            bodyBytes: body.count
        )
    }

    func listenerPeerSnapshot(advertisedPayloadMode: String?, inboundMessage: Any, outgoingWire: Data) throws -> ListenerPeerSnapshot {
        let resolvedMode = resolveInboundPayloadMode(advertisedPayloadMode)
        let codec = try ObstacleBridgeWebSocketPayloadCodec.mode(resolvedMode)
        let decoded: Data?
        do {
            if let data = inboundMessage as? Data { decoded = try ObstacleBridgeWebSocketPayloadCodec.decode(.binary(data), mode: codec) }
            else if let text = inboundMessage as? String { decoded = try ObstacleBridgeWebSocketPayloadCodec.decode(.text(text), mode: codec) }
            else { decoded = nil }
        } catch {
            decoded = nil
        }
        let encoded = try ObstacleBridgeWebSocketPayloadCodec.encode(outgoingWire, mode: codec)
        if case .binary(let data) = encoded {
            return ListenerPeerSnapshot(
                payloadMode: resolvedMode,
                decodedHex: decoded.map(hexFromData),
                sentPayloadKind: "binary",
                sentPayloadValue: hexFromData(data)
            )
        }
        return ListenerPeerSnapshot(
            payloadMode: resolvedMode,
            decodedHex: decoded.map(hexFromData),
            sentPayloadKind: "text",
            sentPayloadValue: { if case .text(let text) = encoded { return text }; return "" }()
        )
    }

    func parseProxySpec(_ spec: String, secure: Bool) -> (host: String, port: Int)? {
        let preferred = secure ? ["https", "wss"] : ["http", "ws"]
        var fallback: (String, Int)?
        for rawItem in spec.split(separator: ";") {
            let item = rawItem.trimmingCharacters(in: .whitespacesAndNewlines)
            if item.isEmpty { continue }
            if !item.contains("=") {
                if let parsed = parseProxyAuthority(item) {
                    fallback = parsed
                }
                continue
            }
            let parts = item.split(separator: "=", maxSplits: 1).map(String.init)
            let scheme = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard let parsed = parseProxyAuthority(parts[1]) else { continue }
            if preferred.contains(scheme) {
                return parsed
            }
            if fallback == nil {
                fallback = parsed
            }
        }
        return fallback
    }

    func buildProxyConnectRequest(targetHost: String, targetPort: Int, authHeader: String?) -> String {
        let authority = formatConnectAuthority(targetHost, targetPort)
        var lines = [
            "CONNECT \(authority) HTTP/1.1",
            "Host: \(authority)",
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "User-Agent: ObstacleBridge-ws-proxy/1.0",
        ]
        if let authHeader, !authHeader.isEmpty {
            lines.append("Proxy-Authorization: \(authHeader)")
        }
        return lines.joined(separator: "\r\n") + "\r\n\r\n"
    }

    private func resolveInboundPayloadMode(_ requestedMode: String?) -> String {
        let normalized = requestedMode?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if normalized.isEmpty {
            return payloadMode
        }
        switch normalized {
        case "binary", "base64", "json-base64", "semi-text-shape":
            return normalized
        default:
            return payloadMode
        }
    }

    private func decodeAppWire(_ wire: Data) throws -> Data {
        switch try decodeWireFrame(wire) {
        case .app(let payload):
            return payload
        case .ping:
            throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket ping control frame is not app payload")
        case .pong:
            throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("websocket pong control frame is not app payload")
        }
    }

    private func decodeWireFrame(_ wire: Data) throws -> InboundFrame {
        do {
            let frame = try ObstacleBridgeOverlayFrameCodec.decodeBody(wire)
            switch frame.kind {
            case .application:
                return .app(frame.payload)
            case .ping:
                let timestamps = try ObstacleBridgeOverlayFrameCodec.pingTimestamps(frame)
                return .ping(txNS: timestamps.txNS, echoNS: timestamps.echoNS)
            case .pong:
                return .pong(echoTxNS: try ObstacleBridgeOverlayFrameCodec.pongEchoTimestamp(frame))
            }
        } catch {
            throw ObstacleBridgeWebSocketOverlayRuntimeError.invalidPayload("invalid websocket overlay frame")
        }
    }

    private func parseProxyAuthority(_ text: String) -> (host: String, port: Int)? {
        var host = text.trimmingCharacters(in: .whitespacesAndNewlines)
        var port = 8080
        if let url = URL(string: host), let urlHost = url.host {
            host = urlHost
            if url.port != nil {
                port = url.port ?? 8080
            } else if url.scheme == "https" {
                port = 443
            }
        } else if host.hasPrefix("[") {
            if let closing = host.firstIndex(of: "]") {
                let maybePort = host[host.index(after: closing)...]
                if maybePort.hasPrefix(":") {
                    port = Int(maybePort.dropFirst()) ?? 8080
                }
                host = String(host[host.index(after: host.startIndex)..<closing])
            }
        } else if host.filter({ $0 == ":" }).count == 1, let colon = host.lastIndex(of: ":") {
            let maybePort = String(host[host.index(after: colon)...])
            if let parsedPort = Int(maybePort) {
                port = parsedPort
                host = String(host[..<colon])
            }
        }
        let normalizedHost = normalizeHost(host)
        return normalizedHost.isEmpty ? nil : (normalizedHost, port)
    }

    private func formatConnectAuthority(_ host: String, _ port: Int) -> String {
        let normalized = normalizeHost(host)
        if normalized.contains(":") {
            return "[\(normalized)]:\(port)"
        }
        return "\(normalized):\(port)"
    }

    private func normalizeHost(_ host: String) -> String {
        var out = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if out.hasPrefix("[") && out.hasSuffix("]") {
            out.removeFirst()
            out.removeLast()
        }
        return out
    }

    private func hexFromData(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

}
