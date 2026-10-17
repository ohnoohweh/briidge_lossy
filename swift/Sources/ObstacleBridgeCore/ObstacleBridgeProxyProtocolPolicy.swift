import Foundation

struct ObstacleBridgeProxyCredentials {
    let username: String
    let password: String
}

enum ObstacleBridgeProxyServerError: Error, LocalizedError {
    case invalidPort(Int)

    var errorDescription: String? {
        switch self {
        case .invalidPort(let port):
            return "Invalid proxy server port: \(port)"
        }
    }
}

/// Portable HTTP/SOCKS request parsing and proxy authentication policy.
/// Platform adapters retain listener, connection, and socket ownership.
enum ObstacleBridgeProxyProtocolCodec {
    struct HTTPRequestHead {
        let method: String
        let target: String
        let version: String
        let headers: [String: String]
        let headerLength: Int
        let rawHeader: Data
    }

    struct SOCKS5ConnectRequest {
        let command: UInt8
        let host: String
        let port: Int
        let consumed: Int
        let addressType: UInt8
    }

    static func parseHTTPRequestHead(_ data: Data) -> HTTPRequestHead? {
        guard let marker = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let headerLength = marker.upperBound
        let rawHeader = data[..<headerLength]
        guard let headerText = String(data: rawHeader, encoding: .isoLatin1) else { return nil }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[2].uppercased().hasPrefix("HTTP/") else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespacesAndNewlines)
            headers[name] = value
        }
        return HTTPRequestHead(method: parts[0], target: parts[1], version: parts[2], headers: headers, headerLength: headerLength, rawHeader: Data(rawHeader))
    }

    static func rewriteHTTPRequestForOriginServer(_ request: HTTPRequestHead) -> Data {
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
                if lower.hasPrefix("proxy-authorization:") || lower.hasPrefix("proxy-connection:") { continue }
                lines.append(line)
            }
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    static func parseAuthority(_ raw: String, defaultPort: Int) -> (host: String, port: Int)? {
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
        return value.isEmpty ? nil : (value, defaultPort)
    }

    static func basicAuthorizationHeader(username: String, password: String) -> String {
        "Basic \(Data("\(username):\(password)".utf8).base64EncodedString())"
    }

    static func authorized(headers: [String: String], credentials: ObstacleBridgeProxyCredentials?) -> Bool {
        guard let credentials else { return true }
        guard let raw = headers["proxy-authorization"] else { return false }
        let prefix = "basic "
        guard raw.lowercased().hasPrefix(prefix) else { return false }
        let encoded = String(raw.dropFirst(prefix.count)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: encoded), let decoded = String(data: data, encoding: .utf8) else { return false }
        return decoded == "\(credentials.username):\(credentials.password)"
    }

    static func parseSOCKS5ConnectRequest(_ data: Data) -> SOCKS5ConnectRequest? {
        let bytes = [UInt8](data)
        guard bytes.count >= 4, bytes[0] == 0x05 else { return nil }
        let command = bytes[1]
        let addressType = bytes[3]
        var cursor = 4
        let host: String
        switch addressType {
        case 0x01:
            guard bytes.count >= cursor + 6 else { return nil }
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
            guard bytes.count >= cursor + 18 else { return nil }
            host = stride(from: 0, to: 8, by: 1).map {
                String((UInt16(bytes[cursor + $0 * 2]) << 8) | UInt16(bytes[cursor + $0 * 2 + 1]), radix: 16)
            }.joined(separator: ":")
            cursor += 16
        default:
            return nil
        }
        let port = Int(UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1]))
        cursor += 2
        guard !host.isEmpty, port > 0 else { return nil }
        return SOCKS5ConnectRequest(command: command, host: host, port: port, consumed: cursor, addressType: addressType)
    }
}
