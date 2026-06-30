import Foundation

enum ProxyProtocolRunnerError: Error {
    case invalidRequest
    case unsupportedAction
}

private func dataFromHex(_ value: String) -> Data? {
    let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard text.count % 2 == 0 else {
        return nil
    }
    var out = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else {
            return nil
        }
        out.append(byte)
        index = next
    }
    return out
}

private func hexFromData(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func run(_ request: [String: Any]) throws -> [String: Any] {
    guard let action = request["action"] as? String else {
        throw ProxyProtocolRunnerError.invalidRequest
    }
    switch action {
    case "parse_http":
        guard let requestHex = request["request_hex"] as? String,
              let data = dataFromHex(requestHex),
              let parsed = ObstacleBridgeProxyProtocolCodec.parseHTTPRequestHead(data)
        else {
            throw ProxyProtocolRunnerError.invalidRequest
        }
        let rewritten = ObstacleBridgeProxyProtocolCodec.rewriteHTTPRequestForOriginServer(parsed)
        let authority = ObstacleBridgeProxyProtocolCodec.parseAuthority(parsed.target, defaultPort: 443)
        return [
            "method": parsed.method,
            "target": parsed.target,
            "version": parsed.version,
            "host_header": parsed.headers["host"] ?? NSNull(),
            "header_length": parsed.headerLength,
            "rewritten_hex": hexFromData(rewritten),
            "authorized": ObstacleBridgeProxyProtocolCodec.authorized(
                headers: parsed.headers,
                credentials: ObstacleBridgeProxyServer.Credentials(username: "obproxy", password: "secret")
            ),
            "authority_host": authority?.host ?? NSNull(),
            "authority_port": authority?.port ?? NSNull(),
        ]
    case "basic_auth":
        return [
            "header": ObstacleBridgeProxyProtocolCodec.basicAuthorizationHeader(username: "obproxy", password: "secret")
        ]
    case "parse_socks5":
        guard let requestHex = request["request_hex"] as? String,
              let data = dataFromHex(requestHex),
              let parsed = ObstacleBridgeProxyProtocolCodec.parseSOCKS5ConnectRequest(data)
        else {
            throw ProxyProtocolRunnerError.invalidRequest
        }
        return [
            "command": Int(parsed.command),
            "host": parsed.host,
            "port": parsed.port,
            "consumed": parsed.consumed,
            "address_type": Int(parsed.addressType),
        ]
    default:
        throw ProxyProtocolRunnerError.unsupportedAction
    }
}

@main
struct ProxyProtocolRunnerMain {
    static func main() throws {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let object = try JSONSerialization.jsonObject(with: input) as? [String: Any]
        let response = try run(object ?? [:])
        let output = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
        FileHandle.standardOutput.write(output)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
