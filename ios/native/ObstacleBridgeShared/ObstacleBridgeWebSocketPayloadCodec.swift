import Foundation

protocol ObstacleBridgeWebSocketPayloadCodec {
    var mode: String { get }
    func encode(_ wire: Data) throws -> Any
    func decode(_ message: Any) throws -> Data?
    func maxEncodedSize(_ wireSize: Int) -> Int
}

enum ObstacleBridgeWebSocketPayloadCodecError: Error {
    case unsupportedMode(String)
    case invalidJSONPayload
    case invalidJSONDataField
    case invalidSemiTextShapeSymbol(String)
    case invalidSemiTextShapeTrailingPadding
}

enum ObstacleBridgeWebSocketPayloadCodecFactory {
    static func build(mode rawMode: String) throws -> ObstacleBridgeWebSocketPayloadCodec {
        switch rawMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case ObstacleBridgeWebSocketBinaryPayloadCodec.codecMode:
            return ObstacleBridgeWebSocketBinaryPayloadCodec()
        case ObstacleBridgeWebSocketBase64PayloadCodec.codecMode:
            return ObstacleBridgeWebSocketBase64PayloadCodec()
        case ObstacleBridgeWebSocketJsonBase64PayloadCodec.codecMode:
            return ObstacleBridgeWebSocketJsonBase64PayloadCodec()
        case ObstacleBridgeWebSocketSemiTextShapePayloadCodec.codecMode:
            return ObstacleBridgeWebSocketSemiTextShapePayloadCodec()
        default:
            throw ObstacleBridgeWebSocketPayloadCodecError.unsupportedMode(rawMode)
        }
    }
}

struct ObstacleBridgeWebSocketBinaryPayloadCodec: ObstacleBridgeWebSocketPayloadCodec {
    static let codecMode = "binary"
    var mode: String { Self.codecMode }

    func encode(_ wire: Data) throws -> Any {
        return wire
    }

    func decode(_ message: Any) throws -> Data? {
        if let data = message as? Data {
            return data
        }
        if let bytes = message as? [UInt8] {
            return Data(bytes)
        }
        return nil
    }

    func maxEncodedSize(_ wireSize: Int) -> Int {
        return max(0, Int(wireSize))
    }
}

struct ObstacleBridgeWebSocketBase64PayloadCodec: ObstacleBridgeWebSocketPayloadCodec {
    static let codecMode = "base64"
    var mode: String { Self.codecMode }

    func encode(_ wire: Data) throws -> Any {
        return wire.base64EncodedString()
    }

    func decode(_ message: Any) throws -> Data? {
        if let data = message as? Data {
            return data
        }
        guard let text = message as? String else {
            return nil
        }
        return Data(base64Encoded: text, options: [.ignoreUnknownCharacters])
    }

    func maxEncodedSize(_ wireSize: Int) -> Int {
        let size = max(0, Int(wireSize))
        if size <= 0 {
            return 0
        }
        return 4 * ((size + 2) / 3)
    }
}

struct ObstacleBridgeWebSocketJsonBase64PayloadCodec: ObstacleBridgeWebSocketPayloadCodec {
    static let codecMode = "json-base64"
    static let jsonWrapperSize = #"{"data":""}"#.count
    var mode: String { Self.codecMode }

    func encode(_ wire: Data) throws -> Any {
        let payload = ["data": wire.base64EncodedString()]
        let encoded = try JSONSerialization.data(withJSONObject: payload, options: [])
        return String(decoding: encoded, as: UTF8.self)
    }

    func decode(_ message: Any) throws -> Data? {
        if let data = message as? Data {
            return data
        }
        guard let text = message as? String else {
            return nil
        }
        guard let jsonData = text.data(using: .utf8) else {
            throw ObstacleBridgeWebSocketPayloadCodecError.invalidJSONPayload
        }
        let decoded = try JSONSerialization.jsonObject(with: jsonData, options: [])
        guard let object = decoded as? [String: Any] else {
            throw ObstacleBridgeWebSocketPayloadCodecError.invalidJSONPayload
        }
        guard let dataField = object["data"] as? String else {
            throw ObstacleBridgeWebSocketPayloadCodecError.invalidJSONDataField
        }
        guard let out = Data(base64Encoded: dataField, options: [.ignoreUnknownCharacters]) else {
            throw ObstacleBridgeWebSocketPayloadCodecError.invalidJSONDataField
        }
        return out
    }

    func maxEncodedSize(_ wireSize: Int) -> Int {
        let size = max(0, Int(wireSize))
        if size <= 0 {
            return Self.jsonWrapperSize
        }
        return Self.jsonWrapperSize + (4 * ((size + 2) / 3))
    }
}

struct ObstacleBridgeWebSocketSemiTextShapePayloadCodec: ObstacleBridgeWebSocketPayloadCodec {
    static let codecMode = "semi-text-shape"
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+")
    static let decodeMap: [Character: Int] = {
        var out: [Character: Int] = [:]
        for (index, ch) in alphabet.enumerated() {
            out[ch] = index
        }
        return out
    }()
    static let groupSize = 8
    var mode: String { Self.codecMode }

    func encode(_ wire: Data) throws -> Any {
        let bits = wire.map { String($0, radix: 2).leftPadded(to: 8, with: "0") }.joined()
        if bits.isEmpty {
            return ""
        }
        var symbols: [Character] = []
        var start = bits.startIndex
        while start < bits.endIndex {
            let end = bits.index(start, offsetBy: 6, limitedBy: bits.endIndex) ?? bits.endIndex
            var chunk = String(bits[start..<end])
            if chunk.count < 6 {
                chunk.append(String(repeating: "0", count: 6 - chunk.count))
            }
            let value = Int(chunk, radix: 2) ?? 0
            symbols.append(Self.alphabet[value])
            start = end
        }
        var groups: [String] = []
        var groupStart = 0
        while groupStart < symbols.count {
            let groupEnd = min(groupStart + Self.groupSize, symbols.count)
            groups.append(String(symbols[groupStart..<groupEnd]))
            groupStart = groupEnd
        }
        return groups.joined(separator: " ")
    }

    func decode(_ message: Any) throws -> Data? {
        if let data = message as? Data {
            return data
        }
        guard let text = message as? String else {
            return nil
        }
        let normalized = text.split(whereSeparator: { $0.isWhitespace }).joined()
        if normalized.isEmpty {
            return Data()
        }
        var bits = ""
        for ch in normalized {
            guard let value = Self.decodeMap[ch] else {
                throw ObstacleBridgeWebSocketPayloadCodecError.invalidSemiTextShapeSymbol(String(ch))
            }
            bits.append(String(value, radix: 2).leftPadded(to: 6, with: "0"))
        }
        let fullBytes = (bits.count / 8) * 8
        let fullByteEnd = bits.index(bits.startIndex, offsetBy: fullBytes)
        let trailing = String(bits[fullByteEnd...])
        if !trailing.isEmpty && trailing.contains(where: { $0 != "0" }) {
            throw ObstacleBridgeWebSocketPayloadCodecError.invalidSemiTextShapeTrailingPadding
        }
        var out = Data()
        var start = bits.startIndex
        while bits.distance(from: start, to: fullByteEnd) >= 8 {
            let end = bits.index(start, offsetBy: 8)
            let chunk = String(bits[start..<end])
            out.append(UInt8(chunk, radix: 2) ?? 0)
            start = end
        }
        return out
    }

    func maxEncodedSize(_ wireSize: Int) -> Int {
        let size = max(0, Int(wireSize))
        if size <= 0 {
            return 0
        }
        let symbols = (size * 8 + 5) / 6
        let spaces = symbols > 0 ? (symbols - 1) / Self.groupSize : 0
        return symbols + spaces
    }
}

private extension String {
    func leftPadded(to length: Int, with character: Character) -> String {
        if count >= length {
            return self
        }
        return String(repeating: String(character), count: length - count) + self
    }
}