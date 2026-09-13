import Foundation

public enum ObstacleBridgeWebSocketPayload: Equatable, Sendable { case binary(Data), text(String) }
public enum ObstacleBridgeWebSocketPayloadMode: String, CaseIterable, Sendable { case binary, base64, jsonBase64 = "json-base64", semiTextShape = "semi-text-shape" }
public enum ObstacleBridgeWebSocketPayloadCodecError: Error, Equatable, Sendable { case unsupportedMode, invalidPayload }

/// Cross-platform WebSocket payload representation. RFC 6455 framing belongs
/// to adapters; this owner maps the common overlay bytes to binary or text.
public enum ObstacleBridgeWebSocketPayloadCodec {
    public static func mode(_ raw: String) throws -> ObstacleBridgeWebSocketPayloadMode {
        guard let value = ObstacleBridgeWebSocketPayloadMode(rawValue: raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) else { throw ObstacleBridgeWebSocketPayloadCodecError.unsupportedMode }
        return value
    }
    public static func encode(_ wire: Data, mode: ObstacleBridgeWebSocketPayloadMode) throws -> ObstacleBridgeWebSocketPayload {
        switch mode {
        case .binary: return .binary(wire)
        case .base64: return .text(wire.base64EncodedString())
        case .jsonBase64:
            let value = try JSONSerialization.data(withJSONObject: ["data": wire.base64EncodedString()])
            return .text(String(decoding: value, as: UTF8.self))
        case .semiTextShape: return .text(semiEncode(wire))
        }
    }
    public static func decode(_ payload: ObstacleBridgeWebSocketPayload, mode: ObstacleBridgeWebSocketPayloadMode) throws -> Data {
        if case .binary(let data) = payload { return data }
        guard case .text(let text) = payload else { throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload }
        switch mode {
        case .binary: throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload
        case .base64: guard let data = Data(base64Encoded: text, options: [.ignoreUnknownCharacters]) else { throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload }; return data
        case .jsonBase64:
            guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)), let encoded = (object as? [String: Any])?["data"] as? String, let data = Data(base64Encoded: encoded, options: [.ignoreUnknownCharacters]) else { throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload }; return data
        case .semiTextShape: return try semiDecode(text)
        }
    }
    public static func maximumEncodedSize(_ wireSize: Int, mode: ObstacleBridgeWebSocketPayloadMode) -> Int {
        let size = max(0, wireSize)
        switch mode {
        case .binary: return size
        case .base64: return size == 0 ? 0 : 4 * ((size + 2) / 3)
        case .jsonBase64: return 11 + (size == 0 ? 0 : 4 * ((size + 2) / 3))
        case .semiTextShape:
            let symbols = (size * 8 + 5) / 6
            return symbols + (symbols == 0 ? 0 : (symbols - 1) / 8)
        }
    }
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+")
    private static func semiEncode(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }; var bits = data.map { String($0, radix: 2).leftPad(8) }.joined(); let remainder = bits.count % 6; if remainder != 0 { bits += String(repeating: "0", count: 6 - remainder) }
        let chars = stride(from: 0, to: bits.count, by: 6).map { alphabet[Int(bits.dropFirst($0).prefix(6), radix: 2)!] }
        return stride(from: 0, to: chars.count, by: 8).map { String(chars[$0..<min($0 + 8, chars.count)]) }.joined(separator: " ")
    }
    private static func semiDecode(_ text: String) throws -> Data {
        let chars = text.filter { !$0.isWhitespace }; guard !chars.isEmpty else { return Data() }; var bits = ""
        for char in chars { guard let index = alphabet.firstIndex(of: char) else { throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload }; bits += String(index, radix: 2).leftPad(6) }
        let byteCount = bits.count / 8; let rest = bits.dropFirst(byteCount * 8); guard rest.allSatisfy({ $0 == "0" }) else { throw ObstacleBridgeWebSocketPayloadCodecError.invalidPayload }
        return Data(stride(from: 0, to: byteCount * 8, by: 8).map { UInt8(bits.dropFirst($0).prefix(8), radix: 2)! })
    }
}
private extension String { func leftPad(_ width: Int) -> String { count >= width ? self : String(repeating: "0", count: width - count) + self } }
