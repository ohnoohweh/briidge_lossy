import Foundation

/// Common bounded framing for private desktop-worker sockets. The inherited
/// connected socket is the authentication capability; this type never opens a
/// listener or accepts an ambient endpoint.
public enum ObstacleBridgeWorkerIPC {
    public static let version: UInt8 = 1
    public static let maximumFrameBytes = 1_048_576
    private static let magic = Data([0x4f, 0x42, 0x49, 0x50]) // OBIP
    public static let headerBytes = 20

    public enum Kind: UInt8 {
        case hello = 1, ready, request, response, event, data, error, goodbye
    }

    public enum Failure: Error {
        case invalidFrame, frameTooLarge, invalidControl, invalidHello
    }

    public struct Frame {
        public let kind: Kind
        public let generation: UInt64
        public let payload: Data
    }

    public static func encode(kind: Kind, generation: UInt64, payload: Data = Data()) throws -> Data {
        guard generation > 0 else { throw Failure.invalidFrame }
        guard payload.count <= maximumFrameBytes else { throw Failure.frameTooLarge }
        var frame = magic
        frame.append(version)
        frame.append(kind.rawValue)
        frame.append(contentsOf: [0, 0]) // reserved flags
        var bigGeneration = generation.bigEndian
        withUnsafeBytes(of: &bigGeneration) { frame.append(contentsOf: $0) }
        var size = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &size) { frame.append(contentsOf: $0) }
        frame.append(payload)
        return frame
    }

    public static func decode(_ data: Data) throws -> (Frame?, Data) {
        guard let size = try frameSize(data) else { return (nil, data) }
        guard let kind = Kind(rawValue: data[5]) else { throw Failure.invalidFrame }
        let generation = data[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let total = headerBytes + size
        guard data.count >= total else { return (nil, data) }
        return (Frame(kind: kind, generation: generation, payload: Data(data[headerBytes..<total])), Data(data.dropFirst(total)))
    }

    public static func frameSize(_ data: Data) throws -> Int? {
        guard data.count >= headerBytes else { return nil }
        guard data.prefix(4) == magic, data[4] == version, data[6] == 0, data[7] == 0,
              Kind(rawValue: data[5]) != nil
        else { throw Failure.invalidFrame }
        let generation = data[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let size = data[16..<20].reduce(0) { ($0 << 8) | Int($1) }
        guard generation > 0 else { throw Failure.invalidFrame }
        guard size <= maximumFrameBytes else { throw Failure.frameTooLarge }
        return size
    }

    public static func encodeControl(kind: Kind, generation: UInt64, value: [String: Any]) throws -> Data {
        guard kind != .data, JSONSerialization.isValidJSONObject(value) else { throw Failure.invalidControl }
        return try encode(kind: kind, generation: generation, payload: JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
    }

    public static func decodeControl(_ frame: Frame) throws -> [String: Any] {
        let scanner = try ControlJSONScanner(frame.payload)
        guard frame.kind != .data,
              !scanner.hasDuplicateObjectKey,
              let value = try JSONSerialization.jsonObject(with: frame.payload) as? [String: Any]
        else { throw Failure.invalidControl }
        return value
    }

    public static func hello(generation: UInt64, role: String, capabilities: [String]) throws -> Data {
        let unique = Array(Set(capabilities)).sorted()
        guard !role.isEmpty, role.count <= 64,
              unique.allSatisfy({ !$0.isEmpty && $0.count <= 64 })
        else { throw Failure.invalidHello }
        return try encodeControl(kind: .hello, generation: generation, value: ["capabilities": unique, "role": role])
    }

    public static func negotiatedCapabilities(_ frame: Frame, supported: Set<String>) throws -> (role: String, capabilities: [String]) {
        guard frame.kind == .hello else { throw Failure.invalidHello }
        let value = try decodeControl(frame)
        guard let role = value["role"] as? String, !role.isEmpty, role.count <= 64,
              let advertised = value["capabilities"] as? [String],
              Set(advertised).count == advertised.count,
              advertised.allSatisfy({ !$0.isEmpty && $0.count <= 64 })
        else { throw Failure.invalidHello }
        return (role, advertised.filter(supported.contains).sorted())
    }

    /// JSONSerialization accepts a duplicate member by silently retaining one
    /// value. The Python peer rejects that ambiguity, so scan JSON objects
    /// before decoding to keep the cross-language control boundary fail-closed.
    private struct ControlJSONScanner {
        private let bytes: [UInt8]
        private var index = 0
        private(set) var hasDuplicateObjectKey = false

        init(_ data: Data) throws {
            bytes = Array(data)
            try parseDocument()
        }

        private mutating func parseDocument() throws {
            try parseValue()
            skipWhitespace()
            guard index == bytes.count else { throw Failure.invalidControl }
        }

        private mutating func parseValue() throws {
            skipWhitespace()
            guard index < bytes.count else { throw Failure.invalidControl }
            switch bytes[index] {
            case 0x7B: try parseObject() // {
            case 0x5B: try parseArray() // [
            case 0x22: _ = try parseString() // "
            case 0x74: try consumeLiteral([0x74, 0x72, 0x75, 0x65]) // true
            case 0x66: try consumeLiteral([0x66, 0x61, 0x6C, 0x73, 0x65]) // false
            case 0x6E: try consumeLiteral([0x6E, 0x75, 0x6C, 0x6C]) // null
            case 0x2D, 0x30...0x39: try parseNumber()
            default: throw Failure.invalidControl
            }
        }

        private mutating func parseObject() throws {
            index += 1
            skipWhitespace()
            if consume(0x7D) { return } // }
            var keys = Set<String>()
            while true {
                skipWhitespace()
                guard index < bytes.count, bytes[index] == 0x22 else { throw Failure.invalidControl }
                let key = try parseString()
                if !keys.insert(key).inserted { hasDuplicateObjectKey = true }
                skipWhitespace()
                guard consume(0x3A) else { throw Failure.invalidControl } // :
                try parseValue()
                skipWhitespace()
                if consume(0x7D) { return }
                guard consume(0x2C) else { throw Failure.invalidControl } // ,
            }
        }

        private mutating func parseArray() throws {
            index += 1
            skipWhitespace()
            if consume(0x5D) { return } // ]
            while true {
                try parseValue()
                skipWhitespace()
                if consume(0x5D) { return }
                guard consume(0x2C) else { throw Failure.invalidControl } // ,
            }
        }

        private mutating func parseString() throws -> String {
            let start = index
            index += 1 // opening quote
            while index < bytes.count {
                let byte = bytes[index]
                if byte == 0x22 {
                    index += 1
                    guard let value = try? JSONSerialization.jsonObject(
                        with: Data(bytes[start..<index]), options: [.allowFragments]
                    ) as? String else { throw Failure.invalidControl }
                    return value
                }
                if byte < 0x20 { throw Failure.invalidControl }
                if byte == 0x5C { // escape
                    index += 1
                    guard index < bytes.count else { throw Failure.invalidControl }
                    if bytes[index] == 0x75 {
                        guard index + 4 < bytes.count else { throw Failure.invalidControl }
                        index += 4
                    }
                }
                index += 1
            }
            throw Failure.invalidControl
        }

        private mutating func parseNumber() throws {
            let start = index
            while index < bytes.count,
                  bytes[index] == 0x2D || bytes[index] == 0x2B || bytes[index] == 0x2E ||
                    bytes[index] == 0x65 || bytes[index] == 0x45 || (0x30...0x39).contains(bytes[index]) {
                index += 1
            }
            guard index > start else { throw Failure.invalidControl }
        }

        private mutating func consumeLiteral(_ literal: [UInt8]) throws {
            guard index + literal.count <= bytes.count,
                  Array(bytes[index..<(index + literal.count)]) == literal
            else { throw Failure.invalidControl }
            index += literal.count
        }

        private mutating func skipWhitespace() {
            while index < bytes.count, [0x09, 0x0A, 0x0D, 0x20].contains(bytes[index]) { index += 1 }
        }

        private mutating func consume(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }
    }
}
