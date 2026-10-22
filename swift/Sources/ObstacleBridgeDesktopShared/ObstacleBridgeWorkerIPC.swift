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
        guard frame.kind != .data,
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
}
