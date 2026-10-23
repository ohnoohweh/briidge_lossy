import Foundation
import CoreFoundation

/// OS-independent framing and JSON control contract for Python and compiled
/// Swift TUN helpers. Local transport selection does not change this wire ABI.
public enum ObstacleBridgeTunHelperProtocolV1 {
    public static let version = 1
    public static let maximumFrameBytes = 1_048_576
    public static let headerBytes = 5
    public static let maximumOperationScalars = 64

    public enum FrameKind: UInt8, Sendable {
        case controlRequest = 1, controlResponse = 2, packetFromHelper = 3, packetToHelper = 4, event = 5
    }

    public enum Error: Swift.Error, Equatable { case malformedFrame, frameTooLarge, malformedControl }

    public static func frame(kind: FrameKind, body: Data) throws -> Data {
        guard body.count <= maximumFrameBytes else { throw Error.frameTooLarge }
        var length = UInt32(body.count).bigEndian
        var result = Data([kind.rawValue])
        result.append(Data(bytes: &length, count: MemoryLayout<UInt32>.size))
        result.append(body)
        return result
    }

    public static func header(_ data: Data) throws -> (kind: FrameKind, bodyLength: Int) {
        guard data.count == headerBytes, let kind = FrameKind(rawValue: data[data.startIndex]) else { throw Error.malformedFrame }
        let length = data.dropFirst().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= UInt32(maximumFrameBytes) else { throw Error.frameTooLarge }
        return (kind, Int(length))
    }

    public static func control(operation: String, payload: [String: Any]) throws -> Data {
        return try JSONSerialization.data(withJSONObject: ["version": version, "op": normalizedOperation(operation), "payload": payload], options: [.sortedKeys])
    }

    public static func decodeControl(_ data: Data) throws -> (operation: String, payload: [String: Any]) {
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawVersion = value["version"] as? NSNumber,
              CFGetTypeID(rawVersion) != CFBooleanGetTypeID(),
              rawVersion.intValue == version,
              rawVersion.doubleValue == Double(version),
              let rawOperation = value["op"] as? String,
              let payload = value["payload"] as? [String: Any] else { throw Error.malformedControl }
        return (try normalizedOperation(rawOperation), payload)
    }

    private static func normalizedOperation(_ value: String) throws -> String {
        let operation = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !operation.isEmpty, operation.unicodeScalars.count <= maximumOperationScalars else { throw Error.malformedControl }
        return operation
    }
}
