import Foundation

public indirect enum ObstacleBridgeJSONValue: Equatable, Sendable {
    case object([String: ObstacleBridgeJSONValue])
    case array([ObstacleBridgeJSONValue])
    case string(String)
    case integer(Int64)
    case double(Double)
    case bool(Bool)
    case null

    public static func parse(_ data: Data) throws -> ObstacleBridgeJSONValue {
        try fromFoundation(JSONSerialization.jsonObject(with: data))
    }

    public func canonicalData(preferredKeyOrder: [String] = []) -> Data {
        Data(canonicalString(preferredKeyOrder: preferredKeyOrder).utf8)
    }

    private static func fromFoundation(_ value: Any) throws -> ObstacleBridgeJSONValue {
        if value is NSNull { return .null }
        if let value = value as? String { return .string(value) }
        if let value = value as? NSNumber {
            if String(cString: value.objCType) == "c" { return .bool(value.boolValue) }
            let double = value.doubleValue
            return Double(value.int64Value) == double ? .integer(value.int64Value) : .double(double)
        }
        if let value = value as? Bool { return .bool(value) }
        if let value = value as? [Any] { return .array(try value.map(fromFoundation)) }
        if let value = value as? [String: Any] {
            return .object(try value.mapValues(fromFoundation))
        }
        throw ObstacleBridgeBinaryCodecError.invalidLength
    }

    private func canonicalString(preferredKeyOrder: [String] = []) -> String {
        switch self {
        case .object(let value):
            let keys = preferredKeyOrder.filter { value[$0] != nil }
                + value.keys.filter { !preferredKeyOrder.contains($0) }.sorted()
            return "{" + keys.map { Self.quote($0) + ":" + (value[$0] ?? .null).canonicalString() }.joined(separator: ",") + "}"
        case .array(let value): return "[" + value.map { $0.canonicalString() }.joined(separator: ",") + "]"
        case .string(let value): return Self.quote(value)
        case .integer(let value): return String(value)
        case .double(let value): return value.rounded(.towardZero) == value ? String(Int64(value)) : String(value)
        case .bool(let value): return value ? "true" : "false"
        case .null: return "null"
        }
    }

    private static func quote(_ value: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: [value])
        let array = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
        return String(array.dropFirst().dropLast())
    }
}

public struct ObstacleBridgeServiceSpec: Equatable, Sendable {
    public let serviceID: UInt16
    public let name: String?
    public let listenProtocol: ObstacleBridgeChannelMuxProtocol
    public let listenHost: String
    public let listenPort: UInt16
    public let targetProtocol: ObstacleBridgeChannelMuxProtocol
    public let targetHost: String
    public let targetPort: UInt16
    public let lifecycleHooks: [String: ObstacleBridgeJSONValue]?
    public let options: [String: ObstacleBridgeJSONValue]?

    public init(serviceID: UInt16, name: String?, listenProtocol: ObstacleBridgeChannelMuxProtocol, listenHost: String, listenPort: UInt16, targetProtocol: ObstacleBridgeChannelMuxProtocol, targetHost: String, targetPort: UInt16, lifecycleHooks: [String: ObstacleBridgeJSONValue]? = nil, options: [String: ObstacleBridgeJSONValue]? = nil) {
        self.serviceID = serviceID; self.name = name; self.listenProtocol = listenProtocol; self.listenHost = listenHost; self.listenPort = listenPort
        self.targetProtocol = targetProtocol; self.targetHost = targetHost; self.targetPort = targetPort; self.lifecycleHooks = lifecycleHooks; self.options = options
    }
}

public struct ObstacleBridgeOpenPayload: Equatable, Sendable {
    public let instanceID: UInt64
    public let connectionSequence: UInt32
    public let service: ObstacleBridgeServiceSpec
}

public enum ObstacleBridgeServiceCodecError: Error, Equatable, Sendable { case invalidPayload, payloadTooLarge, duplicateServiceID }

public enum ObstacleBridgeServiceCodec {
    private static let serviceKeyOrder = ["svc_id", "l_proto", "l_bind", "l_port", "r_proto", "r_host", "r_port", "name", "lifecycle_hooks", "options"]
    private static let metadataKeyOrder = ["name", "lifecycle_hooks", "options"]

    public static func encodeOpen(instanceID: UInt64, connectionSequence: UInt32, service: ObstacleBridgeServiceSpec) throws -> Data {
        let bind = Data(service.listenHost.utf8), host = Data(service.targetHost.utf8)
        guard bind.count <= Int(UInt16.max), host.count <= Int(UInt16.max) else { throw ObstacleBridgeServiceCodecError.payloadTooLarge }
        let metadata = ObstacleBridgeJSONValue.object(["name": service.name.map(ObstacleBridgeJSONValue.string) ?? .null, "lifecycle_hooks": service.lifecycleHooks.map(ObstacleBridgeJSONValue.object) ?? .null, "options": service.options.map(ObstacleBridgeJSONValue.object) ?? .null]).canonicalData(preferredKeyOrder: metadataKeyOrder)
        var writer = ObstacleBridgeBinaryWriter(capacity: 25 + bind.count + host.count + metadata.count)
        writer.appendUTF8("O5"); writer.append(instanceID); writer.append(connectionSequence); writer.append(service.serviceID); writer.append(service.listenProtocol.rawValue); writer.append(UInt16(bind.count)); writer.append(bind); writer.append(service.listenPort); writer.append(service.targetProtocol.rawValue); writer.append(UInt16(host.count)); writer.append(host); writer.append(service.targetPort); writer.append(UInt32(metadata.count)); writer.append(metadata)
        return writer.encoded
    }

    public static func decodeOpen(_ data: Data) throws -> ObstacleBridgeOpenPayload {
        var reader = ObstacleBridgeBinaryReader(data)
        do {
            let version = try reader.readData(count: 2)
            let instance = try reader.readUInt64(), sequence = try reader.readUInt32(), serviceID = try reader.readUInt16()
            let listenProtocol = try protocolValue(try reader.readUInt8())
            if version == Data("O4".utf8) {
                let listenHost = try reader.readUTF8(count: Int(try reader.readUInt8())), listenPort = try reader.readUInt16()
                let targetProtocol = try protocolValue(try reader.readUInt8())
                let targetHost = try reader.readUTF8(count: Int(try reader.readUInt8())), targetPort = try reader.readUInt16()
                guard reader.isAtEnd else { throw ObstacleBridgeServiceCodecError.invalidPayload }
                return .init(instanceID: instance, connectionSequence: sequence, service: .init(serviceID: serviceID, name: nil, listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort))
            }
            guard version == Data("O5".utf8) else { throw ObstacleBridgeServiceCodecError.invalidPayload }
            let listenHost = try reader.readUTF8(count: Int(try reader.readUInt16())), listenPort = try reader.readUInt16()
            let targetProtocol = try protocolValue(try reader.readUInt8())
            let targetHost = try reader.readUTF8(count: Int(try reader.readUInt16())), targetPort = try reader.readUInt16()
            let metadata = try ObstacleBridgeJSONValue.parse(reader.readData(count: Int(try reader.readUInt32())))
            guard reader.isAtEnd, case .object(let values) = metadata else { throw ObstacleBridgeServiceCodecError.invalidPayload }
            return .init(instanceID: instance, connectionSequence: sequence, service: .init(serviceID: serviceID, name: values["name"]?.stringValue, listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort, lifecycleHooks: values["lifecycle_hooks"]?.objectValue, options: values["options"]?.objectValue))
        } catch let error as ObstacleBridgeServiceCodecError { throw error
        } catch { throw ObstacleBridgeServiceCodecError.invalidPayload }
    }

    public static func encodeRemoteServices(instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeServiceSpec]) throws -> Data {
        try validate(services)
        let rows = Data(("[" + services.map { String(decoding: serviceJSON($0).canonicalData(preferredKeyOrder: serviceKeyOrder), as: UTF8.self) }.joined(separator: ",") + "]").utf8)
        guard rows.count <= Int(UInt32.max) else { throw ObstacleBridgeServiceCodecError.payloadTooLarge }
        var writer = ObstacleBridgeBinaryWriter(capacity: 19 + rows.count)
        writer.appendUTF8("RS3"); writer.append(instanceID); writer.append(connectionSequence); writer.append(UInt32(rows.count)); writer.append(rows)
        return writer.encoded
    }

    public static func decodeRemoteServices(_ data: Data) throws -> (instanceID: UInt64, connectionSequence: UInt32, services: [ObstacleBridgeServiceSpec]) {
        var reader = ObstacleBridgeBinaryReader(data)
        do {
            let version = try reader.readData(count: 3), instance = try reader.readUInt64(), sequence = try reader.readUInt32()
            let services: [ObstacleBridgeServiceSpec]
            if version == Data("RS3".utf8) {
                let body = try reader.readData(count: Int(try reader.readUInt32()))
                guard reader.isAtEnd, case .array(let rows) = try ObstacleBridgeJSONValue.parse(body) else { throw ObstacleBridgeServiceCodecError.invalidPayload }
                services = try rows.map { guard case .object(let row) = $0 else { throw ObstacleBridgeServiceCodecError.invalidPayload }; return try service(from: row) }
            } else if version == Data("RS2".utf8) {
                let count = Int(try reader.readUInt16())
                services = try (0..<count).map { _ in
                    let serviceID = try reader.readUInt16(), listenProtocol = try protocolValue(reader.readUInt8()), listenHost = try reader.readUTF8(count: Int(reader.readUInt8())), listenPort = try reader.readUInt16(), targetProtocol = try protocolValue(reader.readUInt8()), targetHost = try reader.readUTF8(count: Int(reader.readUInt8())), targetPort = try reader.readUInt16()
                    return .init(serviceID: serviceID, name: nil, listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort)
                }
                guard reader.isAtEnd else { throw ObstacleBridgeServiceCodecError.invalidPayload }
            } else { throw ObstacleBridgeServiceCodecError.invalidPayload }
            try validate(services)
            return (instance, sequence, services)
        } catch let error as ObstacleBridgeServiceCodecError { throw error
        } catch { throw ObstacleBridgeServiceCodecError.invalidPayload }
    }

    private static func validate(_ services: [ObstacleBridgeServiceSpec]) throws {
        guard Set(services.map(\.serviceID)).count == services.count else { throw ObstacleBridgeServiceCodecError.duplicateServiceID }
    }
    private static func protocolValue(_ raw: UInt8) throws -> ObstacleBridgeChannelMuxProtocol {
        guard let value = ObstacleBridgeChannelMuxProtocol(rawValue: raw) else { throw ObstacleBridgeServiceCodecError.invalidPayload }; return value
    }
    private static func protocolName(_ value: ObstacleBridgeChannelMuxProtocol) -> String { value == .tcp ? "tcp" : value == .udp ? "udp" : "tun" }
    private static func serviceJSON(_ service: ObstacleBridgeServiceSpec) -> ObstacleBridgeJSONValue { .object(["svc_id": .integer(Int64(service.serviceID)), "l_proto": .string(protocolName(service.listenProtocol)), "l_bind": .string(service.listenHost), "l_port": .integer(Int64(service.listenPort)), "r_proto": .string(protocolName(service.targetProtocol)), "r_host": .string(service.targetHost), "r_port": .integer(Int64(service.targetPort)), "name": service.name.map(ObstacleBridgeJSONValue.string) ?? .null, "lifecycle_hooks": service.lifecycleHooks.map(ObstacleBridgeJSONValue.object) ?? .null, "options": service.options.map(ObstacleBridgeJSONValue.object) ?? .null]) }
    private static func service(from row: [String: ObstacleBridgeJSONValue]) throws -> ObstacleBridgeServiceSpec {
        guard let serviceID = row["svc_id"]?.uint16Value, let listenProtocol = protocolValue(named: row["l_proto"]?.stringValue), let listenHost = row["l_bind"]?.stringValue, let listenPort = row["l_port"]?.uint16Value, let targetProtocol = protocolValue(named: row["r_proto"]?.stringValue), let targetHost = row["r_host"]?.stringValue, let targetPort = row["r_port"]?.uint16Value else { throw ObstacleBridgeServiceCodecError.invalidPayload }
        return .init(serviceID: serviceID, name: row["name"]?.stringValue, listenProtocol: listenProtocol, listenHost: listenHost, listenPort: listenPort, targetProtocol: targetProtocol, targetHost: targetHost, targetPort: targetPort, lifecycleHooks: row["lifecycle_hooks"]?.objectValue, options: row["options"]?.objectValue)
    }
    private static func protocolValue(named name: String?) -> ObstacleBridgeChannelMuxProtocol? {
        switch name?.lowercased() {
        case "udp": return .udp
        case "tcp": return .tcp
        case "tun": return .tun
        default: return nil
        }
    }
}

private extension ObstacleBridgeJSONValue {
    var stringValue: String? { if case .string(let value) = self { value } else { nil } }
    var objectValue: [String: ObstacleBridgeJSONValue]? { if case .object(let value) = self { value } else { nil } }
    var uint16Value: UInt16? { switch self { case .integer(let value) where (1...Int64(UInt16.max)).contains(value): UInt16(value); case .double(let value) where value.rounded() == value && (1...Double(UInt16.max)).contains(value): UInt16(value); default: nil } }
}
