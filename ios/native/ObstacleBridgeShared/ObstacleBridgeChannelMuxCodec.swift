import CoreFoundation
import Foundation

enum ObstacleBridgeChannelMuxCodecError: Error {
    case invalidChannelID
    case payloadTooLarge
    case stringTooLarge
    case invalidJSON
    case invalidPayload
}

struct ObstacleBridgeChannelMuxCodec {
    static let muxHeaderSize = 8
    static let controlChunkHeaderSize = 12
    static let controlChunkMaxInflight = 512
    static let controlChunkReassemblyTTLS = 20.0
    private static let controlChunkMagic = Data("CKV1".utf8)

    enum Proto: Int {
        case udp = 0
        case tcp = 1
        case tun = 2
    }

    enum MType: Int {
        case data = 0
        case open = 1
        case close = 2
        case remoteServicesSetV1 = 3
        case remoteServicesSetV2 = 4
        case dataFrag = 5
        case remoteServicesSetV2Chunk = 6
        case openChunk = 7
    }

    enum JSONValue: Equatable {
        case object([String: JSONValue])
        case array([JSONValue])
        case string(String)
        case integer(Int64)
        case double(Double)
        case bool(Bool)
        case null
    }

    struct ServiceSpec: Equatable {
        var svcID: Int
        var lProto: String
        var lBind: String
        var lPort: Int
        var rProto: String
        var rHost: String
        var rPort: Int
        var name: String?
        var lifecycleHooks: [String: JSONValue]?
        var options: [String: JSONValue]?
    }

    struct MuxFrame: Equatable {
        var chanID: Int
        var proto: Proto
        var counter: Int
        var mtype: MType
        var body: Data
    }

    struct ParsedOpen: Equatable {
        var instanceID: UInt64
        var connectionSeq: UInt32
        var spec: ServiceSpec
    }

    struct ControlChunkKey: Hashable {
        var peerID: Int
        var chanID: Int
        var proto: Proto
        var mtype: MType
        var txID: UInt32
    }

    struct ControlChunkState {
        var total: Int
        var parts: [Int: Data]
        var received: Int
        var updated: TimeInterval
    }

    final class ControlChunkReassembler {
        private let maxInflight: Int
        private let ttlSeconds: TimeInterval
        private var states: [ControlChunkKey: ControlChunkState] = [:]

        init(
            maxInflight: Int = ObstacleBridgeChannelMuxCodec.controlChunkMaxInflight,
            ttlSeconds: TimeInterval = ObstacleBridgeChannelMuxCodec.controlChunkReassemblyTTLS
        ) {
            self.maxInflight = maxInflight
            self.ttlSeconds = ttlSeconds
        }

        func consume(
            chanID: Int,
            proto: Proto,
            mtype: MType,
            payload: Data,
            peerID: Int?,
            now: TimeInterval = Date().timeIntervalSince1970
        ) -> Data? {
            guard
                let header = ObstacleBridgeChannelMuxCodec.parseControlChunkHeader(payload),
                header.magic == ObstacleBridgeChannelMuxCodec.controlChunkMagic,
                header.chunkTotal > 0,
                header.chunkTotal <= 0xFFFF,
                header.chunkIndex < header.chunkTotal
            else {
                return nil
            }

            let key = ControlChunkKey(
                peerID: peerID ?? 0,
                chanID: chanID,
                proto: proto,
                mtype: mtype,
                txID: header.txID
            )
            let chunk = payload.dropFirst(ObstacleBridgeChannelMuxCodec.controlChunkHeaderSize)
            var state = states[key]

            if state == nil {
                if states.count >= maxInflight {
                    prune(now: now)
                    if states.count >= maxInflight {
                        return nil
                    }
                }
                state = ControlChunkState(
                    total: header.chunkTotal,
                    parts: [:],
                    received: 0,
                    updated: now
                )
            } else if state?.total != header.chunkTotal {
                states.removeValue(forKey: key)
                return nil
            }

            guard var nextState = state else {
                return nil
            }
            if nextState.parts[header.chunkIndex] == nil {
                nextState.parts[header.chunkIndex] = Data(chunk)
                nextState.received += chunk.count
            }
            nextState.updated = now
            states[key] = nextState

            if nextState.parts.count < header.chunkTotal {
                return nil
            }

            var assembled = Data()
            for index in 0..<header.chunkTotal {
                guard let part = nextState.parts[index] else {
                    return nil
                }
                assembled.append(part)
            }
            states.removeValue(forKey: key)
            return assembled
        }

        func prune(now: TimeInterval = Date().timeIntervalSince1970) {
            let expired = states.keys.filter { key in
                guard let state = states[key] else {
                    return false
                }
                return (now - state.updated) >= ttlSeconds
            }
            for key in expired {
                states.removeValue(forKey: key)
            }
        }
    }

    private static let openMetaKeyOrder = ["name", "lifecycle_hooks", "options"]
    private static let serviceSpecKeyOrder = [
        "svc_id",
        "l_proto",
        "l_bind",
        "l_port",
        "r_proto",
        "r_host",
        "r_port",
        "name",
        "lifecycle_hooks",
        "options",
    ]

    static func packMux(
        chanID: Int,
        proto: Proto,
        counter: Int,
        mtype: MType,
        body: Data
    ) throws -> Data {
        guard (0...0xFFFF).contains(chanID) else {
            throw ObstacleBridgeChannelMuxCodecError.invalidChannelID
        }
        guard body.count <= 0xFFFF else {
            throw ObstacleBridgeChannelMuxCodecError.payloadTooLarge
        }
        var payload = Data()
        payload.appendUInt16(UInt16(chanID))
        payload.appendUInt8(UInt8(proto.rawValue))
        payload.appendUInt16(UInt16(counter & 0xFFFF))
        payload.appendUInt8(UInt8(mtype.rawValue))
        payload.appendUInt16(UInt16(body.count))
        payload.append(body)
        return payload
    }

    static func unpackMux(_ payload: Data) -> MuxFrame? {
        guard payload.count >= 8 else {
            return nil
        }
        var offset = 0
        guard
            let chanID = readUInt16(from: payload, offset: &offset),
            let protoRaw = readUInt8(from: payload, offset: &offset),
            let counter = readUInt16(from: payload, offset: &offset),
            let mtypeRaw = readUInt8(from: payload, offset: &offset),
            let declaredLength = readUInt16(from: payload, offset: &offset),
            payload.count >= offset + Int(declaredLength),
            let proto = Proto(rawValue: Int(protoRaw)),
            let mtype = MType(rawValue: Int(mtypeRaw))
        else {
            return nil
        }
        return MuxFrame(
            chanID: Int(chanID),
            proto: proto,
            counter: Int(counter),
            mtype: mtype,
            body: payload.subdata(in: offset..<(offset + Int(declaredLength)))
        )
    }

    static func buildOpenPayload(
        instanceID: UInt64,
        connectionSeq: UInt32,
        spec: ServiceSpec
    ) throws -> Data {
        let bindData = Data(spec.lBind.utf8)
        let hostData = Data(spec.rHost.utf8)
        guard bindData.count <= 0xFFFF, hostData.count <= 0xFFFF else {
            throw ObstacleBridgeChannelMuxCodecError.stringTooLarge
        }
        let metadata = JSONValue.object([
            "name": spec.name.map(JSONValue.string) ?? .null,
            "lifecycle_hooks": spec.lifecycleHooks.map(JSONValue.object) ?? .null,
            "options": spec.options.map(JSONValue.object) ?? .null,
        ])
        let metadataData = Data(
            canonicalJSONString(for: metadata, preferredKeyOrder: openMetaKeyOrder).utf8
        )

        var payload = Data()
        payload.append(Data("O5".utf8))
        payload.appendUInt64(instanceID)
        payload.appendUInt32(connectionSeq)
        payload.appendUInt16(UInt16(spec.svcID))
        payload.appendUInt8(protoCode(for: spec.lProto))
        payload.appendUInt16(UInt16(bindData.count))
        payload.append(bindData)
        payload.appendUInt16(UInt16(spec.lPort))
        payload.appendUInt8(protoCode(for: spec.rProto))
        payload.appendUInt16(UInt16(hostData.count))
        payload.append(hostData)
        payload.appendUInt16(UInt16(spec.rPort))
        payload.appendUInt32(UInt32(metadataData.count))
        payload.append(metadataData)
        return payload
    }

    static func parseOpenPayload(_ payload: Data) -> ParsedOpen? {
        if payload.starts(with: Data("O5".utf8)) {
            return parseOpenV5(payload)
        }
        if payload.starts(with: Data("O4".utf8)) {
            return parseOpenV4(payload)
        }
        return nil
    }

    static func encodeRemoteServicesSetV2(
        instanceID: UInt64,
        connectionSeq: UInt32,
        services: [ServiceSpec]
    ) throws -> Data {
        let rows = services.map {
            canonicalJSONString(for: serviceSpecJSON($0), preferredKeyOrder: serviceSpecKeyOrder)
        }
        let blob = Data("[\(rows.joined(separator: ","))]".utf8)
        var payload = Data()
        payload.append(Data("RS3".utf8))
        payload.appendUInt64(instanceID)
        payload.appendUInt32(connectionSeq)
        payload.appendUInt32(UInt32(blob.count))
        payload.append(blob)
        return payload
    }

    static func decodeRemoteServicesSetV2(_ payload: Data) -> (UInt64, UInt32, [ServiceSpec])? {
        if payload.starts(with: Data("RS3".utf8)) {
            return decodeRemoteServicesRS3(payload)
        }
        if payload.starts(with: Data("RS2".utf8)) {
            return decodeRemoteServicesRS2(payload)
        }
        return nil
    }

    static func nextControlChunkTxID(current: UInt32) -> (txID: UInt32, next: UInt32) {
        var txID = current & 0xFFFFFFFF
        if txID == 0 {
            txID = 1
        }
        let next = txID == 0xFFFFFFFF ? UInt32(1) : txID &+ 1
        return (txID, next)
    }

    static func chunkControlPayload(
        txID: UInt32,
        maxAppPayload: Int,
        payload: Data
    ) -> [Data] {
        let maxDataLength = max(0, maxAppPayload - muxHeaderSize)
        let chunkPayloadCap = maxDataLength - controlChunkHeaderSize
        guard chunkPayloadCap > 0 else {
            return []
        }
        let totalChunks = max(1, (payload.count + chunkPayloadCap - 1) / chunkPayloadCap)
        guard totalChunks <= 0xFFFF else {
            return []
        }

        var frames: [Data] = []
        frames.reserveCapacity(totalChunks)
        for index in 0..<totalChunks {
            let start = index * chunkPayloadCap
            let end = min(start + chunkPayloadCap, payload.count)
            let part = payload.subdata(in: start..<end)
            var frame = Data()
            frame.append(controlChunkMagic)
            frame.appendUInt32(txID)
            frame.appendUInt16(UInt16(index))
            frame.appendUInt16(UInt16(totalChunks))
            frame.append(part)
            frames.append(frame)
        }
        return frames
    }

    static func jsonValue(from object: Any) -> JSONValue? {
        if object is NSNull {
            return .null
        }
        if let string = object as? String {
            return .string(string)
        }
        if let number = object as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return .bool(number.boolValue)
            }
            let doubleValue = number.doubleValue
            if Double(number.int64Value) == doubleValue {
                return .integer(number.int64Value)
            }
            return .double(doubleValue)
        }
        if let array = object as? [Any] {
            return .array(array.compactMap(jsonValue(from:)))
        }
        if let dict = object as? [String: Any] {
            var converted: [String: JSONValue] = [:]
            for (key, value) in dict {
                guard let item = jsonValue(from: value) else {
                    return nil
                }
                converted[key] = item
            }
            return .object(converted)
        }
        return nil
    }

    static func foundationObject(from value: JSONValue) -> Any {
        switch value {
        case .object(let dict):
            return dict.mapValues(foundationObject(from:))
        case .array(let items):
            return items.map(foundationObject(from:))
        case .string(let string):
            return string
        case .integer(let value):
            return value
        case .double(let value):
            return value
        case .bool(let value):
            return value
        case .null:
            return NSNull()
        }
    }

    private static func parseOpenV5(_ payload: Data) -> ParsedOpen? {
        guard payload.count >= 25 else {
            return nil
        }
        var offset = 2
        guard
            let instanceID = readUInt64(from: payload, offset: &offset),
            let connectionSeq = readUInt32(from: payload, offset: &offset),
            let svcID = readUInt16(from: payload, offset: &offset),
            let lProto = readUInt8(from: payload, offset: &offset),
            let bindLength = readUInt16(from: payload, offset: &offset),
            let lBind = readString(from: payload, offset: &offset, length: Int(bindLength)),
            let lPort = readUInt16(from: payload, offset: &offset),
            let rProto = readUInt8(from: payload, offset: &offset),
            let hostLength = readUInt16(from: payload, offset: &offset),
            let rHost = readString(from: payload, offset: &offset, length: Int(hostLength)),
            let rPort = readUInt16(from: payload, offset: &offset),
            let metadataLength = readUInt32(from: payload, offset: &offset),
            let metadataData = readData(from: payload, offset: &offset, length: Int(metadataLength)),
            let metadataValue = parseJSONValue(metadataData)
        else {
            return nil
        }
        guard offset == payload.count else {
            return nil
        }
        let metadata = metadataValue.objectValue ?? [:]
        return ParsedOpen(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            spec: ServiceSpec(
                svcID: Int(svcID),
                lProto: protoName(for: Int(lProto)),
                lBind: lBind,
                lPort: Int(lPort),
                rProto: protoName(for: Int(rProto)),
                rHost: rHost,
                rPort: Int(rPort),
                name: metadata["name"]?.stringValue,
                lifecycleHooks: metadata["lifecycle_hooks"]?.objectValue,
                options: metadata["options"]?.objectValue
            )
        )
    }

    private static func parseOpenV4(_ payload: Data) -> ParsedOpen? {
        guard payload.count >= 21 else {
            return nil
        }
        var offset = 2
        guard
            let instanceID = readUInt64(from: payload, offset: &offset),
            let connectionSeq = readUInt32(from: payload, offset: &offset),
            let svcID = readUInt16(from: payload, offset: &offset),
            let lProto = readUInt8(from: payload, offset: &offset),
            let bindLength = readUInt8(from: payload, offset: &offset),
            let lBind = readString(from: payload, offset: &offset, length: Int(bindLength)),
            let lPort = readUInt16(from: payload, offset: &offset),
            let rProto = readUInt8(from: payload, offset: &offset),
            let hostLength = readUInt8(from: payload, offset: &offset),
            let rHost = readString(from: payload, offset: &offset, length: Int(hostLength)),
            let rPort = readUInt16(from: payload, offset: &offset)
        else {
            return nil
        }
        guard offset == payload.count else {
            return nil
        }
        return ParsedOpen(
            instanceID: instanceID,
            connectionSeq: connectionSeq,
            spec: ServiceSpec(
                svcID: Int(svcID),
                lProto: protoName(for: Int(lProto)),
                lBind: lBind,
                lPort: Int(lPort),
                rProto: protoName(for: Int(rProto)),
                rHost: rHost,
                rPort: Int(rPort),
                name: nil,
                lifecycleHooks: nil,
                options: nil
            )
        )
    }

    private static func decodeRemoteServicesRS3(_ payload: Data) -> (UInt64, UInt32, [ServiceSpec])? {
        guard payload.count >= 19 else {
            return nil
        }
        var offset = 3
        guard
            let instanceID = readUInt64(from: payload, offset: &offset),
            let connectionSeq = readUInt32(from: payload, offset: &offset),
            let blobLength = readUInt32(from: payload, offset: &offset),
            let blob = readData(from: payload, offset: &offset, length: Int(blobLength)),
            let jsonValue = parseJSONValue(blob),
            let rows = jsonValue.arrayValue
        else {
            return nil
        }
        guard offset == payload.count else {
            return nil
        }
        var services: [ServiceSpec] = []
        for row in rows {
            guard let service = serviceSpec(from: row.objectValue ?? [:]) else {
                return nil
            }
            services.append(service)
        }
        return (instanceID, connectionSeq, services)
    }

    private static func decodeRemoteServicesRS2(_ payload: Data) -> (UInt64, UInt32, [ServiceSpec])? {
        guard payload.count >= 17 else {
            return nil
        }
        var offset = 3
        guard
            let instanceID = readUInt64(from: payload, offset: &offset),
            let connectionSeq = readUInt32(from: payload, offset: &offset),
            let count = readUInt16(from: payload, offset: &offset)
        else {
            return nil
        }
        var services: [ServiceSpec] = []
        for _ in 0..<count {
            guard
                let svcID = readUInt16(from: payload, offset: &offset),
                let lProto = readUInt8(from: payload, offset: &offset),
                let bindLength = readUInt8(from: payload, offset: &offset),
                let lBind = readString(from: payload, offset: &offset, length: Int(bindLength)),
                let lPort = readUInt16(from: payload, offset: &offset),
                let rProto = readUInt8(from: payload, offset: &offset),
                let hostLength = readUInt8(from: payload, offset: &offset),
                let rHost = readString(from: payload, offset: &offset, length: Int(hostLength)),
                let rPort = readUInt16(from: payload, offset: &offset)
            else {
                return nil
            }
            services.append(
                ServiceSpec(
                    svcID: Int(svcID),
                    lProto: protoName(for: Int(lProto)),
                    lBind: lBind,
                    lPort: Int(lPort),
                    rProto: protoName(for: Int(rProto)),
                    rHost: rHost,
                    rPort: Int(rPort),
                    name: nil,
                    lifecycleHooks: nil,
                    options: nil
                )
            )
        }
        guard offset == payload.count else {
            return nil
        }
        return (instanceID, connectionSeq, services)
    }

    private static func serviceSpecJSON(_ spec: ServiceSpec) -> JSONValue {
        return .object([
            "svc_id": .integer(Int64(spec.svcID)),
            "l_proto": .string(spec.lProto),
            "l_bind": .string(spec.lBind),
            "l_port": .integer(Int64(spec.lPort)),
            "r_proto": .string(spec.rProto),
            "r_host": .string(spec.rHost),
            "r_port": .integer(Int64(spec.rPort)),
            "name": spec.name.map(JSONValue.string) ?? .null,
            "lifecycle_hooks": spec.lifecycleHooks.map(JSONValue.object) ?? .null,
            "options": spec.options.map(JSONValue.object) ?? .null,
        ])
    }

    static func sharedTunOwnershipSnapshot(for spec: ServiceSpec) -> JSONValue? {
        guard
            let options = spec.options,
            let shared = options["shared_tun_ownership"]?.objectValue,
            let peerValues = shared["peers"]?.arrayValue,
            !peerValues.isEmpty
        else {
            return nil
        }

        var peerRefs: [JSONValue] = []
        var peerObjects: [JSONValue] = []
        var ownerByIPv4: [String: JSONValue] = [:]
        var ownerByIPv6: [String: JSONValue] = [:]
        var addressCount = 0

        for peerValue in peerValues {
            guard let peerObject = peerValue.objectValue else {
                continue
            }
            let peerRef = peerObject["peer_ref"]?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !peerRef.isEmpty else {
                continue
            }
            let ipv4 = normalizedSharedTunAddressArray(peerObject["ipv4"]?.arrayValue, suffix: "/32")
            let ipv6 = normalizedSharedTunAddressArray(peerObject["ipv6"]?.arrayValue, suffix: "/128")
            for address in ipv4 {
                ownerByIPv4[address] = .string(peerRef)
            }
            for address in ipv6 {
                ownerByIPv6[address] = .string(peerRef)
            }
            let peerAddressCount = ipv4.count + ipv6.count
            addressCount += peerAddressCount
            peerRefs.append(.string(peerRef))
            peerObjects.append(
                .object([
                    "peer_ref": .string(peerRef),
                    "ipv4": .array(ipv4.map(JSONValue.string)),
                    "ipv6": .array(ipv6.map(JSONValue.string)),
                    "address_count": .integer(Int64(peerAddressCount)),
                ])
            )
        }

        guard !peerObjects.isEmpty else {
            return nil
        }
        return .object([
            "mode": .string(shared["mode"]?.stringValue ?? "server_shared"),
            "peer_count": .integer(Int64(peerObjects.count)),
            "address_count": .integer(Int64(addressCount)),
            "peer_refs": .array(peerRefs),
            "peers": .array(peerObjects),
            "owner_by_ipv4": .object(ownerByIPv4),
            "owner_by_ipv6": .object(ownerByIPv6),
        ])
    }

    private static func normalizedSharedTunAddressArray(
        _ rawValues: [JSONValue]?,
        suffix: String
    ) -> [String] {
        return (rawValues ?? []).compactMap { value in
            guard let raw = value.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
                return nil
            }
            if raw.hasSuffix(suffix) {
                return String(raw.dropLast(suffix.count))
            }
            return raw
        }
    }

    private static func serviceSpec(from object: [String: JSONValue]) -> ServiceSpec? {
        guard
            let svcID = object["svc_id"]?.intValue,
            let lProto = object["l_proto"]?.stringValue,
            let lBind = object["l_bind"]?.stringValue,
            let lPort = object["l_port"]?.intValue,
            let rProto = object["r_proto"]?.stringValue,
            let rHost = object["r_host"]?.stringValue,
            let rPort = object["r_port"]?.intValue
        else {
            return nil
        }
        return ServiceSpec(
            svcID: svcID,
            lProto: lProto,
            lBind: lBind,
            lPort: lPort,
            rProto: rProto,
            rHost: rHost,
            rPort: rPort,
            name: object["name"]?.stringValue,
            lifecycleHooks: object["lifecycle_hooks"]?.objectValue,
            options: object["options"]?.objectValue
        )
    }

    private static func parseJSONValue(_ data: Data) -> JSONValue? {
        guard let object = try? JSONSerialization.jsonObject(with: data, options: []) else {
            return nil
        }
        return jsonValue(from: object)
    }

    private static func parseControlChunkHeader(
        _ payload: Data
    ) -> (magic: Data, txID: UInt32, chunkIndex: Int, chunkTotal: Int)? {
        guard payload.count >= controlChunkHeaderSize else {
            return nil
        }
        var offset = 0
        guard
            let magic = readData(from: payload, offset: &offset, length: 4),
            let txID = readUInt32(from: payload, offset: &offset),
            let chunkIndex = readUInt16(from: payload, offset: &offset),
            let chunkTotal = readUInt16(from: payload, offset: &offset)
        else {
            return nil
        }
        return (magic, txID, Int(chunkIndex), Int(chunkTotal))
    }

    private static func protoCode(for name: String) -> UInt8 {
        switch name.lowercased() {
        case "udp":
            return UInt8(Proto.udp.rawValue)
        case "tcp":
            return UInt8(Proto.tcp.rawValue)
        case "tun":
            return UInt8(Proto.tun.rawValue)
        default:
            return UInt8.max
        }
    }

    private static func protoName(for code: Int) -> String {
        switch code {
        case Proto.udp.rawValue:
            return "udp"
        case Proto.tcp.rawValue:
            return "tcp"
        case Proto.tun.rawValue:
            return "tun"
        default:
            return ""
        }
    }

    private static func canonicalJSONString(
        for value: JSONValue,
        preferredKeyOrder: [String] = []
    ) -> String {
        switch value {
        case .object(let dict):
            let preferred = preferredKeyOrder.filter { dict[$0] != nil }
            let remaining = dict.keys.filter { !preferred.contains($0) }.sorted()
            let keys = preferred + remaining
            let parts = keys.map { key in
                let encodedKey = encodeJSONString(key)
                let encodedValue = canonicalJSONString(for: dict[key] ?? .null)
                return "\(encodedKey):\(encodedValue)"
            }
            return "{\(parts.joined(separator: ","))}"
        case .array(let items):
            return "[\(items.map { canonicalJSONString(for: $0) }.joined(separator: ","))]"
        case .string(let string):
            return encodeJSONString(string)
        case .integer(let value):
            return String(value)
        case .double(let value):
            if value.rounded(.towardZero) == value {
                return String(Int64(value))
            }
            return String(value)
        case .bool(let value):
            return value ? "true" : "false"
        case .null:
            return "null"
        }
    }

    private static func encodeJSONString(_ value: String) -> String {
        let payload = [value]
        let data = try? JSONSerialization.data(withJSONObject: payload, options: [])
        let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
        return String(text.dropFirst().dropLast())
    }

    private static func readUInt8(from data: Data, offset: inout Int) -> UInt8? {
        guard offset + 1 <= data.count else {
            return nil
        }
        let value = data[offset]
        offset += 1
        return value
    }

    private static func readUInt16(from data: Data, offset: inout Int) -> UInt16? {
        guard offset + 2 <= data.count else {
            return nil
        }
        let value = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
        offset += 2
        return value
    }

    private static func readUInt32(from data: Data, offset: inout Int) -> UInt32? {
        guard offset + 4 <= data.count else {
            return nil
        }
        let value = (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
        offset += 4
        return value
    }

    private static func readUInt64(from data: Data, offset: inout Int) -> UInt64? {
        guard offset + 8 <= data.count else {
            return nil
        }
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value << 8) | UInt64(data[offset + index])
        }
        offset += 8
        return value
    }

    private static func readData(from data: Data, offset: inout Int, length: Int) -> Data? {
        guard offset + length <= data.count else {
            return nil
        }
        let payload = data.subdata(in: offset..<(offset + length))
        offset += length
        return payload
    }

    private static func readString(from data: Data, offset: inout Int, length: Int) -> String? {
        guard let payload = readData(from: data, offset: &offset, length: length) else {
            return nil
        }
        return String(data: payload, encoding: .utf8)
    }
}

extension Data {
    mutating func appendUInt8(_ value: UInt8) {
        append(contentsOf: [value])
    }

    mutating func appendUInt16(_ value: UInt16) {
        let bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: bigEndian) { bytes in
            append(contentsOf: bytes)
        }
    }

    mutating func appendUInt32(_ value: UInt32) {
        let bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: bigEndian) { bytes in
            append(contentsOf: bytes)
        }
    }

    mutating func appendUInt64(_ value: UInt64) {
        let bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: bigEndian) { bytes in
            append(contentsOf: bytes)
        }
    }
}

private extension ObstacleBridgeChannelMuxCodec.JSONValue {
    var stringValue: String? {
        if case .string(let value) = self {
            return value
        }
        return nil
    }

    var intValue: Int? {
        switch self {
        case .integer(let value):
            return Int(value)
        case .double(let value):
            return Int(value)
        default:
            return nil
        }
    }

    var objectValue: [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
        if case .object(let value) = self {
            return value
        }
        return nil
    }

    var arrayValue: [ObstacleBridgeChannelMuxCodec.JSONValue]? {
        if case .array(let value) = self {
            return value
        }
        return nil
    }
}
