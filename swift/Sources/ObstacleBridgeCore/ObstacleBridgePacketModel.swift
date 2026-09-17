import Foundation

/// Bounded IP-packet and ChannelMux-fragment primitives shared by packet
/// adapters.  This layer deliberately has no packet-device, socket, route, or
/// platform address dependency.
public enum ObstacleBridgePacketModelError: Error, Equatable, Sendable {
    case emptyPacket
    case unsupportedVersion
    case malformedIPv4
    case malformedIPv6
    case invalidAddressLength
    case invalidFragment
}

public enum ObstacleBridgeIPVersion: UInt8, Sendable {
    case ipv4 = 4
    case ipv6 = 6
}

public struct ObstacleBridgeIPPacket: Equatable, Sendable {
    public let version: ObstacleBridgeIPVersion
    public let sourceAddress: Data
    public let destinationAddress: Data
    public let nextHeader: UInt8
    public let headerLength: Int
    public let totalLength: Int
    /// A terminal transport protocol that is safe to checksum after source
    /// replacement. Fragmented and opaque extension chains intentionally
    /// leave this nil.
    public let transportProtocol: UInt8?
    public let transportHeaderOffset: Int?

    public static func parse(_ bytes: Data) throws -> Self {
        guard let first = bytes.first else { throw ObstacleBridgePacketModelError.emptyPacket }
        switch first >> 4 {
        case ObstacleBridgeIPVersion.ipv4.rawValue:
            guard bytes.count >= 20 else { throw ObstacleBridgePacketModelError.malformedIPv4 }
            let headerLength = Int(first & 0x0F) * 4
            let totalLength = Int(bytes[2]) << 8 | Int(bytes[3])
            guard headerLength >= 20, totalLength >= headerLength, totalLength <= bytes.count else {
                throw ObstacleBridgePacketModelError.malformedIPv4
            }
            let fragmentation = Int(bytes[6]) << 8 | Int(bytes[7])
            let isFragmented = (fragmentation & 0x3FFF) != 0
            return .init(
                version: .ipv4,
                sourceAddress: bytes.subdata(in: 12..<16),
                destinationAddress: bytes.subdata(in: 16..<20),
                nextHeader: bytes[9],
                headerLength: headerLength,
                totalLength: totalLength,
                transportProtocol: isFragmented ? nil : bytes[9],
                transportHeaderOffset: isFragmented ? nil : headerLength
            )
        case ObstacleBridgeIPVersion.ipv6.rawValue:
            guard bytes.count >= 40 else { throw ObstacleBridgePacketModelError.malformedIPv6 }
            let payloadLength = Int(bytes[4]) << 8 | Int(bytes[5])
            let totalLength = 40 + payloadLength
            guard totalLength <= bytes.count else { throw ObstacleBridgePacketModelError.malformedIPv6 }
            let transport = try ipv6Transport(bytes: [UInt8](bytes), packetEnd: totalLength)
            return .init(
                version: .ipv6,
                sourceAddress: bytes.subdata(in: 8..<24),
                destinationAddress: bytes.subdata(in: 24..<40),
                nextHeader: transport.protocol,
                headerLength: transport.offset,
                totalLength: totalLength,
                transportProtocol: transport.repairable ? transport.protocol : nil,
                transportHeaderOffset: transport.repairable ? transport.offset : nil
            )
        default:
            throw ObstacleBridgePacketModelError.unsupportedVersion
        }
    }

    public static func replacingSource(in bytes: Data, with address: Data) throws -> Data {
        let packet = try parse(bytes)
        let range: Range<Int>
        switch packet.version {
        case .ipv4:
            guard address.count == 4 else { throw ObstacleBridgePacketModelError.invalidAddressLength }
            range = 12..<16
        case .ipv6:
            guard address.count == 16 else { throw ObstacleBridgePacketModelError.invalidAddressLength }
            range = 8..<24
        }
        var result = bytes
        result.replaceSubrange(range, with: address)
        return result
    }

    /// Replaces a source address and repairs the IPv4 header plus ICMP, TCP,
    /// or UDP checksum when Core can locate a complete transport payload.
    /// IPv6 Hop-by-Hop, Routing, Destination Options, and Authentication
    /// extension headers are traversed. Fragmented and opaque payloads retain
    /// their original transport checksum because no complete payload is
    /// available for recomputation.
    public static func replacingSourceAndRepairingChecksums(in bytes: Data, with address: Data) throws -> Data {
        let packet = try parse(bytes)
        guard packet.sourceAddress != address else { return bytes }
        var result = [UInt8](try replacingSource(in: bytes, with: address))
        let packetEnd = packet.totalLength
        switch packet.version {
        case .ipv4:
            result[10] = 0
            result[11] = 0
            let headerChecksum = internetChecksum(Data(result[0..<packet.headerLength]))
            result[10] = UInt8(headerChecksum >> 8)
            result[11] = UInt8(headerChecksum & 0xFF)
            repairIPv4TransportChecksum(&result, packet: packet, packetEnd: packetEnd)
        case .ipv6:
            repairIPv6TransportChecksum(&result, packet: packet, packetEnd: packetEnd)
        }
        return Data(result)
    }

    public static func internetChecksum(_ bytes: Data) -> UInt16 {
        let values = [UInt8](bytes)
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < values.count {
            sum &+= UInt32(values[index]) << 8 | UInt32(values[index + 1])
            index += 2
        }
        if index < values.count { sum &+= UInt32(values[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }

    private static func repairIPv4TransportChecksum(_ bytes: inout [UInt8], packet: ObstacleBridgeIPPacket, packetEnd: Int) {
        guard let transportProtocol = packet.transportProtocol,
              let payloadStart = packet.transportHeaderOffset else { return }
        let checksumOffset: Int
        let zeroMeansFFFF: Bool
        switch transportProtocol {
        case 1: checksumOffset = 2; zeroMeansFFFF = false
        case 6: checksumOffset = 16; zeroMeansFFFF = false
        case 17: checksumOffset = 6; zeroMeansFFFF = true
        default: return
        }
        let payloadLength = packetEnd - payloadStart
        guard payloadLength > checksumOffset + 1 else { return }
        let checksumIndex = payloadStart + checksumOffset
        bytes[checksumIndex] = 0
        bytes[checksumIndex + 1] = 0
        var covered = [UInt8]()
        if transportProtocol == 1 {
            covered.append(contentsOf: bytes[payloadStart..<packetEnd])
        } else {
            covered.append(contentsOf: bytes[12..<16])
            covered.append(contentsOf: bytes[16..<20])
            covered.append(0)
            covered.append(transportProtocol)
            covered.append(UInt8(payloadLength >> 8))
            covered.append(UInt8(payloadLength & 0xFF))
            covered.append(contentsOf: bytes[payloadStart..<packetEnd])
        }
        var checksum = internetChecksum(Data(covered))
        if zeroMeansFFFF && checksum == 0 { checksum = 0xFFFF }
        bytes[checksumIndex] = UInt8(checksum >> 8)
        bytes[checksumIndex + 1] = UInt8(checksum & 0xFF)
    }

    private static func repairIPv6TransportChecksum(_ bytes: inout [UInt8], packet: ObstacleBridgeIPPacket, packetEnd: Int) {
        guard let transportProtocol = packet.transportProtocol,
              let payloadStart = packet.transportHeaderOffset else { return }
        let checksumOffset: Int
        let zeroMeansFFFF: Bool
        switch transportProtocol {
        case 6: checksumOffset = 16; zeroMeansFFFF = false
        case 17: checksumOffset = 6; zeroMeansFFFF = true
        case 58: checksumOffset = 2; zeroMeansFFFF = false
        default: return
        }
        let payloadLength = packetEnd - payloadStart
        guard payloadLength > checksumOffset + 1 else { return }
        let checksumIndex = payloadStart + checksumOffset
        bytes[checksumIndex] = 0
        bytes[checksumIndex + 1] = 0
        var covered = [UInt8]()
        covered.append(contentsOf: bytes[8..<24])
        covered.append(contentsOf: bytes[24..<40])
        covered.append(UInt8(payloadLength >> 24))
        covered.append(UInt8(payloadLength >> 16))
        covered.append(UInt8(payloadLength >> 8))
        covered.append(UInt8(payloadLength & 0xFF))
        covered.append(0)
        covered.append(0)
        covered.append(0)
        covered.append(transportProtocol)
        covered.append(contentsOf: bytes[payloadStart..<packetEnd])
        var checksum = internetChecksum(Data(covered))
        if zeroMeansFFFF && checksum == 0 { checksum = 0xFFFF }
        bytes[checksumIndex] = UInt8(checksum >> 8)
        bytes[checksumIndex + 1] = UInt8(checksum & 0xFF)
    }

    private static func ipv6Transport(bytes: [UInt8], packetEnd: Int) throws -> (protocol: UInt8, offset: Int, repairable: Bool) {
        var nextHeader = bytes[6]
        var offset = 40
        var headersSeen = 0
        while true {
            guard headersSeen < 8 else { throw ObstacleBridgePacketModelError.malformedIPv6 }
            switch nextHeader {
            case 0, 43, 60:
                guard offset + 2 <= packetEnd else { throw ObstacleBridgePacketModelError.malformedIPv6 }
                let extensionLength = (Int(bytes[offset + 1]) + 1) * 8
                guard extensionLength >= 8, offset + extensionLength <= packetEnd else {
                    throw ObstacleBridgePacketModelError.malformedIPv6
                }
                nextHeader = bytes[offset]
                offset += extensionLength
                headersSeen += 1
            case 51:
                guard offset + 2 <= packetEnd else { throw ObstacleBridgePacketModelError.malformedIPv6 }
                let extensionLength = (Int(bytes[offset + 1]) + 2) * 4
                guard extensionLength >= 8, offset + extensionLength <= packetEnd else {
                    throw ObstacleBridgePacketModelError.malformedIPv6
                }
                nextHeader = bytes[offset]
                offset += extensionLength
                headersSeen += 1
            case 44:
                guard offset + 8 <= packetEnd else { throw ObstacleBridgePacketModelError.malformedIPv6 }
                let fragmentBits = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
                let isFragmented = (fragmentBits & 0xFFF9) != 0
                nextHeader = bytes[offset]
                offset += 8
                return (nextHeader, offset, !isFragmented)
            case 50, 59:
                return (nextHeader, offset, false)
            default:
                return (nextHeader, offset, true)
            }
        }
    }
}

/// The eight-byte ChannelMux fragment header and a bounded, deterministic
/// reassembler.  The owner supplies the channel identifier so equal fragment
/// IDs from separate channels cannot collide.
public struct ObstacleBridgePacketFragment: Equatable, Sendable {
    public let datagramID: UInt32
    public let totalLength: UInt16
    public let offset: UInt16
    public let payload: Data

    public init(datagramID: UInt32, totalLength: UInt16, offset: UInt16, payload: Data) {
        self.datagramID = datagramID
        self.totalLength = totalLength
        self.offset = offset
        self.payload = payload
    }

    public init(wire: Data) throws {
        guard wire.count >= 8 else { throw ObstacleBridgePacketModelError.invalidFragment }
        self.init(
            datagramID: UInt32(wire[0]) << 24 | UInt32(wire[1]) << 16 | UInt32(wire[2]) << 8 | UInt32(wire[3]),
            totalLength: UInt16(wire[4]) << 8 | UInt16(wire[5]),
            offset: UInt16(wire[6]) << 8 | UInt16(wire[7]),
            payload: wire.subdata(in: 8..<wire.count)
        )
        guard totalLength > 0, offset < totalLength, !payload.isEmpty,
              Int(offset) + payload.count <= Int(totalLength) else {
            throw ObstacleBridgePacketModelError.invalidFragment
        }
    }

    public var wire: Data {
        var output = Data([
            UInt8((datagramID >> 24) & 0xFF), UInt8((datagramID >> 16) & 0xFF),
            UInt8((datagramID >> 8) & 0xFF), UInt8(datagramID & 0xFF),
            UInt8((totalLength >> 8) & 0xFF), UInt8(totalLength & 0xFF),
            UInt8((offset >> 8) & 0xFF), UInt8(offset & 0xFF),
        ])
        output.append(payload)
        return output
    }

    public static func fragment(_ packet: Data, datagramID: UInt32, maximumPayload: Int) throws -> [Self] {
        guard !packet.isEmpty, packet.count <= Int(UInt16.max), maximumPayload > 0 else {
            throw ObstacleBridgePacketModelError.invalidFragment
        }
        return stride(from: 0, to: packet.count, by: maximumPayload).map { offset in
            let end = min(packet.count, offset + maximumPayload)
            return .init(datagramID: datagramID, totalLength: UInt16(packet.count), offset: UInt16(offset), payload: packet.subdata(in: offset..<end))
        }
    }
}

public enum ObstacleBridgePacketReassemblyResult: Equatable, Sendable {
    case pending
    case complete(Data)
    case rejected
}

public final class ObstacleBridgePacketReassembler: @unchecked Sendable {
    private struct Key: Hashable { let channelID: UInt16; let datagramID: UInt32 }
    private struct State { let totalLength: Int; var parts: [Int: Data]; var received: Int }
    private let maximumDatagrams: Int
    private let maximumPacketLength: Int
    private var states: [Key: State] = [:]

    public init(maximumDatagrams: Int = 32, maximumPacketLength: Int = Int(UInt16.max)) {
        self.maximumDatagrams = max(1, maximumDatagrams)
        self.maximumPacketLength = max(1, min(maximumPacketLength, Int(UInt16.max)))
    }

    public func consume(channelID: UInt16, wire: Data) -> ObstacleBridgePacketReassemblyResult {
        guard let fragment = try? ObstacleBridgePacketFragment(wire: wire), Int(fragment.totalLength) <= maximumPacketLength else {
            return .rejected
        }
        let key = Key(channelID: channelID, datagramID: fragment.datagramID)
        guard var state = states[key] ?? (states.count < maximumDatagrams ? State(totalLength: Int(fragment.totalLength), parts: [:], received: 0) : nil),
              state.totalLength == Int(fragment.totalLength) else {
            states.removeValue(forKey: key)
            return .rejected
        }
        let offset = Int(fragment.offset)
        if let existing = state.parts[offset] {
            guard existing == fragment.payload else { states.removeValue(forKey: key); return .rejected }
        } else {
            for (existingOffset, existingPayload) in state.parts where offset < existingOffset + existingPayload.count && existingOffset < offset + fragment.payload.count {
                states.removeValue(forKey: key)
                return .rejected
            }
            state.parts[offset] = fragment.payload
            state.received += fragment.payload.count
        }
        guard state.received <= state.totalLength else { states.removeValue(forKey: key); return .rejected }
        guard state.received == state.totalLength else { states[key] = state; return .pending }
        var output = Data()
        for (offset, payload) in state.parts.sorted(by: { $0.key < $1.key }) {
            guard output.count == offset else { states.removeValue(forKey: key); return .rejected }
            output.append(payload)
        }
        states.removeValue(forKey: key)
        return output.count == state.totalLength ? .complete(output) : .rejected
    }

    public func withdraw(channelID: UInt16) {
        states = states.filter { $0.key.channelID != channelID }
    }

    public func reset() {
        states.removeAll(keepingCapacity: true)
    }

    public func receivedBytes(channelID: UInt16, datagramID: UInt32) -> Int {
        states[Key(channelID: channelID, datagramID: datagramID)]?.received ?? 0
    }
}

/// Portable lifecycle state for one logical TUN endpoint. Packet-device
/// adapters provide I/O only; they ask this state object which ChannelMux
/// channel is active and feed lifecycle events back into it.
public final class ObstacleBridgeTunChannelState: @unchecked Sendable {
    private var boundChannelIDs: Set<Int> = []
    private var preferredChannelID: Int?

    public init() {}

    public var preferredChannel: Int? { preferredChannelID }
    public var channels: [Int] { boundChannelIDs.sorted() }

    public func isBound(_ channelID: Int) -> Bool {
        boundChannelIDs.contains(channelID)
    }

    public func bind(_ channelID: Int) {
        guard (1...Int(UInt16.max)).contains(channelID) else { return }
        boundChannelIDs.insert(channelID)
        if preferredChannelID == nil {
            preferredChannelID = channelID
        }
    }

    @discardableResult
    public func close(_ channelID: Int) -> Bool {
        guard boundChannelIDs.remove(channelID) != nil else { return false }
        if preferredChannelID == channelID {
            preferredChannelID = boundChannelIDs.sorted().first
        }
        return true
    }

    public func reset() {
        boundChannelIDs.removeAll(keepingCapacity: true)
        preferredChannelID = nil
    }
}

public struct ObstacleBridgeTunPeerBinding: Equatable, Sendable {
    public var peerID: Int
    public var preferredChannelID: Int?
    public var channelIDs: [Int]

    public init(peerID: Int, preferredChannelID: Int?, channelIDs: [Int]) {
        self.peerID = peerID
        self.channelIDs = Array(Set(channelIDs.filter { (1...Int(UInt16.max)).contains($0) })).sorted()
        self.preferredChannelID = self.channelIDs.contains(preferredChannelID ?? -1)
            ? preferredChannelID
            : self.channelIDs.first
    }
}

public struct ObstacleBridgeTunPeerBindingCleanup: Equatable, Sendable {
    public let bindings: [ObstacleBridgeTunPeerBinding]
    public let peerReferenceByID: [Int: String]
    public let peerIDByReference: [String: Int]
}

/// Deterministic binding and disconnect cleanup rules for a shared logical
/// TUN. Native adapters retain their peer handles and packet-device callbacks.
public enum ObstacleBridgeTunPeerBindingPolicy {
    public static func apply(
        initialBindings: [ObstacleBridgeTunPeerBinding],
        operations: [(peerID: Int, channelID: Int, drop: Bool)]
    ) -> [ObstacleBridgeTunPeerBinding] {
        var states = Dictionary(uniqueKeysWithValues: initialBindings.map {
            ($0.peerID, ObstacleBridgeTunPeerBinding(peerID: $0.peerID, preferredChannelID: $0.preferredChannelID, channelIDs: $0.channelIDs))
        })
        for operation in operations {
            if operation.drop {
                guard let state = states[operation.peerID] else { continue }
                let remaining = state.channelIDs.filter { $0 != operation.channelID }
                if remaining.isEmpty {
                    states.removeValue(forKey: operation.peerID)
                } else {
                    states[operation.peerID] = .init(peerID: operation.peerID, preferredChannelID: state.preferredChannelID, channelIDs: remaining)
                }
                continue
            }
            let existing = states[operation.peerID]
            states[operation.peerID] = .init(
                peerID: operation.peerID,
                preferredChannelID: existing?.preferredChannelID,
                channelIDs: (existing?.channelIDs ?? []) + [operation.channelID]
            )
        }
        return states.values.sorted { $0.peerID < $1.peerID }
    }

    public static func cleanup(
        bindings: [ObstacleBridgeTunPeerBinding],
        peerReferenceByID: [Int: String],
        peerIDByReference: [String: Int],
        disconnectedPeerID: Int
    ) -> ObstacleBridgeTunPeerBindingCleanup {
        let remainingReferences = peerReferenceByID.filter { $0.key != disconnectedPeerID }
        var remainingIDs = peerIDByReference
        for (peerID, reference) in peerReferenceByID where peerID == disconnectedPeerID {
            if remainingIDs[reference] == disconnectedPeerID {
                remainingIDs.removeValue(forKey: reference)
            }
        }
        return .init(
            bindings: bindings.filter { $0.peerID != disconnectedPeerID }.sorted { $0.peerID < $1.peerID },
            peerReferenceByID: remainingReferences,
            peerIDByReference: remainingIDs
        )
    }
}
