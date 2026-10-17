// Packet construction and parsing are portable; packet-device I/O stays in
// the platform adapter that invokes this Core policy.
import Foundation

enum ObstacleBridgeTunPing {
    static let probeMagic = Data([0x4F, 0x42, 0x54, 0x50]) // OBTP
    static let probeKindPeer: UInt8 = 1
    static let probeKindGlobal: UInt8 = 2

    enum Family {
        case ipv4
        case ipv6
    }

    struct EchoReply {
        let family: Family
        let sourceIP: String
        let destinationIP: String
        let identifier: UInt16
        let sequence: UInt16
        let payload: Data
    }

    static func checksum16(_ payload: Data) -> UInt16 {
        var bytes = [UInt8](payload)
        if (bytes.count % 2) != 0 {
            bytes.append(0)
        }
        var total: UInt32 = 0
        var index = 0
        while index < bytes.count {
            total += (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            total = (total & 0xFFFF) + (total >> 16)
            index += 2
        }
        while (total >> 16) != 0 {
            total = (total & 0xFFFF) + (total >> 16)
        }
        return UInt16((~total) & 0xFFFF)
    }

    static func probePayload(probeKind: UInt8, nonce: Data, sentMonotonicNS: UInt64) -> Data {
        let safeNonce = Data(nonce.prefix(8)) + Data(repeating: 0, count: max(0, 8 - nonce.count))
        var payload = Data()
        payload.append(probeMagic)
        payload.append(probeKind)
        payload.append(safeNonce.prefix(8))
        var sent = sentMonotonicNS.bigEndian
        withUnsafeBytes(of: &sent) { payload.append(contentsOf: $0) }
        return payload
    }

    static func buildIPv4EchoRequest(
        sourceIP: String,
        destinationIP: String,
        identifier: UInt16,
        sequence: UInt16,
        payload: Data,
        ttl: UInt8 = 64,
        ipIdentification: UInt16 = 0
    ) -> Data? {
        guard let src = ipv4AddressBytes(sourceIP),
              let dst = ipv4AddressBytes(destinationIP) else {
            return nil
        }
        var icmp = [UInt8](repeating: 0, count: 8 + payload.count)
        icmp[0] = 8
        icmp[1] = 0
        icmp[4] = UInt8((identifier >> 8) & 0xFF)
        icmp[5] = UInt8(identifier & 0xFF)
        icmp[6] = UInt8((sequence >> 8) & 0xFF)
        icmp[7] = UInt8(sequence & 0xFF)
        let payloadBytes = [UInt8](payload)
        if !payloadBytes.isEmpty {
            icmp.replaceSubrange(8..<(8 + payloadBytes.count), with: payloadBytes)
        }
        let icmpChecksum = checksum16(Data(icmp))
        icmp[2] = UInt8((icmpChecksum >> 8) & 0xFF)
        icmp[3] = UInt8(icmpChecksum & 0xFF)

        let totalLength = UInt16(20 + icmp.count)
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x45
        header[2] = UInt8((totalLength >> 8) & 0xFF)
        header[3] = UInt8(totalLength & 0xFF)
        header[4] = UInt8((ipIdentification >> 8) & 0xFF)
        header[5] = UInt8(ipIdentification & 0xFF)
        header[8] = max(1, ttl)
        header[9] = 1
        header.replaceSubrange(12..<16, with: src)
        header.replaceSubrange(16..<20, with: dst)
        let headerChecksum = checksum16(Data(header))
        header[10] = UInt8((headerChecksum >> 8) & 0xFF)
        header[11] = UInt8(headerChecksum & 0xFF)
        return Data(header + icmp)
    }

    static func buildIPv6EchoRequest(
        sourceIP: String,
        destinationIP: String,
        identifier: UInt16,
        sequence: UInt16,
        payload: Data,
        hopLimit: UInt8 = 64
    ) -> Data? {
        guard let src = ipv6AddressBytes(sourceIP),
              let dst = ipv6AddressBytes(destinationIP) else {
            return nil
        }
        var icmp = [UInt8](repeating: 0, count: 8 + payload.count)
        icmp[0] = 128
        icmp[1] = 0
        icmp[4] = UInt8((identifier >> 8) & 0xFF)
        icmp[5] = UInt8(identifier & 0xFF)
        icmp[6] = UInt8((sequence >> 8) & 0xFF)
        icmp[7] = UInt8(sequence & 0xFF)
        let payloadBytes = [UInt8](payload)
        if !payloadBytes.isEmpty {
            icmp.replaceSubrange(8..<(8 + payloadBytes.count), with: payloadBytes)
        }
        var pseudo = Data(src)
        pseudo.append(contentsOf: dst)
        var length = UInt32(icmp.count).bigEndian
        withUnsafeBytes(of: &length) { pseudo.append(contentsOf: $0) }
        pseudo.append(Data(repeating: 0, count: 3))
        pseudo.append(58)
        pseudo.append(contentsOf: icmp)
        let icmpChecksum = checksum16(pseudo)
        icmp[2] = UInt8((icmpChecksum >> 8) & 0xFF)
        icmp[3] = UInt8(icmpChecksum & 0xFF)

        var header = [UInt8](repeating: 0, count: 40)
        header[0] = 0x60
        let payloadLength = UInt16(icmp.count)
        header[4] = UInt8((payloadLength >> 8) & 0xFF)
        header[5] = UInt8(payloadLength & 0xFF)
        header[6] = 58
        header[7] = max(1, hopLimit)
        header.replaceSubrange(8..<24, with: src)
        header.replaceSubrange(24..<40, with: dst)
        return Data(header + icmp)
    }

    static func parseEchoReply(_ packet: Data) -> EchoReply? {
        guard let first = packet.first else {
            return nil
        }
        let version = Int((first >> 4) & 0x0F)
        if version == 4 {
            guard packet.count >= 28 else {
                return nil
            }
            let ihl = Int(packet[0] & 0x0F) * 4
            guard ihl >= 20, packet.count >= (ihl + 8), packet[9] == 1 else {
                return nil
            }
            let payload = packet.subdata(in: ihl..<packet.count)
            guard payload.count >= 8, payload[0] == 0, payload[1] == 0 else {
                return nil
            }
            guard let sourceIP = renderIPv4Address(packet.subdata(in: 12..<16)),
                  let destinationIP = renderIPv4Address(packet.subdata(in: 16..<20)) else {
                return nil
            }
            return EchoReply(
                family: .ipv4,
                sourceIP: sourceIP,
                destinationIP: destinationIP,
                identifier: (UInt16(payload[4]) << 8) | UInt16(payload[5]),
                sequence: (UInt16(payload[6]) << 8) | UInt16(payload[7]),
                payload: payload.subdata(in: 8..<payload.count)
            )
        }
        if version == 6 {
            guard packet.count >= 48, packet[6] == 58 else {
                return nil
            }
            let payload = packet.subdata(in: 40..<packet.count)
            guard payload.count >= 8, payload[0] == 129, payload[1] == 0 else {
                return nil
            }
            guard let sourceIP = renderIPv6Address(packet.subdata(in: 8..<24)),
                  let destinationIP = renderIPv6Address(packet.subdata(in: 24..<40)) else {
                return nil
            }
            return EchoReply(
                family: .ipv6,
                sourceIP: sourceIP,
                destinationIP: destinationIP,
                identifier: (UInt16(payload[4]) << 8) | UInt16(payload[5]),
                sequence: (UInt16(payload[6]) << 8) | UInt16(payload[7]),
                payload: payload.subdata(in: 8..<payload.count)
            )
        }
        return nil
    }

    static func ipFamily(_ value: String) -> Family? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if ipv4AddressBytes(trimmed) != nil {
            return .ipv4
        }
        if ipv6AddressBytes(trimmed) != nil {
            return .ipv6
        }
        return nil
    }

    private static func ipv4AddressBytes(_ value: String) -> [UInt8]? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let components = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else {
            return nil
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(4)
        for component in components {
            guard !component.isEmpty, let byte = UInt8(component) else {
                return nil
            }
            bytes.append(byte)
        }
        return bytes
    }

    private static func ipv6AddressBytes(_ value: String) -> [UInt8]? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("%") else {
            return nil
        }
        let halves = trimmed.components(separatedBy: "::")
        guard halves.count <= 2 else {
            return nil
        }
        let hasCompression = halves.count == 2
        let leading = ipv6Groups(halves[0], permitsIPv4Tail: !hasCompression)
        let trailing = hasCompression ? ipv6Groups(halves[1], permitsIPv4Tail: true) : []
        guard let leading, let trailing else {
            return nil
        }
        let groupCount = leading.count + trailing.count
        guard (hasCompression && groupCount < 8) || (!hasCompression && groupCount == 8) else {
            return nil
        }
        let groups = leading + Array(repeating: 0, count: 8 - groupCount) + trailing
        return groups.flatMap { group in [UInt8(group >> 8), UInt8(group & 0xFF)] }
    }

    private static func renderIPv4Address(_ data: Data) -> String? {
        guard data.count == 4 else {
            return nil
        }
        return data.map(String.init).joined(separator: ".")
    }

    private static func renderIPv6Address(_ data: Data) -> String? {
        guard data.count == 16 else {
            return nil
        }
        let bytes = [UInt8](data)
        let groups = stride(from: 0, to: bytes.count, by: 2).map {
            (UInt16(bytes[$0]) << 8) | UInt16(bytes[$0 + 1])
        }
        var bestStart: Int?
        var bestLength = 0
        var index = 0
        while index < groups.count {
            guard groups[index] == 0 else {
                index += 1
                continue
            }
            let start = index
            while index < groups.count, groups[index] == 0 {
                index += 1
            }
            let length = index - start
            if length >= 2, length > bestLength {
                bestStart = start
                bestLength = length
            }
        }
        guard let bestStart else {
            return groups.map { String($0, radix: 16) }.joined(separator: ":")
        }
        let left = groups[..<bestStart].map { String($0, radix: 16) }.joined(separator: ":")
        let right = groups[(bestStart + bestLength)...].map { String($0, radix: 16) }.joined(separator: ":")
        return left + "::" + right
    }

    private static func ipv6Groups(_ text: String, permitsIPv4Tail: Bool) -> [UInt16]? {
        guard !text.isEmpty else { return [] }
        let tokens = text.split(separator: ":", omittingEmptySubsequences: false)
        guard !tokens.contains(where: { $0.isEmpty }) else { return nil }
        var groups: [UInt16] = []
        for (index, token) in tokens.enumerated() {
            if token.contains(".") {
                guard permitsIPv4Tail, index == tokens.count - 1,
                      let ipv4 = ipv4AddressBytes(String(token)) else {
                    return nil
                }
                groups.append((UInt16(ipv4[0]) << 8) | UInt16(ipv4[1]))
                groups.append((UInt16(ipv4[2]) << 8) | UInt16(ipv4[3]))
            } else {
                guard token.count <= 4, let group = UInt16(token, radix: 16) else {
                    return nil
                }
                groups.append(group)
            }
        }
        return groups
    }
}
