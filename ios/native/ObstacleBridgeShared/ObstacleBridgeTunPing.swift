import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum ObstacleBridgeTunPing {
    static let probeMagic = Data([0x4F, 0x42, 0x54, 0x50]) // OBTP
    static let probeKindPeer: UInt8 = 1
    static let probeKindGlobal: UInt8 = 2

    struct EchoReply {
        let family: Int32
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
                family: AF_INET,
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
                family: AF_INET6,
                sourceIP: sourceIP,
                destinationIP: destinationIP,
                identifier: (UInt16(payload[4]) << 8) | UInt16(payload[5]),
                sequence: (UInt16(payload[6]) << 8) | UInt16(payload[7]),
                payload: payload.subdata(in: 8..<payload.count)
            )
        }
        return nil
    }

    static func ipFamily(_ value: String) -> Int32? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if ipv4AddressBytes(trimmed) != nil {
            return AF_INET
        }
        if ipv6AddressBytes(trimmed) != nil {
            return AF_INET6
        }
        return nil
    }

    private static func ipv4AddressBytes(_ value: String) -> [UInt8]? {
        var addr = in_addr()
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else {
            return nil
        }
        var network = addr.s_addr
        return withUnsafeBytes(of: &network) { Array($0) }
    }

    private static func ipv6AddressBytes(_ value: String) -> [UInt8]? {
        var addr = in6_addr()
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else {
            return nil
        }
        return withUnsafeBytes(of: &addr.__u6_addr.__u6_addr8) { Array($0) }
    }

    private static func renderIPv4Address(_ data: Data) -> String? {
        guard data.count == 4 else {
            return nil
        }
        var storage: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &storage) { dst in
            data.copyBytes(to: dst)
        }
        var network = storage
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &network, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func renderIPv6Address(_ data: Data) -> String? {
        guard data.count == 16 else {
            return nil
        }
        var storage = in6_addr()
        _ = withUnsafeMutableBytes(of: &storage.__u6_addr.__u6_addr8) { dst in
            data.copyBytes(to: dst)
        }
        var network = storage
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &network, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }
}
