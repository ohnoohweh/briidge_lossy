import Foundation

public final class ObstacleBridgePeerAddressProtocolRuntime {
    public struct InboundSnapshot {
        public let consumed: Bool
        public let emittedFrames: [Data]
    }

    private static let magic = Data([0x4f, 0x42, 0x50, 0x41]) // OBPA
    private static let version: UInt8 = 2
    private static let typeRequest: UInt8 = 1
    private static let typeReply: UInt8 = 2
    private static let headerSize = 7

    private let clientMode: Bool
    private(set) var observedPublicIP = ""
    private(set) var observedPublicPort: Int?
    private var requestSent = false

    public init(clientMode: Bool) {
        self.clientMode = clientMode
    }

    public func handleTransportConnected() -> [Data] {
        guard clientMode, !requestSent else { return [] }
        requestSent = true
        return [Self.header(type: Self.typeRequest, family: 0)]
    }

    public func handleTransportDisconnected() {
        requestSent = false
        observedPublicIP = ""
        observedPublicPort = nil
    }

    public func handleInboundFrame(
        _ payload: Data,
        observedPeerHost: String? = nil,
        observedPeerPort: Int? = nil
    ) -> InboundSnapshot {
        guard payload.count >= Self.headerSize,
              payload.prefix(4) == Self.magic,
              payload[4] == Self.version
        else {
            return InboundSnapshot(consumed: false, emittedFrames: [])
        }
        let frameType = payload[5]
        let family = payload[6]
        let body = Data(payload.dropFirst(Self.headerSize))
        if frameType == Self.typeRequest, family == 0, body.isEmpty, !clientMode {
            guard let host = observedPeerHost,
                  let port = observedPeerPort,
                  (1...65535).contains(port),
                  let encoded = Self.encodeAddress(host)
            else {
                return InboundSnapshot(consumed: true, emittedFrames: [])
            }
            return InboundSnapshot(
                consumed: true,
                emittedFrames: [Self.header(type: Self.typeReply, family: encoded.family) + encoded.bytes + Self.encodePort(port)]
            )
        }
        if frameType == Self.typeReply, clientMode,
           let decoded = Self.decodeEndpoint(family: family, bytes: body) {
            observedPublicIP = decoded.host
            observedPublicPort = decoded.port
            return InboundSnapshot(consumed: true, emittedFrames: [])
        }
        return InboundSnapshot(consumed: false, emittedFrames: [])
    }

    private static func header(type: UInt8, family: UInt8) -> Data {
        magic + Data([version, type, family])
    }

    private static func encodePort(_ port: Int) -> Data {
        let networkPort = UInt16(port).bigEndian
        return withUnsafeBytes(of: networkPort) { Data($0) }
    }

    private static func encodeAddress(_ rawHost: String) -> (family: UInt8, bytes: Data)? {
        let host = rawHost.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawHost
        if let ipv4 = ipv4Bytes(host) { return (4, ipv4) }
        guard let ipv6 = ipv6Bytes(host) else { return nil }
        // Dual-stack listeners represent IPv4 clients as ::ffff:a.b.c.d.
        if ipv6.prefix(10).allSatisfy({ $0 == 0 }), ipv6[10] == 0xff, ipv6[11] == 0xff {
            return (4, Data(ipv6.suffix(4)))
        }
        return (6, ipv6)
    }

    private static func decodeEndpoint(family: UInt8, bytes: Data) -> (host: String, port: Int)? {
        let expectedSize = family == 4 ? 4 : family == 6 ? 16 : 0
        guard expectedSize > 0, bytes.count == expectedSize + 2 else { return nil }
        let addressBytes = Data(bytes.prefix(expectedSize))
        let host: String?
        if family == 4 {
            host = addressBytes.map(String.init).joined(separator: ".")
        } else {
            host = ipv6Text(addressBytes)
        }
        guard let host else { return nil }
        let portBytes = bytes.suffix(2)
        let port = portBytes.reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
        guard port > 0 else { return nil }
        return (host, Int(port))
    }

    private static func ipv4Bytes(_ host: String) -> Data? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isNumber }),
                  let value = UInt8(part), String(value) == part || (part == "0") else { return nil }
            bytes.append(value)
        }
        return Data(bytes)
    }

    private static func ipv6Bytes(_ host: String) -> Data? {
        guard !host.isEmpty, host.filter({ $0 == ":" }).count >= 2 else { return nil }
        let hasCompression = host.contains("::")
        guard !host.contains(":::") else { return nil }
        func parse(_ side: Substring?) -> [UInt16]? {
            guard let side, !side.isEmpty else { return [] }
            var groups: [UInt16] = []
            let pieces = side.split(separator: ":", omittingEmptySubsequences: false)
            for (index, piece) in pieces.enumerated() {
                guard !piece.isEmpty else { return nil }
                if piece.contains(".") {
                    guard index == pieces.count - 1, let ipv4 = ipv4Bytes(String(piece)) else { return nil }
                    groups += [UInt16(ipv4[0]) << 8 | UInt16(ipv4[1]), UInt16(ipv4[2]) << 8 | UInt16(ipv4[3])]
                } else {
                    guard piece.count <= 4, let value = UInt16(piece, radix: 16) else { return nil }
                    groups.append(value)
                }
            }
            return groups
        }
        let split = host.components(separatedBy: "::")
        guard split.count <= 2, let left = parse(split.first.map { $0[...] }),
              let right = parse(split.count == 2 ? Substring(split[1]) : nil)
        else { return nil }
        let count = left.count + right.count
        guard (hasCompression && count < 8) || (!hasCompression && count == 8) else { return nil }
        let groups = left + Array(repeating: 0, count: 8 - count) + right
        var bytes = Data()
        for group in groups { bytes.append(UInt8(group >> 8)); bytes.append(UInt8(group & 0xff)) }
        return bytes
    }

    private static func ipv6Text(_ bytes: Data) -> String? {
        guard bytes.count == 16 else { return nil }
        let groups = stride(from: 0, to: 16, by: 2).map { UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]) }
        var bestStart = -1, bestCount = 0, start = 0
        while start < 8 {
            guard groups[start] == 0 else { start += 1; continue }
            var end = start
            while end < 8 && groups[end] == 0 { end += 1 }
            if end - start > bestCount { bestStart = start; bestCount = end - start }
            start = end
        }
        if bestCount < 2 { bestStart = -1 }
        var output = "", index = 0
        while index < 8 {
            if index == bestStart { output += "::"; index += bestCount; continue }
            if !output.isEmpty && !output.hasSuffix(":") { output += ":" }
            output += String(groups[index], radix: 16)
            index += 1
        }
        return output.isEmpty ? "::" : output
    }
}
