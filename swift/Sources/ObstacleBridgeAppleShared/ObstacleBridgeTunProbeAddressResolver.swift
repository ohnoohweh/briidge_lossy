import Foundation
import Darwin

enum ObstacleBridgeTunProbeAddressResolver {
    static func resolveHost(_ host: String, family: Int32) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: family,
            ai_socktype: SOCK_RAW,
            ai_protocol: family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family ? IPPROTO_ICMPV6 : IPPROTO_ICMP,
            ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(trimmed, nil, &hints, &result) == 0, let result else { return nil }
        defer { freeaddrinfo(result) }
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let info = cursor?.pointee {
            if info.ai_family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family,
               let address = info.ai_addr?.withMemoryRebound(to: sockaddr_in.self, capacity: 1, { $0.pointee }) {
                var copy = address.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(ObstacleBridgeTunProbeDiagnosticsSupport.ipv4Family, &copy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            } else if info.ai_family == ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family,
                      let address = info.ai_addr?.withMemoryRebound(to: sockaddr_in6.self, capacity: 1, { $0.pointee }) {
                var copy = address.sin6_addr
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(ObstacleBridgeTunProbeDiagnosticsSupport.ipv6Family, &copy, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            }
            cursor = info.ai_next
        }
        return nil
    }
}
