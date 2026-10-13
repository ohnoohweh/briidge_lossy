import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct ObstacleBridgeResolvedAddress {
    let family: Int32
    let host: String
    let port: Int
    let storage: Data
    let length: socklen_t
}

enum ObstacleBridgePeerAddressResolver {
    typealias ResolveMode = ObstacleBridgePeerAddressPolicy.ResolveMode

    private static func portableFamily(_ family: Int32) -> ObstacleBridgePeerAddressPolicy.Family? {
        switch family {
        case AF_INET:
            return .ipv4
        case AF_INET6:
            return .ipv6
        default:
            return nil
        }
    }

    private static func socketFamily(_ family: ObstacleBridgePeerAddressPolicy.Family) -> Int32 {
        switch family {
        case .ipv4:
            return AF_INET
        case .ipv6:
            return AF_INET6
        }
    }

    static func familyName(_ family: Int32) -> String {
        ObstacleBridgePeerAddressPolicy.familyName(portableFamily(family))
    }

    static func stripBrackets(_ host: String) -> String {
        ObstacleBridgePeerAddressPolicy.stripBrackets(host)
    }

    static func splitConfiguredPeerHosts(_ host: String) -> [String] {
        ObstacleBridgePeerAddressPolicy.splitConfiguredPeerHosts(host)
    }

    static func hostIPFamily(_ host: String) -> Int32? {
        let rendered = stripBrackets(host)
        guard !rendered.isEmpty else {
            return nil
        }
        var ipv4 = in_addr()
        if rendered.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return AF_INET
        }
        var ipv6 = in6_addr()
        if rendered.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return AF_INET6
        }
        return nil
    }

    static func bindFamilyConstraint(_ bindHost: String) -> Int32? {
        let rendered = stripBrackets(bindHost)
        if rendered.isEmpty || rendered == "::" {
            return nil
        }
        return hostIPFamily(rendered)
    }

    static func ipv4MappedIPv6(_ host: String) -> String {
        ObstacleBridgePeerAddressPolicy.ipv4MappedIPv6(host)
    }

    static func numericHostPort(from storage: Data, length: socklen_t) throws -> (String, Int) {
        var hostBuffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var serviceBuffer = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let status: Int32 = storage.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return EAI_FAIL
            }
            let sockaddrPtr = base.assumingMemoryBound(to: sockaddr.self)
            return getnameinfo(
                sockaddrPtr,
                length,
                &hostBuffer,
                socklen_t(hostBuffer.count),
                &serviceBuffer,
                socklen_t(serviceBuffer.count),
                NI_NUMERICHOST | NI_NUMERICSERV
            )
        }
        guard status == 0 else {
            throw NSError(
                domain: "ObstacleBridge.PeerAddressResolver",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "getnameinfo() failed status=\(status)"]
            )
        }
        return (String(cString: hostBuffer), Int(String(cString: serviceBuffer)) ?? 0)
    }

    static func resolvedAddress(from storage: sockaddr_storage, length: socklen_t) -> ObstacleBridgeResolvedAddress? {
        let family = storage.ss_family
        guard family == sa_family_t(AF_INET) || family == sa_family_t(AF_INET6) else {
            return nil
        }
        var copied = storage
        let hostLength = Int(NI_MAXHOST)
        let serviceLength = Int(NI_MAXSERV)
        var hostBuffer = [CChar](repeating: 0, count: hostLength)
        var serviceBuffer = [CChar](repeating: 0, count: serviceLength)
        let infoResult = withUnsafeMutablePointer(to: &copied) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                getnameinfo(sockaddrPtr, length, &hostBuffer, socklen_t(hostLength), &serviceBuffer, socklen_t(serviceLength), NI_NUMERICHOST | NI_NUMERICSERV)
            }
        }
        guard infoResult == 0 else {
            return nil
        }
        let host = String(cString: hostBuffer)
        let port = Int(String(cString: serviceBuffer)) ?? 0
        let data = withUnsafeBytes(of: copied) { raw in
            Data(raw.prefix(Int(length)))
        }
        return ObstacleBridgeResolvedAddress(
            family: Int32(family),
            host: host,
            port: port,
            storage: data,
            length: length
        )
    }

    static func sockaddrNumericHost(from addr: UnsafeMutablePointer<sockaddr>?, length: socklen_t) -> String? {
        guard let addr else {
            return nil
        }
        let hostLength = Int(NI_MAXHOST)
        var hostBuffer = [CChar](repeating: 0, count: hostLength)
        let status = getnameinfo(addr, length, &hostBuffer, socklen_t(hostLength), nil, 0, NI_NUMERICHOST)
        guard status == 0 else {
            return nil
        }
        return String(cString: hostBuffer)
    }

    static func resolveAddressCandidates(host: String, port: Int, passive: Bool, family: Int32, errorDomain: String) throws -> [ObstacleBridgeResolvedAddress] {
        var hints = addrinfo()
        hints.ai_flags = passive ? AI_PASSIVE : 0
        hints.ai_family = family
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_DGRAM
        #else
        hints.ai_socktype = Int32(SOCK_DGRAM.rawValue)
        #endif
        hints.ai_protocol = Int32(IPPROTO_UDP)
        var results: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &results)
        guard status == 0, let info = results else {
            throw NSError(domain: errorDomain, code: 34, userInfo: [NSLocalizedDescriptionKey: "getaddrinfo() failed for \(host):\(port) status=\(status)"])
        }
        defer { freeaddrinfo(results) }
        var candidates: [ObstacleBridgeResolvedAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = info
        while let current = cursor {
            let family = current.pointee.ai_family
            if (family == AF_INET || family == AF_INET6), current.pointee.ai_addr != nil {
                let data = Data(bytes: current.pointee.ai_addr, count: Int(current.pointee.ai_addrlen))
                let numeric = try numericHostPort(from: data, length: current.pointee.ai_addrlen)
                let resolved = ObstacleBridgeResolvedAddress(
                    family: family,
                    host: numeric.0,
                    port: numeric.1,
                    storage: data,
                    length: current.pointee.ai_addrlen
                )
                if !candidates.contains(where: { $0.family == resolved.family && $0.host == resolved.host && $0.port == resolved.port }) {
                    candidates.append(resolved)
                }
            }
            cursor = current.pointee.ai_next
        }
        guard !candidates.isEmpty else {
            throw NSError(domain: errorDomain, code: 36, userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer \(host)"])
        }
        return candidates
    }

    static func resolveAddress(host: String, port: Int, passive: Bool, family: Int32, errorDomain: String) throws -> ObstacleBridgeResolvedAddress {
        guard let first = try resolveAddressCandidates(host: host, port: port, passive: passive, family: family, errorDomain: errorDomain).first else {
            throw NSError(domain: errorDomain, code: 36, userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer \(host)"])
        }
        return first
    }

    static func resolvePeerCandidates(host: String, port: Int, mode: ResolveMode, strictFamily: Bool, errorDomain: String) throws -> [ObstacleBridgeResolvedAddress] {
        let rendered = stripBrackets(host)
        guard !rendered.isEmpty else {
            throw NSError(domain: errorDomain, code: 37, userInfo: [NSLocalizedDescriptionKey: "overlay peer requires a non-empty host name"])
        }
        if let family = hostIPFamily(rendered), let portableFamily = portableFamily(family) {
            switch ObstacleBridgePeerAddressPolicy.literalResolution(
                host: rendered,
                family: portableFamily,
                mode: mode,
                strictFamily: strictFamily
            ) {
            case let .resolve(host: resolvedHost, family: resolvedFamily):
                return [try resolveAddress(
                    host: resolvedHost,
                    port: port,
                    passive: false,
                    family: socketFamily(resolvedFamily),
                    errorDomain: errorDomain
                )]
            case let .incompatible(expected):
                let code = expected == .ipv4 ? 38 : 39
                let expectedName = expected == .ipv4 ? "IPv4" : "IPv6"
                throw NSError(domain: errorDomain, code: code, userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(rendered)' is not an \(expectedName) address"])
            }
        }

        let lookupFamily = strictFamily ? mode.preferredFamily.map(socketFamily) ?? AF_UNSPEC : AF_UNSPEC
        do {
            return try resolveAddressCandidates(host: rendered, port: port, passive: false, family: lookupFamily, errorDomain: errorDomain)
        } catch {
            if rendered.lowercased() == "localhost", let fallback = mode.localhostFallback {
                return [try resolveAddress(host: fallback.host, port: port, passive: false, family: socketFamily(fallback.family), errorDomain: errorDomain)]
            }
            throw error
        }
    }

    static func normalizePeerCandidate(
        _ candidate: ObstacleBridgeResolvedAddress,
        socketFamily: Int32,
        resolveMode: ResolveMode,
        errorDomain: String
    ) throws -> ObstacleBridgeResolvedAddress {
        guard let candidateFamily = portableFamily(candidate.family), let portableSocketFamily = portableFamily(socketFamily) else {
            throw NSError(
                domain: errorDomain,
                code: 41,
                userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(candidate.host)' is not compatible with socket family \(familyName(socketFamily))"]
            )
        }
        switch ObstacleBridgePeerAddressPolicy.normalization(for: candidateFamily, socketFamily: portableSocketFamily) {
        case .keep:
            return candidate
        case .mapIPv4ToIPv6:
            return try resolveAddress(host: ipv4MappedIPv6(candidate.host), port: candidate.port, passive: false, family: AF_INET6, errorDomain: errorDomain)
        case .incompatible:
            break
        }
        throw NSError(
            domain: errorDomain,
            code: 41,
            userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(candidate.host)' is not compatible with socket family \(familyName(socketFamily))"]
        )
    }

    static func resolvePeerAddresses(host: String, port: Int, resolveFamily: String, bindHost: String, errorDomain: String) throws -> [ObstacleBridgeResolvedAddress] {
        let configuredHosts = splitConfiguredPeerHosts(host)
        guard !configuredHosts.isEmpty else {
            throw NSError(domain: errorDomain, code: 37, userInfo: [NSLocalizedDescriptionKey: "overlay peer requires a non-empty host name"])
        }
        let mode = ResolveMode(rawValue: resolveFamily)
        let strictFamily = configuredHosts.count == 1
        var candidates: [ObstacleBridgeResolvedAddress] = []
        if strictFamily {
            candidates = try resolvePeerCandidates(host: configuredHosts[0], port: port, mode: mode, strictFamily: true, errorDomain: errorDomain)
        } else {
            for configuredHost in configuredHosts {
                if let resolved = try? resolvePeerCandidates(host: configuredHost, port: port, mode: mode, strictFamily: false, errorDomain: errorDomain) {
                    candidates.append(contentsOf: resolved)
                }
            }
            if candidates.isEmpty {
                throw NSError(domain: errorDomain, code: 36, userInfo: [NSLocalizedDescriptionKey: "Could not resolve overlay peer '\(host)'"])
            }
        }

        let portableCandidates = candidates.compactMap { candidate -> ObstacleBridgePeerAddressPolicy.Candidate? in
            guard let family = portableFamily(candidate.family) else { return nil }
            return ObstacleBridgePeerAddressPolicy.Candidate(family: family, host: candidate.host, port: candidate.port)
        }
        candidates = ObstacleBridgePeerAddressPolicy.orderedCandidateIndices(portableCandidates, mode: mode).map { candidates[$0] }

        if let bindFamily = bindFamilyConstraint(bindHost) {
            guard let portableBindFamily = portableFamily(bindFamily) else {
                return candidates
            }
            let candidateKeys = candidates.compactMap { candidate -> ObstacleBridgePeerAddressPolicy.Candidate? in
                guard let family = portableFamily(candidate.family) else { return nil }
                return ObstacleBridgePeerAddressPolicy.Candidate(family: family, host: candidate.host, port: candidate.port)
            }
            let compatible = ObstacleBridgePeerAddressPolicy.compatibleCandidateIndices(candidateKeys, family: portableBindFamily).map { candidates[$0] }
            if !compatible.isEmpty {
                return compatible
            }
            let famName = bindFamily == AF_INET6 ? "IPv6" : "IPv4"
            throw NSError(domain: errorDomain, code: 40, userInfo: [NSLocalizedDescriptionKey: "overlay peer '\(host)' resolved, but no \(famName) address is compatible with bind '\(bindHost)'"])
        }

        return candidates
    }
}
