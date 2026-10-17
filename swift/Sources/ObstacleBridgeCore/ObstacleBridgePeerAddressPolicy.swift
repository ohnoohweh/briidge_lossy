import Foundation

/// Portable peer-address selection policy. Platform adapters supply numeric
/// address detection and POSIX/Darwin resolution, then apply these decisions
/// to their native socket-address representations.
enum ObstacleBridgePeerAddressPolicy {
    enum Family: String, Equatable {
        case ipv4
        case ipv6
    }

    enum ResolveMode: Equatable {
        case preferIPv6
        case ipv4
        case ipv6

        init(rawValue: String) {
            switch rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "ipv4":
                self = .ipv4
            case "ipv6":
                self = .ipv6
            default:
                self = .preferIPv6
            }
        }

        func rank(for family: Family) -> Int {
            switch self {
            case .preferIPv6, .ipv6:
                return family == .ipv6 ? 0 : 1
            case .ipv4:
                return family == .ipv4 ? 0 : 1
            }
        }

        var localhostFallback: (host: String, family: Family)? {
            switch self {
            case .ipv4:
                return ("127.0.0.1", .ipv4)
            case .ipv6:
                return ("::1", .ipv6)
            case .preferIPv6:
                return nil
            }
        }

        var preferredFamily: Family? {
            switch self {
            case .ipv4:
                return .ipv4
            case .ipv6:
                return .ipv6
            case .preferIPv6:
                return nil
            }
        }
    }

    struct Candidate: Equatable {
        let family: Family
        let host: String
        let port: Int
    }

    enum LiteralResolution: Equatable {
        case resolve(host: String, family: Family)
        case incompatible(expected: Family)
    }

    enum CandidateNormalization: Equatable {
        case keep
        case mapIPv4ToIPv6
        case incompatible
    }

    static func familyName(_ family: Family?) -> String {
        family?.rawValue ?? "unspecified"
    }

    static func stripBrackets(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            return String(trimmed.dropFirst().dropLast())
        }
        return trimmed
    }

    static func splitConfiguredPeerHosts(_ host: String) -> [String] {
        let rendered = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rendered.isEmpty else {
            return []
        }
        guard rendered.contains(",") || rendered.contains(";") else {
            return [rendered]
        }
        return rendered
            .replacingOccurrences(of: ";", with: ",")
            .split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    static func ipv4MappedIPv6(_ host: String) -> String {
        "::ffff:\(host)"
    }

    static func literalResolution(
        host: String,
        family: Family,
        mode: ResolveMode,
        strictFamily: Bool
    ) -> LiteralResolution {
        guard strictFamily else {
            return .resolve(host: host, family: family)
        }
        switch mode {
        case .ipv4 where family != .ipv4:
            return .incompatible(expected: .ipv4)
        case .ipv6 where family != .ipv6:
            if family == .ipv4 {
                return .resolve(host: ipv4MappedIPv6(host), family: .ipv6)
            }
            return .incompatible(expected: .ipv6)
        default:
            return .resolve(host: host, family: family)
        }
    }

    static func normalization(for candidateFamily: Family, socketFamily: Family) -> CandidateNormalization {
        guard candidateFamily != socketFamily else {
            return .keep
        }
        if socketFamily == .ipv6, candidateFamily == .ipv4 {
            return .mapIPv4ToIPv6
        }
        return .incompatible
    }

    static func orderedCandidateIndices(_ candidates: [Candidate], mode: ResolveMode) -> [Int] {
        candidates.indices.sorted { lhs, rhs in
            let left = candidates[lhs]
            let right = candidates[rhs]
            let leftRank = mode.rank(for: left.family)
            let rightRank = mode.rank(for: right.family)
            if leftRank != rightRank {
                return leftRank < rightRank
            }
            if left.family != right.family {
                return left.family.rawValue < right.family.rawValue
            }
            if left.host != right.host {
                return left.host < right.host
            }
            if left.port != right.port {
                return left.port < right.port
            }
            return lhs < rhs
        }
    }

    static func compatibleCandidateIndices(_ candidates: [Candidate], family: Family) -> [Int] {
        candidates.indices.filter { candidates[$0].family == family }
    }
}

/// Public Linux/Apple adapter port for portable configured-peer normalization.
/// Native owners still resolve and convert socket addresses, while Core owns
/// delimiter, whitespace, and bracket policy so platforms cannot drift.
public enum ObstacleBridgePeerAddressPort {
    public static func configuredPeerCandidates(_ host: String) -> [String] {
        ObstacleBridgePeerAddressPolicy.splitConfiguredPeerHosts(host)
    }
}
