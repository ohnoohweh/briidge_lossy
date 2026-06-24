import Foundation

enum ObstacleBridgeOverlayStackPlannerError: Error, LocalizedError {
    case unsupportedOverlayTransports([String])
    case multiTransportClient
    case unsupportedSecureLinkMode(String)
    case unsupportedSecureLinkTransport(String, String)
    case missingSecureLinkPSK
    case unsupportedCompressAlgo(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedOverlayTransports(let transports):
            return "Unsupported overlay transport(s): \(transports.joined(separator: ", "))"
        case .multiTransportClient:
            return "Multiple --overlay-transport values are currently supported only for listening instances without configured transport peers."
        case .unsupportedSecureLinkMode(let mode):
            return "secure_link_mode=\(mode) is not implemented yet"
        case .unsupportedSecureLinkTransport(let mode, let transport):
            return "secure_link_mode=\(mode) is not supported for overlay_transport=\(transport)"
        case .missingSecureLinkPSK:
            return "secure_link_mode=psk requires --secure-link-psk"
        case .unsupportedCompressAlgo(let algo):
            return "compress_layer_algo=\(algo) is not implemented yet"
        }
    }
}

final class ObstacleBridgeOverlayStackPlanner {
    struct TransportPlan {
        var transport: String
        var peerHost: String?
        var secureLinkMode: String?
        var compressWrapped: Bool
        var compressConfiguredEnabled: Bool
        var layersTopDown: [String]
    }

    private static let allowedTransports: Set<String> = ["myudp", "tcp", "quic", "ws"]
    private static let secureLinkTransports: Set<String> = ["myudp", "tcp", "ws", "quic"]

    static func parseOverlayTransports(raw: String, hasConfiguredPeerByTransport: [String: Bool]) throws -> [String] {
        let trimmed = raw.isEmpty ? "myudp" : raw
        var parts = trimmed.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        parts.removeAll { $0.isEmpty }
        if parts.isEmpty {
            parts = ["myudp"]
        }
        let bad = Array(Set(parts.filter { !allowedTransports.contains($0) })).sorted()
        if !bad.isEmpty {
            throw ObstacleBridgeOverlayStackPlannerError.unsupportedOverlayTransports(bad)
        }
        var seen: [String] = []
        for part in parts where !seen.contains(part) {
            seen.append(part)
        }
        if seen.count > 1 && seen.contains(where: { hasConfiguredPeerByTransport[$0] ?? false }) {
            throw ObstacleBridgeOverlayStackPlannerError.multiTransportClient
        }
        return seen
    }

    static func planTransport(
        transport: String,
        peerHost: String?,
        secureLinkEnabled: Bool,
        secureLinkModeRaw: String,
        secureLinkPSK: String,
        compressLayerEnabled: Bool,
        compressLayerAlgoRaw: String
    ) throws -> TransportPlan {
        let normalizedTransport = transport.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let normalizedPeerHost = normalizeOptionalString(peerHost)
        let normalizedMode = secureLinkModeRaw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let normalizedAlgo = compressLayerAlgoRaw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        var layersBottomUp = [normalizedTransport]
        var secureLinkMode: String?
        if secureLinkEnabled && normalizedMode != "off" {
            guard ["psk", "cert"].contains(normalizedMode) else {
                throw ObstacleBridgeOverlayStackPlannerError.unsupportedSecureLinkMode(normalizedMode)
            }
            guard secureLinkTransports.contains(normalizedTransport) else {
                throw ObstacleBridgeOverlayStackPlannerError.unsupportedSecureLinkTransport(normalizedMode, normalizedTransport)
            }
            if normalizedMode == "psk" && normalizeOptionalString(secureLinkPSK) == nil {
                throw ObstacleBridgeOverlayStackPlannerError.missingSecureLinkPSK
            }
            secureLinkMode = normalizedMode
            layersBottomUp.append("secure_link_\(normalizedMode)")
        }

        let keepPassiveCompressDecoder = !compressLayerEnabled && normalizedPeerHost == nil
        let compressWrapped = compressLayerEnabled || keepPassiveCompressDecoder
        if compressWrapped {
            guard normalizedAlgo == "zlib" else {
                throw ObstacleBridgeOverlayStackPlannerError.unsupportedCompressAlgo(normalizedAlgo)
            }
            layersBottomUp.append("compress_layer")
        }

        return TransportPlan(
            transport: normalizedTransport,
            peerHost: normalizedPeerHost,
            secureLinkMode: secureLinkMode,
            compressWrapped: compressWrapped,
            compressConfiguredEnabled: compressLayerEnabled,
            layersTopDown: Array(layersBottomUp.reversed())
        )
    }

    private static func normalizeOptionalString(_ raw: String?) -> String? {
        guard let raw else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}