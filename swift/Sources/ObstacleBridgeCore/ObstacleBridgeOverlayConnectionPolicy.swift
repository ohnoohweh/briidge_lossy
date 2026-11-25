import Foundation

/// Portable connection-row serialization shared by platform connection owners.
enum ObstacleBridgeNativeConnectionSnapshot {
    static func endpoint(host: String?, port: Int?) -> Any {
        guard let host, let port else { return NSNull() }
        return ["host": host, "port": port]
    }

    static func make(
        proto: String, role: String, state: String, chanID: Int, svcID: Int,
        serviceName: String, sourceHost: String?, sourcePort: Int?,
        localHost: String?, localPort: Int?, remoteHost: String, remotePort: Int,
        stats: [String: Int], rxIdleSeconds: Any = NSNull(), txIdleSeconds: Any = NSNull()
    ) -> [String: Any] {
        [
            "protocol": proto, "role": role, "state": state, "chan_id": chanID,
            "svc_id": svcID, "service_name": serviceName,
            "source": endpoint(host: sourceHost, port: sourcePort),
            "local": endpoint(host: localHost, port: localPort),
            "local_port": localPort ?? NSNull(),
            "remote_destination": endpoint(host: remoteHost, port: remotePort),
            "stats": stats,
            "rx_idle_seconds": rxIdleSeconds,
            "tx_idle_seconds": txIdleSeconds,
        ]
    }
}

struct ObstacleBridgeOverlayConnectionState {
    let proto: String
    let role: String
    let chanID: Int
    let svcID: Int
    let serviceName: String
    let remoteHost: String
    let remotePort: Int
    var state: String
    var localHost: String?
    var localPort: Int?
    var stats: [String: Int]
    var lastRXActivityNS: UInt64 = 0
    var lastTXActivityNS: UInt64 = 0

    func snapshot() -> [String: Any] {
        let now = DispatchTime.now().uptimeNanoseconds
        let rxIdle: Any = lastRXActivityNS > 0 && now >= lastRXActivityNS
            ? Double(now - lastRXActivityNS) / 1_000_000_000.0 : NSNull()
        let txIdle: Any = lastTXActivityNS > 0 && now >= lastTXActivityNS
            ? Double(now - lastTXActivityNS) / 1_000_000_000.0 : NSNull()
        return ObstacleBridgeNativeConnectionSnapshot.make(
            proto: proto, role: role, state: state, chanID: chanID, svcID: svcID,
            serviceName: serviceName, sourceHost: nil, sourcePort: nil,
            localHost: localHost, localPort: localPort, remoteHost: remoteHost,
            remotePort: remotePort, stats: stats, rxIdleSeconds: rxIdle, txIdleSeconds: txIdle
        )
    }
}

/// Portable overlay connection state transitions. Network.framework endpoint
/// projection and connection drivers remain in the Apple adapter.
enum ObstacleBridgeOverlayConnectionSupport {
    static func connectionRows(from states: [Int: ObstacleBridgeOverlayConnectionState]) -> [[String: Any]] {
        states.values.map { $0.snapshot() }.sorted { ($0["chan_id"] as? Int ?? -1) < ($1["chan_id"] as? Int ?? -1) }
    }

    static func makeState(proto: String, role: String, chanID: Int, spec: ObstacleBridgeChannelMuxCodec.ServiceSpec, serviceName: String, state: String, localHost: String?, localPort: Int?) -> ObstacleBridgeOverlayConnectionState {
        ObstacleBridgeOverlayConnectionState(
            proto: proto, role: role, chanID: chanID, svcID: spec.svcID,
            serviceName: serviceName, remoteHost: spec.rHost, remotePort: spec.rPort,
            state: state, localHost: localHost, localPort: localPort,
            stats: ["rx_msgs": 0, "tx_msgs": 0, "rx_bytes": 0, "tx_bytes": 0]
        )
    }

    static func updateConnectedState(states: inout [Int: ObstacleBridgeOverlayConnectionState], proto: String, chanID: Int, localHost: String?, localPort: Int?) {
        guard var state = states[chanID], state.proto == proto else { return }
        state.state = "connected"
        if let localHost { state.localHost = localHost }
        if let localPort { state.localPort = localPort }
        states[chanID] = state
    }

    static func recordTraffic(states: inout [Int: ObstacleBridgeOverlayConnectionState], proto: String, chanID: Int, direction: String, bytes: Int) {
        guard var state = states[chanID], state.proto == proto else { return }
        let keyMessages = direction == "inbound" ? "rx_msgs" : "tx_msgs"
        let keyBytes = direction == "inbound" ? "rx_bytes" : "tx_bytes"
        state.stats[keyMessages, default: 0] += 1
        state.stats[keyBytes, default: 0] += bytes
        let now = DispatchTime.now().uptimeNanoseconds
        if direction == "inbound" {
            state.lastRXActivityNS = now
        } else {
            state.lastTXActivityNS = now
        }
        states[chanID] = state
    }
}
