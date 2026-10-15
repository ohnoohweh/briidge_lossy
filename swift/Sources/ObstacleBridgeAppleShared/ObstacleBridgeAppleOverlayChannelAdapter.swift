import Foundation
import Network

extension ObstacleBridgeOverlayChannelCore {
    static func handleTCPTransportEvent(
        _ event: ObstacleBridgeChannelMuxTCPTransportOwner.TransportEvent,
        tcpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState],
        serviceNameByID: [Int: String]
    ) {
        switch event {
        case .clientAccepted(let chanID, let spec, let connected):
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp", role: "client", chanID: chanID, spec: spec,
                serviceName: serviceName(spec, serviceNameByID: serviceNameByID),
                state: connected ? "connected" : "connecting", localHost: nil, localPort: nil
            )
        case .clientConnected(let chanID, let localHost, let localPort):
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, localHost: localHost, localPort: localPort)
        case .clientInbound(let chanID, let bytes), .serverInbound(let chanID, let bytes):
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, direction: "inbound", bytes: bytes)
        case .clientOutbound(let chanID, let bytes), .serverOutbound(let chanID, let bytes):
            ObstacleBridgeOverlayConnectionSupport.recordTraffic(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, direction: "outbound", bytes: bytes)
        case .clientClosed(let chanID), .serverClosed(let chanID):
            tcpConnectionStates.removeValue(forKey: chanID)
        case .serverConnected(let chanID):
            ObstacleBridgeOverlayConnectionSupport.updateConnectedState(states: &tcpConnectionStates, proto: "tcp", chanID: chanID, localHost: nil, localPort: nil)
        }
    }

    @discardableResult
    static func acceptLocalTCPConnection(
        _ connection: NWConnection,
        spec: ObstacleBridgeChannelMuxCodec.ServiceSpec,
        listenerHost: String,
        listenerPort: Int,
        tcpTransportOwner: ObstacleBridgeChannelMuxTCPTransportOwner,
        tcpConnectionStates: inout [Int: ObstacleBridgeOverlayConnectionState],
        serviceNameByID: [Int: String],
        cancelConnection: (NWConnection) -> Void
    ) -> Bool {
        if let chanID = tcpTransportOwner.acceptLocalConnection(connection, spec: spec) {
            tcpConnectionStates[chanID] = ObstacleBridgeOverlayConnectionSupport.makeState(
                proto: "tcp",
                role: "server",
                chanID: chanID,
                spec: spec,
                serviceName: serviceName(spec, serviceNameByID: serviceNameByID),
                state: "connecting",
                localHost: listenerHost,
                localPort: listenerPort
            )
            return true
        }
        cancelConnection(connection)
        return false
    }
}
