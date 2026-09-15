import Foundation
import ObstacleBridgeCore

/// Compiled by the macOS host lane and available to an unsigned iOS package
/// consumer. It proves that Apple callers import the canonical core module
/// rather than compiling a private copy of its protocol types.
public enum ObstacleBridgeApplePackageProbe {
    public static func endpoint(host: String, port: UInt16) -> ObstacleBridgeEndpoint {
        ObstacleBridgeEndpoint(host: host, port: port)
    }

    /// Exercises every R003 wire-codec owner through the imported module.
    /// This stays portable so the same consumer compiles for macOS and iOS.
    public static func exerciseWireCodecOwners() throws {
        let mux = try ObstacleBridgeChannelMuxFrameCodec.encode(
            channelID: 1, protocolType: 1, counter: 2, messageType: 0, body: Data("mux".utf8)
        )
        guard try ObstacleBridgeChannelMuxFrameCodec.decode(mux).body == Data("mux".utf8) else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }

        let service = ObstacleBridgeServiceSpec(
            serviceID: 7, name: "probe", listenProtocol: 1, listenHost: "127.0.0.1", listenPort: 7001,
            targetProtocol: 1, targetHost: "127.0.0.1", targetPort: 7002
        )
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        guard try ObstacleBridgeServiceCodec.decodeOpen(open).service == service else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }
        guard !(try ObstacleBridgeControlChunkCodec.chunk(transactionID: 1, maximumApplicationPayload: 32, payload: Data("chunk".utf8))).isEmpty else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }

        let data = try ObstacleBridgeMyUDPCodec.encodeData(payload: Data("udp".utf8), counter: 1, transmittedNanoseconds: 1)
        guard try ObstacleBridgeMyUDPCodec.decodeData(data).payload == Data("udp".utf8) else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }
        let control = try ObstacleBridgeMyUDPCodec.encodeControl(lastInOrder: 1, highestReceived: 2, missing: [2], transmittedNanoseconds: 1)
        guard try ObstacleBridgeMyUDPCodec.decodeControl(control).missing == [2] else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }

        let secureLink = ObstacleBridgeSecureLinkFrameCodec.encode(type: 1, sessionID: 1, counter: 1, payload: Data("secure".utf8))
        guard try ObstacleBridgeSecureLinkFrameCodec.decode(secureLink).payload == Data("secure".utf8) else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }

        let tcp = try ObstacleBridgeOverlayFrameCodec.encodeTCP(.init(kind: .application, payload: Data("tcp".utf8)))
        guard try ObstacleBridgeOverlayFrameCodec.decodeTCP(tcp).payload == Data("tcp".utf8) else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }
        let webSocket = try ObstacleBridgeWebSocketPayloadCodec.encode(Data("ws".utf8), mode: .base64)
        guard try ObstacleBridgeWebSocketPayloadCodec.decode(webSocket, mode: .base64) == Data("ws".utf8) else {
            throw ObstacleBridgeApplePackageProbeError.invalidResult
        }
    }
}

public enum ObstacleBridgeApplePackageProbeError: Error, Equatable, Sendable { case invalidResult }
