import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeChannelMuxSessionTests {
    private let service = ObstacleBridgeServiceSpec(
        serviceID: 7,
        name: "echo",
        listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue,
        listenHost: "127.0.0.1",
        listenPort: 7000,
        targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue,
        targetHost: "127.0.0.1",
        targetPort: 7001
    )

    @Test func localLifecycleIsEmittedAsPortableEffects() throws {
        let session = ObstacleBridgeChannelMuxSession(instanceID: 9, connectionSequence: 4)
        let opened = try session.acceptLocal(service: service)
        guard case .outbound(let open) = try #require(opened.first) else { Issue.record("missing OPEN"); return }
        #expect(open.channelID == 1)
        #expect(open.protocolType == ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue)
        #expect(open.messageType == ObstacleBridgeChannelMuxSessionMessageType.open.rawValue)
        #expect(try ObstacleBridgeServiceCodec.decodeOpen(open.body).service == service)

        let data = try session.localData(channelID: 1, payload: Data("hello".utf8))
        #expect(data == [.outbound(.init(channelID: 1, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 1, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: Data("hello".utf8)))])
        let closed = try session.localEOF(channelID: 1)
        #expect(closed == [.outbound(.init(channelID: 1, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 2, messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data()))])
        #expect(session.snapshot().activeTCPChannels == 0)
    }

    @Test func inboundLifecycleDrivesOnlyLocalEffectsAndRejectsStaleChannels() throws {
        let session = ObstacleBridgeChannelMuxSession(expectedInboundInstanceID: 2, expectedInboundConnectionSequence: 3)
        let openBody = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 2, connectionSequence: 3, service: service)
        #expect(try session.receive(.init(channelID: 12, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 0, messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue, body: openBody)) == [.connectLocal(channelID: 12, service: service)])
        #expect(try session.receive(.init(channelID: 12, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 1, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: Data([1]))) == [.writeLocal(channelID: 12, payload: Data([1]))])
        #expect(try session.receive(.init(channelID: 12, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 2, messageType: ObstacleBridgeChannelMuxSessionMessageType.close.rawValue, body: Data())) == [.closeLocal(channelID: 12)])
        #expect(throws: ObstacleBridgeChannelMuxSessionError.unknownChannel) {
            try session.receive(.init(channelID: 12, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 3, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: Data()))
        }
        #expect(session.snapshot().malformedFrames == 1)
    }

    @Test func inboundServiceMayUseEphemeralLocalPort() throws {
        let session = ObstacleBridgeChannelMuxSession()
        let ephemeral = ObstacleBridgeServiceSpec(
            serviceID: service.serviceID, name: service.name,
            listenProtocol: service.listenProtocol, listenHost: service.listenHost,
            listenPort: 0, targetProtocol: service.targetProtocol,
            targetHost: service.targetHost, targetPort: service.targetPort
        )
        let body = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: ephemeral)
        #expect(try session.receive(.init(channelID: 4, protocolType: ObstacleBridgeChannelMuxSessionProtocol.tcp.rawValue, counter: 0, messageType: ObstacleBridgeChannelMuxSessionMessageType.open.rawValue, body: body)) == [.connectLocal(channelID: 4, service: ephemeral)])
    }

    @Test func boundedQueueAndServiceAdmissionAreCoreDecisions() throws {
        let session = ObstacleBridgeChannelMuxSession(maximumQueuedFrames: 1)
        let invalid = ObstacleBridgeServiceSpec(serviceID: 1, name: nil, listenProtocol: ObstacleBridgeChannelMuxProtocol.tun.rawValue, listenHost: "", listenPort: 1, targetProtocol: ObstacleBridgeChannelMuxProtocol.tun.rawValue, targetHost: "", targetPort: 1)
        #expect(throws: ObstacleBridgeChannelMuxSessionError.unsupportedProtocol) { try session.acceptLocal(service: invalid) }
        _ = try session.acceptLocal(service: service)
        #expect(session.snapshot().openedTCPChannels == 1)
    }

    @Test func oversizedOpenUsesCoreControlChunksAndReassembles() throws {
        let metadata = String(repeating: "x", count: 512)
        let large = ObstacleBridgeServiceSpec(serviceID: 8, name: metadata, listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, listenHost: "127.0.0.1", listenPort: 7000, targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, targetHost: "127.0.0.1", targetPort: 7001)
        let sender = ObstacleBridgeChannelMuxSession(maximumApplicationPayload: 96)
        let frames = try sender.acceptLocal(service: large).compactMap { if case .outbound(let frame) = $0 { return frame }; return nil }
        #expect(frames.count > 1)
        #expect(frames.allSatisfy { $0.messageType == ObstacleBridgeChannelMuxSessionMessageType.openChunk.rawValue })
        let receiver = ObstacleBridgeChannelMuxSession(maximumApplicationPayload: 96)
        var effects: [ObstacleBridgeChannelMuxSessionEffect] = []
        for frame in frames { effects = try receiver.receive(frame) }
        #expect(effects == [.connectLocal(channelID: 1, service: large)])
    }

    @Test func controlChunkCountersAreAdmittedBeforeServiceCreation() throws {
        let large = ObstacleBridgeServiceSpec(
            serviceID: 9,
            name: String(repeating: "x", count: 512),
            listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue,
            listenHost: "127.0.0.1",
            listenPort: 7000,
            targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue,
            targetHost: "127.0.0.1",
            targetPort: 7001
        )
        let sender = ObstacleBridgeChannelMuxSession(maximumApplicationPayload: 96)
        let frames = try sender.acceptLocal(service: large).compactMap { effect -> ObstacleBridgeChannelMuxSessionFrame? in
            guard case .outbound(let frame) = effect else { return nil }
            return frame
        }
        let receiver = ObstacleBridgeChannelMuxSession(maximumApplicationPayload: 96)
        var invalid = frames[0]
        invalid = .init(channelID: invalid.channelID, protocolType: invalid.protocolType, counter: 0, messageType: invalid.messageType, body: invalid.body)
        #expect(throws: ObstacleBridgeChannelMuxSessionError.invalidCounter) {
            try receiver.receive(invalid)
        }
        #expect(receiver.snapshot().activeTCPChannels == 0)

        var effects: [ObstacleBridgeChannelMuxSessionEffect] = []
        for frame in frames { effects = try receiver.receive(frame) }
        #expect(effects == [.connectLocal(channelID: 1, service: large)])
    }

    @Test func epochCountersAndChannelAllocationAreOwnedByCore() throws {
        let tcp = service
        let udp = ObstacleBridgeServiceSpec(
            serviceID: 8,
            name: "dns",
            listenProtocol: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            listenHost: "127.0.0.1",
            listenPort: 53,
            targetProtocol: ObstacleBridgeChannelMuxSessionProtocol.udp.rawValue,
            targetHost: "127.0.0.1",
            targetPort: 53
        )
        let sender = ObstacleBridgeChannelMuxSession(instanceID: 9, connectionSequence: 4)
        let tcpOpen = try #require(sender.acceptLocal(service: tcp).first)
        let udpOpen = try #require(sender.acceptLocal(service: udp).first)
        guard case .outbound(let tcpFrame) = tcpOpen, case .outbound(let udpFrame) = udpOpen else {
            Issue.record("missing OPEN frames")
            return
        }
        #expect(tcpFrame.channelID == 1)
        #expect(udpFrame.channelID == 2)
        #expect(try sender.receive(.init(channelID: 1, protocolType: tcpFrame.protocolType, counter: 1, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: Data("peer".utf8))) == [.writeLocal(channelID: 1, payload: Data("peer".utf8))])

        let receiver = ObstacleBridgeChannelMuxSession(expectedInboundInstanceID: 9, expectedInboundConnectionSequence: 4)
        _ = try receiver.receive(tcpFrame)
        #expect(throws: ObstacleBridgeChannelMuxSessionError.invalidCounter) {
            try receiver.receive(.init(channelID: 1, protocolType: tcpFrame.protocolType, counter: 2, messageType: ObstacleBridgeChannelMuxSessionMessageType.data.rawValue, body: Data()))
        }

        let staleEpoch = ObstacleBridgeChannelMuxSession(expectedInboundInstanceID: 10, expectedInboundConnectionSequence: 4)
        #expect(throws: ObstacleBridgeChannelMuxSessionError.malformedOpen) {
            try staleEpoch.receive(tcpFrame)
        }
    }

    @Test func fragmentsShareThePortableChannelCounterSequence() throws {
        let sender = ObstacleBridgeChannelMuxSession()
        let open = try #require(sender.acceptLocal(service: service).first)
        guard case .outbound(let openFrame) = open else { Issue.record("missing OPEN"); return }
        let fragment = try #require(sender.localDataFragment(channelID: openFrame.channelID, payload: Data([1, 2, 3])).first)
        guard case .outbound(let fragmentFrame) = fragment else { Issue.record("missing fragment"); return }
        #expect(fragmentFrame.messageType == ObstacleBridgeChannelMuxSessionMessageType.dataFragment.rawValue)
        #expect(fragmentFrame.counter == 1)

        let receiver = ObstacleBridgeChannelMuxSession()
        _ = try receiver.receive(openFrame)
        #expect(try receiver.receive(fragmentFrame) == [.writeLocalFragment(channelID: openFrame.channelID, payload: Data([1, 2, 3]))])
        #expect(throws: ObstacleBridgeChannelMuxSessionError.invalidCounter) {
            try receiver.receive(fragmentFrame)
        }
    }
}
