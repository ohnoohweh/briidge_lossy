import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgePacketModelTests {
    @Test func parsesBoundedIPv4AndIPv6Packets() throws {
        let ipv4 = Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2])
        let parsed4 = try ObstacleBridgeIPPacket.parse(ipv4)
        #expect(parsed4.version == .ipv4)
        #expect(parsed4.sourceAddress == Data([192, 0, 2, 1]))
        #expect(parsed4.destinationAddress == Data([198, 51, 100, 2]))
        #expect(parsed4.totalLength == 20)
        #expect(throws: ObstacleBridgePacketModelError.malformedIPv4) {
            try ObstacleBridgeIPPacket.parse(Data([0x45, 0, 0, 40]))
        }

        let ipv6 = Data([0x60, 0, 0, 0, 0, 0, 58, 64] + Array(repeating: 1, count: 16) + Array(repeating: 2, count: 16))
        let parsed6 = try ObstacleBridgeIPPacket.parse(ipv6)
        #expect(parsed6.version == .ipv6)
        #expect(parsed6.sourceAddress == Data(repeating: 1, count: 16))
        #expect(parsed6.destinationAddress == Data(repeating: 2, count: 16))
    }

    @Test func sourceReplacementAndChecksumAreDeterministic() throws {
        let packet = Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2])
        let normalized = try ObstacleBridgeIPPacket.replacingSource(in: packet, with: Data([203, 0, 113, 9]))
        #expect(normalized[12..<16] == Data([203, 0, 113, 9]))
        let repaired = try ObstacleBridgeIPPacket.replacingSourceAndRepairingChecksums(in: packet, with: Data([203, 0, 113, 9]))
        #expect(ObstacleBridgeIPPacket.internetChecksum(Data(repaired.prefix(20))) == 0)
        #expect(ObstacleBridgeIPPacket.internetChecksum(Data([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5])) == 0x1905)
    }

    @Test func ipv6ExtensionHeadersLocateTransportForChecksumRepair() throws {
        var packet = Data([0x60, 0, 0, 0, 0, 28, 60, 64])
        packet.append(Data(repeating: 1, count: 16))
        packet.append(Data(repeating: 2, count: 16))
        packet.append(Data([17, 0, 0, 0, 0, 0, 0, 0])) // Destination Options -> UDP
        packet.append(Data([0, 1, 0, 2, 0, 20, 0, 0]))
        packet.append(Data(repeating: 0xA5, count: 12))
        let parsed = try ObstacleBridgeIPPacket.parse(packet)
        #expect(parsed.nextHeader == 17)
        #expect(parsed.transportProtocol == 17)
        #expect(parsed.transportHeaderOffset == 48)

        let repaired = try ObstacleBridgeIPPacket.replacingSourceAndRepairingChecksums(in: packet, with: Data(repeating: 3, count: 16))
        var covered = Data(repaired[8..<24])
        covered.append(repaired[24..<40])
        covered.append(Data([0, 0, 0, 20, 0, 0, 0, 17]))
        covered.append(repaired[48..<68])
        #expect(ObstacleBridgeIPPacket.internetChecksum(covered) == 0)

        var fragmented = packet
        fragmented[6] = 44
        fragmented[4] = 0
        fragmented[5] = 16
        fragmented.removeSubrange(40..<48)
        fragmented.insert(contentsOf: [17, 0, 0, 1, 0, 0, 0, 1], at: 40)
        let parsedFragment = try ObstacleBridgeIPPacket.parse(fragmented)
        #expect(parsedFragment.transportProtocol == nil)
        #expect(throws: ObstacleBridgePacketModelError.malformedIPv6) {
            try ObstacleBridgeIPPacket.parse(Data(packet.prefix(42)))
        }
    }

    @Test func fragmentReassemblyIsBoundedAndRejectsOverlap() throws {
        let packet = Data("portable-packet".utf8)
        let fragments = try ObstacleBridgePacketFragment.fragment(packet, datagramID: 7, maximumPayload: 5)
        let reassembler = ObstacleBridgePacketReassembler(maximumDatagrams: 1)
        #expect(reassembler.consume(channelID: 3, wire: fragments[1].wire) == .pending)
        #expect(reassembler.consume(channelID: 3, wire: fragments[0].wire) == .pending)
        #expect(reassembler.consume(channelID: 3, wire: fragments[2].wire) == .complete(packet))

        let first = ObstacleBridgePacketFragment(datagramID: 8, totalLength: 4, offset: 0, payload: Data([1, 2]))
        let overlap = ObstacleBridgePacketFragment(datagramID: 8, totalLength: 4, offset: 1, payload: Data([3, 4]))
        #expect(reassembler.consume(channelID: 4, wire: first.wire) == .pending)
        #expect(reassembler.consume(channelID: 4, wire: overlap.wire) == .rejected)
    }

    @Test func tunChannelStateOwnsBindingPreferenceAndEpochReset() {
        let state = ObstacleBridgeTunChannelState()
        state.bind(41)
        state.bind(9)
        state.bind(0)
        #expect(state.channels == [9, 41])
        #expect(state.preferredChannel == 41)
        #expect(state.isBound(41))
        #expect(state.close(41))
        #expect(state.preferredChannel == 9)
        #expect(!state.close(41))
        state.reset()
        #expect(state.channels.isEmpty)
        #expect(state.preferredChannel == nil)
    }

    @Test func sharedTunBindingPolicyIsDeterministicAcrossDropAndDisconnect() {
        let initial = [
            ObstacleBridgeTunPeerBinding(peerID: 7, preferredChannelID: 12, channelIDs: [12, 3, 12]),
            ObstacleBridgeTunPeerBinding(peerID: 2, preferredChannelID: nil, channelIDs: [9]),
        ]
        let bindings = ObstacleBridgeTunPeerBindingPolicy.apply(
            initialBindings: initial,
            operations: [(peerID: 7, channelID: 12, drop: true), (peerID: 2, channelID: 4, drop: false)]
        )
        #expect(bindings == [
            .init(peerID: 2, preferredChannelID: 9, channelIDs: [4, 9]),
            .init(peerID: 7, preferredChannelID: 3, channelIDs: [3]),
        ])
        let cleanup = ObstacleBridgeTunPeerBindingPolicy.cleanup(
            bindings: bindings,
            peerReferenceByID: [2: "two", 7: "seven"],
            peerIDByReference: ["two": 2, "seven": 7],
            disconnectedPeerID: 7
        )
        #expect(cleanup.bindings.map(\.peerID) == [2])
        #expect(cleanup.peerReferenceByID == [2: "two"])
        #expect(cleanup.peerIDByReference == ["two": 2])
    }

    @Test func sharedTunRoutingPolicySelectsOwnedUnicastAndBoundedBroadcast() {
        let active = [
            ObstacleBridgeTunActivePeerChannel(peerID: 7, preferredChannelID: 12),
            ObstacleBridgeTunActivePeerChannel(peerID: 2, preferredChannelID: 4),
            ObstacleBridgeTunActivePeerChannel(peerID: 9, preferredChannelID: nil),
        ]
        let unicast = ObstacleBridgeTunRoutingPolicy.plan(
            ipVersion: 4,
            destinationAddress: "10.0.0.7",
            ownerByIPv4: ["10.0.0.7": "seven"],
            ownerByIPv6: [:],
            peerIDByReference: ["seven": 7],
            activePeers: active
        )
        #expect(unicast.routed)
        #expect(unicast.routeClass == "unicast")
        #expect(unicast.peerIDs == [7])
        #expect(unicast.channelIDs == [12])

        let broadcast = ObstacleBridgeTunRoutingPolicy.plan(
            ipVersion: 4,
            destinationAddress: "255.255.255.255",
            ownerByIPv4: [:],
            ownerByIPv6: [:],
            peerIDByReference: [:],
            activePeers: active
        )
        #expect(broadcast.routed)
        #expect(broadcast.routeClass == "broadcast")
        #expect(broadcast.peerIDs == [2, 7])
        #expect(broadcast.channelIDs == [4, 12])
    }

    @Test func sharedTunInboundAdmissionUsesConfiguredAddressOwnership() {
        #expect(ObstacleBridgeTunInboundAdmissionPolicy.admits(
            sourceAddress: "fd20::2",
            allowedSourceAddresses: ["fd20::2"]
        ))
        #expect(!ObstacleBridgeTunInboundAdmissionPolicy.admits(
            sourceAddress: "fd20::3",
            allowedSourceAddresses: ["fd20::2"]
        ))
        #expect(ObstacleBridgeTunInboundAdmissionPolicy.ownerReference(
            for: "10.0.0.2",
            ownerByIPv4: ["10.0.0.2": "two"],
            ownerByIPv6: ["fd20::2": "two"]
        ) == "two")
        #expect(ObstacleBridgeTunInboundAdmissionPolicy.ownerReference(
            for: "10.0.0.3",
            ownerByIPv4: ["10.0.0.2": "two"],
            ownerByIPv6: [:]
        ) == nil)
    }

    @Test func tunDropLedgerBoundsRecentEventsAndKeepsReasonTotals() {
        let ledger = ObstacleBridgeTunDropLedger(maximumRecent: 2)
        ledger.record(.init(reason: "unknown_destination", direction: "outbound", peerID: 7, packetBytes: 99))
        ledger.record(.init(reason: "source_not_owned_by_peer", direction: "inbound", peerID: 2))
        ledger.record(.init(reason: "unknown_destination", direction: "outbound", peerID: 7))
        let snapshot = ledger.snapshot()
        #expect(snapshot.total == 3)
        #expect(snapshot.byReason == ["unknown_destination": 2, "source_not_owned_by_peer": 1])
        #expect(snapshot.recent.map(\.reason) == ["source_not_owned_by_peer", "unknown_destination"])
        ledger.reset()
        #expect(ledger.snapshot() == .init(total: 0, byReason: [:], recent: []))
    }

    @Test func tunThrottleStateRollsWindowsAndTracksForwardedBytes() {
        var state = ObstacleBridgeTunThrottleState()
        state.advance(nowNS: 100)
        state.recordForwarded(bytes: 90)
        state.recordDrop()
        state.advance(nowNS: 100_000_100)
        #expect(state.previousBytes == 90)
        #expect(state.currentBytes == 0)
        #expect(state.throttleDropCount == 1)
        state.advance(nowNS: 300_000_100)
        #expect(state.previousBytes == 0)
    }

    @Test func tunThrottlePolicyRequiresEveryActiveScopeToFit() {
        let aggregate = ObstacleBridgeTunThrottleState(previousBytes: 100, currentBytes: 10)
        let peer = ObstacleBridgeTunThrottleState(previousBytes: 80, currentBytes: 60)
        #expect(ObstacleBridgeTunThrottlePolicy.admits(
            packetBytes: 10,
            transportPreviousBytes: 120,
            scopes: [(isAggregate: true, state: aggregate), (isAggregate: false, state: peer)]
        ))
        #expect(!ObstacleBridgeTunThrottlePolicy.admits(
            packetBytes: 20,
            transportPreviousBytes: 120,
            scopes: [(isAggregate: true, state: aggregate), (isAggregate: false, state: peer)]
        ))
    }
}
