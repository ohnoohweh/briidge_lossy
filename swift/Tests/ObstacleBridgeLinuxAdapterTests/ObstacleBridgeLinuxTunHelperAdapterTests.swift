import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

struct ObstacleBridgeLinuxTunHelperAdapterTests {
    @Test func unavailableEndpointFailsClosedWithoutPrivilegedFallback() throws {
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(
            socketPath: "/tmp/obstaclebridge-no-helper-\(UUID().uuidString).sock",
            timeoutMilliseconds: 50
        )
        #expect(throws: (any Error).self) {
            try adapter.send(command: .snapshot, payload: [:])
        }
    }

    @Test func rejectsMissingEndpointAndInvalidTimeoutBeforeAnyTransportAttempt() {
        #expect(throws: (any Error).self) {
            _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "")
        }
        #expect(throws: (any Error).self) {
            _ = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: "/tmp/helper.sock", timeoutMilliseconds: 0)
        }
    }

    @Test func unixHelperRoundTripsCoreSequencedCommandsAndPacketBoundary() throws {
        let peer = try UnixHelperPeer(connectionCount: 6)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)

        for command in [ObstacleBridgeTunHelperCommand.openTun, .applyNetwork, .removeNetwork, .snapshot, .stop] {
            let payload: [String: Any] = command == .openTun ? ["ifname": "obtest0", "mtu": 1400] : [:]
            let response = try adapter.send(command: command, payload: payload)
            #expect(response["op"] as? String == command.rawValue)
        }
        _ = try adapter.sendPacketToHelper(Data([0x45, 0x00, 0x12, 0x34]))
        #expect(peer.operations == ["OPEN_TUN", "APPLY_NETWORK", "REMOVE_NETWORK", "SNAPSHOT", "STOP", "WRITE_PACKET"])
        #expect(peer.sequences == [1, 2, 3, 4, 5, 6])
        #expect(peer.packets == [Data([0x45, 0x00, 0x12, 0x34])])
    }

    @Test func helperAppliesAndRollsBackCorePacketTunnelPlan() throws {
        let peer = try UnixHelperPeer(connectionCount: 2)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true, "mtu": 1400]]))
        _ = try adapter.apply(packetTunnelPlan: plan, interfaceName: "obtest0")
        _ = try adapter.rollback(packetTunnelPlan: plan, interfaceName: "obtest0")
        #expect(peer.operations == ["APPLY_NETWORK", "REMOVE_NETWORK"])
        let apply = try #require(peer.payloads.first)
        #expect(apply["ifname"] as? String == "obtest0")
        let routing = try #require(apply["tun_routing"] as? [String: Any])
        #expect(routing["mtu"] as? Int == 1400)
        #expect(routing["included_routes"] as? [String] == ["0.0.0.0/0"])
        #expect(routing["dns_servers"] as? [String] == ["1.1.1.1"])
    }

    @Test func helperApplyFailureRequestsRollbackOnFreshExchange() throws {
        let peer = try UnixHelperPeer(connectionCount: 2, disconnectFirstReply: true)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)
        let plan = try #require(ObstacleBridgeRuntimeConfigPort.packetTunnelPlan(from: ["TUN_routing": ["enabled_on_startup": true]]))
        #expect(throws: (any Error).self) {
            try adapter.applyWithRollback(packetTunnelPlan: plan, interfaceName: "obtest0")
        }
        #expect(peer.operations == ["APPLY_NETWORK", "REMOVE_NETWORK"])
        #expect(peer.sequences == [1, 2])
    }

    @Test func coreRejectsMismatchedUnixHelperSequence() throws {
        let peer = try UnixHelperPeer(connectionCount: 1, corruptFirstSequence: true)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)
        #expect(throws: (any Error).self) {
            try adapter.send(command: .snapshot, payload: [:])
        }
        #expect(peer.sequences == [1])
    }

    @Test func malformedUnixHelperReplyFailsClosed() throws {
        let peer = try UnixHelperPeer(connectionCount: 1, omitFirstResponse: true)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)
        #expect(throws: (any Error).self) {
            try adapter.send(command: .snapshot, payload: [:])
        }
    }

    @Test func reconnectsAfterHelperLossOnFreshCoreOperation() throws {
        let peer = try UnixHelperPeer(connectionCount: 2, disconnectFirstReply: true)
        defer { peer.stop() }
        let adapter = try ObstacleBridgeLinuxTunHelperAdapter(socketPath: peer.path)
        #expect(throws: (any Error).self) {
            try adapter.send(command: .snapshot, payload: [:])
        }
        let response = try adapter.send(command: .snapshot, payload: [:])
        #expect(response["seq"] as? Int == 2)
        #expect(peer.sequences == [1, 2])
    }
}

private final class UnixHelperPeer: @unchecked Sendable {
    let path: String
    private let listener: Int32
    private let expectedConnections: Int
    private let corruptFirstSequence: Bool
    private let omitFirstResponse: Bool
    private let disconnectFirstReply: Bool
    private let lock = NSLock()
    private var capturedOperations: [String] = []
    private var capturedSequences: [Int] = []
    private var capturedPackets: [Data] = []
    private var capturedPayloads: [[String: Any]] = []
    var operations: [String] { lock.lock(); defer { lock.unlock() }; return capturedOperations }
    var sequences: [Int] { lock.lock(); defer { lock.unlock() }; return capturedSequences }
    var packets: [Data] { lock.lock(); defer { lock.unlock() }; return capturedPackets }
    var payloads: [[String: Any]] { lock.lock(); defer { lock.unlock() }; return capturedPayloads }

    init(connectionCount: Int, corruptFirstSequence: Bool = false, omitFirstResponse: Bool = false, disconnectFirstReply: Bool = false) throws {
        self.expectedConnections = connectionCount
        self.corruptFirstSequence = corruptFirstSequence
        self.omitFirstResponse = omitFirstResponse
        self.disconnectFirstReply = disconnectFirstReply
        self.path = "/tmp/obstaclebridge-helper-\(UUID().uuidString).sock"
        self.listener = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        guard listener >= 0 else { throw PeerError.socket }
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8) + [0]
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.baseAddress!.assumingMemoryBound(to: UInt8.self).update(from: bytes, count: bytes.count)
        }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0, listen(listener, 8) == 0 else { _ = close(listener); throw PeerError.socket }
        DispatchQueue.global().async { [weak self] in self?.serve() }
    }

    func stop() {
        _ = shutdown(listener, Int32(SHUT_RDWR))
        _ = close(listener)
        try? FileManager.default.removeItem(atPath: path)
    }

    private func serve() {
        for index in 0..<expectedConnections {
            let fd = accept(listener, nil, nil); guard fd >= 0 else { return }
            defer { _ = close(fd) }
            guard let request = try? readFrame(fd),
                  let object = try? JSONSerialization.jsonObject(with: request) as? [String: Any],
                  let envelope = object["envelope"] as? [String: Any],
                  let sequence = envelope["seq"] as? Int
            else { return }
            let operation = (envelope["command"] as? String) ?? "WRITE_PACKET"
            if let payload = envelope["payload"] as? [String: Any] {
                lock.lock(); capturedPayloads.append(payload); lock.unlock()
            }
            if let payload = envelope["payload"] as? [String: Any],
               let encoded = (payload["packet"] as? [String: Any])?["__ob_data_base64"] as? String,
               let packet = Data(base64Encoded: encoded) {
                lock.lock(); capturedPackets.append(packet); lock.unlock()
            }
            lock.lock(); capturedOperations.append(operation); capturedSequences.append(sequence); lock.unlock()
            if disconnectFirstReply && index == 0 {
                _ = close(fd)
                continue
            }
            let responseSequence = corruptFirstSequence && index == 0 ? sequence + 1 : sequence
            let response: [String: Any] = omitFirstResponse && index == 0 ? [:] : ["response": ["ok": true, "op": operation, "seq": responseSequence, "payload": ["opened": operation != "STOP"]]]
            guard let reply = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) else { return }
            try? writeFrame(reply, fd)
        }
    }

    private func readFrame(_ fd: Int32) throws -> Data {
        let length = try readExactly(MemoryLayout<UInt32>.size, fd).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        return try readExactly(Int(length), fd)
    }
    private func writeFrame(_ body: Data, _ fd: Int32) throws {
        var length = UInt32(body.count).bigEndian; var wire = Data(bytes: &length, count: 4); wire.append(body)
        try writeAll(wire, fd)
    }
    private func readExactly(_ count: Int, _ fd: Int32) throws -> Data {
        var data = Data(); var buffer = [UInt8](repeating: 0, count: max(1, count))
        while data.count < count { let readCount = read(fd, &buffer, count - data.count); guard readCount > 0 else { throw PeerError.socket }; data.append(buffer, count: Int(readCount)) }
        return data
    }
    private func writeAll(_ data: Data, _ fd: Int32) throws {
        var offset = 0
        while offset < data.count { let count = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }; guard count > 0 else { throw PeerError.socket }; offset += Int(count) }
    }
    private enum PeerError: Error { case socket }
}
