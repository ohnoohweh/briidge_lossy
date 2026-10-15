import Dispatch
import Foundation
import ObstacleBridgeCore
#if os(Linux)
import Glibc
#endif

/// Socket owner for a shared-datagram myUDP listener. Reliable peer state is
/// kept exclusively by `ObstacleBridgeMyUDPPeerRegistry` in Core.
public final class ObstacleBridgeLinuxMyUDPListener {
    private struct Endpoint {
        var address: sockaddr_storage
        let length: socklen_t
    }

    public struct ReceivedRecord: Sendable {
        public let peerIdentity: String
        public let payload: Data
    }

    private var descriptor: Int32
    private let descriptorLock = NSLock()
    /// Serializes registry, endpoint, and socket-effect mutation.  The
    /// foreground event loop is its normal owner, but child sessions may send
    /// while that loop is receiving the next datagram.
    private let stateLock = NSLock()
    private let registry = ObstacleBridgeMyUDPPeerRegistry()
    private var endpoints: [ObstacleBridgeMyUDPPeerRegistry.PeerKey: Endpoint] = [:]
    public let port: Int

    public init(port: Int, bindHost: String = "0.0.0.0", receiveTimeoutMilliseconds: Int? = nil) throws {
        guard (0...65_535).contains(port) else { throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), Int32(IPPROTO_UDP))
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.socketFailure(errno) }
        if let receiveTimeoutMilliseconds {
            var timeout = timeval(
                tv_sec: max(1, receiveTimeoutMilliseconds) / 1_000,
                tv_usec: (max(1, receiveTimeoutMilliseconds) % 1_000) * 1_000
            )
            _ = withUnsafePointer(to: &timeout) {
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
            }
        }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        guard inet_pton(AF_INET, bindHost, &address.sin_addr) == 1 else { _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.resolutionFailed }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { let code = errno; _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.socketFailure(code) }
        descriptor = fd
        var actual = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &actual, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { _ = Glibc.close(fd); throw ObstacleBridgeLinuxMyUDPError.socketFailure(errno) }
        self.port = Int(UInt16(bigEndian: actual.sin_port))
    }

    deinit { close() }

    public func close() {
        descriptorLock.lock()
        let fd = descriptor
        descriptor = -1
        descriptorLock.unlock()
        if fd >= 0 { _ = Glibc.close(fd) }
    }

    public var activePeerCount: Int {
        stateLock.lock(); defer { stateLock.unlock() }
        return registry.activeKeys.count
    }

    /// Queues an application record through the Core-owned reliable peer
    /// engine.  Callers address a peer by the identity returned from
    /// `receive`; endpoint storage and myudp framing remain adapter details.
    public func send(_ payload: Data, to peerIdentity: String, epoch: UInt64 = 1) throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        descriptorLock.lock()
        let fd = descriptor
        descriptorLock.unlock()
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        let key = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: peerIdentity, epoch: epoch)
        guard let endpoint = endpoints[key] else { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        let now = DispatchTime.now().uptimeNanoseconds
        let peer = registry.admit(key)
        try peer.enqueueApplicationRecord(payload, nowNanoseconds: now)
        while true {
            let effect = try peer.flush(nowNanoseconds: now)
            guard !effect.outboundDatagrams.isEmpty else { break }
            try execute(effect, endpoint: endpoint, descriptor: fd)
        }
    }

    /// Removes all transport state for an endpoint epoch after its higher
    /// authentication or runtime owner is withdrawn.
    public func withdraw(peerIdentity: String, epoch: UInt64 = 1) {
        stateLock.lock()
        defer { stateLock.unlock() }
        let key = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: peerIdentity, epoch: epoch)
        registry.withdraw(key)
        endpoints.removeValue(forKey: key)
    }

    /// Applies Core's idle-expiry policy and returns endpoint identities that
    /// the adapter/event loop should withdraw from external bookkeeping.
    @discardableResult public func expireIdlePeers(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds,
        idleTimeoutNanoseconds: UInt64
    ) -> [String] {
        stateLock.lock()
        defer { stateLock.unlock() }
        let expired = registry.expire(
            nowNanoseconds: nowNanoseconds,
            idleTimeoutNanoseconds: idleTimeoutNanoseconds
        )
        expired.forEach { endpoints.removeValue(forKey: $0) }
        return expired.map(\.identity)
    }

    /// Executes Core timer effects for every admitted peer and routes each
    /// datagram to the endpoint retained by this socket adapter.
    @discardableResult public func serviceTimers(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) throws -> Int {
        stateLock.lock()
        defer { stateLock.unlock() }
        descriptorLock.lock()
        let fd = descriptor
        descriptorLock.unlock()
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        var emitted = 0
        for key in registry.activeKeys {
            guard let endpoint = endpoints[key], let effect = try registry.tick(key, nowNanoseconds: nowNanoseconds) else { continue }
            try execute(effect, endpoint: endpoint, descriptor: fd)
            emitted += effect.outboundDatagrams.count
        }
        return emitted
    }

    /// Processes one datagram. The caller supplies the epoch selected by its
    /// admission/authentication layer; endpoint identity alone never resets
    /// an established reliable peer.
    public func receive(epoch: UInt64 = 1, admitting: ((String) -> Bool)? = nil) throws -> ReceivedRecord? {
        descriptorLock.lock()
        let fd = descriptor
        descriptorLock.unlock()
        guard fd >= 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(EBADF) }
        var bytes = [UInt8](repeating: 0, count: 1_452)
        var address = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &bytes, bytes.count, 0, $0, &length) }
        }
        guard count > 0 else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        stateLock.lock()
        defer { stateLock.unlock() }
        let identity = peerIdentity(address, length: length)
        guard admitting?(identity) ?? true else { return nil }
        let key = ObstacleBridgeMyUDPPeerRegistry.PeerKey(identity: identity, epoch: epoch)
        guard registry.selectEpoch(identity: identity, epoch: epoch) else {
            throw ObstacleBridgeLinuxMyUDPError.invalidReply
        }
        endpoints = endpoints.filter { existing, _ in
            existing.identity != identity || existing.epoch == epoch
        }
        let endpoint = Endpoint(address: address, length: length)
        endpoints[key] = endpoint
        let effect: ObstacleBridgeMyUDPPeerEngine.Effect
        do { effect = try registry.receiveWire(Data(bytes.prefix(Int(count))), from: key, nowNanoseconds: DispatchTime.now().uptimeNanoseconds) }
        catch { throw ObstacleBridgeLinuxMyUDPError.invalidReply }
        try execute(effect, endpoint: endpoint, descriptor: fd)
        guard let payload = registry.admit(key).takeDeliveredRecord() else { return nil }
        return .init(peerIdentity: identity, payload: payload)
    }

    private func execute(_ effect: ObstacleBridgeMyUDPPeerEngine.Effect, endpoint: Endpoint, descriptor: Int32) throws {
        var address = endpoint.address
        for datagram in effect.outboundDatagrams {
            let sent = datagram.withUnsafeBytes { payload in
                withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(descriptor, payload.baseAddress, datagram.count, 0, $0, endpoint.length) }
                }
            }
            guard sent == datagram.count else { throw ObstacleBridgeLinuxMyUDPError.ioFailure(errno) }
        }
    }

    private func peerIdentity(_ address: sockaddr_storage, length: socklen_t) -> String {
        var copy = address
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        var service = [CChar](repeating: 0, count: Int(NI_MAXSERV))
        let status = withUnsafePointer(to: &copy) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getnameinfo($0, length, &host, socklen_t(host.count), &service, socklen_t(service.count), NI_NUMERICHOST | NI_NUMERICSERV) }
        }
        guard status == 0 else { return "unknown" }
        let hostText = String(decoding: host.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
        let serviceText = String(decoding: service.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
        return "\(hostText):\(serviceText)"
    }
}

/// Event-loop owner for authenticated myudp listener peers.  It intentionally
/// has one socket reader: authenticated child sessions receive records through
/// per-peer isolated handoff boxes, while the shared listener continues to own
/// endpoint selection and Core peer-registry effects.
public final class ObstacleBridgeLinuxMyUDPPSKListener: @unchecked Sendable {
    private final class PeerBox: @unchecked Sendable {
        let identity: String
        let server: ObstacleBridgeSecureLinkPSKServer
        let lock = NSLock()
        let available = DispatchSemaphore(value: 0)
        var authenticated = false
        var closed = false
        var payloads: [Data] = []
        let maximumQueuedRecords: Int

        init(identity: String, psk: Data, maximumQueuedRecords: Int) throws {
            self.identity = identity
            self.server = try ObstacleBridgeSecureLinkPSKServer(psk: psk)
            self.maximumQueuedRecords = max(1, maximumQueuedRecords)
        }

        @discardableResult func append(_ payload: Data) -> Bool {
            lock.lock()
            guard !closed, payloads.count < maximumQueuedRecords else { lock.unlock(); return false }
            payloads.append(payload)
            lock.unlock()
            available.signal()
            return true
        }

        func next() throws -> Data {
            available.wait()
            lock.lock()
            defer { lock.unlock() }
            guard !payloads.isEmpty else { throw ObstacleBridgeLinuxOverlayTransportError.unexpectedEOF }
            return payloads.removeFirst()
        }

        func close() {
            lock.lock(); closed = true; payloads.removeAll(); lock.unlock()
            available.signal()
        }
    }

    public let listener: ObstacleBridgeLinuxMyUDPListener
    private let psk: Data
    private let serverNonce: () -> Data
    private let maximumPeers: Int
    private let maximumQueuedRecordsPerPeer: Int
    private let lock = NSLock()
    private var peers: [String: PeerBox] = [:]
    public var onAuthenticatedSession: ((String, ObstacleBridgeLinuxConfiguredSession) -> Void)?

    public init(port: Int, bindHost: String = "0.0.0.0", psk: Data, maximumPeers: Int = 32, maximumQueuedRecordsPerPeer: Int = 64, serverNonce: @escaping () -> Data) throws {
        guard !psk.isEmpty else { throw ObstacleBridgeLinuxOverlayTransportError.invalidFrame }
        self.listener = try .init(port: port, bindHost: bindHost, receiveTimeoutMilliseconds: 100)
        self.psk = psk
        self.maximumPeers = max(1, maximumPeers)
        self.maximumQueuedRecordsPerPeer = max(1, maximumQueuedRecordsPerPeer)
        self.serverNonce = serverNonce
    }

    public var port: Int { listener.port }
    public var activePeerCount: Int { listener.activePeerCount }
    public func close() {
        lock.lock(); let boxes = Array(peers.values); peers.removeAll(); lock.unlock()
        boxes.forEach { $0.close() }
        listener.close()
    }
    deinit { close() }

    /// Reads and routes one UDP datagram.  Invalid or unauthenticated traffic
    /// receives no application-session callback.
    public func pump(epoch: UInt64 = 1) throws {
        let record: ObstacleBridgeLinuxMyUDPListener.ReceivedRecord?
        do {
            record = try listener.receive(epoch: epoch) { [weak self] identity in
                guard let self else { return false }
                self.lock.lock()
                defer { self.lock.unlock() }
                return self.peers[identity] != nil || self.peers.count < self.maximumPeers
            }
        }
        catch ObstacleBridgeLinuxMyUDPError.ioFailure(let code) where code == EAGAIN || code == EWOULDBLOCK { return }
        guard let record else { return }
        let box: PeerBox
        lock.lock()
        if let existing = peers[record.peerIdentity] {
            box = existing
        } else {
            guard peers.count < maximumPeers else {
                lock.unlock()
                listener.withdraw(peerIdentity: record.peerIdentity, epoch: epoch)
                return
            }
            let created = try PeerBox(identity: record.peerIdentity, psk: psk, maximumQueuedRecords: maximumQueuedRecordsPerPeer)
            peers[record.peerIdentity] = created
            box = created
        }
        lock.unlock()
        if box.authenticated {
            if !box.append(record.payload) { remove(box, epoch: epoch) }
            return
        }
        do {
            if !box.server.isAuthenticated && box.server.state.sessionID == 0 {
                try listener.send(box.server.handleClientHello(record.payload, serverNonce: serverNonce()), to: record.peerIdentity, epoch: epoch)
            } else {
                try listener.send(box.server.handleClientProof(record.payload), to: record.peerIdentity, epoch: epoch)
                box.authenticated = true
                onAuthenticatedSession?(record.peerIdentity, configuredSession(for: box, epoch: epoch))
            }
        } catch {
            remove(box, epoch: epoch)
        }
    }

    @discardableResult public func serviceTimers() throws -> Int { try listener.serviceTimers() }

    /// Expires both the Core transport peer and any corresponding authenticated
    /// handoff box.  A foreground owner calls this at its timer cadence.
    @discardableResult public func expireIdlePeers(
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds,
        idleTimeoutNanoseconds: UInt64
    ) -> [String] {
        let expired = listener.expireIdlePeers(
            nowNanoseconds: nowNanoseconds,
            idleTimeoutNanoseconds: idleTimeoutNanoseconds
        )
        lock.lock()
        let boxes = expired.compactMap { peers.removeValue(forKey: $0) }
        lock.unlock()
        boxes.forEach { $0.close() }
        return expired
    }

    private func configuredSession(for box: PeerBox, epoch: UInt64) -> ObstacleBridgeLinuxConfiguredSession {
        let raw = ObstacleBridgeLinuxOverlayTransportSession(
            exchange: { payload in try self.listener.send(payload, to: box.identity, epoch: epoch); return try box.next() },
            send: { payload in try self.listener.send(payload, to: box.identity, epoch: epoch) },
            receive: { try box.next() },
            close: { [weak self, weak box] in if let box { self?.remove(box, epoch: epoch) } }
        )
        return ObstacleBridgeLinuxConfiguredSession(lowerSession: raw, secureLink: nil, secureLinkServer: box.server, transport: .myudp)
    }

    private func remove(_ box: PeerBox, epoch: UInt64 = 1) {
        lock.lock()
        if peers[box.identity] === box { peers.removeValue(forKey: box.identity) }
        lock.unlock()
        box.close()
        listener.withdraw(peerIdentity: box.identity, epoch: epoch)
    }
}
