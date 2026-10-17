import Dispatch
import Foundation
import Testing
#if os(Linux)
import Glibc
#endif
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxServiceSocketOwnerTests {
    @Test func coreServerRuntimeEffectsArePublicToLinuxAdapters() throws {
        let service = ObstacleBridgeNativeServiceSpec(
            svcID: 9,
            name: "core-effects",
            listenProtocol: "tcp",
            listenBind: "127.0.0.1",
            listenPort: 0,
            targetProtocol: "tcp",
            targetHost: "127.0.0.1",
            targetPort: 7
        )
        let tcp = ObstacleBridgeChannelMuxTcpRuntime(instanceID: 1, connectionSeq: 1)
        let accepted = try #require(try tcp.acceptLocalServerConnection(
            service: service,
            overlayConnected: true,
            acceptingEnabled: true
        ))
        #expect(accepted.frames.count == 1)
        #expect(accepted.activeChannels == [accepted.chanID])

        let udp = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 1, connectionSeq: 1)
        let datagram = try #require(try udp.handleLocalServerDatagram(
            service: service,
            serviceKey: "127.0.0.1:5000",
            payload: Data("core-effects".utf8),
            addrHost: "127.0.0.1",
            addrPort: 5000,
            overlayConnected: true,
            acceptingEnabled: true
        ))
        #expect(datagram.allocatedChannel)
        #expect(datagram.frames.count == 2)
    }

    @Test func coreRuntimeEpochResetWithdrawsTransportBoundChannels() throws {
        let service = ObstacleBridgeNativeServiceSpec(
            svcID: 10, name: "epoch-reset", listenProtocol: "tcp", listenBind: "127.0.0.1", listenPort: 0,
            targetProtocol: "tcp", targetHost: "127.0.0.1", targetPort: 7
        )
        let tcp = ObstacleBridgeChannelMuxTcpRuntime(instanceID: 1, connectionSeq: 1)
        let tcpOpen = try #require(try tcp.acceptLocalServerConnection(service: service, overlayConnected: true, acceptingEnabled: true))
        let tcpReset = tcp.resetTransportEpoch(instanceID: 2, connectionSeq: 2)
        #expect(tcpReset.withdrawnServerChannels == [tcpOpen.chanID])
        #expect(tcpReset.withdrawnClientChannels.isEmpty)

        let udp = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 1, connectionSeq: 1)
        let udpOpen = try #require(try udp.handleLocalServerDatagram(
            service: service, serviceKey: "127.0.0.1:5001", payload: Data("epoch".utf8),
            addrHost: "127.0.0.1", addrPort: 5001, overlayConnected: true, acceptingEnabled: true
        ))
        let udpReset = udp.resetTransportEpoch(instanceID: 2, connectionSeq: 2)
        #expect(udpReset.withdrawnServerChannels == [udpOpen.chanID])
        #expect(udpReset.withdrawnClientChannels.isEmpty)
    }

    @Test func tcpListenerPublishesOpenAndDataFrames() throws {
        let received = LockedFrames()
        let ready = DispatchSemaphore(value: 0)
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: service(protocolType: .tcp)) { _, frames in
            received.append(frames)
            if received.all.count >= 2 { ready.signal() }
        }
        try owner.start()
        defer { owner.stop() }
        let fd = try connect(port: owner.port, type: SOCK_STREAM)
        defer { _ = close(fd) }
        let payload = Data("tcp-payload".utf8)
        #expect(payload.withUnsafeBytes { write(fd, $0.baseAddress, payload.count) } == payload.count)
        #expect(ready.wait(timeout: .now() + 3) == .success)
        let frames = received.all
        #expect(frames.map(\.messageType) == [.open, .data])
        if frames.count == 2 { #expect(frames[1].body == payload) }
    }

    @Test func udpListenerPublishesOpenAndDataFrames() throws {
        let received = LockedFrames()
        let ready = DispatchSemaphore(value: 0)
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: service(protocolType: .udp)) { _, frames in
            received.append(frames)
            if received.all.count >= 2 { ready.signal() }
        }
        try owner.start()
        defer { owner.stop() }
        let fd = try connect(port: owner.port, type: SOCK_DGRAM)
        defer { _ = close(fd) }
        let payload = Data("udp-payload".utf8)
        #expect(payload.withUnsafeBytes { send(fd, $0.baseAddress, payload.count, 0) } == payload.count)
        #expect(ready.wait(timeout: .now() + 3) == .success)
        #expect(received.all.map(\.messageType) == [.open, .data])
        #expect(received.all[0].protocolType == .udp)
        #expect(received.all[1].body == payload)
    }

    @Test func tcpRemoteOpenDialsCoreAdmittedTargetAndDeliversData() throws {
        let target = try listeningTCP()
        defer { _ = close(target.fd) }
        let received = LockedData()
        let connected = DispatchSemaphore(value: 0)
        let delivered = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let accepted = accept(target.fd, nil, nil)
            guard accepted >= 0 else { return }
            defer { _ = close(accepted) }
            connected.signal()
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = read(accepted, &bytes, bytes.count)
            if count > 0 { received.set(Data(bytes.prefix(Int(count)))); delivered.signal() }
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 3, name: "owner", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 3, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 9, protocolType: .tcp, counter: 0, messageType: .open, body: open))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        owner.handleInbound(.init(channelID: 9, protocolType: .tcp, counter: 1, messageType: .data, body: Data("remote-open".utf8)))
        #expect(delivered.wait(timeout: .now() + 3) == .success)
        #expect(received.value == Data("remote-open".utf8))
    }

    @Test func tcpRemoteDialRejectsStaleDataAndEpochResetClosesDescriptor() throws {
        let target = try listeningTCP()
        defer { _ = close(target.fd) }
        let connected = DispatchSemaphore(value: 0)
        let delivered = DispatchSemaphore(value: 0)
        let closed = DispatchSemaphore(value: 0)
        let received = LockedData()
        DispatchQueue.global().async {
            let accepted = accept(target.fd, nil, nil)
            guard accepted >= 0 else { return }
            defer { _ = close(accepted) }
            connected.signal()
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = read(accepted, &bytes, bytes.count)
            if count > 0 { received.set(Data(bytes.prefix(Int(count)))); delivered.signal() }
            if read(accepted, &bytes, bytes.count) == 0 { closed.signal() }
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 5, name: "owner", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 5, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 11, protocolType: .tcp, counter: 0, messageType: .open, body: open))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        owner.handleInbound(.init(channelID: 11, protocolType: .tcp, counter: 0, messageType: .data, body: Data("stale".utf8)))
        owner.handleInbound(.init(channelID: 11, protocolType: .tcp, counter: 1, messageType: .data, body: Data("accepted".utf8)))
        #expect(delivered.wait(timeout: .now() + 3) == .success)
        #expect(received.value == Data("accepted".utf8))
        let reset = owner.resetTransportEpoch(instanceID: 2, connectionSequence: 2)
        #expect(reset.withdrawnTCPChannels == [11])
        #expect(reset.withdrawnUDPChannels.isEmpty)
        #expect(closed.wait(timeout: .now() + 3) == .success)
    }

    @Test func tcpRemoteCloseClosesCoreDialDescriptor() throws {
        let target = try listeningTCP()
        defer { _ = close(target.fd) }
        let connected = DispatchSemaphore(value: 0)
        let closed = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let accepted = accept(target.fd, nil, nil)
            guard accepted >= 0 else { return }
            defer { _ = close(accepted) }
            connected.signal()
            var byte: UInt8 = 0
            if read(accepted, &byte, 1) == 0 { closed.signal() }
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 7, name: "owner", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 7, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 13, protocolType: .tcp, counter: 0, messageType: .open, body: open))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        owner.handleInbound(.init(channelID: 13, protocolType: .tcp, counter: 1, messageType: .close, body: Data()))
        #expect(closed.wait(timeout: .now() + 3) == .success)
    }

    @Test func malformedRemoteOpenDoesNotClaimOrPoisonTCPDial() throws {
        let target = try listeningTCP()
        defer { _ = close(target.fd) }
        let delivered = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let result = LockedDatagramResult()
        DispatchQueue.global().async {
            let accepted = accept(target.fd, nil, nil)
            guard accepted >= 0 else { return }
            defer { _ = close(accepted) }
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = read(accepted, &bytes, bytes.count)
            if count > 0 { result.setFirst(Data(bytes.prefix(Int(count)))); delivered.signal() }
            var descriptor = pollfd(fd: target.fd, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 350) > 0 { result.setSecond(Data("unexpected dial".utf8)) }
            finished.signal()
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 9, name: "owner", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 9, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.tcp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 15, protocolType: .tcp, counter: 0, messageType: .open, body: Data("not-an-open".utf8)))
        owner.handleInbound(.init(channelID: 15, protocolType: .tcp, counter: 0, messageType: .open, body: open))
        owner.handleInbound(.init(channelID: 15, protocolType: .tcp, counter: 1, messageType: .data, body: Data("valid-after-malformed".utf8)))
        #expect(delivered.wait(timeout: .now() + 3) == .success)
        #expect(finished.wait(timeout: .now() + 3) == .success)
        #expect(result.first == Data("valid-after-malformed".utf8))
        #expect(result.second == nil)
    }

    @Test func udpRemoteOpenDialsCoreAdmittedTargetAndDeliversData() throws {
        let target = try boundUDP()
        defer { _ = close(target.fd) }
        let received = LockedData(); let delivered = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = recv(target.fd, &bytes, bytes.count, 0)
            if count > 0 { received.set(Data(bytes.prefix(Int(count)))); delivered.signal() }
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 4, name: "owner", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 4, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 10, protocolType: .udp, counter: 0, messageType: .open, body: open))
        owner.handleInbound(.init(channelID: 10, protocolType: .udp, counter: 1, messageType: .data, body: Data("remote-udp".utf8)))
        #expect(delivered.wait(timeout: .now() + 3) == .success)
        #expect(received.value == Data("remote-udp".utf8))
    }

    @Test func udpRemoteDialEpochResetStopsFurtherDatagrams() throws {
        let target = try boundUDP()
        defer { _ = close(target.fd) }
        let first = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let result = LockedDatagramResult()
        DispatchQueue.global().async {
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = recv(target.fd, &bytes, bytes.count, 0)
            if count > 0 { result.setFirst(Data(bytes.prefix(Int(count)))); first.signal() }
            var descriptor = pollfd(fd: target.fd, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 350) > 0 {
                let secondCount = recv(target.fd, &bytes, bytes.count, 0)
                if secondCount > 0 { result.setSecond(Data(bytes.prefix(Int(secondCount)))) }
            }
            finished.signal()
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 6, name: "owner", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 6, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 12, protocolType: .udp, counter: 0, messageType: .open, body: open))
        owner.handleInbound(.init(channelID: 12, protocolType: .udp, counter: 1, messageType: .data, body: Data("before-reset".utf8)))
        #expect(first.wait(timeout: .now() + 3) == .success)
        let reset = owner.resetTransportEpoch(instanceID: 2, connectionSequence: 2)
        #expect(reset.withdrawnTCPChannels.isEmpty)
        #expect(reset.withdrawnUDPChannels == [12])
        owner.handleInbound(.init(channelID: 12, protocolType: .udp, counter: 2, messageType: .data, body: Data("after-reset".utf8)))
        #expect(finished.wait(timeout: .now() + 3) == .success)
        #expect(result.first == Data("before-reset".utf8))
        #expect(result.second == nil)
    }

    @Test func udpRemoteCloseStopsFurtherDatagrams() throws {
        let target = try boundUDP()
        defer { _ = close(target.fd) }
        let first = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let result = LockedDatagramResult()
        DispatchQueue.global().async {
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = recv(target.fd, &bytes, bytes.count, 0)
            if count > 0 { result.setFirst(Data(bytes.prefix(Int(count)))); first.signal() }
            var descriptor = pollfd(fd: target.fd, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 350) > 0 {
                let secondCount = recv(target.fd, &bytes, bytes.count, 0)
                if secondCount > 0 { result.setSecond(Data(bytes.prefix(Int(secondCount)))) }
            }
            finished.signal()
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 8, name: "owner", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 8, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 14, protocolType: .udp, counter: 0, messageType: .open, body: open))
        owner.handleInbound(.init(channelID: 14, protocolType: .udp, counter: 1, messageType: .data, body: Data("before-close".utf8)))
        #expect(first.wait(timeout: .now() + 3) == .success)
        owner.handleInbound(.init(channelID: 14, protocolType: .udp, counter: 2, messageType: .close, body: Data()))
        owner.handleInbound(.init(channelID: 14, protocolType: .udp, counter: 3, messageType: .data, body: Data("after-close".utf8)))
        #expect(finished.wait(timeout: .now() + 3) == .success)
        #expect(result.first == Data("before-close".utf8))
        #expect(result.second == nil)
    }

    @Test func malformedAndStaleUDPFramesDoNotClaimOrPoisonDial() throws {
        let target = try boundUDP()
        defer { _ = close(target.fd) }
        let delivered = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let result = LockedDatagramResult()
        DispatchQueue.global().async {
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = recv(target.fd, &bytes, bytes.count, 0)
            if count > 0 { result.setFirst(Data(bytes.prefix(Int(count)))); delivered.signal() }
            var descriptor = pollfd(fd: target.fd, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 350) > 0 { result.setSecond(Data("unexpected datagram".utf8)) }
            finished.signal()
        }
        let owner = ObstacleBridgeLinuxServiceSocketOwner(spec: .init(serviceID: 10, name: "owner", listenProtocol: .udp, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: .udp, targetHost: "127.0.0.1", targetPort: target.port)) { _, _ in }
        try owner.start(); defer { owner.stop() }
        let service = ObstacleBridgeServiceSpec(serviceID: 10, name: "target", listenProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: ObstacleBridgeChannelMuxProtocol.udp.rawValue, targetHost: "127.0.0.1", targetPort: UInt16(target.port))
        let open = try ObstacleBridgeServiceCodec.encodeOpen(instanceID: 1, connectionSequence: 1, service: service)
        owner.handleInbound(.init(channelID: 16, protocolType: .udp, counter: 0, messageType: .open, body: Data("not-an-open".utf8)))
        owner.handleInbound(.init(channelID: 16, protocolType: .udp, counter: 0, messageType: .open, body: open))
        owner.handleInbound(.init(channelID: 16, protocolType: .udp, counter: 0, messageType: .data, body: Data("stale".utf8)))
        owner.handleInbound(.init(channelID: 16, protocolType: .udp, counter: 1, messageType: .data, body: Data("valid-after-invalid".utf8)))
        #expect(delivered.wait(timeout: .now() + 3) == .success)
        #expect(finished.wait(timeout: .now() + 3) == .success)
        #expect(result.first == Data("valid-after-invalid".utf8))
        #expect(result.second == nil)
    }

    private func service(protocolType: ObstacleBridgeChannelMuxProtocol) -> ObstacleBridgeLinuxServiceSpec {
        .init(serviceID: 1, name: "test", listenProtocol: protocolType, listenHost: "127.0.0.1", listenPort: 0, targetProtocol: protocolType, targetHost: "127.0.0.1", targetPort: 7)
    }

    private func connect(port: Int, type: __socket_type) throws -> Int32 {
        let fd = socket(AF_INET, Int32(type.rawValue), 0)
        guard fd >= 0 else { throw Errno.failure }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_port = in_port_t(UInt16(port).bigEndian)
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0 else { _ = close(fd); throw Errno.failure }
        return fd
    }

    private func listeningTCP() throws -> (fd: Int32, port: Int) {
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw Errno.failure }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr = in_addr(s_addr: INADDR_LOOPBACK.bigEndian)
        guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) == 0, listen(fd, 1) == 0 else { _ = close(fd); throw Errno.failure }
        var bound = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &bound, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { _ = close(fd); throw Errno.failure }
        return (fd, Int(UInt16(bigEndian: bound.sin_port)))
    }

    private func boundUDP() throws -> (fd: Int32, port: Int) {
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), 0)
        guard fd >= 0 else { throw Errno.failure }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr = in_addr(s_addr: INADDR_LOOPBACK.bigEndian)
        guard withUnsafePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }) == 0 else { _ = close(fd); throw Errno.failure }
        var bound = sockaddr_in(); var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &bound, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { _ = close(fd); throw Errno.failure }
        return (fd, Int(UInt16(bigEndian: bound.sin_port)))
    }

    private enum Errno: Error { case failure }
}

private final class LockedFrames: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [ObstacleBridgeChannelMuxFrame] = []
    var all: [ObstacleBridgeChannelMuxFrame] { lock.lock(); defer { lock.unlock() }; return value }
    func append(_ frames: [ObstacleBridgeChannelMuxFrame]) { lock.lock(); value.append(contentsOf: frames); lock.unlock() }
}

private final class LockedData: @unchecked Sendable {
    private let lock = NSLock(); private var stored = Data()
    var value: Data { lock.lock(); defer { lock.unlock() }; return stored }
    func set(_ data: Data) { lock.lock(); stored = data; lock.unlock() }
}

private final class LockedDatagramResult: @unchecked Sendable {
    private let lock = NSLock(); private var firstValue: Data?; private var secondValue: Data?
    var first: Data? { lock.lock(); defer { lock.unlock() }; return firstValue }
    var second: Data? { lock.lock(); defer { lock.unlock() }; return secondValue }
    func setFirst(_ data: Data) { lock.lock(); firstValue = data; lock.unlock() }
    func setSecond(_ data: Data) { lock.lock(); secondValue = data; lock.unlock() }
}
