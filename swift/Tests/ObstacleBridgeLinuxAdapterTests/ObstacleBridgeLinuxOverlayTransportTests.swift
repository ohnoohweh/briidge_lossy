import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgePortable

struct ObstacleBridgeLinuxOverlayTransportTests {
    @Test func tcpFramingRoundTripsAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .tcp)
        let payload = Data("swift-linux-tcp".utf8)
        #expect(try client.roundTrip(payload) == payload)
        #expect(client.snapshot.state == "connected")
    }

    @Test func webSocketUpgradeAndBinaryFrameRoundTripAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "ws")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .ws, wsPath: "/overlay")
        let payload = try ObstacleBridgeSecureLinkPSKCrypto.serverProof(
            psk: Data(repeating: 7, count: 32),
            sessionID: 9,
            clientNonce: Data(repeating: 1, count: 32),
            serverNonce: Data(repeating: 2, count: 32)
        )
        #expect(try client.roundTrip(payload) == payload)
        #expect(client.snapshot.state == "connected")
    }

    @Test func unqualifiedTransportsAreRejectedBeforeSocketCreation() {
        #expect(throws: ObstacleBridgeLinuxOverlayTransportError.unavailableTransport("Linux QUIC is unavailable: the Network.framework owner has no qualified Linux backend")) {
            try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: 1, transport: .quic)
        }
    }

    @Test func myudpDataFrameRoundTripsAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp")
        defer { peer.stop() }
        let client = try ObstacleBridgeLinuxOverlayTransportClient(host: "127.0.0.1", port: peer.port, transport: .myudp)
        #expect(try client.roundTrip(Data("myudp".utf8)) == Data("myudp".utf8))
        #expect(client.snapshot.state == "connected")
    }

    @Test func configuredMyudpSecureLinkSessionCarriesProtectedDataAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-securelink")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .myudp,
            host: "127.0.0.1",
            port: peer.port,
            secureLinkPSK: Data("linux-swift-psk".utf8)
        ))
        let session = try runtime.connect(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
        defer { runtime.disconnect() }
        #expect(try session.send(Data("myudp-secure".utf8)) == Data("python:myudp-secure".utf8))
        #expect(runtime.status().appReady)
    }

    @Test func myudpSecureLinkCarriesChannelMuxFrameAgainstPythonPeer() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-secure-mux")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.1", port: peer.port, secureLinkPSK: Data("linux-swift-psk".utf8)))
        let session = try runtime.connect(sessionID: 50, clientNonce: Data(repeating: 4, count: 32))
        defer { runtime.disconnect() }
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session)
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 1, protocolType: .udp, counter: 1, messageType: .data, body: Data("mux-myudp".utf8))
        #expect(try mux.exchange(frame) == frame)
    }

    @Test func myudpSupervisorRotatesCandidateAfterFailedEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "myudp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.2,127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(runtime: runtime, policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2))
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        supervisor.start(probe: Data("rotate-myudp".utf8), sessionID: 130, clientNonce: Data(repeating: 12, count: 32))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(runtime.status().activeHost == "127.0.0.1")
        supervisor.stop()
    }

    @Test func myudpSupervisorRecoversAfterSilentPeerTimeout() throws {
        let peer = try PythonOverlayPeer(mode: "myudp-drop-first")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .myudp, host: "127.0.0.1,127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(runtime: runtime, policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2))
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { if $0.state == "connected" { connected.signal() } }
        supervisor.start(probe: Data("silent-myudp".utf8), sessionID: 140, clientNonce: Data(repeating: 13, count: 32))
        #expect(connected.wait(timeout: .now() + 3) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        supervisor.stop()
    }

    @Test func tcpSecureLinkPskSessionAuthenticatesAndCarriesDataAgainstPythonPeer() throws {
        try secureLinkSessionRoundTrip(mode: "tcp-securelink", transport: .tcp)
    }

    @Test func webSocketSecureLinkPskSessionAuthenticatesAndCarriesDataAgainstPythonPeer() throws {
        try secureLinkSessionRoundTrip(mode: "ws-securelink", transport: .ws)
    }

    @Test func configDrivenRuntimePumpsProtectedDataAgainstPythonPeers() throws {
        for (mode, transport) in [("tcp-securelink", ObstacleBridgeLinuxTransport.tcp), ("ws-securelink", .ws)] {
            let peer = try PythonOverlayPeer(mode: mode)
            defer { peer.stop() }
            let config = ObstacleBridgeLinuxRuntimeConfiguration(
                transport: transport,
                host: "127.0.0.1",
                port: peer.port,
                webSocketPath: "/overlay",
                secureLinkPSK: Data("linux-swift-psk".utf8)
            )
            let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: config)
            let session = try runtime.connect(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
            #expect(runtime.status().secureLinkState == "authenticated")
            #expect(runtime.status().appReady)
            #expect(try session.send(Data("runtime-payload".utf8)) == Data("python:runtime-payload".utf8))
            #expect(try session.send(Data("second-payload".utf8)) == Data("python:second-payload".utf8))
            session.close()
            #expect(session.snapshot.state == "disconnected")
            #expect(runtime.snapshot.state == "connected")
            runtime.disconnect()
            #expect(runtime.status().secureLinkState == "disconnected")
            #expect(!runtime.status().appReady)
        }
    }

    @Test func configDrivenRuntimeRotatesToNextConfiguredCandidate() throws {
        let peer = try PythonOverlayPeer(mode: "tcp")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(
            transport: .tcp,
            host: "127.0.0.2,127.0.0.1",
            port: peer.port
        ))
        let session = try runtime.connect(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        defer { session.close() }
        #expect(try session.send(Data("candidate-rotation".utf8)) == Data("candidate-rotation".utf8))
        #expect(runtime.snapshot.attempts == 2)
        #expect(runtime.snapshot.state == "connected")
    }

    @Test func configuredRuntimeReconnectsWithFreshTransportEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-reconnect")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let first = try runtime.connect(sessionID: 7, clientNonce: Data(repeating: 1, count: 32))
        #expect(try first.send(Data("first".utf8)) == Data("first".utf8))
        let second = try runtime.reconnect(sessionID: 8, clientNonce: Data(repeating: 2, count: 32))
        #expect(first.snapshot.state == "disconnected")
        #expect(try second.send(Data("second".utf8)) == Data("second".utf8))
        runtime.disconnect()
        #expect(second.snapshot.state == "disconnected")
        #expect(runtime.snapshot.state == "disconnected")
    }

    @Test func configuredRuntimeRetriesFailedTransactionOnFreshEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-drop-then-echo")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let reply = try runtime.roundTrip(Data("retry".utf8), sessionID: 20, clientNonce: Data(repeating: 4, count: 32), retryCount: 1)
        #expect(reply == Data("retry".utf8))
        #expect(runtime.snapshot.state == "disconnected")
        #expect(runtime.snapshot.attempts == 2)
    }

    @Test func channelMuxFramesUseReadySessionAndRejectStaleEpoch() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-mux-reconnect")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let session = try runtime.connect(sessionID: 120, clientNonce: Data(repeating: 9, count: 32))
        let catalog = ObstacleBridgeChannelMuxFrame(channelID: 0, protocolType: .tcp, counter: 0, messageType: .remoteServicesSetV2, body: Data("RS3[]".utf8))
        let mux = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: session, startupFrames: [catalog])
        let frame = ObstacleBridgeChannelMuxFrame(channelID: 7, protocolType: .tcp, counter: 1, messageType: .data, body: Data("mux".utf8))
        #expect(try mux.exchange(frame) == frame)
        let replacement = try runtime.reconnect(sessionID: 121, clientNonce: Data(repeating: 10, count: 32))
        _ = try ObstacleBridgeLinuxChannelMuxSession(runtime: runtime, session: replacement, startupFrames: [catalog])
        #expect(throws: ObstacleBridgeLinuxChannelMuxError.staleEpoch) { try mux.exchange(frame) }
        runtime.disconnect()
    }

    @Test func reconnectSupervisorRecoversAndStopsPendingTimers() throws {
        let peer = try PythonOverlayPeer(mode: "tcp-drop-then-echo")
        defer { peer.stop() }
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: peer.port))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 10, maximumDelayMilliseconds: 20, maximumAttempts: 2)
        )
        let connected = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "connected" { connected.signal() }
        }
        supervisor.start(probe: Data("supervisor".utf8), sessionID: 90, clientNonce: Data(repeating: 6, count: 32))
        #expect(connected.wait(timeout: .now() + 2) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(supervisor.snapshot.state == "connected")
        supervisor.stop()
        let stopped = expectationSnapshot(supervisor, state: "stopped")
        #expect(stopped)
        #expect(runtime.status().state == "disconnected")
    }

    @Test func reconnectSupervisorReportsBoundedRetryExhaustion() {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 5, maximumDelayMilliseconds: 10, maximumAttempts: 2)
        )
        let failed = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "failed" { failed.signal() }
        }
        supervisor.start(probe: Data("exhaust".utf8), sessionID: 100, clientNonce: Data(repeating: 7, count: 32))
        #expect(failed.wait(timeout: .now() + 2) == .success)
        #expect(supervisor.snapshot.attempts == 2)
        #expect(supervisor.snapshot.failureReason != nil)
        supervisor.stop()
    }

    @Test func reconnectSupervisorStopCancelsPendingRetry() {
        let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: .init(transport: .tcp, host: "127.0.0.1", port: 1))
        let supervisor = ObstacleBridgeLinuxReconnectSupervisor(
            runtime: runtime,
            policy: .init(initialDelayMilliseconds: 250, maximumDelayMilliseconds: 250, maximumAttempts: 3)
        )
        let retryPending = DispatchSemaphore(value: 0)
        let stopped = DispatchSemaphore(value: 0)
        let secondAttempt = DispatchSemaphore(value: 0)
        supervisor.onSnapshot = { snapshot in
            if snapshot.state == "reconnecting", snapshot.attempts == 1, snapshot.nextRetryMilliseconds == 250 { retryPending.signal() }
            if snapshot.state == "stopped" { stopped.signal() }
            if snapshot.attempts >= 2 { secondAttempt.signal() }
        }
        supervisor.start(probe: Data("cancel".utf8), sessionID: 110, clientNonce: Data(repeating: 8, count: 32))
        #expect(retryPending.wait(timeout: .now() + 2) == .success)
        supervisor.stop()
        #expect(stopped.wait(timeout: .now() + 2) == .success)
        #expect(secondAttempt.wait(timeout: .now() + 0.4) == .timedOut)
        #expect(supervisor.snapshot.attempts == 1)
        #expect(supervisor.snapshot.state == "stopped")
    }

    private func expectationSnapshot(_ supervisor: ObstacleBridgeLinuxReconnectSupervisor, state: String) -> Bool {
        let limit = Date().addingTimeInterval(1)
        while Date() < limit {
            if supervisor.snapshot.state == state { return true }
            Thread.sleep(forTimeInterval: 0.005)
        }
        return false
    }

    private func secureLinkSessionRoundTrip(mode: String, transport: ObstacleBridgeLinuxTransport) throws {
        let peer = try PythonOverlayPeer(mode: mode)
        defer { peer.stop() }
        let lower = try ObstacleBridgeLinuxOverlayTransportClient(
            host: "127.0.0.1", port: peer.port, transport: transport, wsPath: "/overlay"
        )
        let session = try lower.openSession()
        defer { session.close() }
        let secureLink = try ObstacleBridgeSecureLinkPSKClient(psk: Data("linux-swift-psk".utf8))
        let hello = try secureLink.begin(sessionID: 42, clientNonce: Data(repeating: 3, count: 32))
        let proof = try secureLink.handleServerHello(session.exchange(hello))
        try secureLink.handleServerAcknowledgement(session.exchange(proof))
        let reply = try secureLink.unprotect(session.exchange(secureLink.protect(Data("payload".utf8))))
        #expect(reply == Data("python:payload".utf8))
        #expect(secureLink.isAuthenticated)
        #expect(lower.snapshot.state == "connected")
    }
}

final class PythonOverlayPeer {
    let process: Process
    let port: Int

    init(mode: String) throws {
        let script = Self.script(for: mode)
        let process = Process()
        let stdout = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-u", "-c", script]
        process.standardOutput = stdout
        process.standardError = Pipe()
        try process.run()
        let line = String(data: stdout.fileHandleForReading.availableData, encoding: .utf8) ?? ""
        guard let port = Int(line.trimmingCharacters(in: .whitespacesAndNewlines)), port > 0 else {
            process.terminate()
            throw OverlayTestError.peerDidNotStart
        }
        self.process = process
        self.port = port
    }

    func stop() {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }

    private static func script(for mode: String) -> String {
        if mode == "myudp-drop-first" {
            return """
            import socket
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            s.recvfrom(1452)
            data,peer=s.recvfrom(1452); s.sendto(data,peer); s.close()
            """
        }
        if mode == "myudp-securelink" || mode == "myudp-secure-mux" {
            return """
            import hashlib, hmac, socket, struct
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            PREFIX = \(mode == "myudp-secure-mux" ? "b''" : "b'python:'")
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            def recv():
                wire,peer=s.recvfrom(1452); assert wire[0]==1 and wire[19:21]==b'\\x01\\x01'
                return wire[27:],int.from_bytes(wire[23:25],'big'),peer
            def send(payload,counter,peer):
                batch=b'\\x01\\x01'+struct.pack('!H',4+len(payload))+struct.pack('!HH',counter,len(payload))+payload
                s.sendto(b'\\x01'+struct.pack('!HQQ',len(batch),0,0)+batch,peer)
            def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
            def expand(prk,info,length):
                out=b''; prior=b''
                for i in range(1,(length+31)//32+1): prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
                return out[:length]
            hello,counter,peer=recv(); sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
            proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest(); send(header(2,sid,0)+sn+b'\\x01'+proof,counter,peer)
            salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn; material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
            client_proof,counter,peer=recv(); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''; ack=header(4,sid,1); send(ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack),counter,peer)
            app,counter,peer=recv(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(2).to_bytes(8,'big'),app[20:],app[:20]); response=header(4,sid,2); send(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(2).to_bytes(8,'big'),PREFIX+plain,response),counter,peer); s.close()
            """
        }
        if mode == "myudp" {
            return """
            import socket
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()[1], flush=True)
            data,peer=s.recvfrom(1452)
            assert len(data)>=27 and data[0]==1 and data[19:21]==b'\\x01\\x01'
            s.sendto(data,peer); s.close()
            """
        }
        if mode == "tcp-reconnect" || mode == "tcp-drop-then-echo" || mode == "tcp-mux-reconnect" {
            return """
            import socket, struct
            DROP_FIRST = \(mode == "tcp-drop-then-echo" ? "True" : "False")
            MUX = \(mode == "tcp-mux-reconnect" ? "True" : "False")
            s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(2); print(s.getsockname()[1], flush=True)
            for i in range(2):
                c,_=s.accept()
                def nread(n):
                    b=b''
                    while len(b)<n:
                        x=c.recv(n-len(b))
                        if not x: raise RuntimeError('eof')
                        b+=x
                    return b
                for j in range(2 if MUX else 1):
                    h=nread(4); n=struct.unpack('!I',h)[0]; b=nread(n); assert b[:1]==b'\\x00'
                    if not DROP_FIRST or i == 1: c.sendall(h+b)
                c.close()
            s.close()
            """
        }
        return """
        import base64, hashlib, hmac, socket, struct
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        MODE = "\(mode)"
        s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True)
        c,_=s.accept()
        def nread(n):
            b=b''
            while len(b)<n:
                x=c.recv(n-len(b))
                if not x: raise RuntimeError('eof')
                b+=x
            return b
        if MODE.startswith('ws'):
            r=b''
            while b'\\r\\n\\r\\n' not in r: r+=c.recv(4096)
            key=[x.split(b':',1)[1].strip() for x in r.split(b'\\r\\n') if x.lower().startswith(b'sec-websocket-key:')][0]
            accept=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            c.sendall(b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: '+accept+b'\\r\\n\\r\\n')
        def read_payload():
            if MODE.startswith('tcp'):
                h=nread(4); n=struct.unpack('!I',h)[0]; b=nread(n); assert b[:1]==b'\\x00'; return b[1:]
            a,b=nread(2); assert a==130 and b&128; n=b&127
            if n==126: n=int.from_bytes(nread(2),'big')
            elif n==127: n=int.from_bytes(nread(8),'big')
            m=nread(4); return bytes(x^m[i%4] for i,x in enumerate(nread(n)))
        def write_payload(p):
            if MODE.startswith('tcp'):
                c.sendall(struct.pack('!I',len(p)+1)+b'\\x00'+p); return
            if len(p)<126: c.sendall(bytes([130,len(p)])+p)
            else: c.sendall(bytes([130,126])+len(p).to_bytes(2,'big')+p)
        def header(t,sid,counter): return bytes([1,t,0,0])+sid.to_bytes(8,'big')+counter.to_bytes(8,'big')
        def expand(prk,info,length):
            out=b''; prior=b''
            for i in range(1,(length+31)//32+1):
                prior=hmac.new(prk,prior+info+bytes([i]),hashlib.sha256).digest(); out+=prior
            return out[:length]
        if MODE.endswith('securelink'):
            hello=read_payload(); assert hello[:2]==b'\\x01\\x01' and hello[20+32:20+34]==b'\\x01\\x00'
            sid=int.from_bytes(hello[4:12],'big'); cn=hello[20:52]; sn=bytes(range(32)); psk=b'linux-swift-psk'
            proof=hmac.new(psk,b'obstaclebridge-securelink-server-proof-v1|'+sid.to_bytes(8,'big')+cn+sn,hashlib.sha256).digest()
            write_payload(header(2,sid,0)+sn+b'\\x01'+proof)
            salt=hashlib.sha256(psk).digest(); info=b'obstaclebridge-securelink-psk-v1|'+sid.to_bytes(8,'big')+cn+sn
            material=expand(hmac.new(salt,psk+cn+sn,hashlib.sha256).digest(),info,64); c2s,s2c=material[:32],material[32:]
            client_proof=read_payload(); assert ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+(1).to_bytes(8,'big'),client_proof[20:],client_proof[:20])==b''
            ack=header(4,sid,1); write_payload(ack+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+(1).to_bytes(8,'big'),b'',ack))
            for counter in (2,3):
                app=read_payload(); plain=ChaCha20Poly1305(c2s).decrypt(b'\\0'*4+counter.to_bytes(8,'big'),app[20:],app[:20])
                response=header(4,sid,counter); write_payload(response+ChaCha20Poly1305(s2c).encrypt(b'\\0'*4+counter.to_bytes(8,'big'),b'python:'+plain,response))
        else:
            payload=read_payload(); write_payload(payload)
        c.close(); s.close()
        """
    }
}

private enum OverlayTestError: Error { case peerDidNotStart }
