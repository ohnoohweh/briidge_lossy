import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
import ObstacleBridgeCore
import ObstacleBridgeDesktopShared
#if os(Linux)
import Glibc
#endif

private final class NativeAdminStatusResponse: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Data()

    func store(_ response: Data?) {
        lock.lock(); defer { lock.unlock() }
        value = response ?? Data()
    }

    func load() -> Data {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

struct ObstacleBridgeLinuxTunDeviceTests {
    private func ipv4Packet() -> Data { Data([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) }

    @Test func rejectsUnsafeInterfaceNamesAndPackets() throws {
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidInterfaceName) {
            _ = try ObstacleBridgeLinuxTunDevice(interfaceName: "invalid/interface", mtu: 1500, packetSink: { _ in })
        }
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidMTU) {
            _ = try ObstacleBridgeLinuxTunDevice(interfaceName: "obtest0", mtu: 67, packetSink: { _ in })
        }
        let pair = try makeSocketPair()
        defer { close(pair.1) }
        let device = try ObstacleBridgeLinuxTunDevice(testFileDescriptor: pair.0, packetSink: { _ in })
        defer { device.stop() }
        #expect(throws: ObstacleBridgeLinuxTunDeviceError.invalidPacketVersion(0)) { try device.writePacket(Data([0])) }
    }

    @Test func ownsBidirectionalNonBlockingPacketIO() throws {
        let pair = try makeSocketPair()
        defer { close(pair.1) }
        let received = expectation()
        let lock = NSLock()
        var packets: [Data] = []
        let device = try ObstacleBridgeLinuxTunDevice(testFileDescriptor: pair.0, packetSink: {
            lock.lock(); packets.append($0); lock.unlock(); received.signal()
        })
        defer { device.stop() }

        let inbound = ipv4Packet()
        try writeAll(inbound, to: pair.1)
        #expect(received.wait(timeout: .now() + 1) == .success)
        lock.lock(); let captured = packets; lock.unlock()
        #expect(captured == [inbound])

        let outbound = Data([0x60, 0, 0, 0, 0, 0, 17, 64] + Array(repeating: 0, count: 32))
        try device.writePacket(outbound)
        #expect(try readExactly(outbound.count, from: pair.1) == outbound)
    }

    @Test func nativeAdminChildUsesInheritedControlAndExitsOnOwnerLoss() throws {
        let control = try makeSocketPair()
        let lifetime = try makeSocketPair()
        let log = try makeDatagramSocketPair()
        let childControl = dup(control.1)
        let childLifetime = dup(lifetime.1)
        let childLog = dup(log.1)
        guard childControl >= 0, childLifetime >= 0, childLog >= 0 else { throw POSIXError(.EMFILE) }
        close(control.1); close(lifetime.1); close(log.1)
        defer { close(control.0) }
        defer { close(log.0) }
        var parentLifetimeFD = lifetime.0
        defer {
            if parentLifetimeFD >= 0 { close(parentLifetimeFD) }
        }
        let stopped = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { stopped.signal() }
            try? ObstacleBridgeNativeAdminWorker.run(
                controlFD: childControl,
                lifetimeFD: childLifetime,
                logFD: childLog,
                generation: 7,
                serviceFactory: { arguments, parentRPC in
                    let service = try ObstacleBridgeNativeAdminLinuxService(arguments: arguments, parentRPC: parentRPC)
                    return .init(port: service.port, stop: { service.stop() })
                }
            )
        }

        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .hello, generation: 7, value: [
            "v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": 7,
        ]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "worker.hello")
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .request, generation: 7, value: ["v": 1, "kind": "admin.start", "args": ["admin_web_bind": "127.0.0.1", "admin_web_port": 0, "admin_web_username": "admin", "admin_web_password": "secret", "admin_web_token": "control", "admin_web_name": "native-test", "overlay_transport": "tcp", "dashboard": true, "telemetry_spool_directory": "/tmp/obstaclebridge-telemetry"], "log_root_level": 0]), to: control.0)
        let request = try readControl(from: control.0)
        #expect(request["kind"] as? String == "admin.call")
        #expect(request["id"] as? String == "bootstrap-status")
        #expect(request["method"] as? String == "get_status_snapshot")
        #expect((request["args"] as? [Any])?.isEmpty == true)
        #expect(request["kwargs"] as? [String: Any] != nil)
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": "bootstrap-status", "ok": true, "result": [String: Any]()]), to: control.0)
        let ready = try readControl(from: control.0)
        #expect(ready["kind"] as? String == "admin.ready")
        #expect(ready["implementation"] as? String == "native")
        let port = (ready["port"] as? NSNumber)?.intValue ?? 0
        #expect(port > 0)
        let index = try nativeAdminHTTPRequest(port: port, method: "GET", path: "/")
        #expect(String(data: index, encoding: .utf8)?.contains("HTTP/1.1 200 OK") == true)
        #expect(String(data: index, encoding: .utf8)?.contains("<!doctype html>") == true)
        let rejected = try nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/status")
        #expect(String(data: rejected, encoding: .utf8)?.contains("HTTP/1.1 401 Unauthorized") == true)
        let challengeResponse = try nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/auth/challenge")
        let challengeBody = try JSONSerialization.jsonObject(with: try httpBody(challengeResponse)) as? [String: Any]
        let challengeID = challengeBody?["challenge_id"] as? String ?? ""
        let seed = challengeBody?["seed"] as? String ?? ""
        #expect(!challengeID.isEmpty)
        let proof = ObstacleBridgeCrypto.sha256(Data("\(seed):admin:secret".utf8)).map { String(format: "%02x", $0) }.joined()
        let loginBody = try JSONSerialization.data(withJSONObject: ["challenge_id": challengeID, "proof": proof])
        let loginResponse = try nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/auth/login", body: loginBody)
        #expect(String(data: loginResponse, encoding: .utf8)?.contains("HTTP/1.1 200 OK") == true)
        let cookie = String(data: loginResponse, encoding: .utf8)?
            .split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("set-cookie:") })?
            .split(separator: ":", maxSplits: 1).dropFirst().first?
            .split(separator: ";", maxSplits: 1).first.map { String($0).trimmingCharacters(in: .whitespaces) } ?? ""
        #expect(!cookie.isEmpty)
        let healthResponse = try nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/health", headers: ["Cookie": cookie])
        #expect(String(data: healthResponse, encoding: .utf8)?.contains("HTTP/1.1 200 OK") == true)
        #expect(String(data: healthResponse, encoding: .utf8)?.contains("{\"ok\":true}") == true)
        let malformedWebSocketResponse = try nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/live?topic=status", headers: ["Cookie": cookie, "Upgrade": "websocket", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="])
        #expect(String(data: malformedWebSocketResponse, encoding: .utf8)?.contains("HTTP/1.1 400 Bad Request") == true)
        let websocketRPCReady = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { websocketRPCReady.signal() }
            do {
                guard let statusRequest = try? self.readControl(from: control.0),
                      let statusRequestID = statusRequest["id"] as? String else { return }
                try self.writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": statusRequestID, "ok": true, "result": ["state": "live"]]), to: control.0)
                guard let peersRequest = try? self.readControl(from: control.0),
                      let peersRequestID = peersRequest["id"] as? String else { return }
                try self.writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": peersRequestID, "ok": true, "result": ["peers": [["id": "0:1"]]]]), to: control.0)
            } catch {
                return
            }
        }
        let websocketResponse = try nativeAdminWebSocketRequest(port: port, cookie: cookie)
        #expect(websocketRPCReady.wait(timeout: .now() + 1) == .success)
        #expect(websocketResponse.range(of: Data("HTTP/1.1 101 Switching Protocols".utf8)) != nil)
        #expect(websocketResponse.range(of: Data("\"type\":\"hello\"".utf8)) != nil)
        #expect(websocketResponse.range(of: Data("\"type\":\"status\"".utf8)) != nil)
        #expect(websocketResponse.range(of: Data("\"state\":\"live\"".utf8)) != nil)
        #expect(websocketResponse.range(of: Data("\"type\":\"peers\"".utf8)) != nil)
        #expect(websocketResponse.range(of: Data("\"id\":\"0:1\"".utf8)) != nil)
        let responseReady = DispatchSemaphore(value: 0)
        let response = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { responseReady.signal() }
            let result = try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/status", headers: ["Cookie": cookie])
            response.store(result)
        }
        let statusRequest = try readControl(from: control.0)
        #expect(statusRequest["kind"] as? String == "admin.call")
        #expect(statusRequest["method"] as? String == "get_status_snapshot")
        let statusRequestID = statusRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": statusRequestID, "ok": true, "result": ["state": "ready", "redacted": true]]), to: control.0)
        #expect(responseReady.wait(timeout: .now() + 1) == .success)
        let statusResponse = response.load()
        #expect(String(data: statusResponse, encoding: .utf8)?.contains("HTTP/1.1 200 OK") == true)
        #expect(String(data: statusResponse, encoding: .utf8)?.contains("\"state\":\"ready\"") == true)
        let metaReady = DispatchSemaphore(value: 0)
        let metaResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { metaReady.signal() }
            metaResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/meta", headers: ["Cookie": cookie]))
        }
        let metaRequest = try readControl(from: control.0)
        #expect(metaRequest["method"] as? String == "get_status_snapshot")
        let metaRequestID = metaRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": metaRequestID, "ok": true, "result": ["build": ["commit": "abc123"]]]), to: control.0)
        #expect(metaReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: metaResponse.load(), encoding: .utf8)?.contains("\"app\":\"ObstacleBridgeLinux\"") == true)
        #expect(String(data: metaResponse.load(), encoding: .utf8)?.contains("\"commit\":\"abc123\"") == true)
        #expect(String(data: metaResponse.load(), encoding: .utf8)?.contains("\"admin_web_name\":\"native-test\"") == true)
        #expect(String(data: metaResponse.load(), encoding: .utf8)?.contains("\"overlay_transport\":\"tcp\"") == true)
        #expect(String(data: metaResponse.load(), encoding: .utf8)?.contains("\"dashboard_enabled\":true") == true)
        let telemetryReady = DispatchSemaphore(value: 0)
        let telemetryResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { telemetryReady.signal() }
            telemetryResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/telemetry", headers: ["Cookie": cookie]))
        }
        let telemetryRequest = try readControl(from: control.0)
        #expect(telemetryRequest["method"] as? String == "get_telemetry_client_snapshot")
        let telemetryRequestID = telemetryRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": telemetryRequestID, "ok": true, "result": ["enabled": true, "worker_state": "running"]]), to: control.0)
        #expect(telemetryReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: telemetryResponse.load(), encoding: .utf8)?.contains("\"worker_state\":\"running\"") == true)
        let tunStatusReady = DispatchSemaphore(value: 0)
        let tunStatusResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { tunStatusReady.signal() }
            tunStatusResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/tun-routing/status", headers: ["Cookie": cookie]))
        }
        let tunStatusRequest = try readControl(from: control.0)
        #expect(tunStatusRequest["method"] as? String == "get_status_snapshot")
        let tunStatusRequestID = tunStatusRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: [
            "v": 1, "kind": "admin.reply", "id": tunStatusRequestID, "ok": true,
            "result": ["tun": [["id": "tun0"]], "tun_helper": ["runtime": ["included_routes_active": true, "included_routes_toggle_supported": true]]],
        ]), to: control.0)
        #expect(tunStatusReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: tunStatusResponse.load(), encoding: .utf8)?.contains("\"id\":\"tun0\"") == true)
        #expect(String(data: tunStatusResponse.load(), encoding: .utf8)?.contains("\"supported\":true") == true)
        let liveReady = DispatchSemaphore(value: 0)
        let liveResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { liveReady.signal() }
            liveResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/live?topic=peers", headers: ["Cookie": cookie]))
        }
        let liveRequest = try readControl(from: control.0)
        #expect(liveRequest["method"] as? String == "get_peer_connections_snapshot")
        let liveRequestID = liveRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": liveRequestID, "ok": true, "result": ["peers": [["id": "0:1"]]]]), to: control.0)
        #expect(liveReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: liveResponse.load(), encoding: .utf8)?.contains("\"id\":\"0:1\"") == true)
        let configReady = DispatchSemaphore(value: 0)
        let configResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { configReady.signal() }
            configResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/config", headers: ["Cookie": cookie]))
        }
        let configRequest = try readControl(from: control.0)
        #expect(configRequest["method"] as? String == "get_config_snapshot")
        let configRequestID = configRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": configRequestID, "ok": true, "result": ["config": ["redacted": true]]]), to: control.0)
        let schemaRequest = try readControl(from: control.0)
        #expect(schemaRequest["method"] as? String == "get_config_schema_snapshot")
        let schemaRequestID = schemaRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": schemaRequestID, "ok": true, "result": ["fields": ["debug_logging"]]]), to: control.0)
        #expect(configReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: configResponse.load(), encoding: .utf8)?.contains("\"redacted\":true") == true)
        #expect(String(data: configResponse.load(), encoding: .utf8)?.contains("\"schema\":{\"fields\":[\"debug_logging\"]}") == true)
        let updates: [String: Any] = ["debug_logging": ["debug_enabled": true]]
        let challengeRequestBody = try JSONSerialization.data(withJSONObject: ["updates": updates], options: [.sortedKeys])
        let configChallengeResponse = try nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/config/challenge", body: challengeRequestBody, headers: ["Cookie": cookie])
        let configChallenge = try JSONSerialization.jsonObject(with: try httpBody(configChallengeResponse)) as? [String: Any]
        let configChallengeID = configChallenge?["challenge_id"] as? String ?? ""
        let configSeed = configChallenge?["seed"] as? String ?? ""
        let canonicalUpdates = try JSONSerialization.data(withJSONObject: updates, options: [.sortedKeys])
        let updatesDigest = ObstacleBridgeCrypto.sha256(canonicalUpdates).map { String(format: "%02x", $0) }.joined()
        let configProof = ObstacleBridgeCrypto.sha256(Data("\(configSeed):admin:secret:\(updatesDigest)".utf8)).map { String(format: "%02x", $0) }.joined()
        let confirmedUpdateBody = try JSONSerialization.data(withJSONObject: ["updates": updates, "challenge_id": configChallengeID, "proof": configProof], options: [.sortedKeys])
        let updateReady = DispatchSemaphore(value: 0)
        let updateResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { updateReady.signal() }
            updateResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/config", body: confirmedUpdateBody, headers: ["Cookie": cookie]))
        }
        let updateRequest = try readControl(from: control.0)
        #expect(updateRequest["method"] as? String == "update_config")
        #expect(((updateRequest["args"] as? [[String: Any]])?.first?["debug_logging"] as? [String: Bool])?["debug_enabled"] == true)
        let updateRequestID = updateRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": updateRequestID, "ok": true, "result": [true, ""]]), to: control.0)
        let refreshedConfigRequest = try readControl(from: control.0)
        #expect(refreshedConfigRequest["method"] as? String == "get_config_snapshot")
        let refreshedConfigRequestID = refreshedConfigRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": refreshedConfigRequestID, "ok": true, "result": ["debug_logging": ["debug_enabled": true]]]), to: control.0)
        #expect(updateReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: updateResponse.load(), encoding: .utf8)?.contains("\"ok\":true") == true)
        #expect(String(data: updateResponse.load(), encoding: .utf8)?.contains("\"debug_enabled\":true") == true)
        let remoteServicesBody = try JSONSerialization.data(withJSONObject: ["remote_servers": [["service": "echo", "host": "127.0.0.1", "port": 7]]])
        let remoteServicesReady = DispatchSemaphore(value: 0)
        let remoteServicesResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { remoteServicesReady.signal() }
            remoteServicesResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/channelmux/remote-services", body: remoteServicesBody, headers: ["Cookie": cookie]))
        }
        let remoteServicesRequest = try readControl(from: control.0)
        #expect(remoteServicesRequest["method"] as? String == "replace_remote_services_catalog")
        #expect((remoteServicesRequest["args"] as? [[Any]])?.first?.count == 1)
        let remoteServicesRequestID = remoteServicesRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": remoteServicesRequestID, "ok": true, "result": [true, ""]]), to: control.0)
        #expect(remoteServicesReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: remoteServicesResponse.load(), encoding: .utf8)?.contains("\"service\":\"echo\"") == true)
        let reconnectBody = try JSONSerialization.data(withJSONObject: ["peer_id": "0:1"])
        let blockedReconnect = try nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/reconnect", body: reconnectBody, headers: ["Cookie": cookie])
        #expect(String(data: blockedReconnect, encoding: .utf8)?.contains("HTTP/1.1 403 Forbidden") == true)
        let reconnectReady = DispatchSemaphore(value: 0)
        let reconnectResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { reconnectReady.signal() }
            reconnectResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/reconnect", body: reconnectBody, headers: ["Cookie": cookie, "Authorization": "Bearer control"]))
        }
        let reconnectRequest = try readControl(from: control.0)
        #expect(reconnectRequest["method"] as? String == "request_overlay_reconnect")
        #expect((reconnectRequest["kwargs"] as? [String: Any])?["target_peer_id"] as? String == "0:1")
        let reconnectRequestID = reconnectRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": reconnectRequestID, "ok": true, "result": ["ok": true, "requested": 1]]), to: control.0)
        #expect(reconnectReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: reconnectResponse.load(), encoding: .utf8)?.contains("\"requested\":1") == true)
        let rekeyReady = DispatchSemaphore(value: 0)
        let rekeyResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { rekeyReady.signal() }
            rekeyResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/secure-link/rekey", body: reconnectBody, headers: ["Cookie": cookie]))
        }
        let rekeyRequest = try readControl(from: control.0)
        #expect(rekeyRequest["method"] as? String == "request_secure_link_rekey")
        #expect((rekeyRequest["kwargs"] as? [String: Any])?["target_peer_id"] as? String == "0:1")
        let rekeyRequestID = rekeyRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": rekeyRequestID, "ok": true, "result": ["ok": true, "requested": 1]]), to: control.0)
        #expect(rekeyReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: rekeyResponse.load(), encoding: .utf8)?.contains("\"requested\":1") == true)
        let reloadBody = try JSONSerialization.data(withJSONObject: ["scope": "all", "peer_id": "0:1"])
        let reloadReady = DispatchSemaphore(value: 0)
        let reloadResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { reloadReady.signal() }
            reloadResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/secure-link/reload", body: reloadBody, headers: ["Cookie": cookie]))
        }
        let reloadRequest = try readControl(from: control.0)
        #expect(reloadRequest["method"] as? String == "request_secure_link_reload")
        #expect((reloadRequest["kwargs"] as? [String: Any])?["scope"] as? String == "all")
        #expect((reloadRequest["kwargs"] as? [String: Any])?["target_peer_id"] as? String == "0:1")
        let reloadRequestID = reloadRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": reloadRequestID, "ok": true, "result": ["ok": true, "reloaded": 1]]), to: control.0)
        #expect(reloadReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: reloadResponse.load(), encoding: .utf8)?.contains("\"reloaded\":1") == true)
        let tunRepairReady = DispatchSemaphore(value: 0)
        let tunRepairResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { tunRepairReady.signal() }
            tunRepairResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/tun-helper/repair", headers: ["Cookie": cookie, "Authorization": "Bearer control"]))
        }
        let tunRepairRequest = try readControl(from: control.0)
        #expect(tunRepairRequest["method"] as? String == "request_tun_helper_repair")
        let tunRepairRequestID = tunRepairRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": tunRepairRequestID, "ok": true, "result": ["ok": true, "repaired": ["tun0"], "failed": []]]), to: control.0)
        #expect(tunRepairReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: tunRepairResponse.load(), encoding: .utf8)?.contains("\"repaired\":[\"tun0\"]") == true)
        let tunControlBody = try JSONSerialization.data(withJSONObject: ["enabled": true])
        let blockedTunControl = try nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/tun-routing/control", body: tunControlBody, headers: ["Cookie": cookie])
        #expect(String(data: blockedTunControl, encoding: .utf8)?.contains("HTTP/1.1 403 Forbidden") == true)
        let tunControlReady = DispatchSemaphore(value: 0)
        let tunControlResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { tunControlReady.signal() }
            tunControlResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/tun-routing/control", body: tunControlBody, headers: ["Cookie": cookie, "Authorization": "Bearer control"]))
        }
        let tunControlRequest = try readControl(from: control.0)
        #expect(tunControlRequest["method"] as? String == "request_tun_enabled")
        #expect((tunControlRequest["kwargs"] as? [String: Any])?["enabled"] as? Bool == true)
        let tunControlRequestID = tunControlRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": tunControlRequestID, "ok": true, "result": ["ok": true, "enabled": true]]), to: control.0)
        #expect(tunControlReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: tunControlResponse.load(), encoding: .utf8)?.contains("\"enabled\":true") == true)
        let restartReady = DispatchSemaphore(value: 0)
        let restartResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { restartReady.signal() }
            restartResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/restart", headers: ["Cookie": cookie, "Authorization": "Bearer control"]))
        }
        let restartRequest = try readControl(from: control.0)
        #expect(restartRequest["method"] as? String == "request_restart")
        #expect((restartRequest["kwargs"] as? [String: Any])?["reason"] as? String == "admin_web:/api/restart")
        let restartRequestID = restartRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": restartRequestID, "ok": true, "result": NSNull()]), to: control.0)
        #expect(restartReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: restartResponse.load(), encoding: .utf8)?.contains("\"restarting\":true") == true)
        let shutdownReady = DispatchSemaphore(value: 0)
        let shutdownResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { shutdownReady.signal() }
            shutdownResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "POST", path: "/api/shutdown", headers: ["Cookie": cookie, "Authorization": "Bearer control"]))
        }
        let shutdownRequest = try readControl(from: control.0)
        #expect(shutdownRequest["method"] as? String == "request_shutdown")
        #expect(((shutdownRequest["kwargs"] as? [String: Any])?["exit_code"] as? NSNumber)?.intValue == 76)
        #expect((shutdownRequest["kwargs"] as? [String: Any])?["reason"] as? String == "admin_web:/api/shutdown")
        let shutdownRequestID = shutdownRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": shutdownRequestID, "ok": true, "result": NSNull()]), to: control.0)
        #expect(shutdownReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: shutdownResponse.load(), encoding: .utf8)?.contains("\"shutting_down\":true") == true)
        let logsReady = DispatchSemaphore(value: 0)
        let logsResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { logsReady.signal() }
            logsResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/logs?limit=7", headers: ["Cookie": cookie]))
        }
        let logsRequest = try readControl(from: control.0)
        #expect(logsRequest["method"] as? String == "fetch_logs")
        #expect((logsRequest["args"] as? [NSNumber])?.first?.intValue == 7)
        let logsRequestID = logsRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": logsRequestID, "ok": true, "result": ["native_admin_ready"]]), to: control.0)
        #expect(logsReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: logsResponse.load(), encoding: .utf8)?.contains("native_admin_ready") == true)
        let connectionsReady = DispatchSemaphore(value: 0)
        let connectionsResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { connectionsReady.signal() }
            connectionsResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/connections", headers: ["Cookie": cookie]))
        }
        let connectionsRequest = try readControl(from: control.0)
        #expect(connectionsRequest["method"] as? String == "get_connections_snapshot")
        let connectionsRequestID = connectionsRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": connectionsRequestID, "ok": true, "result": ["tcp": [["state": "open"]]]]), to: control.0)
        #expect(connectionsReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: connectionsResponse.load(), encoding: .utf8)?.contains("\"state\":\"open\"") == true)
        let peersReady = DispatchSemaphore(value: 0)
        let peersResponse = NativeAdminStatusResponse()
        DispatchQueue.global().async {
            defer { peersReady.signal() }
            peersResponse.store(try? self.nativeAdminHTTPRequest(port: port, method: "GET", path: "/api/peers", headers: ["Cookie": cookie]))
        }
        let peersRequest = try readControl(from: control.0)
        #expect(peersRequest["method"] as? String == "get_peer_connections_snapshot")
        let peersRequestID = peersRequest["id"] as? String ?? ""
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: ["v": 1, "kind": "admin.reply", "id": peersRequestID, "ok": true, "result": ["peers": [["id": "0:1"]]]]), to: control.0)
        #expect(peersReady.wait(timeout: .now() + 1) == .success)
        #expect(String(data: peersResponse.load(), encoding: .utf8)?.contains("\"id\":\"0:1\"") == true)
        let record = try JSONSerialization.jsonObject(with: readDatagram(from: log.0)) as? [String: Any]
        #expect(record?["name"] as? String == "admin.native")
        #expect(record?["message"] as? String == "native_admin_ready")
        close(parentLifetimeFD)
        parentLifetimeFD = -1
        #expect(stopped.wait(timeout: .now() + 1) == .success)
    }

    @Test func nativeAdminChildBoundsBootstrapStatusReplyWait() throws {
        let control = try makeSocketPair()
        let lifetime = try makeSocketPair()
        let childControl = dup(control.1)
        let childLifetime = dup(lifetime.1)
        guard childControl >= 0, childLifetime >= 0 else { throw POSIXError(.EMFILE) }
        close(control.1); close(lifetime.1)
        defer { close(control.0); close(lifetime.0) }
        let stopped = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { stopped.signal() }
            try? ObstacleBridgeNativeAdminWorker.run(controlFD: childControl, lifetimeFD: childLifetime, generation: 9)
        }

        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .hello, generation: 9, value: [
            "v": 1, "kind": "worker.hello", "role": "supervisor", "capabilities": ["admin.control"], "generation": 9,
        ]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "worker.hello")
        try writeAll(try ObstacleBridgeWorkerIPC.encodeControl(kind: .request, generation: 9, value: ["v": 1, "kind": "admin.start", "args": [String: Any]()]), to: control.0)
        #expect(try readControl(from: control.0)["kind"] as? String == "admin.call")
        #expect(stopped.wait(timeout: .now() + 2) == .success)
    }

    @Test func nativeAdminChildRejectsNonUnixStreamCapabilities() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard pipe(&descriptors) == 0 else { throw POSIXError(.EMFILE) }
        defer { close(descriptors[0]); close(descriptors[1]) }
        #expect(throws: (any Error).self) {
            try ObstacleBridgeNativeAdminWorker.run(controlFD: descriptors[0], lifetimeFD: descriptors[1], generation: 1)
        }
    }

    /// This is intentionally opt-in: opening a kernel TUN device requires
    /// CAP_NET_ADMIN and must not make ordinary CI depend on host privileges.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OBSTACLEBRIDGE_PRIVILEGED_TUN"] == "1"))
    func privilegedKernelTunOpensAndAcceptsIPv4() throws {
        let name = "obq\(getpid() % 100_000)"
        let device = try ObstacleBridgeLinuxTunDevice(interfaceName: name, mtu: 1500, packetSink: { _ in })
        defer { device.stop() }
        try device.start()
        #expect(device.actualInterfaceName == name)
        try device.writePacket(ipv4Packet())
    }

    private func expectation() -> DispatchSemaphore { DispatchSemaphore(value: 0) }

    private func makeSocketPair() throws -> (Int32, Int32) {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &descriptors) == 0 else { throw POSIXError(.ENFILE) }
        return (descriptors[0], descriptors[1])
    }

    private func makeDatagramSocketPair() throws -> (Int32, Int32) {
        var descriptors = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &descriptors) == 0 else { throw POSIXError(.ENFILE) }
        return (descriptors[0], descriptors[1])
    }

    private func nativeAdminHTTPRequest(port: Int, method: String, path: String, body: Data = Data(), headers: [String: String] = [:]) throws -> Data {
        let client = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard client >= 0 else { throw POSIXError(.EMFILE) }
        defer { close(client) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard connected == 0 else { throw POSIXError(.ECONNREFUSED) }
        let extraHeaders = headers.map { "\($0.key): \($0.value)\r\n" }.joined()
        try writeAll(Data("\(method) \(path) HTTP/1.1\r\nHost: localhost\r\nContent-Length: \(body.count)\r\n\(extraHeaders)Connection: close\r\n\r\n".utf8) + body, to: client)
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(client, &buffer, buffer.count)
            guard count >= 0 else { throw POSIXError(.EIO) }
            if count == 0 { return result }
            result.append(buffer, count: Int(count))
        }
    }

    private func nativeAdminWebSocketRequest(port: Int, cookie: String) throws -> Data {
        let client = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard client >= 0 else { throw POSIXError(.EMFILE) }
        defer { close(client) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard connected == 0 else { throw POSIXError(.ECONNREFUSED) }
        try writeAll(Data("GET /api/live?topic=status HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: \(cookie)\r\n\r\n".utf8), to: client)
        var output = try readSocketChunk(from: client)
        output.append(try readSocketChunk(from: client))
        let control = try JSONSerialization.data(withJSONObject: ["subscribe": ["peers"], "request": "peers"])
        try writeAll(maskedWebSocketTextFrame(control), to: client)
        output.append(try readSocketChunk(from: client))
        output.append(try readSocketChunk(from: client))
        return output
    }

    private func maskedWebSocketTextFrame(_ payload: Data) -> Data {
        let mask: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        var frame = Data([0x81, 0x80 | UInt8(payload.count)])
        frame.append(contentsOf: mask)
        for (offset, byte) in payload.enumerated() { frame.append(byte ^ mask[offset % mask.count]) }
        return frame
    }

    private func readSocketChunk(from descriptor: Int32) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = read(descriptor, &buffer, buffer.count)
        guard count > 0 else { throw POSIXError(.EIO) }
        return Data(buffer.prefix(Int(count)))
    }

    private func httpBody(_ response: Data) throws -> Data {
        guard let separator = response.range(of: Data("\r\n\r\n".utf8)) else { throw POSIXError(.EPROTO) }
        return Data(response[separator.upperBound...])
    }

    private func readDatagram(from descriptor: Int32) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 8192)
        let count = read(descriptor, &bytes, bytes.count)
        guard count > 0 else { throw POSIXError(.EIO) }
        return Data(bytes.prefix(count))
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let result = data.withUnsafeBytes { bytes in
                write(descriptor, bytes.baseAddress!.advanced(by: offset), data.count - offset)
            }
            guard result > 0 else { throw POSIXError(.EIO) }
            offset += result
        }
    }

    private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
        var output = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let result = output.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress!.advanced(by: offset), count - offset)
            }
            guard result > 0 else { throw POSIXError(.EIO) }
            offset += result
        }
        return Data(output)
    }

    private func readControl(from descriptor: Int32) throws -> [String: Any] {
        let header = try readExactly(ObstacleBridgeWorkerIPC.headerBytes, from: descriptor)
        guard let size = try ObstacleBridgeWorkerIPC.frameSize(header),
              let frame = try ObstacleBridgeWorkerIPC.decode(header + readExactly(size, from: descriptor)).0
        else { throw POSIXError(.EIO) }
        return try ObstacleBridgeWorkerIPC.decodeControl(frame)
    }
}
