import Foundation
import Testing
@testable import ObstacleBridgeDesktopShared

#if os(Linux)
import Glibc
#else
import Darwin
#endif

struct ObstacleBridgeWorkerIPCTests {
    @Test func controlDecodeRejectsDuplicateObjectMembersAtEveryDepth() throws {
        for payload in [
            #"{"op":"SNAPSHOT","op":"STOP","payload":{}}"#,
            #"{"op":"SNAPSHOT","payload":{"detail":"one","detail":"two"}}"#,
            #"{"op":"SNAPSHOT","\u006fp":"STOP","payload":{}}"#,
        ] {
            let frame = ObstacleBridgeWorkerIPC.Frame(kind: .request, generation: 1, payload: Data(payload.utf8))
            #expect(throws: (any Error).self) { try ObstacleBridgeWorkerIPC.decodeControl(frame) }
        }
    }

    @Test func controlDecodeRetainsValidNestedObjectMembers() throws {
        let payload = #"{"op":"SNAPSHOT","payload":{"detail":"ready","items":[{"id":1},{"id":2}]}}"#
        let frame = ObstacleBridgeWorkerIPC.Frame(kind: .request, generation: 1, payload: Data(payload.utf8))
        let value = try ObstacleBridgeWorkerIPC.decodeControl(frame)
        #expect(value["op"] as? String == "SNAPSHOT")
        #expect((value["payload"] as? [String: Any])?["detail"] as? String == "ready")
    }

    @Test func nativeAdminParentRPCPoisonsChannelAfterStaleReply() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        let socketType = SOCK_STREAM
        guard socketpair(AF_UNIX, socketType, 0, &descriptors) == 0 else { throw POSIXError(.ENFILE) }
        defer { close(descriptors[1]) }
        let child = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        let parent = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: false)
        let rpc = ObstacleBridgeNativeAdminWorker.ParentRPC(control: child, generation: 7)
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { finished.signal() }
            do { _ = try rpc.call(method: "get_status_snapshot", requestID: "first") }
            catch { }
        }
        let request = try readControl(parent)
        #expect(request["id"] as? String == "first")
        parent.write(try ObstacleBridgeWorkerIPC.encodeControl(kind: .response, generation: 7, value: [
            "v": 1, "kind": "admin.reply", "id": "stale", "ok": true, "result": [:],
        ]))
        #expect(finished.wait(timeout: .now() + 1) == .success)
        #expect(throws: (any Error).self) { _ = try rpc.call(method: "get_status_snapshot", requestID: "second") }
    }

    private func readControl(_ handle: FileHandle) throws -> [String: Any] {
        let header = try readExactly(handle, count: ObstacleBridgeWorkerIPC.headerBytes)
        let length = try #require(try ObstacleBridgeWorkerIPC.frameSize(header))
        let (frame, remainder) = try ObstacleBridgeWorkerIPC.decode(header + readExactly(handle, count: length))
        let decoded = try #require(frame)
        #expect(remainder.isEmpty)
        return try ObstacleBridgeWorkerIPC.decodeControl(decoded)
    }

    private func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var output = Data()
        while output.count < count {
            guard let part = try handle.read(upToCount: count - output.count) else { throw POSIXError(.ECONNRESET) }
            guard !part.isEmpty else { throw POSIXError(.ECONNRESET) }
            output.append(part)
        }
        return output
    }
}
