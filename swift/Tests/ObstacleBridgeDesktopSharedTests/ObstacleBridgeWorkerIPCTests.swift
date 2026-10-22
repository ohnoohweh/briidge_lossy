import Foundation
import Testing
@testable import ObstacleBridgeDesktopShared

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
}
