import Foundation
import Testing
@testable import ObstacleBridgeCore

struct ObstacleBridgeServiceCatalogTests {
    private let first = ObstacleBridgeServiceSpec(
        serviceID: 1, name: "first", listenProtocol: 1,
        listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: 1,
        targetHost: "127.0.0.1", targetPort: 7002
    )
    private let second = ObstacleBridgeServiceSpec(
        serviceID: 2, name: "second", listenProtocol: 0,
        listenHost: "127.0.0.1", listenPort: 7003, targetProtocol: 0,
        targetHost: "127.0.0.1", targetPort: 7004
    )

    @Test func replacementIsAtomicAndRejectsSameEpochReplays() throws {
        let store = ObstacleBridgeServiceCatalogStore()
        let initial = try store.install(instanceID: 7, connectionSequence: 1, services: [first])
        #expect(initial.accepted)
        #expect(initial.removed.isEmpty)
        #expect(initial.installed == [first])

        let replay = try store.install(instanceID: 7, connectionSequence: 1, services: [second])
        #expect(!replay.accepted)
        #expect(replay.installed == [first])

        let replacement = try store.install(instanceID: 7, connectionSequence: 2, services: [second])
        #expect(replacement.accepted)
        #expect(replacement.removed == [first])
        #expect(replacement.installed == [second])
        #expect(store.withdraw().removed == [second])
    }

    @Test func catalogValidationIsPortable() {
        let duplicate = ObstacleBridgeServiceSpec(
            serviceID: 1, name: "duplicate", listenProtocol: 1,
            listenHost: "127.0.0.1", listenPort: 7005, targetProtocol: 1,
            targetHost: "127.0.0.1", targetPort: 7006
        )
        #expect(throws: ObstacleBridgeServiceCatalogError.duplicateServiceID) {
            try ObstacleBridgeServiceCatalogStore().install(instanceID: 1, connectionSequence: 1, services: [first, duplicate])
        }
    }
}
