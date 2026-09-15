import Foundation
import Testing
@testable import ObstacleBridgeLinuxAdapters
@testable import ObstacleBridgeCore

struct ObstacleBridgeLinuxServiceCatalogTests {
    @Test func rs3CatalogRoundTripsStructuredServices() throws {
        let service = ObstacleBridgeLinuxServiceSpec(serviceID: 1, name: "echo", listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: 7001, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: 7002)
        let wire = try ObstacleBridgeLinuxServiceCatalog.encode(instanceID: 9, connectionSequence: 3, services: [service])
        #expect(wire.starts(with: Data("RS3".utf8)))
        let decoded = try ObstacleBridgeLinuxServiceCatalog.decode(wire)
        #expect(decoded.instanceID == 9)
        #expect(decoded.connectionSequence == 3)
        #expect(decoded.services == [service])
    }

    @Test func rs3CatalogRejectsMalformedOrMismatchedService() {
        #expect(throws: ObstacleBridgeLinuxServiceCatalogError.invalidPayload) {
            try ObstacleBridgeLinuxServiceCatalog.decode(Data("RS3".utf8))
        }
    }

    @Test func catalogReplacesAndWithdrawsOnlyNewPeerEpochs() throws {
        let first = service(id: 1, port: 7001)
        let second = service(id: 2, port: 7003)
        let store = ObstacleBridgeLinuxServiceCatalogStore()
        let initial = try store.install(instanceID: 9, connectionSequence: 2, services: [first])
        #expect(initial.accepted)
        #expect(initial.removed.isEmpty)
        #expect(initial.installed == [first])

        let replay = try store.install(instanceID: 9, connectionSequence: 2, services: [second])
        #expect(!replay.accepted)
        #expect(replay.installed == [first])

        let replacement = try store.install(instanceID: 9, connectionSequence: 3, services: [second])
        #expect(replacement.accepted)
        #expect(replacement.removed == [first])
        #expect(replacement.installed == [second])

        let freshInstance = try store.install(instanceID: 10, connectionSequence: 1, services: [first])
        #expect(freshInstance.accepted)
        #expect(freshInstance.removed == [second])
        #expect(freshInstance.installed == [first])

        let withdrawn = store.withdraw()
        #expect(withdrawn.removed == [first])
        #expect(withdrawn.installed.isEmpty)
    }

    private func service(id: UInt16, port: Int) -> ObstacleBridgeLinuxServiceSpec {
        .init(serviceID: id, name: nil, listenProtocol: .tcp, listenHost: "127.0.0.1", listenPort: port, targetProtocol: .tcp, targetHost: "127.0.0.1", targetPort: port + 1)
    }
}
