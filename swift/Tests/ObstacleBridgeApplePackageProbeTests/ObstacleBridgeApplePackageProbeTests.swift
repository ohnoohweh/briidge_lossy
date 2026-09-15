import Testing
@testable import ObstacleBridgeApplePackageProbe

@Test func importedCoreWireCodecOwnersExecuteForAppleConsumer() throws {
    #expect(ObstacleBridgeApplePackageProbe.endpoint(host: "192.0.2.1", port: 443).port == 443)
    try ObstacleBridgeApplePackageProbe.exerciseWireCodecOwners()
}
