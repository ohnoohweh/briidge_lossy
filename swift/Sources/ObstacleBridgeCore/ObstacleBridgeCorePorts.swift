import Foundation

/// OS-neutral endpoint value. DNS resolution and socket ownership remain below
/// this contract; core code never receives a sockaddr, URLSession, or handle.
public struct ObstacleBridgeEndpoint: Equatable, Hashable, Sendable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

/// A normalized textual IP value. Parsing and platform-native address storage
/// are adapter responsibilities until the typed IP model lands in LSW-R003.
public struct ObstacleBridgeIPAddress: Equatable, Hashable, Sendable {
    public let text: String

    public init(_ text: String) {
        self.text = text
    }
}

public enum ObstacleBridgeCoreEvent: Equatable, Sendable {
    case transportConnected(epoch: UInt64, endpoint: ObstacleBridgeEndpoint)
    case transportDisconnected(epoch: UInt64, reason: String)
    case applicationPayload(epoch: UInt64, payload: Data)
    case diagnostic(epoch: UInt64, name: String, value: String)
}

public enum ObstacleBridgeCorePortError: Error, Equatable, Sendable {
    case unavailable
    case closed
    case invalidInput
    case ioFailure(String)
}

public protocol ObstacleBridgeClock: Sendable {
    func nowNanoseconds() -> UInt64
}

public protocol ObstacleBridgeScheduledTask: Sendable {
    func cancel()
}

public protocol ObstacleBridgeScheduler: Sendable {
    func schedule(afterNanoseconds: UInt64, _ action: @escaping @Sendable () -> Void) -> any ObstacleBridgeScheduledTask
}

public protocol ObstacleBridgeEntropySource: Sendable {
    func bytes(count: Int) throws -> Data
}

public protocol ObstacleBridgeStream: AnyObject, Sendable {
    func send(_ payload: Data) throws
    func receive() throws -> Data
    func close()
}

public protocol ObstacleBridgeDatagramTransport: AnyObject, Sendable {
    func send(_ payload: Data, to endpoint: ObstacleBridgeEndpoint) throws
    func receive() throws -> (payload: Data, endpoint: ObstacleBridgeEndpoint)
    func close()
}

public protocol ObstacleBridgeListener: AnyObject, Sendable {
    func accept() throws -> any ObstacleBridgeStream
    func close()
}

public protocol ObstacleBridgeResolver: Sendable {
    func resolve(_ host: String, port: UInt16) throws -> [ObstacleBridgeEndpoint]
}

public protocol ObstacleBridgePacketDevice: AnyObject, Sendable {
    var name: String { get }
    func readPacket() throws -> Data
    func writePacket(_ packet: Data) throws
    func close()
}

public protocol ObstacleBridgeCompressionEngine: Sendable {
    func compress(_ input: Data) throws -> Data
    func decompress(_ input: Data, maximumOutputSize: Int) throws -> Data
}

public protocol ObstacleBridgePersistence: Sendable {
    func load(key: String) throws -> Data?
    func save(_ value: Data, key: String) throws
    func remove(key: String) throws
}

public protocol ObstacleBridgeHookExecutor: Sendable {
    func run(name: String, arguments: [String], environment: [String: String]) throws
}
