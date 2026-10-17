import Dispatch
import Foundation
import ObstacleBridgeCore

/// Linux HTTPS/mTLS drain owner. All spool sequencing, acknowledgement range
/// validation, byte budget, and backoff remain in Core's upload policy.
public final class ObstacleBridgeLinuxTelemetryUploader: @unchecked Sendable {
    public typealias Executor = (ObstacleBridgeTelemetryUploadPolicy.Request) throws -> (status: Int, body: Data)
    private let policy: ObstacleBridgeTelemetryUploadPolicy
    private let executor: Executor
    private let queue = DispatchQueue(label: "org.obstaclebridge.linux.telemetry-upload")
    private let lock = NSLock()
    private var cancelled = false
    private var attempts: UInt64 = 0
    private var accepted: UInt64 = 0
    private var rejected: UInt64 = 0
    private var lastError = ""

    public init(policy: ObstacleBridgeTelemetryUploadPolicy, certificatePath: String, privateKeyPath: String, trustRootsPath: String, executor: Executor? = nil) {
        self.policy = policy
        self.executor = executor ?? { request in
            try Self.perform(request, certificatePath: certificatePath, privateKeyPath: privateKeyPath, trustRootsPath: trustRootsPath)
        }
    }

    public func uploadOnce() {
        guard let request = policy.nextRequest() else { return }
        lock.lock(); let active = !cancelled; if active { attempts &+= 1 }; lock.unlock()
        guard active else { policy.fail(); return }
        queue.async { [weak self] in
            guard let self else { return }
            do {
                let reply = try self.executor(request)
                guard reply.status == 202,
                      let json = try JSONSerialization.jsonObject(with: reply.body) as? [String: Any],
                      json["ok"] as? Bool == true,
                      let number = json["accepted_through"] as? NSNumber,
                      self.policy.accept(acceptedThrough: number.uint64Value) > 0
                else { throw UploadError.invalidAcknowledgement }
                self.lock.lock(); self.accepted &+= 1; self.lastError = ""; self.lock.unlock()
            } catch {
                self.policy.fail()
                self.lock.lock(); self.rejected &+= 1; self.lastError = String(describing: error).prefix(160).description; self.lock.unlock()
            }
        }
    }

    public func cancel() { lock.lock(); cancelled = true; lock.unlock(); policy.fail() }
    public func statusSnapshot() -> [String: Any] {
        lock.lock(); let snapshot: [String: Any] = ["attempts": attempts, "accepted_batches": accepted, "rejected_batches": rejected, "last_error": lastError.isEmpty ? NSNull() : lastError]; lock.unlock()
        return snapshot.merging(policy.statusSnapshot()) { current, _ in current }
    }

    private static func perform(_ request: ObstacleBridgeTelemetryUploadPolicy.Request, certificatePath: String, privateKeyPath: String, trustRootsPath: String) throws -> (status: Int, body: Data) {
        guard let host = request.endpoint.host else { throw UploadError.invalidEndpoint }
        let port = request.endpoint.port ?? 443
        let connection = try ObstacleBridgeLinuxTLSWebSocketConnection(host: host, port: port, trustRootsPath: trustRootsPath, clientCertificatePath: certificatePath, clientPrivateKeyPath: privateKeyPath, timeoutMilliseconds: 5_000)
        defer { connection.close() }
        let target = request.endpoint.path.isEmpty ? "/" : request.endpoint.path
        let path = request.endpoint.query.map { target + "?" + $0 } ?? target
        let head = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: \(request.payload.count)\r\nConnection: close\r\n\r\n"
        try connection.write(Data(head.utf8) + request.payload)
        let response = try connection.readUntil(Data("\r\n\r\n".utf8), maximum: 16_384)
        guard let header = String(data: response, encoding: .utf8), let first = header.split(separator: "\r\n").first else { throw UploadError.invalidAcknowledgement }
        let status = Int(first.split(separator: " ").dropFirst().first ?? "") ?? 0
        let length = header.split(separator: "\r\n").compactMap { line -> Int? in let p = line.split(separator: ":", maxSplits: 1); return p.count == 2 && p[0].lowercased() == "content-length" ? Int(p[1].trimmingCharacters(in: .whitespaces)) : nil }.first ?? 0
        return (status, length == 0 ? Data() : try connection.readExactly(length))
    }
    private enum UploadError: Error { case invalidEndpoint, invalidAcknowledgement }
}
