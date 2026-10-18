import Foundation
#if os(macOS)
import Darwin
#else
import Glibc
#endif

@main
struct NativeProxySupervisorRunner {
    static func main() throws {
        guard let line = readLine(), let input = line.data(using: .utf8),
              let doc = try JSONSerialization.jsonObject(with: input) as? [String: Any],
              let implementation = doc["implementation"] as? String,
              let executable = doc["executable"] as? String,
              let config = doc["config"] as? [String: Any] else { exit(2) }
        var loggingWorker: ObstacleBridgeLogWorkerSupervisor?
        if let logging = doc["logging"] as? [String: Any],
           let logImplementation = logging["implementation"] as? String,
           let logExecutable = logging["executable"] as? String {
            let logger = try ObstacleBridgeLogWorkerSupervisor(implementation: logImplementation, executable: logExecutable)
            try logger.start()
            loggingWorker = logger
        }
        let worker = try ObstacleBridgeSupervisedProxyWorker(implementation: implementation, executable: executable, loggingWorker: loggingWorker)
        do {
            try worker.start(config: config)
            emit(worker.snapshot())
            while let command = readLine() {
                if command == "status" { emit(worker.snapshot()) }
                if command == "log-status" { emit(loggingWorker?.status() ?? [:]) }
                if command == "logs" { emit(loggingWorker?.fetch(limit: 100) ?? [:]) }
                if command == "producer-probe", let loggingWorker { try probeProducer(loggingWorker) }
                if command == "stop" { break }
            }
            worker.stop()
            loggingWorker?.stop()
        } catch {
            worker.stop()
            loggingWorker?.stop()
            emit(["error": "worker startup failed"])
            exit(1)
        }
    }

    static func probeProducer(_ logger: ObstacleBridgeLogWorkerSupervisor) throws {
        let relay = try logger.makeProducerRelay()
        defer { relay.stop() }
        let fd = relay.childHandle.fileDescriptor
        let frames: [[String: Any]] = [
            ["v": 1, "kind": "logs.query", "request_id": "forbidden-child-query"],
            ["v": 1, "created": Date().timeIntervalSince1970, "name": "producer.test", "level": "INFO", "levelno": 20, "message": "relay marker", "process": Int(getpid()), "thread": "probe"],
        ]
        for frame in frames {
            let data = try JSONSerialization.data(withJSONObject: frame)
            #if os(Linux)
            let flags = Int32(MSG_DONTWAIT | MSG_NOSIGNAL)
            #else
            let flags = Int32(MSG_DONTWAIT)
            #endif
            guard data.withUnsafeBytes({ send(fd, $0.baseAddress, $0.count, flags) }) == data.count else { throw ObstacleBridgeLogWorkerSupervisor.Failure.unavailable }
        }
        Thread.sleep(forTimeInterval: 0.1)
        var buffer = [UInt8](repeating: 0, count: 8192)
        let count = recv(fd, &buffer, buffer.count, Int32(MSG_DONTWAIT))
        emit(["producer_received_reply": count > 0])
    }

    static func emit(_ payload: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: payload), let text = String(data: data, encoding: .utf8) {
            print(text)
            fflush(stdout)
        }
    }
}
