import Foundation

@main
struct NativeLogSupervisorRunner {
    static func main() throws {
        guard let line = readLine(), let input = line.data(using: .utf8),
              let doc = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { exit(2) }
        if let configuration = doc["configuration"] as? [String: Any] {
            do { emit(["selection": try ObstacleBridgeLogWorkerSupervisor.configured(from: configuration) == nil ? "off" : "enabled"]) }
            catch { emit(["selection": "invalid"]) }
            return
        }
        guard let implementation = doc["implementation"] as? String,
              let executable = doc["executable"] as? String else { exit(2) }
        let worker = try ObstacleBridgeLogWorkerSupervisor(implementation: implementation, executable: executable)
        do {
            try worker.start()
            emit(worker.status())
            while let command = readLine() {
                switch command {
                case "record": worker.emit(name: "desktop.test", level: "INFO", levelNumber: 20, message: "private worker record")
                case "fetch": emit(worker.fetch(limit: 20))
                case "status": emit(worker.status())
                case "burst":
                    let started = Date()
                    for _ in 0..<3_000 { worker.emit(name: "desktop.test", level: "INFO", levelNumber: 20, message: "nonblocking record") }
                    emit(["elapsed_ms": Int(Date().timeIntervalSince(started) * 1000), "status": worker.status()])
                case "stop": worker.stop(); return
                default: break
                }
            }
            worker.stop()
        } catch {
            emit(["error": "worker startup failed"])
            exit(1)
        }
    }

    static func emit(_ payload: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: payload), let text = String(data: data, encoding: .utf8) {
            print(text)
            fflush(stdout)
        }
    }
}
