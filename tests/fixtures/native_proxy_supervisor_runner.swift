import Foundation

@main
struct NativeProxySupervisorRunner {
    static func main() throws {
        guard let line = readLine(), let input = line.data(using: .utf8),
              let doc = try JSONSerialization.jsonObject(with: input) as? [String: Any],
              let implementation = doc["implementation"] as? String,
              let executable = doc["executable"] as? String,
              let config = doc["config"] as? [String: Any] else { exit(2) }
        let worker = try ObstacleBridgeSupervisedProxyWorker(implementation: implementation, executable: executable)
        do {
            try worker.start(config: config)
            emit(worker.snapshot())
            while let command = readLine() {
                if command == "status" { emit(worker.snapshot()) }
                if command == "stop" { break }
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
