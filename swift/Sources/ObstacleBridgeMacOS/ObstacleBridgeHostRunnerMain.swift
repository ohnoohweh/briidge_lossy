import Foundation

@main
struct ObstacleBridgeHostRunnerMain {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments.count == 2, arguments[0] == "--peer-worker-control-fd", let fd = Int32(arguments[1]) {
                try ObstacleBridgeNativePeerWorker.run(controlFD: fd)
            } else {
                try ObstacleBridgeHostRunner.runMain(arguments: arguments)
            }
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }
}
