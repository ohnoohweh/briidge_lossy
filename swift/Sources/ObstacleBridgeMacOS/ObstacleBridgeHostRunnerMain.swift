import Foundation

@main
struct ObstacleBridgeHostRunnerMain {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            if arguments.count == 2, arguments[0] == "--peer-worker-control-fd", let fd = Int32(arguments[1]) {
                try ObstacleBridgeNativePeerWorker.run(controlFD: fd)
            } else if arguments.count == 4,
                      arguments[0] == "--peer-worker-control-fd", let controlFD = Int32(arguments[1]),
                      arguments[2] == "--log-fd", let logFD = Int32(arguments[3]) {
                try ObstacleBridgeNativePeerWorker.run(controlFD: controlFD, logFD: logFD)
            } else if arguments.count == 6,
                      arguments[0] == ObstacleBridgeMacOSTunHelperService.nativeAdminChildControlArgument, let controlFD = Int32(arguments[1]),
                      arguments[2] == "--admin-worker-lifetime-fd", let lifetimeFD = Int32(arguments[3]),
                      arguments[4] == "--generation", let generation = Int(arguments[5]) {
                try ObstacleBridgeNativeAdminWorker.run(controlFD: controlFD, lifetimeFD: lifetimeFD, generation: generation)
            } else if arguments.count == 8,
                      arguments[0] == ObstacleBridgeMacOSTunHelperService.nativeAdminChildControlArgument, let controlFD = Int32(arguments[1]),
                      arguments[2] == "--admin-worker-lifetime-fd", let lifetimeFD = Int32(arguments[3]),
                      arguments[4] == "--generation", let generation = Int(arguments[5]),
                      arguments[6] == ObstacleBridgeMacOSTunHelperService.nativeAdminChildLogArgument, let logFD = Int32(arguments[7]) {
                try ObstacleBridgeNativeAdminWorker.run(controlFD: controlFD, lifetimeFD: lifetimeFD, logFD: logFD, generation: generation)
            } else {
                try ObstacleBridgeHostRunner.runMain(arguments: arguments)
            }
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }
}
