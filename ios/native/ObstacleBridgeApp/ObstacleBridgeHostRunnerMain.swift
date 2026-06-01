import Foundation

@main
struct ObstacleBridgeHostRunnerMain {
    static func main() {
        do {
            try ObstacleBridgeHostRunner.runMain(arguments: Array(CommandLine.arguments.dropFirst()))
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }
}
