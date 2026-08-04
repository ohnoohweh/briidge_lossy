import Foundation
import Dispatch

@main
enum ObstacleBridgeTunPrivilegedHelperMain {
    static func main() {
        let args = Set(CommandLine.arguments.dropFirst())
        if args.contains("--version") {
            print("ObstacleBridgeTunHelper skeleton 1")
            return
        }
        if args.contains("--status-json") {
            writeStatusJSON()
            return
        }
        runXPCListener()
    }

    private static func writeStatusJSON() {
        let payload: [String: Any] = [
            "ok": true,
            "implemented": false,
            "bundle_identifier": ObstacleBridgeMacOSTunHelperService.helperBundleIdentifier,
            "executable_name": ObstacleBridgeMacOSTunHelperService.helperExecutableName,
            "helper_version": ObstacleBridgeMacOSTunHelperService.expectedHelperVersion,
            "supported_commands": ObstacleBridgeTunHelperCommand.allCases.map { $0.rawValue },
            "supported_frame_kinds": ObstacleBridgeTunHelperFrameKind.allCases.map { $0.rawValue },
        ]
        let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        if let data {
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private static func runXPCListener() {
        let delegate = ObstacleBridgeTunHelperXPCListenerDelegate()
        let listener = NSXPCListener(machServiceName: ObstacleBridgeMacOSTunHelperService.xpcMachServiceName)
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime(delegate) {
            dispatchMain()
        }
    }
}
