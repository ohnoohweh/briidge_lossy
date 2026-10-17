import Foundation
import Dispatch

@main
enum ObstacleBridgeTunPrivilegedHelperMain {
    static func main() {
        let args = Set(CommandLine.arguments.dropFirst())
        let values = Array(CommandLine.arguments.dropFirst())
        if values.count == 3 || (values.count == 5 && values[3] == "--idle-sec") {
            guard values[0] == "--tun-helper-server", let idle = values.count == 5 ? TimeInterval(values[4]) : Optional(TimeInterval(5)) else { fputs("ObstacleBridgeTunHelper: invalid tun-helper-server arguments\n", stderr); exit(2) }
            do { try ObstacleBridgeMacOSProtocolV1TunHelperServer(socketPath: values[1], token: values[2], idleTimeout: idle).run() }
            catch { fputs("ObstacleBridgeTunHelper: \(error.localizedDescription)\n", stderr); exit(1) }
            return
        }
        if args.contains("--version") {
            print("ObstacleBridgeTunHelper skeleton 1")
            return
        }
        if args.contains("--helper-build-info") {
            writeBuildInfoJSON()
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
            "python_helper_protocol_version": ObstacleBridgeMacOSTunHelperService.pythonHelperProtocolVersion,
            "supported_commands": ObstacleBridgeTunHelperCommand.allCases.map { $0.rawValue },
            "supported_frame_kinds": ObstacleBridgeTunHelperFrameKind.allCases.map { $0.rawValue },
        ]
        let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        if let data {
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }

    private static func writeBuildInfoJSON() {
        let payload: [String: Any] = [
            "artifact": "ObstacleBridgeTunHelper", "commit": ObstacleBridgeGeneratedBuildStamp.providerBuildCommit,
            "dirty": ObstacleBridgeGeneratedBuildStamp.providerBuildDirty, "diff_sha": ObstacleBridgeGeneratedBuildStamp.providerBuildDiffSHA,
            "build_timestamp_utc": ObstacleBridgeGeneratedBuildStamp.providerBuildTimestampUTC, "source": "embedded-build-info",
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data("\n".utf8)) }
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
