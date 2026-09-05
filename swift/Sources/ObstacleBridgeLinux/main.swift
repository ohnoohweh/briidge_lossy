import Foundation
import ObstacleBridgeLinuxAdapters
import ObstacleBridgePortable

@main
enum ObstacleBridgeLinuxMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        switch arguments {
        case ["--help"], ["-h"]:
            printHelp()
        case ["--version"]:
            print("\(ObstacleBridgePortableRuntime.productName) build baseline (\(ObstacleBridgeLinuxAdapters.platform))")
        case let values where values.count == 5 && values[0] == "--transport-probe":
            runTransportProbe(transportName: values[1], host: values[2], portText: values[3], payloadBase64: values[4])
        case let values where values.count == 2 && values[0] == "--runtime-config":
            validateRuntimeConfig(path: values[1])
        case let values where values.count == 3 && values[0] == "--runtime-config" && values[2] == "--status":
            printRuntimeStatus(configPath: values[1])
        case let values where values.count == 4 && values[0] == "--runtime-config" && values[2] == "--runtime-probe":
            runRuntimeProbe(configPath: values[1], payloadBase64: values[3])
        case []:
            printHelp()
        default:
            writeError("ObstacleBridgeLinux: unsupported argument(s): \(arguments.joined(separator: " "))")
            writeError("Run ObstacleBridgeLinux --help for the LSW-002 build-baseline interface.")
            exit(2)
        }
    }

    private static func printHelp() {
        print("""
        ObstacleBridgeLinux — Linux Swift client build baseline

        Usage:
          ObstacleBridgeLinux --help
          ObstacleBridgeLinux --version
          ObstacleBridgeLinux --transport-probe <tcp|ws> <host> <port> <payload-base64>
          ObstacleBridgeLinux --runtime-config <path>
          ObstacleBridgeLinux --runtime-config <path> --status
          ObstacleBridgeLinux --runtime-config <path> --runtime-probe <payload-base64>

        The transport probe validates Linux POSIX lower-layer TCP or cleartext
        WebSocket framing. --runtime-config validates the existing sectioned
        config shape and Linux transport admission without exposing secrets.
        --runtime-probe sends one configured lower-layer or PSK-protected
        payload; it is not the long-lived Linux overlay runtime.
        ChannelMux, TUN, and Admin Web are delivered by later work packages.
        """)
    }

    private static func runTransportProbe(transportName: String, host: String, portText: String, payloadBase64: String) {
        guard let transport = ObstacleBridgeLinuxTransport(rawValue: transportName),
              let port = Int(portText),
              let payload = Data(base64Encoded: payloadBase64)
        else {
            writeError("ObstacleBridgeLinux: transport probe requires a supported transport, port, and base64 payload")
            exit(2)
        }
        do {
            let client = try ObstacleBridgeLinuxOverlayTransportClient(host: host, port: port, transport: transport)
            let response = try client.roundTrip(payload)
            print(response.base64EncodedString())
        } catch {
            writeError("ObstacleBridgeLinux: transport probe failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func validateRuntimeConfig(path: String) {
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: path)
            let secureLink = config.secureLinkPSK == nil ? "off" : "psk"
            print("validated transport=\(config.transport.rawValue) host=\(config.host) port=\(config.port) secure_link=\(secureLink)")
        } catch {
            writeError("ObstacleBridgeLinux: runtime config rejected: \(error.localizedDescription)")
            exit(2)
        }
    }

    private static func runRuntimeProbe(configPath: String, payloadBase64: String) {
        guard let payload = Data(base64Encoded: payloadBase64) else {
            writeError("ObstacleBridgeLinux: runtime probe requires a base64 payload")
            exit(2)
        }
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: configPath)
            var generator = SystemRandomNumberGenerator()
            let sessionID = UInt64.random(in: 1...UInt64.max, using: &generator)
            let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
            let runtime = ObstacleBridgeLinuxConfiguredRuntime(configuration: config)
            let response = try runtime.roundTrip(payload, sessionID: sessionID, clientNonce: nonce)
            print(response.base64EncodedString())
        } catch {
            writeError("ObstacleBridgeLinux: runtime probe failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func printRuntimeStatus(configPath: String) {
        do {
            let config = try ObstacleBridgeLinuxRuntimeConfiguration.load(path: configPath)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            print(String(decoding: try encoder.encode(ObstacleBridgeLinuxConfiguredRuntime(configuration: config).status()), as: UTF8.self))
        } catch {
            writeError("ObstacleBridgeLinux: runtime status unavailable: \(error.localizedDescription)")
            exit(2)
        }
    }

    private static func writeError(_ message: String) {
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}
