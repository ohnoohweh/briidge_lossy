import Foundation

#if os(macOS)
#if canImport(ServiceManagement)
import ServiceManagement
#endif

enum ObstacleBridgeMacOSTunHelperService {
    static let helperBundleIdentifier = "com.obstaclebridge.macos.ObstacleBridge.TunHelper"
    static let helperExecutableName = "ObstacleBridgeTunHelper"
    static let expectedHelperVersion = "1"
    static let helperLaunchDaemonPlistName = "\(helperBundleIdentifier).plist"
    static let xpcMachServiceName = "\(helperBundleIdentifier).xpc"
    static let helperLaunchServicesRelativePath = "Contents/Library/LaunchServices/\(helperExecutableName)"
    static let helperLaunchDaemonRelativePath = "Contents/Library/LaunchDaemons/\(helperLaunchDaemonPlistName)"

    static func statusSnapshot(appBundleURL explicitAppBundleURL: URL? = nil) -> [String: Any] {
        let appBundleURL = explicitAppBundleURL ?? detectedAppBundleURL()
        let helperURL = appBundleURL?.appendingPathComponent(helperLaunchServicesRelativePath)
        let launchDaemonPlistURL = appBundleURL?.appendingPathComponent(helperLaunchDaemonRelativePath)
        let helperPresent = helperURL.map { FileManager.default.isExecutableFile(atPath: $0.path) } ?? false
        let plistPresent = launchDaemonPlistURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false
        let helperSelfCheck = bundledHelperSelfCheck(helperURL: helperURL, helperPresent: helperPresent)
        let helperVersion = helperSelfCheck["helper_version"] as? String ?? ""
        let helperVersionMatches = helperPresent && helperVersion == expectedHelperVersion
        let helperStatusOK = helperSelfCheck["ok"] as? Bool ?? false
        let helperVersionMismatch = helperPresent && plistPresent && helperStatusOK && !helperVersionMatches
        let serviceStatus = smAppServiceStatusString()
        let installSupported = helperPresent && plistPresent && helperVersionMatches && smAppServiceAvailable
        let registered = serviceStatus == "enabled" || serviceStatus == "requires_approval"
        let approvalRequired = serviceStatus == "requires_approval"
        let phase = lifecyclePhase(
            appBundlePresent: appBundleURL != nil,
            helperPresent: helperPresent,
            plistPresent: plistPresent,
            helperVersionMatches: helperVersionMatches,
            serviceStatus: serviceStatus
        )
        let xpcReachability = xpcReachabilitySnapshot(serviceStatus: serviceStatus)
        let lastError = packageLastError(
            appBundlePresent: appBundleURL != nil,
            helperPresent: helperPresent,
            plistPresent: plistPresent,
            helperStatusOK: helperStatusOK,
            helperVersion: helperVersion,
            helperVersionMatches: helperVersionMatches,
            smAppServiceAvailable: smAppServiceAvailable
        )

        var result: [String: Any] = [
            "bundle_identifier": helperBundleIdentifier,
            "executable_name": helperExecutableName,
            "expected_helper_version": expectedHelperVersion,
            "bundled_helper_version": helperVersion,
            "bundled_helper_status_ok": helperStatusOK,
            "bundled_helper_status_error": helperSelfCheck["error"] as? String ?? "",
            "helper_version_matches_expected": helperVersionMatches,
            "helper_package_valid": helperPresent && plistPresent && helperVersionMatches,
            "launch_daemon_plist_name": helperLaunchDaemonPlistName,
            "xpc_mach_service_name": xpcMachServiceName,
            "app_bundle_path": appBundleURL?.path ?? "",
            "bundled_helper_path": helperURL?.path ?? "",
            "bundled_helper_present": helperPresent,
            "launch_daemon_plist_path": launchDaemonPlistURL?.path ?? "",
            "launch_daemon_plist_present": plistPresent,
            "smappservice_available": smAppServiceAvailable,
            "smappservice_status": serviceStatus,
            "install_supported": installSupported,
            "registered": registered,
            "running": xpcReachability["ok"] as? Bool ?? false,
            "xpc_reachable": xpcReachability["ok"] as? Bool ?? false,
            "xpc_last_error": xpcReachability["error"] as? String ?? "",
            "approval_required": approvalRequired,
            "approval_action": approvalRequired ? "open_system_settings_login_items" : "",
            "approval_action_available": smAppServiceAvailable,
            "approval_hint": approvalRequired ? "Approve the ObstacleBridge TUN helper in System Settings > General > Login Items & Extensions." : "",
            "repair_action": helperVersionMismatch ? "stop_then_register" : "",
            "repair_hint": helperVersionMismatch ? "The bundled TUN helper version does not match this app. Stop/unregister the helper, rebuild or replace the app bundle, then register it again." : "",
            "lifecycle_phase": phase,
            "last_error": lastError,
        ]
        if let helperPID = xpcReachability["helper_pid"] {
            result["xpc_helper_pid"] = helperPID
        }
        if let runtime = xpcReachability["runtime"] {
            result["xpc_runtime"] = runtime
        }
        return result
    }

    static func registerSkeletonResult(appBundleURL: URL? = nil) -> [String: Any] {
        registerResult(appBundleURL: appBundleURL)
    }

    static func startSkeletonResult(appBundleURL: URL? = nil) -> [String: Any] {
        startResult(appBundleURL: appBundleURL)
    }

    static func stopSkeletonResult(appBundleURL: URL? = nil) -> [String: Any] {
        stopResult(appBundleURL: appBundleURL)
    }

    static func registerResult(appBundleURL: URL? = nil) -> [String: Any] {
        registerLikeResult(action: "register", appBundleURL: appBundleURL)
    }

    static func startResult(appBundleURL: URL? = nil) -> [String: Any] {
        registerLikeResult(action: "start", appBundleURL: appBundleURL)
    }

    static func stopResult(action: String = "stop", appBundleURL: URL? = nil) -> [String: Any] {
        #if canImport(ServiceManagement)
        if #available(macOS 13.0, *) {
            do {
                try daemonService().unregister()
                return lifecycleResult(ok: true, action: action, reason: "", appBundleURL: appBundleURL)
            } catch {
                return lifecycleResult(ok: false, action: action, reason: error.localizedDescription, appBundleURL: appBundleURL)
            }
        }
        #endif
        return lifecycleResult(
            ok: false,
            action: action,
            reason: "SMAppService is unavailable on this macOS version",
            appBundleURL: appBundleURL
        )
    }

    static func openApprovalSettingsResult(appBundleURL: URL? = nil) -> [String: Any] {
        #if canImport(ServiceManagement)
        if #available(macOS 13.0, *) {
            SMAppService.openSystemSettingsLoginItems()
            return lifecycleResult(ok: true, action: "open_approval_settings", reason: "", appBundleURL: appBundleURL)
        }
        #endif
        return lifecycleResult(
            ok: false,
            action: "open_approval_settings",
            reason: "SMAppService is unavailable on this macOS version",
            appBundleURL: appBundleURL
        )
    }

    private static func xpcReachabilitySnapshot(serviceStatus: String) -> [String: Any] {
        guard serviceStatus == "enabled" else {
            return [
                "ok": false,
                "error": "helper service is not enabled",
            ]
        }
        return ObstacleBridgeTunHelperXPC.ping(machServiceName: xpcMachServiceName)
    }

    private static func registerLikeResult(action: String, appBundleURL: URL?) -> [String: Any] {
        let status = statusSnapshot(appBundleURL: appBundleURL)
        guard (status["install_supported"] as? Bool) == true else {
            return lifecycleResult(
                ok: false,
                action: action,
                reason: String(describing: status["last_error"] ?? "helper package is incomplete"),
                appBundleURL: appBundleURL
            )
        }
        #if canImport(ServiceManagement)
        if #available(macOS 13.0, *) {
            do {
                try daemonService().register()
                return lifecycleResult(ok: true, action: action, reason: "", appBundleURL: appBundleURL)
            } catch {
                return lifecycleResult(ok: false, action: action, reason: error.localizedDescription, appBundleURL: appBundleURL)
            }
        }
        #endif
        return lifecycleResult(
            ok: false,
            action: action,
            reason: "SMAppService is unavailable on this macOS version",
            appBundleURL: appBundleURL
        )
    }

    private static func lifecycleResult(
        ok: Bool,
        action: String,
        reason: String,
        appBundleURL: URL?
    ) -> [String: Any] {
        [
            "ok": ok,
            "action": action,
            "reason": reason,
            "status": statusSnapshot(appBundleURL: appBundleURL),
        ]
    }

    private static func lifecyclePhase(
        appBundlePresent: Bool,
        helperPresent: Bool,
        plistPresent: Bool,
        helperVersionMatches: Bool,
        serviceStatus: String
    ) -> String {
        if !appBundlePresent {
            return "app_bundle_not_detected"
        }
        if !helperPresent || !plistPresent {
            return "bundle_incomplete"
        }
        if !helperVersionMatches {
            return "helper_version_mismatch"
        }
        switch serviceStatus {
        case "enabled":
            return "registered"
        case "requires_approval":
            return "requires_approval"
        case "not_registered":
            return "bundled_not_registered"
        case "not_found":
            return "not_found"
        default:
            return "unknown"
        }
    }

    private static func packageLastError(
        appBundlePresent: Bool,
        helperPresent: Bool,
        plistPresent: Bool,
        helperStatusOK: Bool,
        helperVersion: String,
        helperVersionMatches: Bool,
        smAppServiceAvailable: Bool
    ) -> String {
        if !appBundlePresent {
            return "app bundle not detected"
        }
        if !helperPresent {
            return "bundled helper executable is missing"
        }
        if !plistPresent {
            return "bundled helper launch daemon plist is missing"
        }
        if !helperStatusOK {
            return "bundled helper status check failed"
        }
        if !helperVersionMatches {
            return "bundled helper version \(helperVersion) does not match expected \(expectedHelperVersion)"
        }
        if !smAppServiceAvailable {
            return "SMAppService is unavailable on this macOS version"
        }
        return ""
    }

    private static func bundledHelperSelfCheck(helperURL: URL?, helperPresent: Bool) -> [String: Any] {
        guard helperPresent, let helperURL else {
            return [
                "ok": false,
                "error": "bundled helper executable is missing",
            ]
        }
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = helperURL
        process.arguments = ["--status-json"]
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
            ]
        }
        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = errorPipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let stderr = String(data: errorOutput, encoding: .utf8) ?? ""
            return [
                "ok": false,
                "error": "helper status exited \(process.terminationStatus): \(stderr)",
            ]
        }
        guard let object = try? JSONSerialization.jsonObject(with: output),
              let payload = object as? [String: Any] else {
            return [
                "ok": false,
                "error": "helper status did not return JSON",
            ]
        }
        return payload
    }

    private static var smAppServiceAvailable: Bool {
        #if canImport(ServiceManagement)
        if #available(macOS 13.0, *) {
            return true
        }
        return false
        #else
        return false
        #endif
    }

    private static func smAppServiceStatusString() -> String {
        #if canImport(ServiceManagement)
        if #available(macOS 13.0, *) {
            return statusString(daemonService().status)
        }
        #endif
        return "unavailable"
    }

    #if canImport(ServiceManagement)
    @available(macOS 13.0, *)
    private static func daemonService() -> SMAppService {
        SMAppService.daemon(plistName: helperLaunchDaemonPlistName)
    }

    @available(macOS 13.0, *)
    private static func statusString(_ status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered:
            return "not_registered"
        case .enabled:
            return "enabled"
        case .requiresApproval:
            return "requires_approval"
        case .notFound:
            return "not_found"
        @unknown default:
            return "unknown"
        }
    }
    #endif

    private static func detectedAppBundleURL() -> URL? {
        let candidates = [
            Bundle.main.bundleURL,
            URL(fileURLWithPath: CommandLine.arguments.first ?? ""),
        ]
        for candidate in candidates {
            if let bundleURL = enclosingAppBundleURL(from: candidate) {
                return bundleURL
            }
        }
        return nil
    }

    private static func enclosingAppBundleURL(from url: URL) -> URL? {
        var current = url.standardizedFileURL
        while current.path != "/" {
            if current.pathExtension == "app" {
                return current
            }
            current.deleteLastPathComponent()
        }
        return nil
    }
}
#endif
