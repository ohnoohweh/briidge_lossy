import Foundation
import NetworkExtension

@objc(ObstacleBridgeTunnelControl)
final class ObstacleBridgeTunnelControl: NSObject {
    private static let providerBundleIdentifier = "com.obstaclebridge.obstacle-bridge-ios.IPServer"
    private static let localizedDescription = "AdminWeb"
    private static let legacyLocalizedDescription = "ObstacleBridge"
    private static let connectionDisplayNamePrefix = "ObstacleBridge Local Admin"
    private static let providerConfigurationVersion = "2026-05-11-webadmin-tunnel-address-v1"
    private static let tunnelAddress = "10.77.0.2"
    private static let webAdminBind = "0.0.0.0"
    private static let webAdminPort = 18080
    private static let queue = DispatchQueue(label: "com.obstaclebridge.tunnel-control", qos: .utility)
    private static let statusDefaultsKey = "ObstacleBridgeTunnelControlStatus"
    private static let appGroupIdentifier = "group.com.obstaclebridge.shared"
    private static var activeManager: NETunnelProviderManager?

    @objc class func startIPServerTunnel() -> NSString {
        recordEvent("start_requested")
        queue.async {
            configureTunnel(startAfterInstall: true)
        }
        return jsonString([
            "ok": true,
            "requested": true,
            "provider_bundle_identifier": providerBundleIdentifier,
        ]) as NSString
    }

    @objc class func prepareIPServerTunnel() -> NSString {
        recordEvent("prepare_requested")
        queue.async {
            configureTunnel(startAfterInstall: false)
        }
        return jsonString([
            "ok": true,
            "requested": true,
            "provider_bundle_identifier": providerBundleIdentifier,
            "mode": "prepare_only",
        ]) as NSString
    }

    @objc class func harvestSharedLogs() -> NSString {
        jsonString(harvestSharedLogsInternal()) as NSString
    }

    @objc class func status() -> NSString {
        refreshStatusAsync()
        if let cached = UserDefaults.standard.dictionary(forKey: statusDefaultsKey) {
            return jsonString(cached) as NSString
        }
        return jsonString([
            "ok": true,
            "provider_bundle_identifier": providerBundleIdentifier,
            "installed": false,
            "enabled": false,
            "status": "unknown",
            "status_raw": -1,
            "cached": false,
        ]) as NSString
    }

    private class func configureTunnel(startAfterInstall: Bool) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                updateStatus(ok: false, event: "load_preferences_failed", error: error.localizedDescription)
                return
            }
            let allManagers = managers ?? []

            let selection = selectCanonicalManager(from: allManagers)
            let managersToRemove = selection.duplicates

            if !managersToRemove.isEmpty {
                removeDuplicateManagers(managersToRemove) {
                    queue.asyncAfter(deadline: .now() + 1.0) {
                        configureTunnel(startAfterInstall: startAfterInstall)
                    }
                }
                return
            }

            activeManager = selection.manager
            if selection.needsSave {

                configure(selection.manager)
                saveReloadAndMaybeStart(
                    selection.manager,
                    created: selection.created,
                    startAfterInstall: startAfterInstall
                )
            } else {
                updateStatus(
                    ok: true,
                    event: startAfterInstall ? "preferences_reused" : "preferences_prepared_reused",
                    manager: selection.manager,
                    extra: ["duplicates_removed": selection.duplicates.count]
                )
                restoreProtocolIdentityIfNeeded(selection.manager)
                if startAfterInstall {
                    start(selection.manager)
                    queue.asyncAfter(deadline: .now() + 3.0) {
                        updateStatus(ok: true, event: "post_start_status", manager: selection.manager)
                        updateStatus(
                            ok: true,
                            event: "provider_snapshot_deferred",
                            manager: selection.manager,
                            extra: ["context": "post_start_reused", "reason": "avoid_startup_provider_message_race"]
                        )
                    }
                } else {
                    updateStatus(
                        ok: true,
                        event: "profile_prepared",
                        manager: selection.manager,
                        extra: ["started": false]
                    )
                }
            }
        }
    }

    private class func selectCanonicalManager(
        from managers: [NETunnelProviderManager]
    ) -> (manager: NETunnelProviderManager, duplicates: [NETunnelProviderManager], needsSave: Bool, created: Bool) {
        let related = managers.filter(isObstacleBridgeManager).sorted { a, b in
            let aScore =
                (a.localizedDescription == localizedDescription ? 4 : 0) +
                (a.isEnabled ? 2 : 0) +
                (hasCurrentProviderConfiguration(a) ? 1 : 0)

            let bScore =
                (b.localizedDescription == localizedDescription ? 4 : 0) +
                (b.isEnabled ? 2 : 0) +
                (hasCurrentProviderConfiguration(b) ? 1 : 0)

            return aScore > bScore
        }
        if let canonical = related.first(where: hasCurrentProviderIdentifier) {
            let duplicates = related.filter { $0 !== canonical }
            let needsNameRepair = canonical.localizedDescription != localizedDescription
            let needsConfigurationRepair = !hasCurrentProviderConfiguration(canonical)
            return (
                manager: canonical,
                duplicates: duplicates,
                needsSave: !canonical.isEnabled || needsNameRepair || needsConfigurationRepair,
                created: false
            )
        }
        if let repairable = related.first {
            let duplicates = related.dropFirst().map { $0 }
            return (
                manager: repairable,
                duplicates: duplicates,
                needsSave: true,
                created: false
            )
        }
        return (
            manager: NETunnelProviderManager(),
            duplicates: [],
            needsSave: true,
            created: true
        )
    }

    private class func isObstacleBridgeManager(_ manager: NETunnelProviderManager) -> Bool {
        hasCurrentProviderIdentifier(manager)
    }
    
    private class func isLegacyObstacleBridgeManager(_ manager: NETunnelProviderManager) -> Bool {
        if hasCurrentProviderIdentifier(manager) {
            return false
        }

        return manager.localizedDescription == legacyLocalizedDescription
            || manager.localizedDescription?.contains("ObstacleBridge") == true
    }


    private class func hasCurrentProviderIdentifier(_ manager: NETunnelProviderManager) -> Bool {
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleIdentifier
    }

    private class func hasCurrentProviderConfiguration(_ manager: NETunnelProviderManager) -> Bool {
        guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
        }
        return (tunnelProtocol.providerConfiguration?["configuration_version"] as? String) == providerConfigurationVersion
    }

    private class func isObstacleBridgeUsername(_ username: String?) -> Bool {
        guard let username else {
            return false
        }
        return username.hasPrefix(connectionDisplayNamePrefix)
    }

    private class func desiredProtocolUsername() -> String {
        "\(connectionDisplayNamePrefix) (\(providerConfigurationVersion))"
    }

    private class func removeDuplicateManagers(
        _ managers: [NETunnelProviderManager],
        completion: @escaping () -> Void
    ) {
        guard !managers.isEmpty else {
            completion()
            return
        }

        updateStatus(
            ok: true,
            event: "duplicate_cleanup_requested",
            extra: ["duplicate_count": managers.count]
        )

        let group = DispatchGroup()

        for manager in managers {
            group.enter()
            manager.removeFromPreferences { error in
                defer { group.leave() }

                if let error {
                    updateStatus(
                        ok: false,
                        event: "duplicate_cleanup_failed",
                        manager: manager,
                        error: error.localizedDescription
                    )
                    return
                }

                updateStatus(ok: true, event: "duplicate_cleanup_removed", manager: manager)
            }
        }

        group.notify(queue: queue) {
            updateStatus(
                ok: true,
                event: "duplicate_cleanup_completed",
                extra: ["duplicate_count": managers.count]
            )
            completion()
        }
    }

    private class func saveReloadAndMaybeStart(
        _ manager: NETunnelProviderManager,
        created: Bool,
        startAfterInstall: Bool
    ) {
        manager.saveToPreferences { error in
            if let error {
                updateStatus(ok: false, event: "save_preferences_failed", manager: manager, error: error.localizedDescription)
                return
            }
            updateStatus(ok: true, event: "preferences_saved", manager: manager, extra: ["created": created])

            reloadCanonicalManager(event: "preferences_reloaded") { reloadedManager in
                guard let reloadedManager else {
                    return
                }

                let repairedAfterReload = restoreProtocolIdentityIfNeeded(reloadedManager)
                updateStatus(
                    ok: true,
                    event: "preferences_reloaded_checked",
                    manager: reloadedManager,
                    extra: ["repaired_after_reload": repairedAfterReload]
                )

                if repairedAfterReload {
                    reloadedManager.saveToPreferences { error in
                        if let error {
                            updateStatus(
                                ok: false,
                                event: "post_reload_repair_save_failed",
                                manager: reloadedManager,
                                error: error.localizedDescription
                            )
                            return
                        }

                        updateStatus(ok: true, event: "post_reload_repair_saved", manager: reloadedManager)

                        reloadCanonicalManager(event: "post_reload_repair_reloaded") { repairedManager in
                            guard let repairedManager else {
                                return
                            }

                            if startAfterInstall {
                                start(repairedManager)
                            } else {
                                updateStatus(
                                    ok: true,
                                    event: "profile_prepared",
                                    manager: repairedManager,
                                    extra: ["created": created, "started": false]
                                )
                            }
                        }
                    }
                    return
                }

                if startAfterInstall {
                    start(reloadedManager)
                } else {
                    updateStatus(
                        ok: true,
                        event: "profile_prepared",
                        manager: reloadedManager,
                        extra: ["created": created, "started": false]
                    )
                }
            }
        }
    }

    private class func configure(_ manager: NETunnelProviderManager) {
        let tunnelProtocol = NETunnelProviderProtocol()
        applyIdentity(to: tunnelProtocol, manager: manager)
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true
        updateStatus(
            ok: true,
            event: "configured",
            manager: manager,
            extra: [
                "configuration_version": providerConfigurationVersion,
                "runtime_config_keys": Array(loadRuntimeConfiguration().keys).sorted(),
                "provider_configuration_mode": "minimal",
            ]
        )
    }

    @discardableResult
    private class func restoreProtocolIdentityIfNeeded(_ manager: NETunnelProviderManager) -> Bool {
        guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
        }
        let repaired = applyIdentity(to: tunnelProtocol, manager: manager)
        if repaired {
            updateStatus(ok: true, event: "protocol_identity_repaired", manager: manager)
        }
        return repaired
    }

    @discardableResult
    private class func applyIdentity(
        to tunnelProtocol: NETunnelProviderProtocol,
        manager: NETunnelProviderManager
    ) -> Bool {
        var repaired = false
        if tunnelProtocol.providerBundleIdentifier != providerBundleIdentifier {
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            repaired = true
        }
        if tunnelProtocol.serverAddress != tunnelAddress {
            tunnelProtocol.serverAddress = tunnelAddress
            repaired = true
        }
        let desiredUsername = desiredProtocolUsername()
        if tunnelProtocol.username != desiredUsername {
            tunnelProtocol.username = desiredUsername
            repaired = true
        }
        if manager.localizedDescription != localizedDescription {
            manager.localizedDescription = localizedDescription
            repaired = true
        }
        let providerConfiguration = providerConfigurationPayload()
        if NSDictionary(dictionary: tunnelProtocol.providerConfiguration ?? [:]) != NSDictionary(dictionary: providerConfiguration) {
            tunnelProtocol.providerConfiguration = providerConfiguration
            repaired = true
        }
        return repaired
    }

    private class func providerConfigurationPayload() -> [String: Any] {
        [
            "schema": "obstaclebridge.ios.packet-tunnel.v1",
            "configuration_version": providerConfigurationVersion,
            "runtime_config_ref": "app-group:ObstacleBridge.cfg",
            "runtime_config": ipserverRuntimeConfiguration(),
            "network_settings": [
                "tunnel_address": tunnelAddress,
                "tunnel_prefix": 32,
                "included_routes": ["10.77.0.0/24"],
                "excluded_routes": [],
                "dns_servers": ["1.1.1.1"],
                "mtu": 1280,
            ],
        ]
    }

    private class func harvestSharedLogsInternal() -> [String: Any] {
        guard let appDocuments = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return ["ok": false, "error": "app documents directory unavailable"]
        }
        guard let sharedContainer = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else {
            return ["ok": false, "error": "shared app-group container unavailable"]
        }

        let destinationDirectory = appDocuments.appendingPathComponent("logs", isDirectory: true)
        let sourceDirectory = sharedContainer.appendingPathComponent("logs", isDirectory: true)
        let fm = FileManager.default
        try? fm.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
        try? fm.createDirectory(at: sourceDirectory, withIntermediateDirectories: true)

        let destinationPrefix = "vpn-"
        if let existing = try? fm.contentsOfDirectory(at: destinationDirectory, includingPropertiesForKeys: nil) {
            for url in existing where url.lastPathComponent.hasPrefix(destinationPrefix) {
                try? fm.removeItem(at: url)
            }
        }

        var copied: [String] = []
        var cleared: [String] = []
        var errors: [[String: String]] = []

        let files = (try? fm.contentsOfDirectory(
            at: sourceDirectory,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )) ?? []

        let sourceInventory: [[String: Any]] = files.map { url in
            let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey])
            return [
                "name": url.lastPathComponent,
                "path": url.path,
                "is_regular": values?.isRegularFile ?? false,
                "size": values?.fileSize ?? -1,
                "modified": values?.contentModificationDate.map { ISO8601DateFormatter().string(from: $0) } ?? "",
            ]
        }

        recordEvent(
            "shared_logs_source_inventory",
            payload: [
                "source_directory": sourceDirectory.path,
                "file_count": sourceInventory.count,
                "files": sourceInventory,
            ]
        )

        for sourceURL in files {
            let values = try? sourceURL.resourceValues(forKeys: [.isRegularFileKey])
            guard values?.isRegularFile == true else {
                continue
            }
            let destinationURL = destinationDirectory.appendingPathComponent(destinationPrefix + sourceURL.lastPathComponent)
            do {
                if fm.fileExists(atPath: destinationURL.path) {
                    try fm.removeItem(at: destinationURL)
                }
                try fm.copyItem(at: sourceURL, to: destinationURL)
                copied.append(destinationURL.lastPathComponent)
                try fm.removeItem(at: sourceURL)
                cleared.append(sourceURL.lastPathComponent)
            } catch {
                errors.append([
                    "file": sourceURL.lastPathComponent,
                    "error": error.localizedDescription,
                ])
            }
        }

        let payload: [String: Any] = [
            "ok": errors.isEmpty,
            "copied_files": copied,
            "cleared_files": cleared,
            "errors": errors,
            "source_directory": sourceDirectory.path,
            "destination_directory": destinationDirectory.path,
            "source_inventory": sourceInventory,
        ]

        recordEvent("shared_logs_harvested", payload: payload)
        return payload
    }

    private class func reloadCanonicalManager(
        event: String,
        completion: @escaping (NETunnelProviderManager?) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                updateStatus(ok: false, event: "\(event)_load_all_failed", error: error.localizedDescription)
                completion(nil)
                return
            }

            let selection = selectCanonicalManager(from: managers ?? [])
            activeManager = selection.manager
            updateStatus(
                ok: true,
                event: event,
                manager: selection.manager,
                extra: [
                    "manager_count": managers?.count ?? 0,
                    "duplicate_count": selection.duplicates.count,
                    "needs_save": selection.needsSave,
                    "created": selection.created,
                ]
            )
            completion(selection.manager)
        }
    }

    private class func start(_ manager: NETunnelProviderManager) {
        let status = manager.connection.status
        if status == .connected || status == .connecting || status == .reasserting {
            updateStatus(ok: true, event: "already_started", manager: manager, extra: ["started": true])
            return
        }

        do {
            try manager.connection.startVPNTunnel()
            updateStatus(ok: true, event: "start_succeeded", manager: manager, extra: ["started": true])
        } catch {
            updateStatus(ok: false, event: "start_failed", manager: manager, error: error.localizedDescription)
        }
    }

    private class func requestProviderSnapshot(_ manager: NETunnelProviderManager, context: String) {
        guard manager.connection.status == .connected else {
            updateStatus(
                ok: true,
                event: "provider_snapshot_skipped",
                manager: manager,
                extra: [
                    "context": context,
                    "reason": "not_connected",
                ]
            )
            return
        }
        guard let session = manager.connection as? NETunnelProviderSession else {
            updateStatus(
                ok: false,
                event: "provider_snapshot_unavailable",
                manager: manager,
                error: "VPN connection is not a NETunnelProviderSession",
                extra: ["context": context]
            )
            return
        }
        let request: [String: Any] = [
            "command": "snapshot",
            "context": context,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: request) else {
            updateStatus(
                ok: false,
                event: "provider_snapshot_encode_failed",
                manager: manager,
                error: "failed to encode provider snapshot request",
                extra: ["context": context]
            )
            return
        }

        do {
            try session.sendProviderMessage(data) { responseData in
                guard let responseData else {
                    updateStatus(
                        ok: false,
                        event: "provider_snapshot_empty",
                        manager: manager,
                        error: "provider returned no snapshot data",
                        extra: ["context": context]
                    )
                    return
                }
                let response = (try? JSONSerialization.jsonObject(with: responseData)) as? [String: Any]
                updateStatus(
                    ok: true,
                    event: "provider_snapshot_received",
                    manager: manager,
                    extra: [
                        "context": context,
                        "provider_response": response ?? ["raw_bytes": responseData.count],
                    ]
                )
                if let response, response["mode"] as? String == "python_probe" {
                    requestProviderMessage(manager, command: "native_python_probe", context: context)
                }
            }
        } catch {
            updateStatus(
                ok: false,
                event: "provider_snapshot_failed",
                manager: manager,
                error: error.localizedDescription,
                extra: ["context": context]
            )
        }
    }

    private class func requestProviderMessage(_ manager: NETunnelProviderManager, command: String, context: String) {
        guard let session = manager.connection as? NETunnelProviderSession else {
            updateStatus(
                ok: false,
                event: "provider_message_unavailable",
                manager: manager,
                error: "VPN connection is not a NETunnelProviderSession",
                extra: [
                    "command": command,
                    "context": context,
                ]
            )
            return
        }
        let request: [String: Any] = [
            "command": command,
            "context": context,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: request) else {
            updateStatus(
                ok: false,
                event: "provider_message_encode_failed",
                manager: manager,
                error: "failed to encode provider message",
                extra: [
                    "command": command,
                    "context": context,
                ]
            )
            return
        }
        do {
            try session.sendProviderMessage(data) { responseData in
                guard let responseData else {
                    updateStatus(
                        ok: false,
                        event: "provider_message_empty",
                        manager: manager,
                        error: "provider returned no message data",
                        extra: [
                            "command": command,
                            "context": context,
                        ]
                    )
                    return
                }
                let response = (try? JSONSerialization.jsonObject(with: responseData)) as? [String: Any]
                updateStatus(
                    ok: true,
                    event: "provider_message_received",
                    manager: manager,
                    extra: [
                        "command": command,
                        "context": context,
                        "provider_response": response ?? ["raw_bytes": responseData.count],
                    ]
                )
                if command == "native_python_probe", response?["ok"] as? Bool == true {
                    requestProviderMessage(
                        manager,
                        command: "probe_module:obstacle_bridge",
                        context: context
                    )
                } else if command == "probe_module:obstacle_bridge", response?["ok"] as? Bool == true {
                    requestProviderMessage(
                        manager,
                        command: "probe_module:obstacle_bridge.core",
                        context: context
                    )
                } else if command == "probe_module:obstacle_bridge.core", response?["ok"] as? Bool == true {
                    requestProviderMessage(
                        manager,
                        command: "probe_module:obstacle_bridge_ios.diagnostics",
                        context: context
                    )
                } else if command == "probe_module:obstacle_bridge_ios.diagnostics", response?["ok"] as? Bool == true {
                    requestProviderMessage(
                        manager,
                        command: "probe_module:obstacle_bridge_ios.app",
                        context: context
                    )
                } else if command == "probe_module:obstacle_bridge_ios.app", response?["ok"] as? Bool == true {
                    requestProviderMessage(
                        manager,
                        command: "probe_module:obstacle_bridge_ios.ipserver_extension",
                        context: context
                    )
                }
            }
        } catch {
            updateStatus(
                ok: false,
                event: "provider_message_failed",
                manager: manager,
                error: error.localizedDescription,
                extra: [
                    "command": command,
                    "context": context,
                ]
            )
        }
    }

    private class func refreshStatusAsync() {
        queue.async {
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    updateStatus(ok: false, event: "status_load_failed", error: error.localizedDescription)
                    return
                }
                let manager = (managers ?? []).first(where: isObstacleBridgeManager)
                updateStatus(ok: true, event: "status_refreshed", manager: manager ?? activeManager)
            }
        }
    }

    private class func updateStatus(
        ok: Bool,
        event: String,
        manager: NETunnelProviderManager? = nil,
        error: String? = nil,
        extra: [String: Any] = [:]
    ) {
        var payload: [String: Any] = [
            "ok": ok,
            "event": event,
            "provider_bundle_identifier": providerBundleIdentifier,
            "installed": manager != nil,
            "enabled": manager?.isEnabled ?? false,
            "status": statusText(manager?.connection.status),
            "status_raw": manager?.connection.status.rawValue ?? -1,
            "cached": true,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ]
        if let error {
            payload["error"] = error
        }
        if let manager {
            payload["localized_description"] = manager.localizedDescription ?? ""
            if let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol {
                payload["protocol_server_address"] = protocolConfiguration.serverAddress ?? ""
                payload["protocol_username"] = protocolConfiguration.username ?? ""
                payload["protocol_provider_bundle_identifier"] = protocolConfiguration.providerBundleIdentifier ?? ""
                payload["provider_configuration_version"] =
                    protocolConfiguration.providerConfiguration?["configuration_version"] as? String ?? ""
            }
        }
        for (key, value) in extra {
            payload[key] = value
        }
        UserDefaults.standard.set(payload, forKey: statusDefaultsKey)
        recordEvent(event, payload: payload)
    }

    private class func recordEvent(_ event: String, payload: [String: Any] = [:]) {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return
        }
        let logDirectory = documents.appendingPathComponent("logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        let logURL = logDirectory.appendingPathComponent("ios-native-tunnel-control.jsonl")
        var line = payload
        line["native_event"] = event
        line["timestamp"] = ISO8601DateFormatter().string(from: Date())
        guard JSONSerialization.isValidJSONObject(line),
              let data = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8)
        else {
            return
        }
        if let handle = try? FileHandle(forWritingTo: logURL) {
            defer {
                try? handle.close()
            }
            handle.seekToEndOfFile()
            handle.write(Data((text + "\n").utf8))
            return
        }
        try? (text + "\n").write(to: logURL, atomically: true, encoding: .utf8)
    }

    private class func loadRuntimeConfiguration() -> [String: Any] {
        let defaults: [String: Any] = [
            "admin_web": true,
            "admin_web_bind": webAdminBind,
            "admin_web_port": webAdminPort,
            "admin_web_path": "/",
            "log": "DEBUG",
            "file_level": "DEBUG",
            "console_level": "INFO",
        ]
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return defaults
        }
        let configURL = documents.appendingPathComponent("config/ObstacleBridge.cfg")
        guard let data = try? Data(contentsOf: configURL),
              let object = try? JSONSerialization.jsonObject(with: data),
              let payload = object as? [String: Any]
        else {
            return defaults
        }
        var flattened = defaults
        for (key, value) in payload {
            if let section = value as? [String: Any] {
                for (sectionKey, sectionValue) in section {
                    flattened[sectionKey] = sectionValue
                }
            } else {
                flattened[key] = value
            }
        }
        return flattened
    }

    private class func ipserverRuntimeConfiguration() -> [String: Any] {
        var config = loadRuntimeConfiguration()
        config["admin_web"] = true
        config["admin_web_bind"] = webAdminBind
        config["admin_web_port"] = webAdminPort
        config["admin_web_path"] = "/"
        return config
    }

    private class func statusText(_ status: NEVPNStatus?) -> String {
        guard let status else {
            return "unknown"
        }
        switch status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "unknown"
        }
    }

    private class func jsonString(_ payload: [String: Any]) -> String {
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8)
        else {
            return "{\"ok\":false,\"error\":\"failed to encode tunnel-control response\"}"
        }
        return text
    }
}
