import AppKit
import Foundation
import WebKit

@main
final class ObstacleBridgeMacAppMain: NSObject, NSApplicationDelegate, WKScriptMessageHandler {
    private var window: NSWindow?
    private var webView: WKWebView?
    private var statusLabel: NSTextField?
    private var reloadButton: NSButton?
    private var refreshTimer: Timer?
    private var currentWebAdminURL: URL?
    private static let webControlMessageHandlerName = "obstacleBridgeControl"

    static func main() {
        let app = NSApplication.shared
        let delegate = ObstacleBridgeMacAppMain()
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildWindow()
        do {
            try seedDocumentsSurfaceIfNeeded()
        } catch {
            updateStatus("Failed to prepare app documents: \(error.localizedDescription)")
        }

        let startPayload = decodeJSON(ObstacleBridgeTunnelControl.startIPServerTunnel())
        if let mode = startPayload["mode"] as? String {
            updateStatus("Starting \(mode) runtime...")
        } else {
            updateStatus("Starting runtime...")
        }
        scheduleWebAdminPolling()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == Self.webControlMessageHandlerName else {
            return
        }
        guard let payload = message.body as? [String: Any],
              let action = payload["action"] as? String else {
            return
        }
        switch action {
        case "exit":
            exitProgramFromEmbeddedWebAdmin()
        case "restart":
            restartProgramFromEmbeddedWebAdmin()
        default:
            break
        }
    }

    private func buildWindow() {
        let contentRect = NSRect(x: 0, y: 0, width: 1180, height: 820)
        let window = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "ObstacleBridge"
        window.center()

        let container = NSView(frame: contentRect)
        container.autoresizingMask = [.width, .height]

        let statusLabel = NSTextField(labelWithString: "Preparing runtime...")
        statusLabel.frame = NSRect(x: 16, y: contentRect.height - 34, width: contentRect.width - 120, height: 18)
        statusLabel.autoresizingMask = [.width, .minYMargin]
        statusLabel.lineBreakMode = .byTruncatingMiddle
        statusLabel.textColor = .secondaryLabelColor

        let reloadButton = NSButton(title: "Reload", target: self, action: #selector(reloadWebAdmin))
        reloadButton.frame = NSRect(x: contentRect.width - 92, y: contentRect.height - 39, width: 76, height: 26)
        reloadButton.autoresizingMask = [.minXMargin, .minYMargin]
        reloadButton.bezelStyle = .rounded
        reloadButton.toolTip = "Reload WebAdmin"

        let webFrame = NSRect(x: 0, y: 0, width: contentRect.width, height: contentRect.height - 44)
        let webConfig = WKWebViewConfiguration()
        let userContentController = WKUserContentController()
        userContentController.add(self, name: Self.webControlMessageHandlerName)
        let controlInterceptor = WKUserScript(
            source: Self.embeddedControlInterceptorScript(handlerName: Self.webControlMessageHandlerName),
            injectionTime: .atDocumentEnd,
            forMainFrameOnly: true
        )
        userContentController.addUserScript(controlInterceptor)
        webConfig.userContentController = userContentController
        let webView = WKWebView(frame: webFrame, configuration: webConfig)
        webView.autoresizingMask = [.width, .height]
        webView.loadHTMLString(
            """
            <html>
              <body style="font-family: -apple-system; color: #334155; padding: 24px;">
                <h2 style="margin: 0 0 12px 0;">ObstacleBridge</h2>
                <p style="margin: 0;">Starting the app-owned runtime and waiting for WebAdmin…</p>
              </body>
            </html>
            """,
            baseURL: nil
        )

        container.addSubview(webView)
        container.addSubview(statusLabel)
        container.addSubview(reloadButton)
        window.contentView = container
        window.makeKeyAndOrderFront(nil)

        self.window = window
        self.webView = webView
        self.statusLabel = statusLabel
        self.reloadButton = reloadButton
    }

    private func buildMenu() {
        let mainMenu = NSMenu()

        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Reload", action: #selector(reloadWebAdmin), keyEquivalent: "r")
        appMenu.addItem(NSMenuItem.separator())
        let quitTitle = "Quit \(ProcessInfo.processInfo.processName)"
        appMenu.addItem(withTitle: quitTitle, action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        NSApp.mainMenu = mainMenu
    }

    private static func embeddedControlInterceptorScript(handlerName: String) -> String {
        """
        (function() {
          function send(action) {
            try {
              const bridge = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.\(handlerName);
              if (bridge) bridge.postMessage({ action: action });
            } catch (_) {}
          }
          document.addEventListener('click', function(event) {
            const restartButton = event.target && event.target.closest ? event.target.closest('#restartBtn') : null;
            if (restartButton) {
              event.preventDefault();
              event.stopImmediatePropagation();
              send('restart');
              return;
            }
            const exitButton = event.target && event.target.closest ? event.target.closest('#exitBtn') : null;
            if (exitButton) {
              event.preventDefault();
              event.stopImmediatePropagation();
              send('exit');
            }
          }, true);
        })();
        """
    }

    private func exitProgramFromEmbeddedWebAdmin() {
        updateStatus("Stopping ObstacleBridge…")
        requestControlAction(path: "/api/shutdown") { [weak self] in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                NSApp.terminate(self)
            }
        }
    }

    private func restartProgramFromEmbeddedWebAdmin() {
        updateStatus("Restarting ObstacleBridge…")
        webView?.loadHTMLString(
            """
            <html>
              <body style="font-family: -apple-system; color: #334155; padding: 24px;">
                <h2 style="margin: 0 0 12px 0;">ObstacleBridge</h2>
                <p style="margin: 0;">Restarting the runtime and waiting for WebAdmin…</p>
              </body>
            </html>
            """,
            baseURL: nil
        )
        requestControlAction(path: "/api/restart") { [weak self] in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                self?.scheduleWebAdminPolling()
            }
        }
    }

    private func requestControlAction(path: String, completion: @escaping () -> Void) {
        refreshTimer?.invalidate()
        refreshTimer = nil

        guard let url = controlActionURL(path: path) else {
            completion()
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 2.0
        URLSession.shared.dataTask(with: request) { _, _, _ in
            DispatchQueue.main.async {
                completion()
            }
        }.resume()
    }

    private func controlActionURL(path: String) -> URL? {
        let base = currentWebAdminURL ?? webAdminURL()
        guard let base else {
            return nil
        }
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            return nil
        }
        components.path = path
        components.query = nil
        components.fragment = nil
        return components.url
    }

    private func updateStatus(_ text: String) {
        statusLabel?.stringValue = text
    }

    @objc
    private func reloadWebAdmin() {
        if currentWebAdminURL != nil {
            updateStatus("Reloading WebAdmin…")
            webView?.reload()
            return
        }
        scheduleWebAdminPolling()
    }

    private func scheduleWebAdminPolling() {
        refreshTimer?.invalidate()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.probeAndLoadWebAdmin()
        }
        refreshTimer?.tolerance = 0.1
        probeAndLoadWebAdmin()
    }

    private func probeAndLoadWebAdmin() {
        guard let url = webAdminURL() else {
            updateStatus("Admin Web is disabled in configuration.")
            return
        }
        currentWebAdminURL = url
        updateStatus("Waiting for \(url.absoluteString)")

        var request = URLRequest(url: url)
        request.timeoutInterval = 1.0
        URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
            guard let self else { return }
            let ok = (response as? HTTPURLResponse).map { (200 ..< 500).contains($0.statusCode) } ?? false
            DispatchQueue.main.async {
                if ok {
                    self.refreshTimer?.invalidate()
                    self.refreshTimer = nil
                    self.updateStatus(url.absoluteString)
                    self.webView?.load(URLRequest(url: url))
                } else if let error {
                    self.updateStatus("Waiting for WebAdmin at \(url.absoluteString) (\(error.localizedDescription))")
                }
            }
        }.resume()
    }

    private func webAdminURL() -> URL? {
        let runtimeConfig = Self.loadRuntimeConfigJSON()
        let flat = ObstacleBridgeRuntimeConfig.flatten(runtimeConfig)
        if let enabled = ObstacleBridgeRuntimeConfig.boolValue(from: flat["admin_web"]), !enabled {
            return nil
        }

        let bind = (ObstacleBridgeRuntimeConfig.stringValue(from: flat["admin_web_bind"]) ?? "127.0.0.1")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let host: String
        switch bind {
        case "", "0.0.0.0", "::", "*", "localhost":
            host = "127.0.0.1"
        default:
            host = bind
        }
        let port = ObstacleBridgeRuntimeConfig.intValue(from: flat["admin_web_port"]) ?? 18080
        var path = (ObstacleBridgeRuntimeConfig.stringValue(from: flat["admin_web_path"]) ?? "/").trimmingCharacters(in: .whitespacesAndNewlines)
        if path.isEmpty {
            path = "/"
        } else if !path.hasPrefix("/") {
            path = "/" + path
        }
        return URL(string: "http://\(host):\(port)\(path)")
    }

    private static func loadRuntimeConfigJSON() -> [String: Any] {
        guard let root = appRuntimeRootURL() else {
            return [:]
        }
        let configURL = root
            .appendingPathComponent("config", isDirectory: true)
            .appendingPathComponent("ObstacleBridge.cfg", isDirectory: false)
        guard
            let data = try? Data(contentsOf: configURL),
            let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return [:]
        }
        return payload
    }

    private func seedDocumentsSurfaceIfNeeded() throws {
        guard let documents = Self.appRuntimeRootURL() else {
            return
        }
        let fm = FileManager.default
        let configDirectory = documents.appendingPathComponent("config", isDirectory: true)
        let logsDirectory = documents.appendingPathComponent("logs", isDirectory: true)
        let profilesDirectory = documents.appendingPathComponent("profiles", isDirectory: true)
        let adminWebDirectory = documents.appendingPathComponent("admin_web", isDirectory: true)
        let webDirectory = documents.appendingPathComponent("web", isDirectory: true)

        try fm.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        try fm.createDirectory(at: logsDirectory, withIntermediateDirectories: true)
        try fm.createDirectory(at: profilesDirectory, withIntermediateDirectories: true)

        try copyBundledDirectoryIfNeeded(named: "admin_web", to: adminWebDirectory)
        try copyBundledDirectoryIfNeeded(named: "web", to: webDirectory)

        let configURL = configDirectory.appendingPathComponent("ObstacleBridge.cfg")
        let payload: [String: Any] = [
            "admin_web": [
                "admin_web": true,
                "admin_web_bind": "127.0.0.1",
                "admin_web_port": 18080,
                "admin_web_path": "/",
                "admin_web_dir": adminWebDirectory.path,
            ],
            "debug_logging": [
                "log": "DEBUG",
                "file_level": "DEBUG",
                "console_level": "INFO",
                "log_file": logsDirectory.appendingPathComponent("obstaclebridge.log").path,
                "log_file_max_bytes": 1_048_576,
                "log_file_backup_count": 5,
            ],
            "iOS_TUN_connector": [
                "packetflow_connector": "swift_host_runner",
                "bind_host": "127.0.0.1",
                "bind_port": 1600,
                "peer_host": "",
                "peer_port": 0,
                "ifname": "ios-utun",
                "mtu": 1600,
            ],
            "ws_session": [
                "ws_static_dir": webDirectory.path,
            ],
        ]
        if !fm.fileExists(atPath: configURL.path) {
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: configURL, options: [.atomic])
            return
        }

        guard let existingData = try? Data(contentsOf: configURL),
              let object = try? JSONSerialization.jsonObject(with: existingData),
              var existing = object as? [String: Any]
        else {
            return
        }

        var changed = false
        if var admin = existing["admin_web"] as? [String: Any], (admin["admin_web_dir"] as? String) != adminWebDirectory.path {
            admin["admin_web_dir"] = adminWebDirectory.path
            existing["admin_web"] = admin
            changed = true
        }
        if var debug = existing["debug_logging"] as? [String: Any], (debug["log_file"] as? String) != logsDirectory.appendingPathComponent("obstaclebridge.log").path {
            debug["log_file"] = logsDirectory.appendingPathComponent("obstaclebridge.log").path
            existing["debug_logging"] = debug
            changed = true
        }
        if var ws = existing["ws_session"] as? [String: Any], (ws["ws_static_dir"] as? String) != webDirectory.path {
            ws["ws_static_dir"] = webDirectory.path
            existing["ws_session"] = ws
            changed = true
        }
        if changed {
            let data = try JSONSerialization.data(withJSONObject: existing, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: configURL, options: [.atomic])
        }
    }

    private func copyBundledDirectoryIfNeeded(named name: String, to destination: URL) throws {
        let fm = FileManager.default
        guard let resourceRoot = Bundle.main.resourceURL else {
            try fm.createDirectory(at: destination, withIntermediateDirectories: true)
            return
        }
        let source = resourceRoot.appendingPathComponent(name, isDirectory: true)
        guard fm.fileExists(atPath: source.path) else {
            try fm.createDirectory(at: destination, withIntermediateDirectories: true)
            return
        }
        if !fm.fileExists(atPath: destination.path) {
            try fm.copyItem(at: source, to: destination)
            return
        }
        try refreshDirectoryContents(at: destination, from: source)
    }

    private func refreshDirectoryContents(at destination: URL, from source: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        let sourceEntries = try fm.contentsOfDirectory(
            at: source,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        let destinationEntries = try fm.contentsOfDirectory(
            at: destination,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        let sourceNames = Set(sourceEntries.map(\.lastPathComponent))
        for existing in destinationEntries where !sourceNames.contains(existing.lastPathComponent) {
            try? fm.removeItem(at: existing)
        }
        for entry in sourceEntries {
            let target = destination.appendingPathComponent(entry.lastPathComponent, isDirectory: false)
            let isDirectory = (try? entry.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDirectory {
                if fm.fileExists(atPath: target.path) {
                    try? fm.removeItem(at: target)
                }
                try fm.copyItem(at: entry, to: target)
                continue
            }
            if fm.fileExists(atPath: target.path) {
                try fm.removeItem(at: target)
            }
            try fm.copyItem(at: entry, to: target)
        }
    }

    private static func appRuntimeRootURL() -> URL? {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let root = base.appendingPathComponent("ObstacleBridge", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func decodeJSON(_ payload: NSString) -> [String: Any] {
        guard let data = String(payload).data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return [:]
        }
        return object
    }
}
