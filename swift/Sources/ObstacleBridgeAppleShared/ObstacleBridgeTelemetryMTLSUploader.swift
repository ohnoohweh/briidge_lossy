import Foundation
#if canImport(Security)
import Security

/// The URLSession callback surface owns only the enrolled client credential.
private final class ObstacleBridgeTelemetryMTLSDelegate: NSObject, URLSessionDelegate {
    private let credential: URLCredential

    init(credential: URLCredential) {
        self.credential = credential
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

/// The synchronous admin API needs an immediate telemetry status projection.
/// Keep every policy and uploader-counter operation behind this one lock rather
/// than transferring the policy between executors. The URLSession callback
/// captures only this audited state object.
private final class ObstacleBridgeTelemetryLockedUploadState: @unchecked Sendable {
    // OBSTACLEBRIDGE-CONCURRENCY: lock; test=test_macos_telemetry_uploader_uses_audited_synchronous_state
    private let lock = NSLock()
    private let policy: ObstacleBridgeTelemetryUploadPolicy
    private var attempts: UInt64 = 0
    private var acceptedBatches: UInt64 = 0
    private var rejectedBatches: UInt64 = 0
    private var lastError = ""
    private var lastSuccessUnixTS: Double?
    private var lastAttemptUnixTS: Double?

    init(policy: ObstacleBridgeTelemetryUploadPolicy) {
        self.policy = policy
    }

    func beginUpload() -> ObstacleBridgeTelemetryUploadPolicy.Request? {
        lock.lock(); defer { lock.unlock() }
        guard let pending = policy.nextRequest() else { return nil }
        attempts &+= 1
        lastAttemptUnixTS = Date().timeIntervalSince1970
        return pending
    }

    func finishUpload(data: Data?, response: URLResponse?, error: Error?) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard error == nil,
              (response as? HTTPURLResponse)?.statusCode == 202,
              let data,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["ok"] as? Bool == true,
              let accepted = object["accepted_through"] as? NSNumber,
              policy.accept(acceptedThrough: accepted.uint64Value) > 0
        else {
            policy.fail()
            rejectedBatches &+= 1
            lastError = String(describing: error ?? NSError(domain: "ObstacleBridgeTelemetry", code: (response as? HTTPURLResponse)?.statusCode ?? -1)).prefix(160).description
            return false
        }
        acceptedBatches &+= 1
        lastSuccessUnixTS = Date().timeIntervalSince1970
        lastError = ""
        return true
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        policy.fail()
    }

    func statusSnapshot() -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        let snapshot: [String: Any] = [
            "attempts": attempts,
            "accepted_batches": acceptedBatches,
            "rejected_batches": rejectedBatches,
            "last_error": lastError.isEmpty ? NSNull() : lastError,
            "last_success_unix_ts": lastSuccessUnixTS ?? NSNull(),
            "last_attempt_unix_ts": lastAttemptUnixTS ?? NSNull(),
        ]
        return snapshot.merging(policy.statusSnapshot()) { current, _ in current }
    }
}

/// Apple HTTPS transport for `telemetry/v1`. Callers supply the enrolled client
/// identity; this type neither reads credentials from configuration nor logs them.
final class ObstacleBridgeTelemetryMTLSUploader {
    private let uploadState: ObstacleBridgeTelemetryLockedUploadState
    private let sessionDelegate: ObstacleBridgeTelemetryMTLSDelegate
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration, delegate: sessionDelegate, delegateQueue: nil)
    }()

    init(policy: ObstacleBridgeTelemetryUploadPolicy, identity: SecIdentity, certificates: [Any] = []) {
        uploadState = ObstacleBridgeTelemetryLockedUploadState(policy: policy)
        sessionDelegate = ObstacleBridgeTelemetryMTLSDelegate(
            credential: URLCredential(identity: identity, certificates: certificates, persistence: .forSession)
        )
    }

    /// Starts at most one upload; policy failure keeps the spool untouched.
    func uploadOnce(completion: @escaping @Sendable (Bool) -> Void = { _ in }) {
        let uploadState = uploadState
        guard let pending = uploadState.beginUpload() else { completion(false); return }
        var request = URLRequest(url: pending.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        session.uploadTask(with: request, from: pending.payload) { data, response, error in
            completion(uploadState.finishUpload(data: data, response: response, error: error))
        }.resume()
    }

    func statusSnapshot() -> [String: Any] {
        uploadState.statusSnapshot()
    }

    /// Cancels outstanding network work during runtime shutdown. The spool
    /// remains authoritative, so a later runtime can retry its unacknowledged
    /// batch without waiting for this session to finish.
    func cancel() {
        uploadState.cancel()
        session.invalidateAndCancel()
    }

}

enum ObstacleBridgeTelemetryIdentityStore {
    private static let sharedAccessGroupSuffix = ".com.obstaclebridge.shared"
    private static let identityTag = "com.obstaclebridge.telemetry.identity"
    private static let stagedIdentityFilename = "ObstacleBridge-telemetry-identity.p12"
    private static let stagedPasswordFilename = "ObstacleBridge-telemetry-identity.password"

    /// Imports a one-shot app-Documents PKCS#12 staging pair into the Keychain
    /// access group shared with the Packet Tunnel, then removes the staging
    /// material. A failed import deliberately leaves both files for correction.
    static func importStagedIdentityIfPresent() -> String {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return "documents_unavailable" }
        let p12URL = documents.appendingPathComponent(stagedIdentityFilename)
        let passwordURL = documents.appendingPathComponent(stagedPasswordFilename)
        guard FileManager.default.fileExists(atPath: p12URL.path) else { return "not_staged" }
        guard let password = try? String(contentsOf: passwordURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !password.isEmpty else { return "password_missing" }
        guard let accessGroup = telemetryAccessGroup() else { return "shared_keychain_unavailable" }
        guard let p12 = try? Data(contentsOf: p12URL) else { return "identity_unreadable" }
        var imported: CFArray?
        let status = SecPKCS12Import(p12 as CFData, [kSecImportExportPassphrase as String: password] as CFDictionary, &imported)
        guard status == errSecSuccess,
              let item = (imported as? [[String: Any]])?.first,
              let importedIdentity = item[kSecImportItemIdentity as String]
        else { return "identity_import_failed" }
        // SecPKCS12Import guarantees this value is a SecIdentity.  A forced
        // bridge is required on recent iOS SDKs, which reject a conditional
        // downcast to this CoreFoundation type as an always-successful cast.
        let identity = importedIdentity as! SecIdentity
        var privateKey: SecKey?
        var certificate: SecCertificate?
        guard SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess,
              SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
              let privateKey, let certificate
        else { return "identity_extract_failed" }
        let tag = Data(identityTag.utf8)
        SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag, kSecAttrAccessGroup: accessGroup] as CFDictionary)
        SecItemDelete([kSecClass: kSecClassCertificate, kSecAttrLabel: identityTag, kSecAttrAccessGroup: accessGroup] as CFDictionary)
        let keyStatus = SecItemAdd([
            kSecClass: kSecClassKey, kSecValueRef: privateKey, kSecAttrApplicationTag: tag,
            kSecAttrAccessGroup: accessGroup, kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard keyStatus == errSecSuccess else { return "shared_key_import_failed" }
        let certificateStatus = SecItemAdd([
            kSecClass: kSecClassCertificate, kSecValueRef: certificate, kSecAttrLabel: identityTag,
            kSecAttrAccessGroup: accessGroup, kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard certificateStatus == errSecSuccess else {
            SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: tag, kSecAttrAccessGroup: accessGroup] as CFDictionary)
            return "shared_certificate_import_failed"
        }
        try? FileManager.default.removeItem(at: p12URL)
        try? FileManager.default.removeItem(at: passwordURL)
        return "imported"
    }

    static func clearAppGroupDiagnosticLogs() -> [String: Any] {
        guard let sharedContainer = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.obstaclebridge.shared"
        ) else {
            return ["ok": false, "error": "shared app-group container unavailable"]
        }
        let logs = sharedContainer.appendingPathComponent("logs", isDirectory: true)
        let fileManager = FileManager.default
        let entries = (try? fileManager.contentsOfDirectory(at: logs, includingPropertiesForKeys: nil)) ?? []
        var removed: [String] = []
        var failures: [String] = []
        for entry in entries {
            do {
                try fileManager.removeItem(at: entry)
                removed.append(entry.lastPathComponent)
            } catch {
                failures.append(entry.lastPathComponent)
            }
        }
        return ["ok": failures.isEmpty, "removed": removed, "failures": failures]
    }

    static func telemetryIdentity() -> (identity: SecIdentity, installationID: String)? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
        if let accessGroup = telemetryAccessGroup() { query[kSecAttrAccessGroup] = accessGroup }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity]
        else { return nil }
        let telemetryIdentities = identities.compactMap { identity -> (identity: SecIdentity, installationID: String)? in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate
            else { return nil }
            var commonName: CFString?
            guard SecCertificateCopyCommonName(certificate, &commonName) == errSecSuccess,
                  let installationID = commonName as String?, !installationID.isEmpty,
                  installationID.count <= ObstacleBridgeTelemetry.maximumIdentifierLength
            else { return nil }
            return (identity, installationID)
        }
        return telemetryIdentities.count == 1 ? telemetryIdentities[0] : nil
    }

    private static func telemetryAccessGroup() -> String? {
        #if os(iOS)
        // SecTask entitlement inspection is a macOS API.  The iOS build
        // supplies this resolved value in each target's Info.plist.
        guard let accessGroup = Bundle.main.object(forInfoDictionaryKey: "ObstacleBridgeTelemetryKeychainAccessGroup") as? String,
              accessGroup.hasSuffix(sharedAccessGroupSuffix)
        else { return nil }
        return accessGroup
        #elseif os(macOS)
        guard let task = SecTaskCreateFromSelf(nil),
              let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil) as? [String]
        else { return nil }
        return groups.first(where: { $0.hasSuffix(sharedAccessGroupSuffix) })
        #else
        return nil
        #endif
    }
}
#endif

enum ObstacleBridgeTelemetryAdminStatus {
    static func snapshot(runtimeConfig: [String: Any], emitter: ObstacleBridgeTelemetryEmitter? = nil, spool: ObstacleBridgeTelemetrySpool? = nil, uploader: ObstacleBridgeTelemetryMTLSUploader? = nil) -> [String: Any] {
        let enabled = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["telemetry_enabled"]) ?? false
        let endpoint = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["telemetry_endpoint"])
        let parsed = endpoint.flatMap(URL.init(string:))
        #if canImport(Security)
        let identityAvailable = ObstacleBridgeTelemetryIdentityStore.telemetryIdentity() != nil
        #else
        let identityAvailable = false
        #endif
        var snapshot: [String: Any] = [
            "enabled": enabled,
            "configured": enabled && parsed?.scheme?.lowercased() == "https" && identityAvailable,
            "runtime_state": enabled ? (uploader == nil ? "not_running" : "running") : "disabled",
            "endpoint_scheme": parsed?.scheme?.lowercased() ?? "",
            "endpoint_host": parsed?.host ?? "",
            "identity_available": identityAvailable,
        ]
        snapshot["emitter"] = emitter?.statusSnapshot() ?? ["available": false]
        snapshot["spool"] = spool?.statusSnapshot() ?? ["available": false]
        snapshot["uploader"] = uploader?.statusSnapshot() ?? ["available": false]
        return snapshot
    }
}
