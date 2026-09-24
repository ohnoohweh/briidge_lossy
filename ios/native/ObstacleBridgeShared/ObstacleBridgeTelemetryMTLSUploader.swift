import Foundation
#if canImport(Security)
import Security

/// Apple HTTPS transport for `telemetry/v1`. Callers supply the enrolled client
/// identity; this type neither reads credentials from configuration nor logs them.
final class ObstacleBridgeTelemetryMTLSUploader: NSObject, URLSessionDelegate {
    private let policy: ObstacleBridgeTelemetryUploadPolicy
    private let credential: URLCredential
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    init(policy: ObstacleBridgeTelemetryUploadPolicy, identity: SecIdentity, certificates: [Any] = []) {
        self.policy = policy
        credential = URLCredential(identity: identity, certificates: certificates, persistence: .forSession)
        super.init()
    }

    /// Starts at most one upload; policy failure keeps the spool untouched.
    func uploadOnce(completion: @escaping (Bool) -> Void = { _ in }) {
        guard let pending = policy.nextRequest() else { completion(false); return }
        var request = URLRequest(url: pending.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        session.uploadTask(with: request, from: pending.payload) { [weak self] data, response, error in
            guard let self, error == nil,
                  (response as? HTTPURLResponse)?.statusCode == 202,
                  let data,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["ok"] as? Bool == true,
                  let accepted = object["accepted_through"] as? NSNumber,
                  self.policy.accept(acceptedThrough: accepted.uint64Value) > 0
            else { self?.policy.fail(); completion(false); return }
            completion(true)
        }.resume()
    }

    /// Cancels outstanding network work during runtime shutdown. The spool
    /// remains authoritative, so a later runtime can retry its unacknowledged
    /// batch without waiting for this session to finish.
    func cancel() {
        policy.fail()
        session.invalidateAndCancel()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

enum ObstacleBridgeTelemetryIdentityStore {
    static func telemetryIdentity() -> (identity: SecIdentity, installationID: String)? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
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
}
#endif

enum ObstacleBridgeTelemetryAdminStatus {
    static func snapshot(runtimeConfig: [String: Any]) -> [String: Any] {
        let enabled = ObstacleBridgeRuntimeConfig.boolValue(from: runtimeConfig["telemetry_enabled"]) ?? false
        let endpoint = ObstacleBridgeRuntimeConfig.stringValue(from: runtimeConfig["telemetry_endpoint"])
        let parsed = endpoint.flatMap(URL.init(string:))
        #if canImport(Security)
        let identityAvailable = ObstacleBridgeTelemetryIdentityStore.telemetryIdentity() != nil
        #else
        let identityAvailable = false
        #endif
        return [
            "enabled": enabled,
            "configured": enabled && parsed?.scheme?.lowercased() == "https" && identityAvailable,
            "endpoint_scheme": parsed?.scheme?.lowercased() ?? "",
            "endpoint_host": parsed?.host ?? "",
            "identity_available": identityAvailable,
        ]
    }
}
