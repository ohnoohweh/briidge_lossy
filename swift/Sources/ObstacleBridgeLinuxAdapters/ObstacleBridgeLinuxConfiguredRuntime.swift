import Foundation
import ObstacleBridgePortable

public struct ObstacleBridgeLinuxRuntimeStatus: Codable, Equatable, Sendable {
    public let transport: String
    public let state: String
    public let attempts: Int
    public let failureReason: String?
    public let configuredCandidates: [String]
    public let activeHost: String?
    public let port: Int
    public let secureLinkMode: String
    public let secureLinkState: String
    public let appReady: Bool
}

/// Config-driven lower transport plus optional SecureLink PSK state. The
/// session is explicit: callers must close it when their higher-level runtime
/// decides the transport epoch has ended.
public final class ObstacleBridgeLinuxConfiguredSession {
    private let lower: ObstacleBridgeLinuxOverlayTransportClient
    private let lowerSession: ObstacleBridgeLinuxOverlayTransportSession
    private let secureLink: ObstacleBridgeSecureLinkPSKClient?
    private(set) public var snapshot: ObstacleBridgeLinuxOverlaySnapshot

    fileprivate init(lower: ObstacleBridgeLinuxOverlayTransportClient, lowerSession: ObstacleBridgeLinuxOverlayTransportSession, secureLink: ObstacleBridgeSecureLinkPSKClient?, transport: ObstacleBridgeLinuxTransport) {
        self.lower = lower
        self.lowerSession = lowerSession
        self.secureLink = secureLink
        self.snapshot = .init(transport: transport.rawValue, state: "connected", attempts: 1, failureReason: nil)
    }

    public func send(_ payload: Data) throws -> Data {
        do {
            if let secureLink {
                return try secureLink.unprotect(lowerSession.exchange(secureLink.protect(payload)))
            }
            return try lowerSession.exchange(payload)
        } catch {
            snapshot = .init(transport: snapshot.transport, state: "failed", attempts: snapshot.attempts, failureReason: error.localizedDescription)
            throw error
        }
    }

    public func close() {
        lowerSession.close()
        if snapshot.state != "failed" {
            snapshot = .init(transport: snapshot.transport, state: "disconnected", attempts: snapshot.attempts, failureReason: nil)
        }
    }

    deinit { close() }
}

/// Config-driven connection admission. ChannelMux, TUN, automatic reconnect,
/// and Admin ownership remain intentionally outside this LSW-004 slice.
public final class ObstacleBridgeLinuxConfiguredRuntime {
    public let configuration: ObstacleBridgeLinuxRuntimeConfiguration
    private(set) public var snapshot: ObstacleBridgeLinuxOverlaySnapshot
    private var activeSession: ObstacleBridgeLinuxConfiguredSession?
    private var activeHost: String?
    private var secureLinkState: String
    private(set) public var connectionEpoch: UInt64 = 0
    private var candidateStartIndex = 0

    public init(configuration: ObstacleBridgeLinuxRuntimeConfiguration) {
        self.configuration = configuration
        self.snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: 0, failureReason: nil)
        self.secureLinkState = configuration.secureLinkPSK == nil ? "off" : "disconnected"
    }

    public func connect(sessionID: UInt64, clientNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        activeSession?.close()
        activeSession = nil
        var lastError: Error?
        for offset in configuration.peerCandidates.indices {
            let index = (candidateStartIndex + offset) % configuration.peerCandidates.count
            let host = configuration.peerCandidates[index]
            let lower: ObstacleBridgeLinuxOverlayTransportClient
            do {
                lower = try ObstacleBridgeLinuxOverlayTransportClient(host: host, port: configuration.port, transport: configuration.transport, wsPath: configuration.webSocketPath)
                let lowerSession = try lower.openSession()
                let secureLink: ObstacleBridgeSecureLinkPSKClient?
                if let psk = configuration.secureLinkPSK {
                    let client = try ObstacleBridgeSecureLinkPSKClient(psk: psk)
                    let hello = try client.begin(sessionID: sessionID, clientNonce: clientNonce)
                    let clientProof = try client.handleServerHello(lowerSession.exchange(hello))
                    try client.handleServerAcknowledgement(lowerSession.exchange(clientProof))
                    secureLink = client
                    secureLinkState = "authenticated"
                } else {
                    secureLink = nil
                    secureLinkState = "off"
                }
                snapshot = .init(transport: configuration.transport.rawValue, state: "connected", attempts: index + 1, failureReason: nil)
                connectionEpoch &+= 1
                activeHost = host
                candidateStartIndex = index
                let session = ObstacleBridgeLinuxConfiguredSession(lower: lower, lowerSession: lowerSession, secureLink: secureLink, transport: configuration.transport)
                activeSession = session
                return session
            } catch {
                lastError = error
                activeHost = nil
                secureLinkState = configuration.secureLinkPSK == nil ? "off" : "failed"
                snapshot = .init(transport: configuration.transport.rawValue, state: "failed", attempts: index + 1, failureReason: error.localizedDescription)
            }
        }
        throw lastError ?? ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    /// Ends the current transport epoch and establishes a fresh one. A caller
    /// supplies fresh SecureLink identifiers so protected counters can never be
    /// reused across a reconnect.
    public func reconnect(sessionID: UInt64, clientNonce: Data) throws -> ObstacleBridgeLinuxConfiguredSession {
        disconnect()
        return try connect(sessionID: sessionID, clientNonce: clientNonce)
    }

    /// Advances the configured peer order after a connected epoch proves
    /// unusable (for example, a myudp receive timeout).
    public func advanceCandidate() {
        guard !configuration.peerCandidates.isEmpty else { return }
        candidateStartIndex = (candidateStartIndex + 1) % configuration.peerCandidates.count
    }

    public func disconnect() {
        activeSession?.close()
        activeSession = nil
        activeHost = nil
        secureLinkState = configuration.secureLinkPSK == nil ? "off" : "disconnected"
        if snapshot.state != "failed" {
            snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: snapshot.attempts, failureReason: nil)
        }
    }

    /// Redacted state suitable for an Admin/API adapter. It deliberately
    /// identifies only the configured secure-link mode, never its secret.
    public func status() -> ObstacleBridgeLinuxRuntimeStatus {
        .init(
            transport: configuration.transport.rawValue,
            state: snapshot.state,
            attempts: snapshot.attempts,
            failureReason: snapshot.failureReason,
            configuredCandidates: configuration.peerCandidates,
            activeHost: activeHost,
            port: configuration.port,
            secureLinkMode: configuration.secureLinkPSK == nil ? "off" : "psk",
            secureLinkState: secureLinkState,
            appReady: snapshot.state == "connected" && (secureLinkState == "off" || secureLinkState == "authenticated")
        )
    }

    /// Sends one payload with bounded fresh-epoch retries. This is a small
    /// synchronous admission primitive, not the timer-driven reconnect policy
    /// that a future long-lived ChannelMux runtime will own.
    public func roundTrip(_ payload: Data, sessionID: UInt64, clientNonce: Data, retryCount: Int = 1) throws -> Data {
        let totalAttempts = max(1, retryCount + 1)
        var lastError: Error?
        for attempt in 0..<totalAttempts {
            let retrySessionID = sessionID &+ UInt64(attempt)
            let effectiveSessionID = retrySessionID == 0 ? 1 : retrySessionID
            var retryNonce = clientNonce
            if attempt > 0, !retryNonce.isEmpty {
                retryNonce[retryNonce.count - 1] ^= UInt8(truncatingIfNeeded: attempt)
            }
            do {
                let session = try connect(sessionID: effectiveSessionID, clientNonce: retryNonce)
                let reply = try session.send(payload)
                disconnect()
                snapshot = .init(transport: configuration.transport.rawValue, state: "disconnected", attempts: attempt + 1, failureReason: nil)
                return reply
            } catch {
                lastError = error
                disconnect()
            }
        }
        snapshot = .init(transport: configuration.transport.rawValue, state: "failed", attempts: totalAttempts, failureReason: lastError?.localizedDescription)
        throw lastError ?? ObstacleBridgeLinuxOverlayTransportError.invalidFrame
    }

    deinit { disconnect() }
}
