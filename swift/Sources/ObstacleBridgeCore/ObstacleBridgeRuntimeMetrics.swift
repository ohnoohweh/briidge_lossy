import Dispatch
import Foundation

/// Fixed-category, aggregate-only runtime timing shared by Linux and Apple
/// runtime owners. No payload, peer identity, or individual callback is kept.
public final class ObstacleBridgeRuntimeMetrics: @unchecked Sendable {
    public static let shared = ObstacleBridgeRuntimeMetrics()

    public enum Category: String, CaseIterable, Sendable {
        case channelMuxCallback = "channelmux_callback"
        case tunCallback = "tun_callback"
        case overlayReceive = "overlay_receive"
        case overlaySend = "overlay_send"
        case overlayReceivePrepare = "overlay_receive_prepare"
        case overlayReceiveData = "overlay_receive_data"
        case overlayReceiveIdle = "overlay_receive_idle"
        case overlayReceiveControl = "overlay_receive_control"
        case secureLink = "securelink"
        case compression
        case compressionEncode = "compression_encode"
        case compressionDecode = "compression_decode"
        case compressionFrame = "compression_frame"
        case appleTransportParseDispatch = "apple_transport_parse_dispatch"
        case appleTransportEgress = "apple_transport_egress"
        case appleTransportSecureLinkRoute = "apple_transport_securelink_route"
        case appleTransportMuxDispatch = "apple_transport_mux_dispatch"
        case appleTransportTunPayload = "apple_transport_tun_payload"
        case appleTransportUdpPayload = "apple_transport_udp_payload"
        case appleTransportTcpServerData = "apple_transport_tcp_server_data"
        case appleTransportTcpClientOpen = "apple_transport_tcp_client_open"
        case appleTransportTcpClientData = "apple_transport_tcp_client_data"
        case appleTransportTcpWriteEnqueue = "apple_transport_tcp_write_enqueue"
        case appleTransportTcpClose = "apple_transport_tcp_close"
        case appleTransportTcpClientOpenCore = "apple_transport_tcp_client_open_core"
        case appleTransportTcpClientOpenPublication = "apple_transport_tcp_client_open_publication"
        case appleTransportTcpConnectionStart = "apple_transport_tcp_connection_start"
        case appleTransportTcpReceiveRegistration = "apple_transport_tcp_receive_registration"
        case appleTransportLifecycle = "apple_transport_lifecycle"
        case secureLinkWorker = "securelink_worker"
        case controlTick = "control_tick"
        case retransmitTick = "retransmit_tick"
        case retransmitReportedMissing = "retransmit_reported_missing"
        case retransmitUnconfirmed = "retransmit_unconfirmed"
        case statusStats = "status_stats"
        case statusSessionSummaries = "status_session_summaries"
        case statusWorkerState = "status_worker_state"
        case statusTelemetryState = "status_telemetry_state"
        case statusTunHelperState = "status_tun_helper_state"
        case statusPeerStackState = "status_peer_stack_state"
        case runtimeMetricsProjection = "runtime_metrics_projection"
        case connectionsSnapshot = "connections_snapshot"
        case peersSnapshot = "peers_snapshot"
        case buildInfo = "build_info"
        case securityAdvisor = "security_advisor"
        case logging
    }

    private struct Aggregate {
        var count = 0
        var totalNS: UInt64 = 0
        var maxNS: UInt64 = 0
        mutating func add(_ durationNS: UInt64) {
            count += 1; totalNS &+= durationNS; maxNS = max(maxNS, durationNS)
        }
    }
    private struct Recent { let completedNS: UInt64; let category: Category; let durationNS: UInt64 }
    private struct CPUPeak { let completedNS: UInt64; let cores: Double; let contributor: [String: Any]? }

    private let lock = NSLock()
    private var lifetime = Dictionary(uniqueKeysWithValues: Category.allCases.map { ($0, Aggregate()) })
    private var recent: [Recent] = []
    private var intervalByCategory = [Category: UInt64]()
    private var previousWallNS: UInt64?
    private var previousCPUNS: UInt64?
    private var overallCPUPeak: Double?
    private var overallContributor: [String: Any]?
    private var recentCPUPeaks: [CPUPeak] = []

    public init() {}

    @discardableResult public func measure<T>(_ category: Category, _ body: () throws -> T) rethrows -> T {
        let started = DispatchTime.now().uptimeNanoseconds
        defer { record(category, durationNS: DispatchTime.now().uptimeNanoseconds &- started) }
        return try body()
    }

    public func record(_ category: Category, durationNS: UInt64, completedNS: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        lock.lock(); defer { lock.unlock() }
        lifetime[category, default: .init()].add(durationNS)
        recent.append(.init(completedNS: completedNS, category: category, durationNS: durationNS))
        intervalByCategory[category, default: 0] &+= durationNS
        trim(nowNS: completedNS)
    }

    /// Platform owners supply process CPU time; Core owns the shared ratio and
    /// bounded contributor calculation.
    public func recordCPUSample(processCPUNS: UInt64, wallNS: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        let wall = wallNS
        lock.lock(); defer { lock.unlock() }
        defer { previousWallNS = wall; previousCPUNS = processCPUNS; intervalByCategory.removeAll(keepingCapacity: true) }
        guard let priorWall = previousWallNS, let priorCPU = previousCPUNS, wall > priorWall, processCPUNS >= priorCPU else { return }
        let wallDelta = wall - priorWall
        let cores = Double(processCPUNS - priorCPU) / Double(wallDelta)
        let leader = intervalByCategory.max { lhs, rhs in lhs.value < rhs.value }
        let contributor = leader.map { ["category": $0.key.rawValue, "observed_cores": Double($0.value) / Double(wallDelta)] }
        let peak = CPUPeak(completedNS: wall, cores: cores, contributor: contributor)
        recentCPUPeaks.append(peak)
        trim(nowNS: wall)
        if overallCPUPeak == nil || cores >= overallCPUPeak! { overallCPUPeak = cores; overallContributor = contributor }
    }

    public func snapshotPayload(nowNS: UInt64? = nil) -> [String: Any] {
        let observationNow = nowNS ?? DispatchTime.now().uptimeNanoseconds
        lock.lock(); defer { lock.unlock() }
        trim(nowNS: observationNow)
        var recentMaxByCategory = [Category: UInt64]()
        for sample in recent {
            recentMaxByCategory[sample.category] = max(
                recentMaxByCategory[sample.category] ?? 0,
                sample.durationNS
            )
        }
        let rows: [[String: Any]] = Category.allCases.map { category in
            let value = lifetime[category] ?? .init()
            let recentMax = recentMaxByCategory[category]
            return ["category": category.rawValue, "count": value.count,
                    "total_ms": Double(value.totalNS) / 1_000_000, "mean_ms": value.count == 0 ? NSNull() : Double(value.totalNS) / Double(value.count) / 1_000_000,
                    "p95_ms": NSNull(), "p99_ms": NSNull(), "max_ms": value.count == 0 ? NSNull() : Double(value.maxNS) / 1_000_000,
                    "last_2_seconds_max_ms": recentMax.map { Double($0) / 1_000_000 } ?? NSNull()]
        }
        let peakRecent = recentCPUPeaks.max { $0.cores < $1.cores }
        let overallSlice = rows.compactMap { row -> (Double, String)? in
            guard let value = row["max_ms"] as? Double, let category = row["category"] as? String else { return nil }
            return (value, category)
        }.max { $0.0 < $1.0 }
        let recentSlice = rows.compactMap { row -> (Double, String)? in
            guard let value = row["last_2_seconds_max_ms"] as? Double, let category = row["category"] as? String else { return nil }
            return (value, category)
        }.max { $0.0 < $1.0 }
        return [
            "cpu_cores_max": ["overall": overallCPUPeak.map { $0 as Any } ?? NSNull(), "last_2_seconds": peakRecent.map { $0.cores as Any } ?? NSNull(),
                              "overall_contributor": overallContributor.map { $0 as Any } ?? NSNull(), "last_2_seconds_contributor": peakRecent.flatMap(\.contributor).map { $0 as Any } ?? NSNull()],
            "work_slice_ms_max": ["overall": overallSlice.map { $0.0 as Any } ?? NSNull(), "last_2_seconds": recentSlice.map { $0.0 as Any } ?? NSNull()],
            "event_loop_lag_ms": ["last": NSNull(), "max": NSNull()],
            "categories": rows,
            "longest_uninterrupted_category": overallSlice?.1 ?? NSNull(),
            "longest_uninterrupted_last_2_seconds_category": recentSlice?.1 ?? NSNull(),
        ]
    }

    private func trim(nowNS: UInt64) {
        let window: UInt64 = 2_000_000_000
        recent.removeAll { nowNS >= $0.completedNS && nowNS - $0.completedNS > window }
        recentCPUPeaks.removeAll { nowNS >= $0.completedNS && nowNS - $0.completedNS > window }
    }
}
