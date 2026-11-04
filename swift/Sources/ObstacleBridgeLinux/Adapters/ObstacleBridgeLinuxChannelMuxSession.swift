import Foundation
import ObstacleBridgeCore

public enum ObstacleBridgeLinuxChannelMuxError: Error, Equatable {
    case notReady
    case staleEpoch
    case tooManyInFlightFrames
}

/// The Linux admission boundary for ChannelMux frames. It deliberately keeps
/// only one synchronous frame in flight, which bounds memory until the full
/// queue/backpressure runtime is introduced with TUN ownership.
public final class ObstacleBridgeLinuxChannelMuxSession {
    private let runtime: ObstacleBridgeLinuxConfiguredRuntime
    private let session: ObstacleBridgeLinuxConfiguredSession
    private let epoch: UInt64
    private let compressionPolicy: ObstacleBridgeMuxCompressionPolicy
    private let compressionTelemetry: ObstacleBridgeMuxCompressionTelemetry
    /// Uses the shared Core severity contract so ChannelMux, SecureLink, and
    /// myUDP observations reach the same foreground log pipeline.
    private let diagnosticSink: ((ObstacleBridgeRuntimeDiagnosticLevel, String, [String: String]) -> Void)?
    private let lock = NSLock()
    private let replyPolicy = ObstacleBridgeChannelMuxReplyPolicy()
    private var awaited: ObstacleBridgeChannelMuxFrame?
    private var reply: ObstacleBridgeChannelMuxFrame?
    private var replySignal: DispatchSemaphore?
    private let controlChunkReassembler = ObstacleBridgeControlChunkReassembler()
    public var onUnsolicitedFrame: ((ObstacleBridgeChannelMuxFrame) -> Void)?

    public init(
        runtime: ObstacleBridgeLinuxConfiguredRuntime,
        session: ObstacleBridgeLinuxConfiguredSession,
        startupFrames: [ObstacleBridgeChannelMuxFrame] = [],
        diagnosticSink: ((ObstacleBridgeRuntimeDiagnosticLevel, String, [String: String]) -> Void)? = nil
    ) throws {
        guard runtime.status().appReady else { throw ObstacleBridgeLinuxChannelMuxError.notReady }
        self.runtime = runtime
        self.session = session
        self.epoch = runtime.connectionEpoch
        self.compressionPolicy = runtime.configuration.compressionPolicy
        self.compressionTelemetry = runtime.compressionTelemetry
        self.diagnosticSink = diagnosticSink
        diagnostic(.info, "channel_mux.epoch_started", extra: ["epoch": String(epoch)])
        for frame in startupFrames {
            guard try exchange(frame) == frame else { throw ObstacleBridgeLinuxChannelMuxError.staleEpoch }
        }
    }

    public func exchange(_ frame: ObstacleBridgeChannelMuxFrame) throws -> ObstacleBridgeChannelMuxFrame {
        let started = DispatchTime.now().uptimeNanoseconds
        defer { ObstacleBridgeRuntimeMetrics.shared.record(.channelMuxCallback, durationNS: DispatchTime.now().uptimeNanoseconds &- started) }
        guard runtime.connectionEpoch == epoch, runtime.status().appReady else {
            diagnostic(.warning, "channel_mux.stale_epoch", frame: frame)
            throw ObstacleBridgeLinuxChannelMuxError.staleEpoch
        }
        let duplex: Bool
        do { duplex = try replyPolicy.beginExchange(frame) }
        catch {
            diagnostic(.warning, "channel_mux.exchange_backpressured", frame: frame)
            throw ObstacleBridgeLinuxChannelMuxError.tooManyInFlightFrames
        }
        let signal = duplex ? DispatchSemaphore(value: 0) : nil
        lock.lock()
        if duplex { awaited = frame; reply = nil; replySignal = signal }
        lock.unlock()
        defer {
            replyPolicy.finishExchange()
            lock.lock(); awaited = nil; replySignal = nil; lock.unlock()
        }
        let wire = try protectedWire(for: frame)
        lifecycle(.info, event: "channel_mux.frame_sent", frame: frame)
        if !duplex { return try decodeInbound(session.send(wire)) }
        try session.sendOneWay(wire)
        guard signal?.wait(timeout: .now() + 10) == .success else { // OBSTACLEBRIDGE-ASYNC-IO-EXCEPTION: bounded legacy request/reply compatibility wait; test=channelMuxFramesUseReadySessionAndRejectStaleEpoch
            diagnostic(.warning, "channel_mux.reply_timed_out", frame: frame)
            throw ObstacleBridgeLinuxChannelMuxError.staleEpoch
        }
        lock.lock(); let value = reply; lock.unlock()
        guard let value else {
            diagnostic(.warning, "channel_mux.reply_missing", frame: frame)
            throw ObstacleBridgeLinuxChannelMuxError.staleEpoch
        }
        return value
    }

    /// Sends a frame whose result is expected to arrive asynchronously (for
    /// example a service OPEN/DATA exchange).  A live duplex peer must not be
    /// forced into the legacy request/reply matcher merely because it has no
    /// immediate ChannelMux acknowledgement to send.
    public func sendUnsolicited(_ frame: ObstacleBridgeChannelMuxFrame) throws {
        let started = DispatchTime.now().uptimeNanoseconds
        defer { ObstacleBridgeRuntimeMetrics.shared.record(.channelMuxCallback, durationNS: DispatchTime.now().uptimeNanoseconds &- started) }
        guard runtime.connectionEpoch == epoch, runtime.status().appReady else {
            diagnostic(.warning, "channel_mux.stale_epoch", frame: frame)
            throw ObstacleBridgeLinuxChannelMuxError.staleEpoch
        }
        try session.sendOneWay(protectedWire(for: frame))
        lifecycle(.info, event: "channel_mux.frame_sent", frame: frame)
    }

    /// Marks this mux as driven by the one live receive owner. Once enabled,
    /// request/reply compatibility waits on that owner instead of reading the
    /// lower descriptor a second time.
    public func activateReceiveOwner() {
        replyPolicy.activateReceiveOwner()
    }

    /// The sole ChannelMux decode boundary for this epoch. Compression belongs
    /// to Core; the Linux wrapper only places it around the transport record.
    public func decodeInbound(_ wire: Data) throws -> ObstacleBridgeChannelMuxFrame {
        let started = DispatchTime.now().uptimeNanoseconds
        defer { ObstacleBridgeRuntimeMetrics.shared.record(.channelMuxCallback, durationNS: DispatchTime.now().uptimeNanoseconds &- started) }
        do {
            let encoded = try ObstacleBridgeChannelMuxFrameCodec.decode(wire)
            let result = try ObstacleBridgeMuxCompression.unprotect(wire)
            let decoded = try ObstacleBridgeChannelMuxCodec.decode(result.wire)
            compressionTelemetry.recordInbound(inputBodyBytes: encoded.body.count, outputBodyBytes: decoded.body.count, decompressed: result.decompressed)
            diagnostic(.debug, "channel_mux.frame_received", frame: decoded, extra: [
                "wire_bytes": String(wire.count),
                "compressed": result.decompressed ? "true" : "false",
            ])
            lifecycle(.info, event: "channel_mux.frame_received", frame: decoded)
            return decoded
        } catch {
            if let encoded = try? ObstacleBridgeChannelMuxFrameCodec.decode(wire),
               encoded.messageType >= ObstacleBridgeMuxCompression.compressedFlag {
                compressionTelemetry.recordFailedDecompression(bodyBytes: encoded.body.count)
            }
            diagnostic(.warning, "channel_mux.protocol_error_detected", extra: [
                "operation": "decode_inbound", "reason": String(describing: error), "wire_bytes": String(wire.count),
            ])
            throw error
        }
    }

    /// Called only by the configured session's receive worker after it has
    /// authenticated and decoded a complete ChannelMux record.
    public func receive(_ inbound: ObstacleBridgeChannelMuxFrame) {
        let started = DispatchTime.now().uptimeNanoseconds
        defer { ObstacleBridgeRuntimeMetrics.shared.record(.channelMuxCallback, durationNS: DispatchTime.now().uptimeNanoseconds &- started) }
        diagnostic(.debug, "channel_mux.frame_received", frame: inbound)
        guard let frame = reassembledControlFrame(from: inbound) else { return }
        lifecycle(.info, event: "channel_mux.frame_received", frame: frame)
        lock.lock()
        if replyPolicy.matchesAwaitedReply(frame) {
            reply = frame
            let signal = replySignal
            lock.unlock()
            signal?.signal()
            return
        }
        let handler = onUnsolicitedFrame
        lock.unlock()
        handler?(frame)
    }

    private func reassembledControlFrame(from frame: ObstacleBridgeChannelMuxFrame) -> ObstacleBridgeChannelMuxFrame? {
        let completedType: ObstacleBridgeChannelMuxMessageType
        switch frame.messageType {
        case .openChunk: completedType = .open
        case .remoteServicesSetV2Chunk: completedType = .remoteServicesSetV2
        default: return frame
        }
        guard let body = controlChunkReassembler.consume(
            channelID: frame.channelID,
            protocolType: frame.protocolType.rawValue,
            messageType: frame.messageType.rawValue,
            payload: frame.body,
            peerID: nil
        ) else { return nil }
        return .init(
            channelID: frame.channelID,
            protocolType: frame.protocolType,
            counter: frame.counter,
            messageType: completedType,
            body: body
        )
    }

    private func protectedWire(for frame: ObstacleBridgeChannelMuxFrame) throws -> Data {
        do {
            let wire = try ObstacleBridgeChannelMuxCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType, body: frame.body)
            let result = try ObstacleBridgeMuxCompression.protect(wire, policy: compressionPolicy)
            let output = try ObstacleBridgeChannelMuxFrameCodec.decode(result.wire)
            compressionTelemetry.recordOutbound(inputBodyBytes: frame.body.count, outputBodyBytes: output.body.count, attempted: result.attempted, compressed: result.compressed)
            diagnostic(.debug, "channel_mux.frame_prepared", frame: frame, extra: [
                "wire_bytes": String(result.wire.count), "compressed": result.compressed ? "true" : "false",
            ])
            return result.wire
        } catch {
            diagnostic(.warning, "channel_mux.protocol_error_detected", frame: frame, extra: [
                "operation": "encode_outbound", "reason": String(describing: error),
            ])
            throw error
        }
    }

    private func lifecycle(_ level: ObstacleBridgeRuntimeDiagnosticLevel, event: String, frame: ObstacleBridgeChannelMuxFrame) {
        guard frame.messageType == .open || frame.messageType == .close || frame.messageType == .remoteServicesSetV2 || frame.messageType == .remoteServicesSetV2Chunk else { return }
        diagnostic(level, event, frame: frame)
    }

    private func diagnostic(
        _ level: ObstacleBridgeRuntimeDiagnosticLevel,
        _ event: String,
        frame: ObstacleBridgeChannelMuxFrame? = nil,
        extra: [String: String] = [:]
    ) {
        var fields = extra
        if let frame {
            fields["channel"] = String(frame.channelID)
            fields["protocol"] = String(frame.protocolType.rawValue)
            fields["message_type"] = String(frame.messageType.rawValue)
            fields["counter"] = String(frame.counter)
            fields["body_bytes"] = String(frame.body.count)
        }
        diagnosticSink?(level, event, fields)
    }
}
