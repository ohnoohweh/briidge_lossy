#if canImport(CZlib)
import CZlib
#elseif canImport(zlib)
import zlib
#endif
import Foundation

/// Portable zlib primitive shared by mux-aware compression wrappers. Platform
/// adapters never own compression or decompression state.
public enum ObstacleBridgeCompression {
    public enum Error: Swift.Error, Equatable, Sendable { case invalidInput, outputLimit }

    public static func compress(_ input: Data, level: Int = 3) throws -> Data {
        guard !input.isEmpty else { return Data() }
        var output = Data(count: Int(compressBound(uLong(input.count))))
        var count = uLongf(output.count)
        let result = input.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { destination in
                compress2(destination.bindMemory(to: Bytef.self).baseAddress, &count, source.bindMemory(to: Bytef.self).baseAddress, uLong(input.count), Int32(max(0, min(9, level))))
            }
        }
        guard result == Z_OK else { throw Error.invalidInput }
        output.removeSubrange(Int(count)..<output.count)
        return output
    }

    public static func decompress(_ input: Data, maximumOutput: Int) throws -> Data {
        guard maximumOutput >= 0 else { throw Error.outputLimit }
        guard !input.isEmpty else { return Data() }
        var capacity = min(maximumOutput, max(64, input.count * 2))
        while capacity <= maximumOutput {
            var output = Data(count: capacity)
            var count = uLongf(capacity)
            let result = input.withUnsafeBytes { source in output.withUnsafeMutableBytes { destination in
                uncompress(destination.bindMemory(to: Bytef.self).baseAddress, &count, source.bindMemory(to: Bytef.self).baseAddress, uLong(input.count))
            }}
            if result == Z_OK { output.removeSubrange(Int(count)..<output.count); return output }
            guard result == Z_BUF_ERROR, capacity < maximumOutput else { throw result == Z_BUF_ERROR ? Error.outputLimit : Error.invalidInput }
            capacity = min(maximumOutput, capacity * 2)
        }
        throw Error.outputLimit
    }
}

/// Mux-aware policy shared by Apple and Linux compression wrappers.
public struct ObstacleBridgeMuxCompressionPolicy: Equatable, Sendable {
    public var enabled: Bool
    public var level: Int
    public var minimumBodyBytes: Int
    public var allowedMessageTypes: Set<UInt8>
    public init(enabled: Bool = true, level: Int = 3, minimumBodyBytes: Int = 64, allowedMessageTypes: Set<UInt8> = [0, 5]) {
        self.enabled = enabled; self.level = level; self.minimumBodyBytes = max(0, minimumBodyBytes); self.allowedMessageTypes = allowedMessageTypes
    }
}

/// Redacted compression accounting for one overlay peer.  It records only
/// framing sizes and outcomes; it never retains payload bytes.
public struct ObstacleBridgeMuxCompressionSnapshot: Codable, Equatable, Sendable {
    public let enabled: Bool
    public let algorithm: String
    public let level: Int
    public let minimumBodyBytes: Int
    public let compressAttemptsTotal: UInt64
    public let compressAppliedTotal: UInt64
    public let compressSkippedNoGainTotal: UInt64
    public let compressInputBytesTotal: UInt64
    public let compressOutputBytesTotal: UInt64
    public let compressedFramesSentTotal: UInt64
    public let compressedFramesReceivedTotal: UInt64
    public let compressedInputBytesSentTotal: UInt64
    public let compressedOutputBytesSentTotal: UInt64
    public let compressedInputBytesReceivedTotal: UInt64
    public let compressedOutputBytesReceivedTotal: UInt64
    public let uncompressedFramesSentTotal: UInt64
    public let uncompressedFramesReceivedTotal: UInt64
    public let uncompressedBytesSentTotal: UInt64
    public let uncompressedBytesReceivedTotal: UInt64
    public let rejectedFramesTotal: UInt64
    public let rejectedBytesTotal: UInt64
}

/// Core owns the classification and accounting vocabulary.  Adapters record
/// their already-decoded frame outcome here instead of duplicating compression
/// policy or zlib parsing in an Admin/status layer.
public final class ObstacleBridgeMuxCompressionTelemetry: @unchecked Sendable {
    private let policy: ObstacleBridgeMuxCompressionPolicy
    private let lock = NSLock()
    private var compressAttemptsTotal: UInt64 = 0
    private var compressAppliedTotal: UInt64 = 0
    private var compressSkippedNoGainTotal: UInt64 = 0
    private var compressInputBytesTotal: UInt64 = 0
    private var compressOutputBytesTotal: UInt64 = 0
    private var compressedFramesSentTotal: UInt64 = 0
    private var compressedFramesReceivedTotal: UInt64 = 0
    private var compressedInputBytesSentTotal: UInt64 = 0
    private var compressedOutputBytesSentTotal: UInt64 = 0
    private var compressedInputBytesReceivedTotal: UInt64 = 0
    private var compressedOutputBytesReceivedTotal: UInt64 = 0
    private var uncompressedFramesSentTotal: UInt64 = 0
    private var uncompressedFramesReceivedTotal: UInt64 = 0
    private var uncompressedBytesSentTotal: UInt64 = 0
    private var uncompressedBytesReceivedTotal: UInt64 = 0
    private var rejectedFramesTotal: UInt64 = 0
    private var rejectedBytesTotal: UInt64 = 0

    public init(policy: ObstacleBridgeMuxCompressionPolicy) { self.policy = policy }

    public func recordOutbound(inputBodyBytes: Int, outputBodyBytes: Int, attempted: Bool, compressed: Bool) {
        let input = UInt64(max(0, inputBodyBytes)); let output = UInt64(max(0, outputBodyBytes))
        lock.lock(); defer { lock.unlock() }
        if attempted {
            compressAttemptsTotal &+= 1
            compressInputBytesTotal &+= input
            compressOutputBytesTotal &+= output
            if compressed { compressAppliedTotal &+= 1 } else { compressSkippedNoGainTotal &+= 1 }
        }
        if compressed {
            compressedFramesSentTotal &+= 1
            compressedInputBytesSentTotal &+= input
            compressedOutputBytesSentTotal &+= output
        }
        else { uncompressedFramesSentTotal &+= 1; uncompressedBytesSentTotal &+= output }
    }

    public func recordInbound(inputBodyBytes: Int, outputBodyBytes: Int, decompressed: Bool) {
        let input = UInt64(max(0, inputBodyBytes)); let output = UInt64(max(0, outputBodyBytes))
        lock.lock(); defer { lock.unlock() }
        if decompressed {
            compressedFramesReceivedTotal &+= 1
            compressedInputBytesReceivedTotal &+= input
            compressedOutputBytesReceivedTotal &+= output
        }
        else { uncompressedFramesReceivedTotal &+= 1; uncompressedBytesReceivedTotal &+= output }
    }

    public func recordRejectedInbound(bodyBytes: Int) {
        lock.lock(); defer { lock.unlock() }
        rejectedFramesTotal &+= 1; rejectedBytesTotal &+= UInt64(max(0, bodyBytes))
    }

    public func snapshot() -> ObstacleBridgeMuxCompressionSnapshot {
        lock.lock(); defer { lock.unlock() }
        return .init(
            enabled: policy.enabled, algorithm: "zlib", level: policy.level, minimumBodyBytes: policy.minimumBodyBytes,
            compressAttemptsTotal: compressAttemptsTotal, compressAppliedTotal: compressAppliedTotal,
            compressSkippedNoGainTotal: compressSkippedNoGainTotal, compressInputBytesTotal: compressInputBytesTotal,
            compressOutputBytesTotal: compressOutputBytesTotal, compressedFramesSentTotal: compressedFramesSentTotal,
            compressedFramesReceivedTotal: compressedFramesReceivedTotal,
            compressedInputBytesSentTotal: compressedInputBytesSentTotal,
            compressedOutputBytesSentTotal: compressedOutputBytesSentTotal,
            compressedInputBytesReceivedTotal: compressedInputBytesReceivedTotal,
            compressedOutputBytesReceivedTotal: compressedOutputBytesReceivedTotal,
            uncompressedFramesSentTotal: uncompressedFramesSentTotal,
            uncompressedFramesReceivedTotal: uncompressedFramesReceivedTotal, uncompressedBytesSentTotal: uncompressedBytesSentTotal,
            uncompressedBytesReceivedTotal: uncompressedBytesReceivedTotal, rejectedFramesTotal: rejectedFramesTotal,
            rejectedBytesTotal: rejectedBytesTotal
        )
    }
}

public enum ObstacleBridgeMuxCompression {
    public static let compressedFlag: UInt8 = 0x80
    public static let knownBaseMessageTypes: Set<UInt8> = [0, 1, 2, 3, 4, 5, 6, 7]

    public static func protect(_ wire: Data, policy: ObstacleBridgeMuxCompressionPolicy = .init()) throws -> (wire: Data, compressed: Bool, attempted: Bool) {
        guard policy.enabled, let frame = try? ObstacleBridgeChannelMuxFrameCodec.decode(wire),
              frame.messageType < compressedFlag, knownBaseMessageTypes.contains(frame.messageType),
              policy.allowedMessageTypes.contains(frame.messageType), frame.body.count >= policy.minimumBodyBytes else { return (wire, false, false) }
        let body = try ObstacleBridgeCompression.compress(frame.body, level: policy.level)
        guard !body.isEmpty, body.count < frame.body.count else { return (wire, false, true) }
        return (try ObstacleBridgeChannelMuxFrameCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType | compressedFlag, body: body), true, true)
    }

    public static func unprotect(_ wire: Data, maximumBodyBytes: Int = Int(UInt16.max)) throws -> (wire: Data, decompressed: Bool) {
        let frame = try ObstacleBridgeChannelMuxFrameCodec.decode(wire)
        guard frame.messageType >= compressedFlag else { return (wire, false) }
        let type = frame.messageType - compressedFlag
        guard knownBaseMessageTypes.contains(type) else { throw ObstacleBridgeCompression.Error.invalidInput }
        let body = try ObstacleBridgeCompression.decompress(frame.body, maximumOutput: maximumBodyBytes)
        return (try ObstacleBridgeChannelMuxFrameCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: type, body: body), true)
    }
}
