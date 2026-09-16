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

public enum ObstacleBridgeMuxCompression {
    public static let compressedFlag: UInt8 = 0x80
    public static let knownBaseMessageTypes: Set<UInt8> = [0, 1, 2, 3, 4, 5, 6, 7]

    public static func protect(_ wire: Data, policy: ObstacleBridgeMuxCompressionPolicy = .init()) throws -> (wire: Data, compressed: Bool) {
        guard policy.enabled, let frame = try? ObstacleBridgeChannelMuxFrameCodec.decode(wire),
              frame.messageType < compressedFlag, knownBaseMessageTypes.contains(frame.messageType),
              policy.allowedMessageTypes.contains(frame.messageType), frame.body.count >= policy.minimumBodyBytes else { return (wire, false) }
        let body = try ObstacleBridgeCompression.compress(frame.body, level: policy.level)
        guard !body.isEmpty, body.count < frame.body.count else { return (wire, false) }
        return (try ObstacleBridgeChannelMuxFrameCodec.encode(channelID: frame.channelID, protocolType: frame.protocolType, counter: frame.counter, messageType: frame.messageType | compressedFlag, body: body), true)
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
