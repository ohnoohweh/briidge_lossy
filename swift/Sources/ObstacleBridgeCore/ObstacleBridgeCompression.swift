import CZlib
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
