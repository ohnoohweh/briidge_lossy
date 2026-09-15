import Foundation

public enum ObstacleBridgeBinaryCodecError: Error, Equatable, Sendable {
    case truncated
    case invalidLength
    case invalidUTF8
}

/// Bounded big-endian reader for every common wire codec. It never exposes an
/// unchecked Data subscript to an adapter.
public struct ObstacleBridgeBinaryReader: Sendable {
    private let data: Data
    private(set) public var offset: Int = 0

    public init(_ data: Data) { self.data = data }
    public var remainingCount: Int { data.count - offset }
    public var isAtEnd: Bool { offset == data.count }

    public mutating func readUInt8() throws -> UInt8 {
        try require(1)
        defer { offset += 1 }
        return data[offset]
    }

    public mutating func readUInt16() throws -> UInt16 {
        try require(2)
        defer { offset += 2 }
        return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    public mutating func readUInt32() throws -> UInt32 {
        try require(4)
        defer { offset += 4 }
        return (0..<4).reduce(UInt32(0)) { ($0 << 8) | UInt32(data[offset + $1]) }
    }

    public mutating func readUInt64() throws -> UInt64 {
        try require(8)
        defer { offset += 8 }
        return (0..<8).reduce(UInt64(0)) { ($0 << 8) | UInt64(data[offset + $1]) }
    }

    public mutating func readData(count: Int) throws -> Data {
        guard count >= 0 else { throw ObstacleBridgeBinaryCodecError.invalidLength }
        try require(count)
        defer { offset += count }
        return Data(data[offset..<(offset + count)])
    }

    public mutating func readUTF8(count: Int) throws -> String {
        let value = try readData(count: count)
        guard let string = String(data: value, encoding: .utf8) else {
            throw ObstacleBridgeBinaryCodecError.invalidUTF8
        }
        return string
    }

    public mutating func expect(_ value: Data) throws {
        guard try readData(count: value.count) == value else {
            throw ObstacleBridgeBinaryCodecError.invalidLength
        }
    }

    private func require(_ count: Int) throws {
        guard count <= remainingCount else { throw ObstacleBridgeBinaryCodecError.truncated }
    }
}

public struct ObstacleBridgeBinaryWriter: Sendable {
    private var data = Data()

    public init(capacity: Int = 0) { data.reserveCapacity(capacity) }
    public mutating func append(_ value: UInt8) { data.append(value) }
    public mutating func append(_ value: UInt16) {
        data.append(UInt8(value >> 8)); data.append(UInt8(value & 0xff))
    }
    public mutating func append(_ value: UInt32) {
        for shift in stride(from: 24, through: 0, by: -8) { data.append(UInt8((value >> UInt32(shift)) & 0xff)) }
    }
    public mutating func append(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) }
    }
    public mutating func append(_ value: Data) { data.append(value) }
    public mutating func appendUTF8(_ value: String) { data.append(Data(value.utf8)) }
    public var encoded: Data { data }
}
