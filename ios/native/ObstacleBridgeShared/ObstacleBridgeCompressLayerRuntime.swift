import Foundation
import zlib

final class ObstacleBridgeCompressLayerRuntime {
    private static let muxHeaderSize = 8

    struct StatusSnapshot {
        var enabled: Bool
        var algorithm: String
        var transport: String
        var level: Int
        var minBytes: Int
        var compressAttemptsTotal: Int
        var compressAppliedTotal: Int
        var compressSkippedNoGainTotal: Int
        var compressInputBytesTotal: Int
        var compressOutputBytesTotal: Int
        var decompressOKTotal: Int
        var decompressFailTotal: Int
    }

    struct SendSnapshot {
        var wirePayload: Data
        var sentBytes: Int
        var compressed: Bool
    }

    struct ReceiveSnapshot {
        var deliveredPayload: Data?
        var deliveredPeerID: Int?
        var dropped: Bool
        var decompressed: Bool
    }

    private struct PeerStats {
        var active = false
        var compressAttemptsTotal = 0
        var compressAppliedTotal = 0
        var compressSkippedNoGainTotal = 0
        var compressInputBytesTotal = 0
        var compressOutputBytesTotal = 0
        var decompressOKTotal = 0
        var decompressFailTotal = 0
    }

    private struct ParsedMuxFrame {
        var chanID: Int
        var proto: Int
        var counter: Int
        var mtype: Int
        var body: Data
    }

    static let compressedFlag = 0x80
    static let defaultAllowedMTypeNames = "data,data_frag"
    static let knownBaseMTypes: Set<Int> = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    static let mtypeNameToID: [String: Int] = [
        "data": 0x00,
        "open": 0x01,
        "close": 0x02,
        "remote_services_set_v1": 0x03,
        "remote_services_set_v2": 0x04,
        "data_frag": 0x05,
        "remote_services_set_v2_chunk": 0x06,
        "open_chunk": 0x07,
    ]

    private let configuredEnabled: Bool
    private let isPeerClient: Bool
    private let algorithm: String
    private let transportName: String
    private let level: Int
    private let minBytes: Int
    private let allowedMTypes: Set<Int>
    private let peerSelectedLevel: Int
    private let peerSelectedMinBytes: Int
    private let peerSelectedAllowedMTypes: Set<Int>
    private let maxAppPayload: Int
    private let maxMuxPayload: Int

    private var compressAttemptsTotal = 0
    private var compressAppliedTotal = 0
    private var compressSkippedNoGainTotal = 0
    private var compressInputBytesTotal = 0
    private var compressOutputBytesTotal = 0
    private var decompressOKTotal = 0
    private var decompressFailTotal = 0
    private var peerCompress: [String: PeerStats] = [:]

    init(
        configuredEnabled: Bool = true,
        isPeerClient: Bool = false,
        algorithm: String = "zlib",
        transportName: String = "tcp",
        level: Int = 3,
        minBytes: Int = 64,
        allowedMTypesRaw: String = ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
        maxAppPayload: Int = 65535,
        peerSelectedLevel: Int = 3,
        peerSelectedMinBytes: Int = 64,
        peerSelectedAllowedMTypesRaw: String = ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames
    ) {
        self.configuredEnabled = configuredEnabled
        self.isPeerClient = isPeerClient
        self.algorithm = algorithm.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        self.transportName = transportName
        self.level = max(0, min(9, level))
        self.minBytes = max(0, minBytes)
        self.allowedMTypes = Self.parseAllowedMTypes(allowedMTypesRaw)
        self.peerSelectedLevel = max(0, min(9, peerSelectedLevel))
        self.peerSelectedMinBytes = max(0, peerSelectedMinBytes)
        self.peerSelectedAllowedMTypes = Self.parseAllowedMTypes(peerSelectedAllowedMTypesRaw)
        self.maxAppPayload = max(0, maxAppPayload)
        self.maxMuxPayload = max(0, self.maxAppPayload - Self.muxHeaderSize)
    }

    func handleInboundPayload(_ payload: Data, peerID: Int? = nil) -> ReceiveSnapshot {
        guard let parsed = Self.parseMuxFrame(payload) else {
            return ReceiveSnapshot(deliveredPayload: payload, deliveredPeerID: peerID, dropped: false, decompressed: false)
        }
        guard parsed.mtype >= Self.compressedFlag else {
            return ReceiveSnapshot(deliveredPayload: payload, deliveredPeerID: peerID, dropped: false, decompressed: false)
        }

        let baseMType = parsed.mtype - Self.compressedFlag
        guard Self.knownBaseMTypes.contains(baseMType) else {
            decompressFailTotal += 1
            addPeerCounter(peerID: peerID, field: \PeerStats.decompressFailTotal, value: 1)
            return ReceiveSnapshot(deliveredPayload: nil, deliveredPeerID: peerID, dropped: true, decompressed: false)
        }

        guard let decoded = Self.safeDecompress(parsed.body, maxOut: maxMuxPayload) else {
            decompressFailTotal += 1
            addPeerCounter(peerID: peerID, field: \PeerStats.decompressFailTotal, value: 1)
            return ReceiveSnapshot(deliveredPayload: nil, deliveredPeerID: peerID, dropped: true, decompressed: false)
        }

        decompressOKTotal += 1
        markPeerActive(peerID: peerID)
        addPeerCounter(peerID: peerID, field: \PeerStats.decompressOKTotal, value: 1)
        let wire = Self.buildMuxFrame(
            chanID: parsed.chanID,
            proto: parsed.proto,
            counter: parsed.counter,
            mtype: baseMType,
            body: decoded
        )
        return ReceiveSnapshot(deliveredPayload: wire, deliveredPeerID: peerID, dropped: false, decompressed: true)
    }

    func handleSendPayload(_ payload: Data, peerID: Int? = nil) -> SendSnapshot {
        guard let parsed = Self.parseMuxFrame(payload) else {
            return SendSnapshot(wirePayload: payload, sentBytes: payload.count, compressed: false)
        }

        let statsPeerID = statsPeerIDForSend(peerID: peerID)
        let policy = sendPolicy(peerID: statsPeerID)
        if algorithm != "zlib"
            || !peerSendEnabled(peerID: statsPeerID)
            || parsed.mtype >= Self.compressedFlag
            || !Self.knownBaseMTypes.contains(parsed.mtype)
            || !policy.allowedMTypes.contains(parsed.mtype)
            || parsed.body.count < policy.minBytes {
            return SendSnapshot(wirePayload: payload, sentBytes: payload.count, compressed: false)
        }

        compressAttemptsTotal += 1
        compressInputBytesTotal += parsed.body.count
        addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressAttemptsTotal, value: 1)
        addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressInputBytesTotal, value: parsed.body.count)

        guard let compressed = Self.safeCompress(parsed.body, level: policy.level), !compressed.isEmpty, compressed.count < parsed.body.count else {
            compressSkippedNoGainTotal += 1
            compressOutputBytesTotal += parsed.body.count
            addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressSkippedNoGainTotal, value: 1)
            addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressOutputBytesTotal, value: parsed.body.count)
            return SendSnapshot(wirePayload: payload, sentBytes: payload.count, compressed: false)
        }

        compressAppliedTotal += 1
        compressOutputBytesTotal += compressed.count
        addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressAppliedTotal, value: 1)
        addPeerCounter(peerID: statsPeerID, field: \PeerStats.compressOutputBytesTotal, value: compressed.count)

        let wire = Self.buildMuxFrame(
            chanID: parsed.chanID,
            proto: parsed.proto,
            counter: parsed.counter,
            mtype: parsed.mtype + Self.compressedFlag,
            body: compressed
        )
        return SendSnapshot(wirePayload: wire, sentBytes: payload.count, compressed: true)
    }

    func statusSnapshot(peerID: Int? = nil) -> StatusSnapshot {
        if let peerID {
            var stats = peerCompress[peerKey(peerID)]
            if stats == nil, isPeerClient {
                stats = peerCompress[peerKey(nil)]
            }
            guard let stats else {
                return snapshot(from: PeerStats(), enabled: isPeerClient ? configuredEnabled : false, level: level, minBytes: minBytes)
            }
            let enabled = isPeerClient ? configuredEnabled : stats.active
            if !isPeerClient, enabled {
                return snapshot(from: stats, enabled: enabled, level: peerSelectedLevel, minBytes: peerSelectedMinBytes)
            }
            return snapshot(from: stats, enabled: enabled, level: level, minBytes: minBytes)
        }

        let anyPeerActive = peerCompress.values.contains { $0.active }
        let counters = PeerStats(
            active: anyPeerActive,
            compressAttemptsTotal: compressAttemptsTotal,
            compressAppliedTotal: compressAppliedTotal,
            compressSkippedNoGainTotal: compressSkippedNoGainTotal,
            compressInputBytesTotal: compressInputBytesTotal,
            compressOutputBytesTotal: compressOutputBytesTotal,
            decompressOKTotal: decompressOKTotal,
            decompressFailTotal: decompressFailTotal
        )
        return snapshot(from: counters, enabled: isPeerClient ? configuredEnabled : anyPeerActive, level: level, minBytes: minBytes)
    }

    private func snapshot(from counters: PeerStats, enabled: Bool, level: Int, minBytes: Int) -> StatusSnapshot {
        return StatusSnapshot(
            enabled: enabled,
            algorithm: algorithm,
            transport: transportName,
            level: level,
            minBytes: minBytes,
            compressAttemptsTotal: counters.compressAttemptsTotal,
            compressAppliedTotal: counters.compressAppliedTotal,
            compressSkippedNoGainTotal: counters.compressSkippedNoGainTotal,
            compressInputBytesTotal: counters.compressInputBytesTotal,
            compressOutputBytesTotal: counters.compressOutputBytesTotal,
            decompressOKTotal: counters.decompressOKTotal,
            decompressFailTotal: counters.decompressFailTotal
        )
    }

    private func peerKey(_ peerID: Int?) -> String {
        if let peerID {
            return String(peerID)
        }
        return "__single__"
    }

    private func peerStats(_ peerID: Int?) -> PeerStats {
        return peerCompress[peerKey(peerID)] ?? PeerStats()
    }

    private func setPeerStats(_ stats: PeerStats, peerID: Int?) {
        peerCompress[peerKey(peerID)] = stats
    }

    private func peerSendEnabled(peerID: Int?) -> Bool {
        if isPeerClient {
            return configuredEnabled
        }
        if peerID == nil {
            return configuredEnabled
        }
        return peerStats(peerID).active
    }

    private func sendPolicy(peerID: Int?) -> (level: Int, minBytes: Int, allowedMTypes: Set<Int>) {
        if !isPeerClient, peerID != nil, peerSendEnabled(peerID: peerID) {
            return (peerSelectedLevel, peerSelectedMinBytes, peerSelectedAllowedMTypes)
        }
        return (level, minBytes, allowedMTypes)
    }

    private func statsPeerIDForSend(peerID: Int?) -> Int? {
        if isPeerClient || peerID != nil {
            return peerID
        }
        let activePeerIDs = peerCompress.compactMap { key, stats -> Int? in
            guard stats.active else {
                return nil
            }
            return Int(key)
        }
        if activePeerIDs.count == 1 {
            return activePeerIDs[0]
        }
        return nil
    }

    private func markPeerActive(peerID: Int?) {
        var stats = peerStats(peerID)
        stats.active = true
        setPeerStats(stats, peerID: peerID)
    }

    private func addPeerCounter(peerID: Int?, field: WritableKeyPath<PeerStats, Int>, value: Int) {
        var stats = peerStats(peerID)
        stats[keyPath: field] += value
        setPeerStats(stats, peerID: peerID)
    }

    static func parseAllowedMTypes(_ raw: String) -> Set<Int> {
        var normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.isEmpty {
            normalized = defaultAllowedMTypeNames
        }
        var out: Set<Int> = []
        for token in normalized.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }) {
            if let value = mtypeNameToID[token] {
                out.insert(value)
            }
        }
        if out.isEmpty {
            return [mtypeNameToID["data"]!, mtypeNameToID["data_frag"]!]
        }
        return out
    }

    private static func parseMuxFrame(_ payload: Data) -> ParsedMuxFrame? {
        guard payload.count >= muxHeaderSize else {
            return nil
        }
        let chanID = Int(readUInt16BE(payload, offset: 0))
        let proto = Int(payload[2])
        let counter = Int(readUInt16BE(payload, offset: 3))
        let mtype = Int(payload[5])
        let bodyLength = Int(readUInt16BE(payload, offset: 6))
        guard payload.count == muxHeaderSize + bodyLength else {
            return nil
        }
        return ParsedMuxFrame(
            chanID: chanID,
            proto: proto,
            counter: counter,
            mtype: mtype,
            body: payload.subdata(in: muxHeaderSize..<(muxHeaderSize + bodyLength))
        )
    }

    private static func buildMuxFrame(chanID: Int, proto: Int, counter: Int, mtype: Int, body: Data) -> Data {
        var frame = Data()
        frame.reserveCapacity(muxHeaderSize + body.count)
        appendUInt16BE(UInt16(clamping: chanID), to: &frame)
        frame.append(UInt8(clamping: proto))
        appendUInt16BE(UInt16(clamping: counter), to: &frame)
        frame.append(UInt8(clamping: mtype))
        appendUInt16BE(UInt16(clamping: body.count), to: &frame)
        frame.append(body)
        return frame
    }

    private static func readUInt16BE(_ data: Data, offset: Int) -> UInt16 {
        return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func appendUInt16BE(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func safeCompress(_ payload: Data, level: Int) -> Data? {
        let bound = compressBound(uLong(payload.count))
        var output = Data(count: Int(bound))
        var outputLength = bound
        let result = payload.withUnsafeBytes { inputBuffer in
            output.withUnsafeMutableBytes { outputBuffer in
                guard
                    let inputBase = inputBuffer.bindMemory(to: Bytef.self).baseAddress,
                    let outputBase = outputBuffer.bindMemory(to: Bytef.self).baseAddress
                else {
                    return Z_BUF_ERROR
                }
                return compress2(outputBase, &outputLength, inputBase, uLong(payload.count), Int32(level))
            }
        }
        guard result == Z_OK else {
            return nil
        }
        output.count = Int(outputLength)
        return output
    }

    private static func safeDecompress(_ payload: Data, maxOut: Int) -> Data? {
        guard maxOut >= 0 else {
            return nil
        }
        let outputCapacity = max(1, maxOut + 1)
        var output = Data(count: outputCapacity)
        var stream = z_stream()
        let initResult = inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initResult == Z_OK else {
            return nil
        }
        defer { inflateEnd(&stream) }

        let status = payload.withUnsafeBytes { inputBuffer in
            output.withUnsafeMutableBytes { outputBuffer in
                stream.next_in = UnsafeMutablePointer<Bytef>(mutating: inputBuffer.bindMemory(to: Bytef.self).baseAddress)
                stream.avail_in = uInt(payload.count)
                stream.next_out = outputBuffer.bindMemory(to: Bytef.self).baseAddress
                stream.avail_out = uInt(outputCapacity)
                return inflate(&stream, Z_FINISH)
            }
        }
        guard status == Z_STREAM_END, stream.avail_in == 0 else {
            return nil
        }
        let outputLength = Int(stream.total_out)
        guard outputLength <= maxOut else {
            return nil
        }
        output.count = outputLength
        return output
    }
}