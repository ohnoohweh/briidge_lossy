import Foundation

enum ChannelMuxCodecRunnerError: Error {
    case invalidRequest
    case unsupportedAction
    case codecFailure
}

private func dataFromHex(_ value: String) -> Data? {
    let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard text.count % 2 == 0 else {
        return nil
    }
    var out = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else {
            return nil
        }
        out.append(byte)
        index = next
    }
    return out
}

private func hexFromData(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

private func appendUInt64BE(_ value: UInt64, to data: inout Data) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { rawBuffer in
        data.append(contentsOf: rawBuffer)
    }
}

private func parseIntKeyedUInt64Map(_ raw: Any?) throws -> [Int: UInt64] {
    guard let dict = raw as? [String: Any] else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    var result: [Int: UInt64] = [:]
    for (key, value) in dict {
        guard let intKey = Int(key), let number = value as? NSNumber else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        result[intKey] = number.uint64Value
    }
    return result
}

private func parseIntKeyedIntMap(_ raw: Any?) throws -> [Int: Int] {
    guard let dict = raw as? [String: Any] else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    var result: [Int: Int] = [:]
    for (key, value) in dict {
        guard let intKey = Int(key), let number = value as? NSNumber else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        result[intKey] = number.intValue
    }
    return result
}

private func parseSendMeta(_ raw: Any?) throws -> [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment] {
    let items = try jsonArray(raw as Any)
    var result: [Int: ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment] = [:]
    for item in items {
        let object = try jsonObject(item)
        guard
            let counter = object["counter"] as? NSNumber,
            let frameType = object["frame_type"] as? NSNumber,
            let lenOrOffset = object["len_or_offset"] as? NSNumber,
            let dataHex = object["data_hex"] as? String,
            let data = dataFromHex(dataHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        result[counter.intValue] = ObstacleBridgeUdpOverlaySessionCodec.OutgoingSegment(
            frameType: frameType.intValue,
            lenOrOffset: lenOrOffset.intValue,
            data: data
        )
    }
    return result
}

private func intKeyedStringMap<T>(_ values: [Int: T], convert: (T) -> String) -> [String: String] {
    var result: [String: String] = [:]
    for key in values.keys.sorted() {
        if let value = values[key] {
            result[String(key)] = convert(value)
        }
    }
    return result
}

private func intKeyedIntMap(_ values: [Int: Int]) -> [String: Int] {
    var result: [String: Int] = [:]
    for key in values.keys.sorted() {
        if let value = values[key] {
            result[String(key)] = value
        }
    }
    return result
}

private func inboundDataSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.InboundDataSnapshot) -> [String: Any] {
    return [
        "control_reasons": snapshot.controlReasons,
        "completed_hex": snapshot.completedPayloads.map(hexFromData),
        "expected": snapshot.expected,
        "pending": snapshot.pending,
        "missing": snapshot.missing,
        "established_ns": String(snapshot.establishedNS),
        "last_rx_tx_ns": String(snapshot.lastRxTxNS),
        "last_rx_wall_ns": String(snapshot.lastRxWallNS),
        "rtt_sample_ms": snapshot.rttSampleMS,
        "rtt_est_ms": snapshot.rttEstMS,
        "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
        "last_sent_last_in_order": snapshot.lastSentLastInOrder,
        "last_control_sent_ns": String(snapshot.lastControlSentNS),
    ]
}

private func inboundIdleSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.InboundIdleSnapshot) -> [String: Any] {
    return [
        "reflected": snapshot.reflected,
        "reflected_frame_hex": snapshot.reflectedFrame.map(hexFromData) ?? NSNull(),
        "established_ns": String(snapshot.establishedNS),
        "last_rx_tx_ns": String(snapshot.lastRxTxNS),
        "last_rx_wall_ns": String(snapshot.lastRxWallNS),
        "rtt_sample_ms": snapshot.rttSampleMS,
        "rtt_est_ms": snapshot.rttEstMS,
        "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
    ]
}

private func inboundControlSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.InboundControlSnapshot) -> [String: Any] {
    return [
        "send_buffer": snapshot.sendBuffer,
        "peer_reported_missing": snapshot.peerReportedMissing,
        "last_ack_peer": snapshot.lastAckPeer,
        "emitted_counters": snapshot.emittedCounters,
        "frames_hex": snapshot.emittedFrames.map(hexFromData),
        "last_retx_ns": intKeyedStringMap(snapshot.lastRetxNS) { String($0) },
        "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
        "peer_missed_count": snapshot.peerMissedCount,
        "last_send_ns": String(snapshot.lastSendNS),
        "flush_requested": snapshot.flushRequested,
        "control_should_emit": snapshot.controlShouldEmit,
        "control_reason": snapshot.controlReason ?? NSNull(),
        "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
        "last_sent_last_in_order": snapshot.lastSentLastInOrder,
        "last_control_sent_ns": String(snapshot.lastControlSentNS),
    ]
}

private func controlTimerSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.ControlTimerSnapshot) -> [String: Any] {
    return [
        "control_should_emit": snapshot.controlShouldEmit,
        "control_reason": snapshot.controlReason ?? NSNull(),
        "last_sent_last_in_order": snapshot.lastSentLastInOrder,
        "last_control_sent_ns": String(snapshot.lastControlSentNS),
    ]
}

private func retransmitTimerSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.RetransmitTimerSnapshot) -> [String: Any] {
    return [
        "emitted_counters": snapshot.emittedCounters,
        "frames_hex": snapshot.emittedFrames.map(hexFromData),
        "last_retx_ns": intKeyedStringMap(snapshot.lastRetxNS) { String($0) },
        "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
        "peer_reported_missing": snapshot.peerReportedMissing,
        "peer_missed_count": snapshot.peerMissedCount,
        "last_send_ns": String(snapshot.lastSendNS),
    ]
}

private func outboundDataSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.OutboundDataSnapshot) -> [String: Any] {
    return [
        "counters": snapshot.counters,
        "frames_hex": snapshot.frames.map(hexFromData),
        "send_buffer": snapshot.sendBuffer,
        "waiting_count": snapshot.waitingCount,
        "send_tx_ns": intKeyedStringMap(snapshot.sendTXNS) { String($0) },
        "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
        "last_send_ns": String(snapshot.lastSendNS),
        "next_counter": snapshot.nextCounter,
    ]
}

private func outboundControlSnapshotObject(_ snapshot: ObstacleBridgeUdpOverlayPeerRuntime.OutboundControlSnapshot) -> [String: Any] {
    return [
        "frame_hex": hexFromData(snapshot.frame),
        "last_sent_last_in_order": snapshot.lastSentLastInOrder,
        "last_control_sent_ns": String(snapshot.lastControlSentNS),
    ]
}

private func localTunSendSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.LocalTunSendSnapshot) -> [String: Any] {
    return [
        "chan_id": snapshot.chanID,
        "allocated_channel": snapshot.allocatedChannel,
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_tun_id": snapshot.nextTunID,
        "next_counter": snapshot.nextCounter,
    ]
}

private func inboundTunOpenSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunOpenSnapshot) -> [String: Any] {
    return [
        "accepted": snapshot.accepted,
        "chan_id": snapshot.chanID,
        "preferred_chan_id": snapshot.preferredChanID ?? NSNull(),
        "remote_spec": snapshot.remoteSpec.map(serviceSpecObject) ?? NSNull(),
    ]
}

private func inboundTunOpenChunkSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunOpenChunkSnapshot) -> [String: Any] {
    return [
        "assembled": snapshot.assembled,
        "accepted": snapshot.accepted,
        "chan_id": snapshot.chanID,
        "preferred_chan_id": snapshot.preferredChanID ?? NSNull(),
        "remote_spec": snapshot.remoteSpec.map(serviceSpecObject) ?? NSNull(),
    ]
}

private func inboundTunDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunDataSnapshot) -> [String: Any] {
    return [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
    ]
}

private func inboundTunFragmentSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunFragmentSnapshot) -> [String: Any] {
    return [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
        "datagram_id": snapshot.datagramID,
        "total_len": snapshot.totalLen,
        "received_bytes": snapshot.receivedBytes,
    ]
}

private func closeSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.CloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "preferred_chan_id": snapshot.preferredChanID ?? NSNull(),
        "bound_chan_ids": snapshot.boundChanIDs,
    ]
}

private func localUdpServerDatagramSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.LocalServerDatagramSnapshot) -> [String: Any] {
    return [
        "chan_id": snapshot.chanID,
        "allocated_channel": snapshot.allocatedChannel,
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_udp_id": snapshot.nextUdpID,
        "next_counter": snapshot.nextCounter,
    ]
}

private func inboundUdpServerDatagramSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.InboundServerDatagramSnapshot) -> [String: Any] {
    return [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
        "addr_host": snapshot.addrHost ?? NSNull(),
        "addr_port": snapshot.addrPort ?? NSNull(),
    ]
}

private func inboundUdpServerFragmentSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.InboundServerFragmentSnapshot) -> [String: Any] {
    return [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
        "addr_host": snapshot.addrHost ?? NSNull(),
        "addr_port": snapshot.addrPort ?? NSNull(),
        "datagram_id": snapshot.datagramID,
        "total_len": snapshot.totalLen,
        "received_bytes": snapshot.receivedBytes,
    ]
}

private func inboundUdpClientOpenSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.InboundClientOpenSnapshot) -> [String: Any] {
    return [
        "accepted": snapshot.accepted,
        "service_id": snapshot.serviceID ?? NSNull(),
        "open_key": snapshot.openKey ?? NSNull(),
        "replaced_channel_id": snapshot.replacedChannelID ?? NSNull(),
        "duplicate_active_channel_id": snapshot.duplicateActiveChannelID ?? NSNull(),
        "connect_requested": snapshot.connectRequested,
        "connected": snapshot.connected,
        "pending_count": snapshot.pendingCount,
        "open_channels": snapshot.openChannels,
        "connected_channels": snapshot.connectedChannels,
    ]
}

private func inboundUdpClientDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.InboundClientDataSnapshot) -> [String: Any] {
    return [
        "buffered": snapshot.buffered,
        "dropped": snapshot.dropped,
        "sent_immediately": snapshot.sentImmediately,
        "pending_count": snapshot.pendingCount,
        "sent_packets_hex": snapshot.sentPackets.map(hexFromData),
    ]
}

private func inboundUdpClientFragmentSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.InboundClientFragmentSnapshot) -> [String: Any] {
    return [
        "buffered": snapshot.buffered,
        "dropped": snapshot.dropped,
        "sent_immediately": snapshot.sentImmediately,
        "pending_count": snapshot.pendingCount,
        "sent_packets_hex": snapshot.sentPackets.map(hexFromData),
        "datagram_id": snapshot.datagramID,
        "total_len": snapshot.totalLen,
        "received_bytes": snapshot.receivedBytes,
    ]
}

private func udpClientConnectSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.ClientConnectSnapshot) -> [String: Any] {
    return [
        "connected": snapshot.connected,
        "service_id": snapshot.serviceID ?? NSNull(),
        "open_key": snapshot.openKey ?? NSNull(),
        "pending_count": snapshot.pendingCount,
        "flushed_packets_hex": snapshot.flushedPackets.map(hexFromData),
        "local_addr_host": snapshot.localAddrHost ?? NSNull(),
        "local_addr_port": snapshot.localAddrPort ?? NSNull(),
        "peer_addr_host": snapshot.peerAddrHost ?? NSNull(),
        "peer_addr_port": snapshot.peerAddrPort ?? NSNull(),
        "connected_channels": snapshot.connectedChannels,
    ]
}

private func localUdpClientDatagramSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.LocalClientDatagramSnapshot) -> [String: Any] {
    return [
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_counter": snapshot.nextCounter,
        "next_fragment_datagram_id": snapshot.nextFragmentDatagramID,
    ]
}

private func closeUdpSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.CloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "next_udp_id": snapshot.nextUdpID,
        "active_channels": snapshot.activeChannels,
    ]
}

private func closeUdpClientSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxUdpRuntime.ClientCloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "open_channels": snapshot.openChannels,
        "connected_channels": snapshot.connectedChannels,
        "pending_channels": snapshot.pendingChannels,
    ]
}

private func inboundTcpClientOpenSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.InboundClientOpenSnapshot) -> [String: Any] {
    return [
        "accepted": snapshot.accepted,
        "service_id": snapshot.serviceID ?? NSNull(),
        "open_key": snapshot.openKey ?? NSNull(),
        "connect_requested": snapshot.connectRequested,
        "connected": snapshot.connected,
        "pending_count": snapshot.pendingCount,
        "open_channels": snapshot.openChannels,
        "connected_channels": snapshot.connectedChannels,
    ]
}

private func localTcpServerAcceptSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.LocalServerAcceptSnapshot) -> [String: Any] {
    return [
        "chan_id": snapshot.chanID,
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_tcp_id": snapshot.nextTcpID,
        "next_counter": snapshot.nextCounter,
        "active_channels": snapshot.activeChannels,
    ]
}

private func localTcpServerDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.LocalServerDataSnapshot) -> [String: Any] {
    return [
        "sent": snapshot.sent,
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_counter": snapshot.nextCounter,
        "active_channels": snapshot.activeChannels,
    ]
}

private func inboundTcpServerDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.InboundServerDataSnapshot) -> [String: Any] {
    return [
        "delivered": snapshot.delivered,
        "written_buffers_hex": snapshot.writtenBuffers.map(hexFromData),
    ]
}

private func inboundTcpClientDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.InboundClientDataSnapshot) -> [String: Any] {
    return [
        "buffered": snapshot.buffered,
        "sent_immediately": snapshot.sentImmediately,
        "pending_count": snapshot.pendingCount,
        "written_buffers_hex": snapshot.writtenBuffers.map(hexFromData),
    ]
}

private func tcpClientConnectSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.ClientConnectSnapshot) -> [String: Any] {
    return [
        "connected": snapshot.connected,
        "service_id": snapshot.serviceID ?? NSNull(),
        "open_key": snapshot.openKey ?? NSNull(),
        "pending_count": snapshot.pendingCount,
        "flushed_buffers_hex": snapshot.flushedBuffers.map(hexFromData),
        "local_addr_host": snapshot.localAddrHost ?? NSNull(),
        "local_addr_port": snapshot.localAddrPort ?? NSNull(),
        "peer_addr_host": snapshot.peerAddrHost ?? NSNull(),
        "peer_addr_port": snapshot.peerAddrPort ?? NSNull(),
        "connected_channels": snapshot.connectedChannels,
    ]
}

private func localTcpClientDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.LocalClientDataSnapshot) -> [String: Any] {
    return [
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_counter": snapshot.nextCounter,
    ]
}

private func localTcpClientCloseSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.LocalClientCloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "frames_hex": snapshot.frames.map(hexFromData),
        "open_channels": snapshot.openChannels,
        "connected_channels": snapshot.connectedChannels,
        "pending_channels": snapshot.pendingChannels,
    ]
}

private func closeTcpClientSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.ClientCloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "open_channels": snapshot.openChannels,
        "connected_channels": snapshot.connectedChannels,
        "pending_channels": snapshot.pendingChannels,
    ]
}

private func closeTcpServerSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTcpRuntime.ServerCloseSnapshot) -> [String: Any] {
    return [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "frames_hex": snapshot.frames.map(hexFromData),
        "active_channels": snapshot.activeChannels,
    ]
}

private func compressStatusSnapshotObject(_ snapshot: ObstacleBridgeCompressLayerRuntime.StatusSnapshot) -> [String: Any] {
    return [
        "enabled": snapshot.enabled,
        "algorithm": snapshot.algorithm,
        "transport": snapshot.transport,
        "level": snapshot.level,
        "min_bytes": snapshot.minBytes,
        "compress_attempts_total": snapshot.compressAttemptsTotal,
        "compress_applied_total": snapshot.compressAppliedTotal,
        "compress_skipped_no_gain_total": snapshot.compressSkippedNoGainTotal,
        "compress_input_bytes_total": snapshot.compressInputBytesTotal,
        "compress_output_bytes_total": snapshot.compressOutputBytesTotal,
        "decompress_ok_total": snapshot.decompressOKTotal,
        "decompress_fail_total": snapshot.decompressFailTotal,
    ]
}

private func overlayStackPlanObject(_ snapshot: ObstacleBridgeOverlayStackPlanner.TransportPlan) -> [String: Any] {
    return [
        "ok": true,
        "transport": snapshot.transport,
        "peer_host": snapshot.peerHost ?? NSNull(),
        "secure_link_mode": snapshot.secureLinkMode ?? NSNull(),
        "compress_wrapped": snapshot.compressWrapped,
        "compress_configured_enabled": snapshot.compressConfiguredEnabled,
        "compress_runtime_enabled": snapshot.compressWrapped ? snapshot.compressConfiguredEnabled : NSNull(),
        "layers_top_down": snapshot.layersTopDown,
    ]
}

private func websocketPayloadCodecSummaryObject(
    mode: String,
    codec: any ObstacleBridgeWebSocketPayloadCodec,
    wire: Data?,
    encoded: Any?,
    decoded: Data?
) -> [String: Any] {
    var encodedKind: Any = NSNull()
    var encodedValue: Any = NSNull()
    if let data = encoded as? Data {
        encodedKind = "binary"
        encodedValue = hexFromData(data)
    } else if let text = encoded as? String {
        encodedKind = "text"
        encodedValue = text
    }
    return [
        "mode": mode,
        "encoded_kind": encodedKind,
        "encoded_value": encodedValue,
        "decoded_hex": decoded.map(hexFromData) ?? NSNull(),
        "frame_max_size": codec.maxEncodedSize((wire?.count ?? 65535)) + (mode == "json-base64" && (wire?.count ?? 0) == 0 ? 0 : 0),
        "max_encoded_size": codec.maxEncodedSize(wire?.count ?? 0),
    ]
}

private func wsOverlayConnectPlanObject(_ snapshot: ObstacleBridgeWebSocketOverlayRuntime.ConnectPlan) -> [String: Any] {
    return [
        "uri": snapshot.uri,
        "max_size": snapshot.maxSize,
        "compression_disabled": snapshot.compressionDisabled,
        "upgrade_headers": snapshot.upgradeHeaders,
        "preflight_required": snapshot.preflightRequired,
        "uses_proxy_socket": snapshot.usesProxySocket,
    ]
}

private struct RawMuxFrame {
    let chanID: Int
    let proto: Int
    let counter: Int
    let mtype: Int
    let body: Data
}

private func parseRawMuxFrame(_ payload: Data) -> RawMuxFrame? {
    guard payload.count >= 8 else {
        return nil
    }
    let chanID = (Int(payload[0]) << 8) | Int(payload[1])
    let proto = Int(payload[2])
    let counter = (Int(payload[3]) << 8) | Int(payload[4])
    let mtype = Int(payload[5])
    let bodyLength = (Int(payload[6]) << 8) | Int(payload[7])
    guard payload.count == 8 + bodyLength else {
        return nil
    }
    return RawMuxFrame(
        chanID: chanID,
        proto: proto,
        counter: counter,
        mtype: mtype,
        body: payload.subdata(in: 8..<(8 + bodyLength))
    )
}

private func jsonObject(_ value: Any) throws -> [String: Any] {
    guard let object = value as? [String: Any] else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    return object
}

private func jsonArray(_ value: Any) throws -> [Any] {
    guard let array = value as? [Any] else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    return array
}

private func parseJSONDictionary(_ value: Any?) -> [String: ObstacleBridgeChannelMuxCodec.JSONValue]? {
    guard let dict = value as? [String: Any] else {
        return nil
    }
    var converted: [String: ObstacleBridgeChannelMuxCodec.JSONValue] = [:]
    for (key, item) in dict {
        guard let value = ObstacleBridgeChannelMuxCodec.jsonValue(from: item) else {
            return nil
        }
        converted[key] = value
    }
    return converted
}

private func parseServiceSpec(_ raw: Any) throws -> ObstacleBridgeChannelMuxCodec.ServiceSpec {
    let object = try jsonObject(raw)
    guard
        let svcID = object["svc_id"] as? NSNumber,
        let lProto = object["l_proto"] as? String,
        let lBind = object["l_bind"] as? String,
        let lPort = object["l_port"] as? NSNumber,
        let rProto = object["r_proto"] as? String,
        let rHost = object["r_host"] as? String,
        let rPort = object["r_port"] as? NSNumber
    else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    return ObstacleBridgeChannelMuxCodec.ServiceSpec(
        svcID: svcID.intValue,
        lProto: lProto,
        lBind: lBind,
        lPort: lPort.intValue,
        rProto: rProto,
        rHost: rHost,
        rPort: rPort.intValue,
        name: object["name"] as? String,
        lifecycleHooks: parseJSONDictionary(object["lifecycle_hooks"]),
        options: parseJSONDictionary(object["options"])
    )
}

private func serviceSpecObject(_ spec: ObstacleBridgeChannelMuxCodec.ServiceSpec) -> [String: Any] {
    let lifecycleHooks = spec.lifecycleHooks.map { hooks in
        ObstacleBridgeChannelMuxCodec.foundationObject(from: .object(hooks))
    } ?? NSNull()
    let options = spec.options.map { values in
        ObstacleBridgeChannelMuxCodec.foundationObject(from: .object(values))
    } ?? NSNull()
    return [
        "svc_id": spec.svcID,
        "l_proto": spec.lProto,
        "l_bind": spec.lBind,
        "l_port": spec.lPort,
        "r_proto": spec.rProto,
        "r_host": spec.rHost,
        "r_port": spec.rPort,
        "name": spec.name ?? NSNull(),
        "lifecycle_hooks": lifecycleHooks,
        "options": options,
    ]
}

private func protoFromRaw(_ value: Any?) throws -> ObstacleBridgeChannelMuxCodec.Proto {
    if let string = value as? String {
        switch string.lowercased() {
        case "udp":
            return .udp
        case "tcp":
            return .tcp
        case "tun":
            return .tun
        default:
            break
        }
    }
    if let number = value as? NSNumber,
       let proto = ObstacleBridgeChannelMuxCodec.Proto(rawValue: number.intValue) {
        return proto
    }
    throw ChannelMuxCodecRunnerError.invalidRequest
}

private func mtypeFromRaw(_ value: Any?) throws -> ObstacleBridgeChannelMuxCodec.MType {
    if let string = value as? String {
        switch string.lowercased() {
        case "data":
            return .data
        case "open":
            return .open
        case "close":
            return .close
        case "remote_services_set_v1":
            return .remoteServicesSetV1
        case "remote_services_set_v2":
            return .remoteServicesSetV2
        case "data_frag":
            return .dataFrag
        case "remote_services_set_v2_chunk":
            return .remoteServicesSetV2Chunk
        case "open_chunk":
            return .openChunk
        default:
            break
        }
    }
    if let number = value as? NSNumber,
       let mtype = ObstacleBridgeChannelMuxCodec.MType(rawValue: number.intValue) {
        return mtype
    }
    throw ChannelMuxCodecRunnerError.invalidRequest
}

private func handle(_ request: [String: Any]) throws -> Any {
    guard let action = request["action"] as? String else {
        throw ChannelMuxCodecRunnerError.invalidRequest
    }
    switch action {
    case "pack_mux":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let counter = request["counter"] as? NSNumber,
            let dataHex = request["data_hex"] as? String,
            let body = dataFromHex(dataHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let payload = try ObstacleBridgeChannelMuxCodec.packMux(
            chanID: chanID.intValue,
            proto: try protoFromRaw(request["proto"]),
            counter: counter.intValue,
            mtype: try mtypeFromRaw(request["mtype"]),
            body: body
        )
        return ["hex": hexFromData(payload)]
    case "unpack_mux":
        guard
            let wireHex = request["wire_hex"] as? String,
            let payload = dataFromHex(wireHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let frame = ObstacleBridgeChannelMuxCodec.unpackMux(payload) else {
            return ["frame": NSNull()]
        }
        return [
            "frame": [
                "chan_id": frame.chanID,
                "proto": frame.proto.rawValue,
                "counter": frame.counter,
                "mtype": frame.mtype.rawValue,
                "data_hex": hexFromData(frame.body),
            ]
        ]
    case "build_open":
        guard
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let specRaw = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let payload = try ObstacleBridgeChannelMuxCodec.buildOpenPayload(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            spec: try parseServiceSpec(specRaw)
        )
        return ["hex": hexFromData(payload)]
    case "parse_open":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let parsed = ObstacleBridgeChannelMuxCodec.parseOpenPayload(payload) else {
            return ["open": NSNull()]
        }
        return [
            "open": [
                "instance_id": String(parsed.instanceID),
                "connection_seq": parsed.connectionSeq,
                "spec": serviceSpecObject(parsed.spec),
            ]
        ]
    case "encode_remote_services":
        guard
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let servicesRaw = request["services"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let services = try jsonArray(servicesRaw).map(parseServiceSpec)
        let payload = try ObstacleBridgeChannelMuxCodec.encodeRemoteServicesSetV2(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            services: services
        )
        return ["hex": hexFromData(payload)]
    case "decode_remote_services":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let decoded = ObstacleBridgeChannelMuxCodec.decodeRemoteServicesSetV2(payload) else {
            return ["remote_services": NSNull()]
        }
        return [
            "remote_services": [
                "instance_id": String(decoded.0),
                "connection_seq": decoded.1,
                "services": decoded.2.map(serviceSpecObject),
            ]
        ]
    case "chunk_control_payload":
        guard
            let txID = request["txid"] as? NSNumber,
            let maxAppPayload = request["max_app_payload"] as? NSNumber,
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let frames = ObstacleBridgeChannelMuxCodec.chunkControlPayload(
            txID: txID.uint32Value,
            maxAppPayload: maxAppPayload.intValue,
            payload: payload
        )
        return ["frames_hex": frames.map(hexFromData)]
    case "reassemble_control_chunks":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let peerID = request["peer_id"] as? NSNumber,
            let chunksRaw = request["chunks_hex"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let chunks = try jsonArray(chunksRaw).map { item -> Data in
            guard let hex = item as? String, let data = dataFromHex(hex) else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return data
        }
        let reassembler = ObstacleBridgeChannelMuxCodec.ControlChunkReassembler()
        var assembled: Data?
        for chunk in chunks {
            assembled = reassembler.consume(
                chanID: chanID.intValue,
                proto: try protoFromRaw(request["proto"]),
                mtype: try mtypeFromRaw(request["mtype"]),
                payload: chunk,
                peerID: peerID.intValue
            ) ?? assembled
        }
        let assembledHex: Any = assembled.map(hexFromData) ?? NSNull()
        return ["assembled_hex": assembledHex]
    case "build_securelink_frame":
        guard
            let slType = request["sl_type"] as? NSNumber,
            let sessionID = request["session_id"] as? NSNumber,
            let counter = request["counter"] as? NSNumber,
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let flags = (request["flags"] as? NSNumber)?.uint8Value ?? 0
        let frame = ObstacleBridgeSecureLinkPskCodec.buildFrame(
            slType: slType.intValue,
            sessionID: sessionID.uint64Value,
            counter: counter.uint64Value,
            payload: payload,
            flags: flags
        )
        return ["hex": hexFromData(frame)]
    case "parse_securelink_frame":
        guard
            let frameHex = request["frame_hex"] as? String,
            let frame = dataFromHex(frameHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let parsed = ObstacleBridgeSecureLinkPskCodec.parseFrame(frame) else {
            return ["frame": NSNull()]
        }
        return [
            "frame": [
                "sl_type": parsed.slType,
                "session_id": String(parsed.sessionID),
                "counter": String(parsed.counter),
                "payload_hex": hexFromData(parsed.payload),
            ]
        ]
    case "securelink_nonce":
        guard let counter = request["counter"] as? NSNumber else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        return ["hex": hexFromData(ObstacleBridgeSecureLinkPskCodec.nonce(counter: counter.uint64Value))]
    case "derive_securelink_keys":
        guard
            let psk = request["psk"] as? String,
            let sessionID = request["session_id"] as? NSNumber,
            let clientNonceHex = request["client_nonce_hex"] as? String,
            let serverNonceHex = request["server_nonce_hex"] as? String,
            let clientNonce = dataFromHex(clientNonceHex),
            let serverNonce = dataFromHex(serverNonceHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let derived = ObstacleBridgeSecureLinkPskCodec.deriveKeys(
            psk: Data(psk.utf8),
            sessionID: sessionID.uint64Value,
            clientNonce: clientNonce,
            serverNonce: serverNonce
        )
        return [
            "c2s_hex": hexFromData(derived.0),
            "s2c_hex": hexFromData(derived.1),
        ]
    case "build_securelink_json":
        guard let object = request["object"] else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let payload = try ObstacleBridgeSecureLinkPskCodec.buildJSONPayload(object)
        return ["hex": hexFromData(payload)]
    case "parse_securelink_json":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let object: Any = ObstacleBridgeSecureLinkPskCodec.parseJSONPayload(payload) ?? NSNull()
        return ["object": object]
    case "build_udp_protocol_frame":
        guard
            let ptype = request["ptype"] as? NSNumber,
            let txNS = request["tx_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let frame = try ObstacleBridgeUdpOverlayCodec.buildProtocolFrame(
            ptype: ptype.intValue,
            payload: payload,
            txNS: txNS.uint64Value,
            echoNS: echoNS.uint64Value
        )
        return ["hex": hexFromData(frame)]
    case "parse_udp_protocol_frame":
        guard
            let frameHex = request["frame_hex"] as? String,
            let frame = dataFromHex(frameHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let parsed = ObstacleBridgeUdpOverlayCodec.parseProtocolFrame(frame) else {
            return ["frame": NSNull()]
        }
        return [
            "frame": [
                "ptype": parsed.ptype,
                "payload_hex": hexFromData(parsed.payload),
                "tx_ns": String(parsed.txNS),
                "echo_ns": String(parsed.echoNS),
            ]
        ]
    case "build_udp_data_frame":
        guard
            let pktCounter = request["pkt_counter"] as? NSNumber,
            let frameType = request["frame_type"] as? NSNumber,
            let lenOrOffset = request["len_or_offset"] as? NSNumber,
            let txNS = request["tx_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let frame = try ObstacleBridgeUdpOverlayCodec.buildDataFrame(
            pktCounter: pktCounter.intValue,
            frameType: frameType.intValue,
            lenOrOffset: lenOrOffset.intValue,
            data: payload,
            txNS: txNS.uint64Value,
            echoNS: echoNS.uint64Value
        )
        return ["hex": hexFromData(frame)]
    case "parse_udp_data_frame":
        guard
            let frameHex = request["frame_hex"] as? String,
            let frame = dataFromHex(frameHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let parsed = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame) else {
            return ["packet": NSNull()]
        }
        return [
            "packet": [
                "pkt_counter": parsed.pktCounter,
                "frame_type": parsed.frameType,
                "len_or_offset": parsed.lenOrOffset,
                "chunk_len": parsed.chunkLen,
                "data_hex": hexFromData(parsed.data),
            ]
        ]
    case "build_udp_control_frame":
        guard
            let lastInOrderRX = request["last_in_order_rx"] as? NSNumber,
            let highestRX = request["highest_rx"] as? NSNumber,
            let txNS = request["tx_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let missedRaw = request["missed"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let missed = try jsonArray(missedRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let frame = try ObstacleBridgeUdpOverlayCodec.buildControlFrame(
            lastInOrderRX: lastInOrderRX.intValue,
            highestRX: highestRX.intValue,
            missed: missed,
            txNS: txNS.uint64Value,
            echoNS: echoNS.uint64Value
        )
        return ["hex": hexFromData(frame)]
    case "parse_udp_control_frame":
        guard
            let frameHex = request["frame_hex"] as? String,
            let frame = dataFromHex(frameHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        guard let parsed = ObstacleBridgeUdpOverlayCodec.parseControlFrame(frame) else {
            return ["packet": NSNull()]
        }
        return [
            "packet": [
                "last_in_order_rx": parsed.lastInOrderRX,
                "highest_rx": parsed.highestRX,
                "missed": parsed.missed,
            ]
        ]
    case "segment_udp_payload":
        guard
            let txNS = request["tx_ns"] as? NSNumber,
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let echoNS = (request["echo_ns"] as? NSNumber)?.uint64Value ?? 0
        let startingCounter = (request["starting_counter"] as? NSNumber)?.intValue ?? 1
        let frames = try ObstacleBridgeUdpOverlaySessionCodec.segmentApplicationPayload(
            payload,
            txNS: txNS.uint64Value,
            echoNS: echoNS,
            startingCounter: startingCounter
        )
        return ["frames_hex": frames.map(hexFromData)]
    case "reassemble_udp_payloads":
        guard let framesRaw = request["frames_hex"] else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let state = ObstacleBridgeUdpOverlaySessionCodec.ReceiveState()
        let frameHexes = try jsonArray(framesRaw).map { item -> String in
            guard let hex = item as? String else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return hex
        }
        var completed: [String] = []
        for frameHex in frameHexes {
            guard
                let frame = dataFromHex(frameHex),
                let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame)
            else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            let result = state.process(packet)
            completed.append(contentsOf: result.1.map(hexFromData))
        }
        return [
            "completed_hex": completed,
            "expected": state.expected,
            "pending": state.pending.keys.sorted(),
            "missing": state.missing.sorted(),
        ]
    case "build_udp_session_control":
        guard
            let expected = request["expected"] as? NSNumber,
            let pendingRaw = request["pending"],
            let missingRaw = request["missing"],
            let txNS = request["tx_ns"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let pending = try jsonArray(pendingRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let missing = try jsonArray(missingRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let echoNS = (request["echo_ns"] as? NSNumber)?.uint64Value ?? 0
        let controlPacket = try ObstacleBridgeUdpOverlaySessionCodec.buildControl(
            expected: expected.intValue,
            pendingKeys: pending,
            missing: missing,
            txNS: txNS.uint64Value,
            echoNS: echoNS
        )
        return [
            "hex": hexFromData(controlPacket.raw),
            "packet": [
                "last_in_order_rx": controlPacket.lastInOrderRX,
                "highest_rx": controlPacket.highestRX,
                "missed": controlPacket.missed,
            ],
        ]
    case "confirm_udp_feedback":
        guard
            let sendBufferRaw = request["send_buffer"],
            let peerReportedRaw = request["peer_reported_missing"],
            let lastInOrder = request["last_in_order"] as? NSNumber,
            let highest = request["highest"] as? NSNumber,
            let missedRaw = request["missed"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(peerReportedRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let missed = try jsonArray(missedRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let snapshot = ObstacleBridgeUdpOverlaySessionCodec.confirmFeedback(
            sendBufferKeys: sendBuffer,
            peerReportedMissing: peerReportedMissing,
            lastInOrder: lastInOrder.intValue,
            highest: highest.intValue,
            missed: missed
        )
        return [
            "send_buffer": snapshot.sendBufferKeys,
            "peer_reported_missing": snapshot.peerReportedMissing,
            "last_ack_peer": snapshot.lastAckPeer,
        ]
    case "evaluate_udp_control_policy_inbound":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let expected = request["expected"] as? NSNumber,
            let missingCount = request["missing_count"] as? NSNumber,
            let grewMissing = request["grew_missing"] as? Bool,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let establishedNS = request["established_ns"] as? NSNumber,
            let rttEstMS = request["rtt_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let decision = ObstacleBridgeUdpOverlaySessionCodec.evaluateInboundControlPolicy(
            nowNS: nowNS.uint64Value,
            expected: expected.intValue,
            missingCount: missingCount.intValue,
            grewMissing: grewMissing,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            establishedNS: establishedNS.uint64Value,
            rttEstMS: rttEstMS.doubleValue
        )
        let reason: Any = decision.reason ?? NSNull()
        return [
            "should_emit": decision.shouldEmit,
            "reason": reason,
        ]
    case "evaluate_udp_control_policy_timer":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let expected = request["expected"] as? NSNumber,
            let missingCount = request["missing_count"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let establishedNS = request["established_ns"] as? NSNumber,
            let rttEstMS = request["rtt_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let decision = ObstacleBridgeUdpOverlaySessionCodec.evaluateTimerControlPolicy(
            nowNS: nowNS.uint64Value,
            expected: expected.intValue,
            missingCount: missingCount.intValue,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            establishedNS: establishedNS.uint64Value,
            rttEstMS: rttEstMS.doubleValue
        )
        let reason: Any = decision.reason ?? NSNull()
        return [
            "should_emit": decision.shouldEmit,
            "reason": reason,
        ]
    case "schedule_udp_retrans_due_to_control":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let missedRaw = request["missed"],
            let rttEstMS = request["rtt_est_ms"] as? NSNumber,
            let sendBufferRaw = request["send_buffer"],
            let lastSendNS = request["last_send_ns"] as? NSNumber,
            let lastRxTxNS = request["last_rx_tx_ns"] as? NSNumber,
            let lastRxWallNS = request["last_rx_wall_ns"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let missed = try jsonArray(missedRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.scheduleRetransmitDueToControl(
            nowNS: nowNS.uint64Value,
            missed: missed,
            rttEstMS: rttEstMS.doubleValue,
            sendBufferKeys: sendBuffer,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            peerReportedMissing: try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
                guard let value = item as? NSNumber else {
                    throw ChannelMuxCodecRunnerError.invalidRequest
                }
                return value.intValue
            },
            lastSendNS: lastSendNS.uint64Value,
            lastRxTxNS: lastRxTxNS.uint64Value,
            lastRxWallNS: lastRxWallNS.uint64Value
        )
        return [
            "emitted_counters": snapshot.emittedCounters,
            "frames_hex": snapshot.emittedFrames.map(hexFromData),
            "last_retx_ns": intKeyedStringMap(snapshot.lastRetxNS) { String($0) },
            "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
            "peer_reported_missing": snapshot.peerReportedMissing,
            "peer_missed_count": snapshot.peerMissedCount,
            "last_send_ns": String(snapshot.lastSendNS),
        ]
    case "sweep_udp_reported_missing_retrans":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let rttEstMS = request["rtt_est_ms"] as? NSNumber,
            let sendBufferRaw = request["send_buffer"],
            let peerMissedCount = request["peer_missed_count"] as? NSNumber,
            let lastSendNS = request["last_send_ns"] as? NSNumber,
            let lastRxTxNS = request["last_rx_tx_ns"] as? NSNumber,
            let lastRxWallNS = request["last_rx_wall_ns"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.sweepReportedMissingRetransmit(
            nowNS: nowNS.uint64Value,
            rttEstMS: rttEstMS.doubleValue,
            sendBufferKeys: sendBuffer,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            peerReportedMissing: peerReportedMissing,
            peerMissedCount: peerMissedCount.intValue,
            lastSendNS: lastSendNS.uint64Value,
            lastRxTxNS: lastRxTxNS.uint64Value,
            lastRxWallNS: lastRxWallNS.uint64Value
        )
        return [
            "emitted_counters": snapshot.emittedCounters,
            "frames_hex": snapshot.emittedFrames.map(hexFromData),
            "last_retx_ns": intKeyedStringMap(snapshot.lastRetxNS) { String($0) },
            "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
            "peer_reported_missing": snapshot.peerReportedMissing,
            "peer_missed_count": snapshot.peerMissedCount,
            "last_send_ns": String(snapshot.lastSendNS),
        ]
    case "sweep_udp_unconfirmed_retrans":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let rttEstMS = request["rtt_est_ms"] as? NSNumber,
            let sendBufferRaw = request["send_buffer"],
            let peerMissedCount = request["peer_missed_count"] as? NSNumber,
            let lastSendNS = request["last_send_ns"] as? NSNumber,
            let lastRxTxNS = request["last_rx_tx_ns"] as? NSNumber,
            let lastRxWallNS = request["last_rx_wall_ns"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.sweepUnconfirmedRetransmit(
            nowNS: nowNS.uint64Value,
            rttEstMS: rttEstMS.doubleValue,
            sendBufferKeys: sendBuffer,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            peerReportedMissing: peerReportedMissing,
            peerMissedCount: peerMissedCount.intValue,
            lastSendNS: lastSendNS.uint64Value,
            lastRxTxNS: lastRxTxNS.uint64Value,
            lastRxWallNS: lastRxWallNS.uint64Value
        )
        return [
            "emitted_counters": snapshot.emittedCounters,
            "frames_hex": snapshot.emittedFrames.map(hexFromData),
            "last_retx_ns": intKeyedStringMap(snapshot.lastRetxNS) { String($0) },
            "send_attempts": intKeyedIntMap(snapshot.sendAttempts),
            "peer_reported_missing": snapshot.peerReportedMissing,
            "peer_missed_count": snapshot.peerMissedCount,
            "last_send_ns": String(snapshot.lastSendNS),
        ]
    case "handle_udp_inbound_control":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let packetLastInOrder = request["packet_last_in_order"] as? NSNumber,
            let packetHighest = request["packet_highest"] as? NSNumber,
            let packetMissedRaw = request["packet_missed"],
            let sendPortPresent = request["send_port_present"] as? Bool,
            let sendBufferRaw = request["send_buffer"],
            let lastSendNS = request["last_send_ns"] as? NSNumber,
            let lastRxTxNS = request["last_rx_tx_ns"] as? NSNumber,
            let lastRxWallNS = request["last_rx_wall_ns"] as? NSNumber,
            let receiverExpected = request["receiver_expected"] as? NSNumber,
            let receiverMissingCount = request["receiver_missing_count"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let establishedNS = request["established_ns"] as? NSNumber,
            let rttEstMS = request["rtt_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let packetMissed = try jsonArray(packetMissedRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.handleInboundControlPacket(
            nowNS: nowNS.uint64Value,
            packetLastInOrder: packetLastInOrder.intValue,
            packetHighest: packetHighest.intValue,
            packetMissed: packetMissed,
            sendPortPresent: sendPortPresent,
            sendBufferKeys: sendBuffer,
            peerReportedMissing: peerReportedMissing,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            lastSendNS: lastSendNS.uint64Value,
            lastRxTxNS: lastRxTxNS.uint64Value,
            lastRxWallNS: lastRxWallNS.uint64Value,
            receiverExpected: receiverExpected.intValue,
            receiverMissingCount: receiverMissingCount.intValue,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            establishedNS: establishedNS.uint64Value,
            rttEstMS: rttEstMS.doubleValue
        )
        let controlReason: Any = snapshot.controlDecision.reason ?? NSNull()
        return [
            "send_buffer": snapshot.feedback.sendBufferKeys,
            "peer_reported_missing": snapshot.feedback.peerReportedMissing,
            "last_ack_peer": snapshot.feedback.lastAckPeer,
            "emitted_counters": snapshot.retransmit.emittedCounters,
            "frames_hex": snapshot.retransmit.emittedFrames.map(hexFromData),
            "last_retx_ns": intKeyedStringMap(snapshot.retransmit.lastRetxNS) { String($0) },
            "send_attempts": intKeyedIntMap(snapshot.retransmit.sendAttempts),
            "peer_missed_count": snapshot.retransmit.peerMissedCount,
            "last_send_ns": String(snapshot.retransmit.lastSendNS),
            "flush_requested": snapshot.flushRequested,
            "control_should_emit": snapshot.controlDecision.shouldEmit,
            "control_reason": controlReason,
        ]
    case "handle_udp_inbound_idle":
        guard
            let nowNS = request["now_ns"] as? NSNumber,
            let txNS = request["tx_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let sendPortPresent = request["send_port_present"] as? Bool,
            let establishedNS = request["established_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let snapshot = try ObstacleBridgeUdpOverlaySessionCodec.handleInboundIdleFrame(
            nowNS: nowNS.uint64Value,
            txNS: txNS.uint64Value,
            echoNS: echoNS.uint64Value,
            sendPortPresent: sendPortPresent,
            establishedNS: establishedNS.uint64Value,
            priorRTTEstMS: priorRTTEstMS.doubleValue,
            priorTransmitDelayEstMS: priorTransmitDelayEstMS.doubleValue
        )
        let reflectedFrame: Any = snapshot.reflectedFrame.map(hexFromData) ?? NSNull()
        return [
            "reflected": snapshot.reflected,
            "reflected_frame_hex": reflectedFrame,
            "established_ns": String(snapshot.establishedNS),
            "last_rx_tx_ns": String(snapshot.lastRxTxNS),
            "last_rx_wall_ns": String(snapshot.lastRxWallNS),
            "rtt_sample_ms": snapshot.rttSampleMS,
            "rtt_est_ms": snapshot.rttEstMS,
            "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
        ]
    case "handle_udp_inbound_data":
        guard
            let frameHex = request["frame_hex"] as? String,
            let frame = dataFromHex(frameHex),
            let nowNS = request["now_ns"] as? NSNumber,
            let txNS = request["tx_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let sendPortPresent = request["send_port_present"] as? Bool,
            let establishedNS = request["established_ns"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber,
            let preFramesRaw = request["pre_frames_hex"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let preFrames = try jsonArray(preFramesRaw).map { item -> Data in
            guard let hex = item as? String, let data = dataFromHex(hex) else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return data
        }
        guard let snapshot = ObstacleBridgeUdpOverlaySessionCodec.handleInboundDataFrames(
            preFrames: preFrames,
            frame: frame,
            nowNS: nowNS.uint64Value,
            txNS: txNS.uint64Value,
            echoNS: echoNS.uint64Value,
            sendPortPresent: sendPortPresent,
            establishedNS: establishedNS.uint64Value,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            priorRTTEstMS: priorRTTEstMS.doubleValue,
            priorTransmitDelayEstMS: priorTransmitDelayEstMS.doubleValue
        ) else {
            return ["snapshot": NSNull()]
        }
        return [
            "snapshot": [
                "control_reasons": snapshot.controlReasons,
                "completed_hex": snapshot.completedPayloads.map(hexFromData),
                "expected": snapshot.expected,
                "pending": snapshot.pending,
                "missing": snapshot.missing,
                "established_ns": String(snapshot.establishedNS),
                "last_rx_tx_ns": String(snapshot.lastRxTxNS),
                "last_rx_wall_ns": String(snapshot.lastRxWallNS),
                "rtt_sample_ms": snapshot.rttSampleMS,
                "rtt_est_ms": snapshot.rttEstMS,
                "transmit_delay_est_ms": snapshot.transmitDelayEstMS,
            ]
        ]
    case "drive_udp_peer_runtime_data_sequence":
        guard
            let eventsRaw = request["events"],
            let sendPortPresent = request["send_port_present"] as? Bool,
            let establishedNS = request["established_ns"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            establishedNS: establishedNS.uint64Value,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            rttEstMS: priorRTTEstMS.doubleValue,
            transmitDelayEstMS: priorTransmitDelayEstMS.doubleValue
        )
        let snapshots = try jsonArray(eventsRaw).map { item -> [String: Any] in
            let object = try jsonObject(item)
            guard
                let frameHex = object["frame_hex"] as? String,
                let frame = dataFromHex(frameHex),
                let nowNS = object["now_ns"] as? NSNumber,
                let txNS = object["tx_ns"] as? NSNumber,
                let echoNS = object["echo_ns"] as? NSNumber
            else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            guard let snapshot = runtime.handleInboundDataFrame(
                frame: frame,
                nowNS: nowNS.uint64Value,
                txNS: txNS.uint64Value,
                echoNS: echoNS.uint64Value,
                sendPortPresent: sendPortPresent
            ) else {
                throw ChannelMuxCodecRunnerError.codecFailure
            }
            return inboundDataSnapshotObject(snapshot)
        }
        return ["snapshots": snapshots]
    case "drive_udp_peer_runtime_idle_sequence":
        guard
            let eventsRaw = request["events"],
            let sendPortPresent = request["send_port_present"] as? Bool,
            let establishedNS = request["established_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            establishedNS: establishedNS.uint64Value,
            rttEstMS: priorRTTEstMS.doubleValue,
            transmitDelayEstMS: priorTransmitDelayEstMS.doubleValue
        )
        let snapshots = try jsonArray(eventsRaw).map { item -> [String: Any] in
            let object = try jsonObject(item)
            guard
                let nowNS = object["now_ns"] as? NSNumber,
                let txNS = object["tx_ns"] as? NSNumber,
                let echoNS = object["echo_ns"] as? NSNumber
            else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            let snapshot = try runtime.handleInboundIdleFrame(
                nowNS: nowNS.uint64Value,
                txNS: txNS.uint64Value,
                echoNS: echoNS.uint64Value,
                sendPortPresent: sendPortPresent
            )
            return inboundIdleSnapshotObject(snapshot)
        }
        return ["snapshots": snapshots]
    case "drive_udp_peer_runtime_control_sequence":
        guard
            let eventsRaw = request["events"],
            let sendPortPresent = request["send_port_present"] as? Bool,
            let establishedNS = request["established_ns"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber,
            let sendBufferRaw = request["send_buffer"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            establishedNS: establishedNS.uint64Value,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            rttEstMS: priorRTTEstMS.doubleValue,
            transmitDelayEstMS: priorTransmitDelayEstMS.doubleValue,
            sendBuffer: sendBuffer,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            peerReportedMissing: peerReportedMissing,
            lastAckPeer: (request["last_ack_peer"] as? NSNumber)?.intValue ?? 0,
            peerMissedCount: (request["peer_missed_count"] as? NSNumber)?.intValue ?? 0,
            lastSendNS: (request["last_send_ns"] as? NSNumber)?.uint64Value ?? 0
        )
        let snapshots = try jsonArray(eventsRaw).map { item -> [String: Any] in
            let object = try jsonObject(item)
            guard
                let nowNS = object["now_ns"] as? NSNumber,
                let packetLastInOrder = object["packet_last_in_order"] as? NSNumber,
                let packetHighest = object["packet_highest"] as? NSNumber,
                let packetMissedRaw = object["packet_missed"]
            else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            let txNS = (object["tx_ns"] as? NSNumber)?.uint64Value ?? 0
            let echoNS = (object["echo_ns"] as? NSNumber)?.uint64Value ?? 0
            let packetMissed = try jsonArray(packetMissedRaw).map { raw -> Int in
                guard let value = raw as? NSNumber else {
                    throw ChannelMuxCodecRunnerError.invalidRequest
                }
                return value.intValue
            }
            let snapshot = try runtime.handleInboundControlPacket(
                nowNS: nowNS.uint64Value,
                txNS: txNS,
                echoNS: echoNS,
                packetLastInOrder: packetLastInOrder.intValue,
                packetHighest: packetHighest.intValue,
                packetMissed: packetMissed,
                sendPortPresent: sendPortPresent
            )
            return inboundControlSnapshotObject(snapshot)
        }
        return ["snapshots": snapshots]
    case "drive_udp_peer_runtime_control_timer":
        guard
            let preFramesRaw = request["pre_frames_hex"],
            let sendPortPresent = request["send_port_present"] as? Bool,
            let nowNS = request["now_ns"] as? NSNumber,
            let establishedNS = request["established_ns"] as? NSNumber,
            let lastSentLastInOrder = request["last_sent_last_in_order"] as? NSNumber,
            let lastControlSentNS = request["last_control_sent_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            establishedNS: establishedNS.uint64Value,
            lastSentLastInOrder: lastSentLastInOrder.intValue,
            lastControlSentNS: lastControlSentNS.uint64Value,
            rttEstMS: priorRTTEstMS.doubleValue,
            transmitDelayEstMS: priorTransmitDelayEstMS.doubleValue
        )
        let preFrames = try jsonArray(preFramesRaw).map { item -> Data in
            guard let hex = item as? String, let data = dataFromHex(hex) else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return data
        }
        for frame in preFrames {
            guard let packet = ObstacleBridgeUdpOverlayCodec.parseDataFrame(frame) else {
                throw ChannelMuxCodecRunnerError.codecFailure
            }
            _ = runtime.handleInboundDataFrame(
                frame: frame,
                nowNS: 0,
                txNS: 0,
                echoNS: 0,
                sendPortPresent: sendPortPresent
            )
            if packet.pktCounter == 0 {
                throw ChannelMuxCodecRunnerError.codecFailure
            }
        }
        return ["snapshot": controlTimerSnapshotObject(runtime.handleControlTimerTick(nowNS: nowNS.uint64Value, sendPortPresent: sendPortPresent))]
    case "drive_udp_peer_runtime_retransmit_timer":
        guard
            let sendPortPresent = request["send_port_present"] as? Bool,
            let nowNS = request["now_ns"] as? NSNumber,
            let priorRTTEstMS = request["prior_rtt_est_ms"] as? NSNumber,
            let priorTransmitDelayEstMS = request["prior_transmit_delay_est_ms"] as? NSNumber,
            let sendBufferRaw = request["send_buffer"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let sendBuffer = try jsonArray(sendBufferRaw).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let peerReportedMissing = try jsonArray(request["peer_reported_missing"] ?? []).map { item -> Int in
            guard let value = item as? NSNumber else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return value.intValue
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            rttEstMS: priorRTTEstMS.doubleValue,
            transmitDelayEstMS: priorTransmitDelayEstMS.doubleValue,
            sendBuffer: sendBuffer,
            sendMeta: try parseSendMeta(request["send_meta"]),
            sendTXNS: try parseIntKeyedUInt64Map(request["send_tx_ns"]),
            lastRetxNS: try parseIntKeyedUInt64Map(request["last_retx_ns"]),
            sendAttempts: try parseIntKeyedIntMap(request["send_attempts"]),
            peerReportedMissing: peerReportedMissing,
            lastAckPeer: (request["last_ack_peer"] as? NSNumber)?.intValue ?? 0,
            peerMissedCount: (request["peer_missed_count"] as? NSNumber)?.intValue ?? 0,
            lastSendNS: (request["last_send_ns"] as? NSNumber)?.uint64Value ?? 0
        )
        let snapshot = try runtime.handleRetransmitTimerTick(nowNS: nowNS.uint64Value, sendPortPresent: sendPortPresent)
        return ["snapshot": retransmitTimerSnapshotObject(snapshot)]
    case "drive_udp_peer_runtime_send_payload":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let nowNS = request["now_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber,
            let nextCounter = request["next_counter"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime(
            nextCounter: nextCounter.intValue,
            maxInFlight: (request["max_inflight"] as? NSNumber)?.intValue ?? 32767
        )
        let snapshot = try runtime.sendApplicationPayload(payload, nowNS: nowNS.uint64Value, echoNS: echoNS.uint64Value)
        return [
            "snapshot": outboundDataSnapshotObject(snapshot),
            "protocol_stats": runtime.protocolStatsSnapshot(),
        ]
    case "drive_udp_peer_runtime_build_control":
        guard
            let preFramesRaw = request["pre_frames_hex"],
            let nowNS = request["now_ns"] as? NSNumber,
            let echoNS = request["echo_ns"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeUdpOverlayPeerRuntime()
        let preFrames = try jsonArray(preFramesRaw).map { item -> Data in
            guard let hex = item as? String, let data = dataFromHex(hex) else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            return data
        }
        for frame in preFrames {
            guard runtime.handleInboundDataFrame(frame: frame, nowNS: 0, txNS: 0, echoNS: 0, sendPortPresent: false) != nil else {
                throw ChannelMuxCodecRunnerError.codecFailure
            }
        }
        let snapshot = try runtime.buildOutboundControl(nowNS: nowNS.uint64Value, echoNS: echoNS.uint64Value)
        return ["snapshot": outboundControlSnapshotObject(snapshot)]
    case "drive_channelmux_local_tun_packet":
        guard
            let packetHex = request["packet_hex"] as? String,
            let packet = dataFromHex(packetHex),
            let mtu = request["mtu"] as? NSNumber,
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTunID = request["next_tun_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTunID: nextTunID.intValue,
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let snapshot = try runtime.handleLocalTunPacket(
            packet: packet,
            mtu: mtu.intValue,
            existingChanID: (request["existing_chan_id"] as? NSNumber)?.intValue,
            spec: try parseServiceSpec(specObject),
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled,
            bufferedFrames: (request["buffered_frames"] as? NSNumber)?.intValue ?? 0,
            nowNS: (request["now_ns"] as? NSNumber)?.uint64Value
        )
        let payload: Any = snapshot.map(localTunSendSnapshotObject) ?? NSNull()
        return ["snapshot": payload]
    case "drive_channelmux_local_tun_packet_sequence":
        guard
            let packetsHex = request["packets_hex"] as? [String],
            let mtu = request["mtu"] as? NSNumber,
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTunID = request["next_tun_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let bufferedFrames = (request["buffered_frames_sequence"] as? [NSNumber])?.map(\.intValue) ?? []
        let nowNSValues = (request["now_ns_sequence"] as? [NSNumber])?.map(\.uint64Value) ?? []
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTunID: nextTunID.intValue,
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let spec = try parseServiceSpec(specObject)
        var existingChanID: Int?
        var snapshots: [Any] = []
        for (index, packetHex) in packetsHex.enumerated() {
            guard let packet = dataFromHex(packetHex) else {
                throw ChannelMuxCodecRunnerError.invalidRequest
            }
            let snapshot = try runtime.handleLocalTunPacket(
                packet: packet,
                mtu: mtu.intValue,
                existingChanID: existingChanID,
                spec: spec,
                overlayConnected: overlayConnected,
                acceptingEnabled: acceptingEnabled,
                bufferedFrames: index < bufferedFrames.count ? bufferedFrames[index] : 0,
                nowNS: index < nowNSValues.count ? nowNSValues[index] : nil
            )
            if let snapshot {
                existingChanID = snapshot.chanID
                snapshots.append(localTunSendSnapshotObject(snapshot))
            } else {
                snapshots.append(NSNull())
            }
        }
        return ["snapshots": snapshots]
    case "drive_channelmux_tun_open_then_local_packet":
        guard
            let openChanID = request["open_chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let packetHex = request["packet_hex"] as? String,
            let packet = dataFromHex(packetHex),
            let mtu = request["mtu"] as? NSNumber,
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTunID = request["next_tun_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let localSpec = try parseServiceSpec(specObject)
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTunID: nextTunID.intValue,
            localSpec: localSpec
        )
        let openSnapshot = runtime.handleInboundTunOpen(
            chanID: openChanID.intValue,
            payload: openPayload
        )
        let localSnapshot = try runtime.handleLocalTunPacket(
            packet: packet,
            mtu: mtu.intValue,
            spec: localSpec,
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled,
            bufferedFrames: (request["buffered_frames"] as? NSNumber)?.intValue ?? 0,
            nowNS: (request["now_ns"] as? NSNumber)?.uint64Value
        )
        return [
            "open_snapshot": inboundTunOpenSnapshotObject(openSnapshot),
            "local_snapshot": (localSnapshot.map(localTunSendSnapshotObject) ?? NSNull()) as Any,
        ]
    case "drive_channelmux_inbound_tun_open_chunk_sequence":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let chunksHex = request["chunks_hex"] as? [String],
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: 0,
            connectionSeq: 0,
            localSpec: try parseServiceSpec(specObject)
        )
        let snapshots = chunksHex.compactMap(dataFromHex).map {
            inboundTunOpenChunkSnapshotObject(
                runtime.handleInboundTunOpenChunk(
                    chanID: chanID.intValue,
                    payload: $0,
                    peerID: (request["peer_id"] as? NSNumber)?.intValue
                )
            )
        }
        return ["snapshots": snapshots]
    case "drive_channelmux_inbound_tun_data":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let bodyHex = request["body_hex"] as? String,
            let body = dataFromHex(bodyHex),
            let mtu = request["mtu"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTunRuntime(instanceID: 0, connectionSeq: 0)
        let snapshot = runtime.handleInboundTunData(
            chanID: chanID.intValue,
            body: body,
            mtu: mtu.intValue,
            boundChanID: (request["bound_chan_id"] as? NSNumber)?.intValue
        )
        return ["snapshot": inboundTunDataSnapshotObject(snapshot)]
    case "drive_channelmux_inbound_tun_fragment_sequence":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let fragmentsHex = request["fragments_hex"] as? [String],
            let mtu = request["mtu"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTunRuntime(instanceID: 0, connectionSeq: 0)
        let snapshots = fragmentsHex.compactMap(dataFromHex).map {
            inboundTunFragmentSnapshotObject(
                runtime.handleInboundTunFragment(
                    chanID: chanID.intValue,
                    payload: $0,
                    mtu: mtu.intValue,
                    boundChanID: (request["bound_chan_id"] as? NSNumber)?.intValue
                )
            )
        }
        return ["snapshots": snapshots]
    case "drive_channelmux_tun_close_then_local_packet":
        guard
            let openChanID = request["open_chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let packetHex = request["packet_hex"] as? String,
            let packet = dataFromHex(packetHex),
            let mtu = request["mtu"] as? NSNumber,
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTunID = request["next_tun_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let localSpec = try parseServiceSpec(specObject)
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTunID: nextTunID.intValue,
            localSpec: localSpec
        )
        _ = runtime.handleInboundTunOpen(chanID: openChanID.intValue, payload: openPayload)
        let closeSnapshot = runtime.handleInboundTunClose(chanID: openChanID.intValue)
        let localSnapshot = try runtime.handleLocalTunPacket(
            packet: packet,
            mtu: mtu.intValue,
            spec: localSpec,
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled
        )
        return [
            "close_snapshot": closeSnapshotObject(closeSnapshot),
            "local_snapshot": (localSnapshot.map(localTunSendSnapshotObject) ?? NSNull()) as Any,
        ]
    case "drive_channelmux_local_udp_server_datagram":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextUdpID = request["next_udp_id"] as? NSNumber,
            let specObject = request["spec"],
            let serviceKey = request["service_key"] as? String,
            let addrHost = request["addr_host"] as? String,
            let addrPort = request["addr_port"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextUdpID: nextUdpID.intValue,
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535,
            datagramCap: (request["datagram_cap"] as? NSNumber)?.intValue ?? 65507
        )
        let snapshot = try runtime.handleLocalServerDatagram(
            spec: try parseServiceSpec(specObject),
            serviceKey: serviceKey,
            payload: payload,
            addrHost: addrHost,
            addrPort: addrPort.intValue,
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled
        )
        let udpPayload: Any = snapshot.map(localUdpServerDatagramSnapshotObject) ?? NSNull()
        return ["snapshot": udpPayload]
    case "drive_channelmux_udp_server_open_then_inbound_data":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let inboundHex = request["inbound_hex"] as? String,
            let inbound = dataFromHex(inboundHex),
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let specObject = request["spec"],
            let serviceKey = request["service_key"] as? String,
            let addrHost = request["addr_host"] as? String,
            let addrPort = request["addr_port"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value
        )
        let local = try runtime.handleLocalServerDatagram(
            spec: try parseServiceSpec(specObject),
            serviceKey: serviceKey,
            payload: payload,
            addrHost: addrHost,
            addrPort: addrPort.intValue,
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let local else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let inboundSnapshot = runtime.handleInboundServerData(chanID: local.chanID, body: inbound)
        return [
            "local_snapshot": localUdpServerDatagramSnapshotObject(local),
            "inbound_snapshot": inboundUdpServerDatagramSnapshotObject(inboundSnapshot),
        ]
    case "drive_channelmux_udp_server_open_then_inbound_fragment_sequence":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let fragmentsHex = request["fragments_hex"] as? [String],
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let specObject = request["spec"],
            let serviceKey = request["service_key"] as? String,
            let addrHost = request["addr_host"] as? String,
            let addrPort = request["addr_port"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value
        )
        let local = try runtime.handleLocalServerDatagram(
            spec: try parseServiceSpec(specObject),
            serviceKey: serviceKey,
            payload: payload,
            addrHost: addrHost,
            addrPort: addrPort.intValue,
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let local else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let snapshots = fragmentsHex.compactMap(dataFromHex).map {
            inboundUdpServerFragmentSnapshotObject(
                runtime.handleInboundServerFragment(chanID: local.chanID, payload: $0)
            )
        }
        return [
            "local_snapshot": localUdpServerDatagramSnapshotObject(local),
            "snapshots": snapshots,
        ]
    case "drive_channelmux_udp_server_close_then_local_datagram":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let specObject = request["spec"],
            let serviceKey = request["service_key"] as? String,
            let addrHost = request["addr_host"] as? String,
            let addrPort = request["addr_port"] as? NSNumber
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value
        )
        let first = try runtime.handleLocalServerDatagram(
            spec: try parseServiceSpec(specObject),
            serviceKey: serviceKey,
            payload: payload,
            addrHost: addrHost,
            addrPort: addrPort.intValue,
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let first else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let closeSnapshot = runtime.handleInboundClose(chanID: first.chanID)
        let second = try runtime.handleLocalServerDatagram(
            spec: try parseServiceSpec(specObject),
            serviceKey: serviceKey,
            payload: payload,
            addrHost: addrHost,
            addrPort: addrPort.intValue,
            overlayConnected: true,
            acceptingEnabled: true
        )
        return [
            "close_snapshot": closeUdpSnapshotObject(closeSnapshot),
            "local_snapshot": (second.map(localUdpServerDatagramSnapshotObject) ?? NSNull()) as Any,
        ]
    case "drive_channelmux_udp_client_open_then_connect":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        return [
            "open_snapshot": inboundUdpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": udpClientConnectSnapshotObject(connectSnapshot),
        ]
    case "drive_channelmux_udp_client_open_buffer_connect_then_data":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let bufferedHex = request["buffered_hex"] as? String,
            let bufferedPayload = dataFromHex(bufferedHex),
            let immediateHex = request["immediate_hex"] as? String,
            let immediatePayload = dataFromHex(immediateHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let bufferedSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: bufferedPayload)
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let immediateSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: immediatePayload)
        return [
            "open_snapshot": inboundUdpClientOpenSnapshotObject(openSnapshot),
            "buffered_snapshot": inboundUdpClientDataSnapshotObject(bufferedSnapshot),
            "connect_snapshot": udpClientConnectSnapshotObject(connectSnapshot),
            "immediate_snapshot": inboundUdpClientDataSnapshotObject(immediateSnapshot),
        ]
    case "drive_channelmux_udp_client_open_connect_then_local_datagram":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(
            instanceID: 0,
            connectionSeq: 0,
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let localSnapshot = try runtime.handleLocalClientDatagram(chanID: chanID.intValue, payload: payload)
        return [
            "open_snapshot": inboundUdpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": udpClientConnectSnapshotObject(connectSnapshot),
            "local_snapshot": (localSnapshot.map(localUdpClientDatagramSnapshotObject) ?? NSNull()) as Any,
        ]
    case "drive_channelmux_udp_client_open_connect_then_inbound_fragment_sequence":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let fragmentsHex = request["fragments_hex"] as? [String]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let snapshots = fragmentsHex.compactMap(dataFromHex).map {
            inboundUdpClientFragmentSnapshotObject(
                runtime.handleInboundClientFragment(chanID: chanID.intValue, payload: $0)
            )
        }
        return [
            "open_snapshot": inboundUdpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": udpClientConnectSnapshotObject(connectSnapshot),
            "snapshots": snapshots,
        ]
    case "drive_channelmux_udp_client_open_buffer_then_close":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let bufferedHex = request["buffered_hex"] as? String,
            let bufferedPayload = dataFromHex(bufferedHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxUdpRuntime(instanceID: 0, connectionSeq: 0)
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let bufferedSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: bufferedPayload)
        let closeSnapshot = runtime.handleInboundClientClose(chanID: chanID.intValue)
        return [
            "open_snapshot": inboundUdpClientOpenSnapshotObject(openSnapshot),
            "buffered_snapshot": inboundUdpClientDataSnapshotObject(bufferedSnapshot),
            "close_snapshot": closeUdpClientSnapshotObject(closeSnapshot),
        ]
    case "drive_channelmux_tcp_client_open_then_connect":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime()
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        return [
            "open_snapshot": inboundTcpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": tcpClientConnectSnapshotObject(connectSnapshot),
        ]
    case "drive_channelmux_tcp_client_open_buffer_connect_then_data":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let bufferedHex = request["buffered_hex"] as? String,
            let bufferedPayload = dataFromHex(bufferedHex),
            let immediateHex = request["immediate_hex"] as? String,
            let immediatePayload = dataFromHex(immediateHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime()
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let bufferedSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: bufferedPayload)
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let immediateSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: immediatePayload)
        return [
            "open_snapshot": inboundTcpClientOpenSnapshotObject(openSnapshot),
            "buffered_snapshot": inboundTcpClientDataSnapshotObject(bufferedSnapshot),
            "connect_snapshot": tcpClientConnectSnapshotObject(connectSnapshot),
            "immediate_snapshot": inboundTcpClientDataSnapshotObject(immediateSnapshot),
        ]
    case "drive_channelmux_tcp_client_open_connect_then_local_data":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let overlayConnected = request["overlay_connected"] as? Bool
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let localSnapshot = try runtime.handleLocalClientData(
            chanID: chanID.intValue,
            payload: payload,
            overlayConnected: overlayConnected
        )
        return [
            "open_snapshot": inboundTcpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": tcpClientConnectSnapshotObject(connectSnapshot),
            "local_snapshot": (localSnapshot.map(localTcpClientDataSnapshotObject) ?? NSNull()) as Any,
        ]
    case "drive_channelmux_tcp_client_open_buffer_then_close":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let bufferedHex = request["buffered_hex"] as? String,
            let bufferedPayload = dataFromHex(bufferedHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime()
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let bufferedSnapshot = runtime.handleInboundClientData(chanID: chanID.intValue, body: bufferedPayload)
        let closeSnapshot = runtime.handleInboundClientClose(chanID: chanID.intValue)
        return [
            "open_snapshot": inboundTcpClientOpenSnapshotObject(openSnapshot),
            "buffered_snapshot": inboundTcpClientDataSnapshotObject(bufferedSnapshot),
            "close_snapshot": closeTcpClientSnapshotObject(closeSnapshot),
        ]
    case "drive_channelmux_tcp_client_open_then_local_eof":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let openPayloadHex = request["open_payload_hex"] as? String,
            let openPayload = dataFromHex(openPayloadHex),
            let overlayConnected = request["overlay_connected"] as? Bool
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let openSnapshot = runtime.handleInboundClientOpen(
            chanID: chanID.intValue,
            payload: openPayload,
            peerID: (request["peer_id"] as? NSNumber)?.intValue
        )
        let connectSnapshot = runtime.handleClientConnected(
            chanID: chanID.intValue,
            localAddrHost: request["local_addr_host"] as? String,
            localAddrPort: (request["local_addr_port"] as? NSNumber)?.intValue,
            peerAddrHost: request["peer_addr_host"] as? String,
            peerAddrPort: (request["peer_addr_port"] as? NSNumber)?.intValue
        )
        let closeSnapshot = try runtime.handleLocalClientEOF(
            chanID: chanID.intValue,
            overlayConnected: overlayConnected
        )
        return [
            "open_snapshot": inboundTcpClientOpenSnapshotObject(openSnapshot),
            "connect_snapshot": tcpClientConnectSnapshotObject(connectSnapshot),
            "close_snapshot": localTcpClientCloseSnapshotObject(closeSnapshot),
        ]
    case "drive_channelmux_tcp_server_accept_then_local_data_then_eof":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let overlayConnected = request["overlay_connected"] as? Bool,
            let acceptingEnabled = request["accepting_enabled"] as? Bool,
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTcpID = request["next_tcp_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTcpID: nextTcpID.intValue,
            sessionMaxAppPayload: (request["session_max_app_payload"] as? NSNumber)?.intValue ?? 65535
        )
        let acceptSnapshot = try runtime.handleAcceptedServerConnection(
            spec: try parseServiceSpec(specObject),
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled
        )
        guard let acceptSnapshot else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let dataSnapshot = try runtime.handleLocalServerData(
            chanID: acceptSnapshot.chanID,
            payload: payload,
            overlayConnected: overlayConnected
        )
        let closeSnapshot = try runtime.handleLocalServerEOF(
            chanID: acceptSnapshot.chanID,
            overlayConnected: overlayConnected
        )
        return [
            "accept_snapshot": localTcpServerAcceptSnapshotObject(acceptSnapshot),
            "data_snapshot": localTcpServerDataSnapshotObject(dataSnapshot),
            "close_snapshot": closeTcpServerSnapshotObject(closeSnapshot),
        ]
    case "drive_channelmux_tcp_server_accept_then_inbound_data":
        guard
            let inboundHex = request["inbound_hex"] as? String,
            let inbound = dataFromHex(inboundHex),
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTcpID = request["next_tcp_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTcpID: nextTcpID.intValue
        )
        let acceptSnapshot = try runtime.handleAcceptedServerConnection(
            spec: try parseServiceSpec(specObject),
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let acceptSnapshot else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let inboundSnapshot = runtime.handleInboundServerData(chanID: acceptSnapshot.chanID, body: inbound)
        return [
            "accept_snapshot": localTcpServerAcceptSnapshotObject(acceptSnapshot),
            "inbound_snapshot": inboundTcpServerDataSnapshotObject(inboundSnapshot),
        ]
    case "drive_channelmux_tcp_server_accept_then_inbound_close":
        guard
            let instanceID = request["instance_id"] as? NSNumber,
            let connectionSeq = request["connection_seq"] as? NSNumber,
            let nextTcpID = request["next_tcp_id"] as? NSNumber,
            let specObject = request["spec"]
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTcpRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTcpID: nextTcpID.intValue
        )
        let acceptSnapshot = try runtime.handleAcceptedServerConnection(
            spec: try parseServiceSpec(specObject),
            overlayConnected: true,
            acceptingEnabled: true
        )
        guard let acceptSnapshot else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let closeSnapshot = runtime.handleInboundServerClose(chanID: acceptSnapshot.chanID)
        return [
            "accept_snapshot": localTcpServerAcceptSnapshotObject(acceptSnapshot),
            "close_snapshot": closeTcpServerSnapshotObject(closeSnapshot),
            "writer_closed": closeSnapshot.localConnectionClosed,
        ]
    case "drive_compress_roundtrip_profitable":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let peerID = (request["peer_id"] as? NSNumber)?.intValue
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        let sendSnapshot = runtime.handleSendPayload(payload)
        guard let sentFrame = parseRawMuxFrame(sendSnapshot.wirePayload) else {
            throw ChannelMuxCodecRunnerError.codecFailure
        }
        let receiveSnapshot = runtime.handleInboundPayload(sendSnapshot.wirePayload, peerID: peerID)
        return [
            "sent_bytes": sendSnapshot.sentBytes,
            "sent_payload_hex": hexFromData(sendSnapshot.wirePayload),
            "sent_peer_id": NSNull(),
            "sent_mtype": sentFrame.mtype,
            "sent_body_len": sentFrame.body.count,
            "restored_payload_hex": receiveSnapshot.deliveredPayload.map(hexFromData) ?? NSNull(),
            "restored_peer_id": receiveSnapshot.deliveredPeerID as Any,
            "status": compressStatusSnapshotObject(runtime.statusSnapshot()),
            "peer_status": compressStatusSnapshotObject(runtime.statusSnapshot(peerID: peerID)),
        ]
    case "drive_compress_client_peer_snapshot":
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        return compressStatusSnapshotObject(runtime.statusSnapshot(peerID: (request["peer_id"] as? NSNumber)?.intValue))
    case "drive_compress_send_no_gain":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        let sendSnapshot = runtime.handleSendPayload(payload)
        guard let sentFrame = parseRawMuxFrame(sendSnapshot.wirePayload) else {
            throw ChannelMuxCodecRunnerError.codecFailure
        }
        return [
            "sent_bytes": sendSnapshot.sentBytes,
            "sent_payload_hex": hexFromData(sendSnapshot.wirePayload),
            "sent_peer_id": NSNull(),
            "sent_mtype": sentFrame.mtype,
            "sent_body_hex": hexFromData(sentFrame.body),
            "status": compressStatusSnapshotObject(runtime.statusSnapshot()),
        ]
    case "drive_compress_invalid_rx":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let peerID = (request["peer_id"] as? NSNumber)?.intValue
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        let receiveSnapshot = runtime.handleInboundPayload(payload, peerID: peerID)
        let delivered: [[Any]] = receiveSnapshot.deliveredPayload.map { [[hexFromData($0), receiveSnapshot.deliveredPeerID ?? NSNull()]] } ?? []
        return [
            "delivered": delivered,
            "status": compressStatusSnapshotObject(runtime.statusSnapshot()),
            "peer_status": compressStatusSnapshotObject(runtime.statusSnapshot(peerID: peerID)),
        ]
    case "drive_compress_oversize_rx":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex)
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let peerID = (request["peer_id"] as? NSNumber)?.intValue
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        let receiveSnapshot = runtime.handleInboundPayload(payload, peerID: peerID)
        let delivered: [[Any]] = receiveSnapshot.deliveredPayload.map { [[hexFromData($0), receiveSnapshot.deliveredPeerID ?? NSNull()]] } ?? []
        return [
            "delivered": delivered,
            "status": compressStatusSnapshotObject(runtime.statusSnapshot()),
            "peer_status": compressStatusSnapshotObject(runtime.statusSnapshot(peerID: peerID)),
        ]
    case "drive_compress_server_activation":
        guard
            let payloadHex = request["payload_hex"] as? String,
            let payload = dataFromHex(payloadHex),
            let compressedInHex = request["compressed_in_hex"] as? String,
            let compressedIn = dataFromHex(compressedInHex),
            let peerID = (request["peer_id"] as? NSNumber)?.intValue
        else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeCompressLayerRuntime(
            configuredEnabled: (request["configured_enabled"] as? Bool) ?? true,
            isPeerClient: (request["is_peer_client"] as? Bool) ?? false,
            transportName: (request["transport"] as? String) ?? "tcp",
            level: (request["level"] as? NSNumber)?.intValue ?? 3,
            minBytes: (request["min_bytes"] as? NSNumber)?.intValue ?? 64,
            allowedMTypesRaw: (request["allowed_mtypes"] as? String) ?? ObstacleBridgeCompressLayerRuntime.defaultAllowedMTypeNames,
            maxAppPayload: (request["max_app_payload"] as? NSNumber)?.intValue ?? 4096
        )
        let beforeEnabled = runtime.statusSnapshot(peerID: peerID).enabled
        let beforeSendSnapshot = runtime.handleSendPayload(payload, peerID: peerID)
        guard let beforeFrame = parseRawMuxFrame(beforeSendSnapshot.wirePayload) else {
            throw ChannelMuxCodecRunnerError.codecFailure
        }
        let receiveSnapshot = runtime.handleInboundPayload(compressedIn, peerID: peerID)
        let afterPeerStatus = runtime.statusSnapshot(peerID: peerID)
        let afterSendSnapshot = runtime.handleSendPayload(payload, peerID: peerID)
        guard let afterFrame = parseRawMuxFrame(afterSendSnapshot.wirePayload) else {
            throw ChannelMuxCodecRunnerError.codecFailure
        }
        let routedSendSnapshot = runtime.handleSendPayload(payload)
        guard let routedFrame = parseRawMuxFrame(routedSendSnapshot.wirePayload) else {
            throw ChannelMuxCodecRunnerError.codecFailure
        }
        let delivered: [[Any]] = receiveSnapshot.deliveredPayload.map { [[hexFromData($0), receiveSnapshot.deliveredPeerID ?? NSNull()]] } ?? []
        return [
            "before_enabled": beforeEnabled,
            "before_sent_bytes": beforeSendSnapshot.sentBytes,
            "before_payload_hex": hexFromData(beforeSendSnapshot.wirePayload),
            "before_peer_id": peerID,
            "before_mtype": beforeFrame.mtype,
            "delivered": delivered,
            "peer_status": compressStatusSnapshotObject(afterPeerStatus),
            "after_sent_bytes": afterSendSnapshot.sentBytes,
            "after_payload_hex": hexFromData(afterSendSnapshot.wirePayload),
            "after_peer_id": peerID,
            "after_mtype": afterFrame.mtype,
            "routed_sent_bytes": routedSendSnapshot.sentBytes,
            "routed_payload_hex": hexFromData(routedSendSnapshot.wirePayload),
            "routed_peer_id": NSNull(),
            "routed_mtype": routedFrame.mtype,
            "status": compressStatusSnapshotObject(runtime.statusSnapshot()),
        ]
    case "drive_overlay_parse":
        let overlayTransport = (request["overlay_transport"] as? String) ?? "myudp"
        let configuredPeerObject = (request["has_configured_peer_by_transport"] as? [String: Bool]) ?? [:]
        do {
            let transports = try ObstacleBridgeOverlayStackPlanner.parseOverlayTransports(
                raw: overlayTransport,
                hasConfiguredPeerByTransport: configuredPeerObject
            )
            return [
                "ok": true,
                "transports": transports,
            ]
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
            ]
        }
    case "drive_overlay_stack_plan":
        guard let transport = request["transport"] as? String else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        do {
            let plan = try ObstacleBridgeOverlayStackPlanner.planTransport(
                transport: transport,
                peerHost: request["peer_host"] as? String,
                secureLinkEnabled: (request["secure_link_enabled"] as? Bool) ?? false,
                secureLinkModeRaw: (request["secure_link_mode"] as? String) ?? "off",
                secureLinkPSK: (request["secure_link_psk"] as? String) ?? "",
                compressLayerEnabled: (request["compress_layer_enabled"] as? Bool) ?? true,
                compressLayerAlgoRaw: (request["compress_layer_algo"] as? String) ?? "zlib"
            )
            return overlayStackPlanObject(plan)
        } catch {
            return [
                "ok": false,
                "error": error.localizedDescription,
            ]
        }
    case "drive_ws_payload_codec":
        guard let mode = request["mode"] as? String else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let codec = try ObstacleBridgeWebSocketPayloadCodecFactory.build(mode: mode)
        let wire = (request["wire_hex"] as? String).flatMap(dataFromHex)
        let encoded = try wire.map { try codec.encode($0) }
        let decodeMessage: Any?
        if let decodeText = request["decode_text"] as? String {
            decodeMessage = decodeText
        } else if let decodeHex = request["decode_hex"] as? String, let decodeData = dataFromHex(decodeHex) {
            decodeMessage = decodeData
        } else {
            decodeMessage = encoded
        }
        let decoded: Data?
        do {
            decoded = try decodeMessage.flatMap { try codec.decode($0) }
        } catch {
            decoded = nil
        }
        var result = websocketPayloadCodecSummaryObject(mode: mode, codec: codec, wire: wire, encoded: encoded, decoded: decoded)
        let maxSize = (request["max_size"] as? NSNumber)?.intValue ?? 65535
        result["frame_max_size"] = codec.maxEncodedSize(maxSize)
        return result
    case "drive_ws_runtime_tx":
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary", sendTimeoutS: ((request["timeout"] as? Bool) ?? false) ? 0.01 : 3.0)
        let wire = Data([0x00]) + Data("hello".utf8)
        let snapshot = try runtime.sendImmediate(wire, sendWillTimeout: (request["timeout"] as? Bool) ?? false)
        return [
            "tx_bytes": snapshot.txBytes,
            "peer_tx": snapshot.peerTxNotifications,
            "sent_payload_kind": snapshot.sentPayloadKinds.first ?? NSNull(),
            "sent_payload_value": snapshot.sentPayloadValues.first as Any,
            "close_calls": snapshot.closeCalls,
            "early_buf_bytes": snapshot.earlyBufBytes,
        ]
    case "drive_ws_runtime_control_frames":
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")
        let txNS: UInt64 = 123456789
        let echoNS: UInt64 = 987654321
        var pingWire = Data([0x01])
        appendUInt64BE(txNS, to: &pingWire)
        appendUInt64BE(echoNS, to: &pingWire)
        let pingFrame = try runtime.decodeClientFrame(.data(pingWire))
        var decodedPing: [String: Any] = [:]
        switch pingFrame {
        case .ping(let decodedTxNS, let decodedEchoNS):
            decodedPing = [
                "kind": "ping",
                "tx_ns": Int(decodedTxNS),
                "echo_ns": Int(decodedEchoNS),
            ]
        default:
            decodedPing = ["kind": "unexpected"]
        }
        var pongWire = Data([0x02])
        appendUInt64BE(txNS, to: &pongWire)
        let pongFrame = try runtime.decodeClientFrame(.data(pongWire))
        var decodedPong: [String: Any] = [:]
        switch pongFrame {
        case .pong(let decodedEchoTxNS):
            decodedPong = [
                "kind": "pong",
                "echo_tx_ns": Int(decodedEchoTxNS),
            ]
        default:
            decodedPong = ["kind": "unexpected"]
        }
        let encodedPong = try runtime.encodeClientPong(echoTxNS: txNS)
        let encodedPongKind: String
        let encodedPongValue: String
        switch encodedPong {
        case .data(let data):
            encodedPongKind = "binary"
            encodedPongValue = hexFromData(data)
        case .string(let text):
            encodedPongKind = "text"
            encodedPongValue = text
        @unknown default:
            encodedPongKind = "unknown"
            encodedPongValue = ""
        }
        return [
            "decoded_ping": decodedPing,
            "decoded_pong": decodedPong,
            "encoded_pong_kind": encodedPongKind,
            "encoded_pong_value": encodedPongValue,
        ]
    case "drive_ws_runtime_socket_config":
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")
        let tcpUserTimeoutAvailable = (request["tcp_user_timeout_available"] as? Bool) ?? false
        let snapshot = runtime.socketConfigSnapshot(socketPresent: true, tcpUserTimeoutAvailable: tcpUserTimeoutAvailable)
        return [
            "keepalive_enabled": snapshot.keepAliveEnabled,
            "tcp_user_timeout_ms": snapshot.tcpUserTimeoutMS as Any,
        ]
    case "drive_ws_runtime_disconnect":
        let grace = (request["grace"] as? NSNumber)?.doubleValue ?? 3.0
        let reconnect = (request["reconnect"] as? Bool) ?? false
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary", reconnectGraceS: grace)
        let scheduled = runtime.scheduleOverlayDisconnect(runFlag: true, initiallyConnected: true)
        let finalSnapshot = reconnect ? runtime.handleAcceptCancellingDisconnect() : runtime.fireDisconnectTimer(wsPresent: false)
        return [
            "scheduled_before": scheduled.disconnectScheduled,
            "overlay_connected": finalSnapshot.overlayConnected,
            "disconnect_scheduled": finalSnapshot.disconnectScheduled,
        ]
    case "drive_ws_runtime_http_preflight":
        guard let statusLine = request["status_line"] as? String else {
            throw ChannelMuxCodecRunnerError.invalidRequest
        }
        let headers = (request["headers"] as? [String: String]) ?? [:]
        let body = dataFromHex((request["body_hex"] as? String) ?? "") ?? Data()
        let hostHeader = (request["host_header"] as? String) ?? "127.0.0.1"
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")
        do {
            let snapshot = try runtime.validateHTTPPreflight(hostHeader: hostHeader, statusLine: statusLine, headers: headers, body: body)
            return [
                "ok": true,
                "request": snapshot.request,
                "status_code": snapshot.statusCode,
                "body_bytes": snapshot.bodyBytes,
            ]
        } catch {
            return [
                "ok": false,
                "request": runtime.buildHTTPPreflightRequest(hostHeader: hostHeader),
                "error": error.localizedDescription,
            ]
        }
    case "drive_ws_runtime_connect_plan":
        let mode = (request["mode"] as? String) ?? "binary"
        let proxyActive = (request["proxy_active"] as? Bool) ?? false
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: mode)
        let snapshot = runtime.buildConnectPlan(
            host: "127.0.0.1",
            port: 54321,
            peerNameHost: "overlay.example",
            peerNamePort: 54321,
            useTLS: false,
            wsPath: "/",
            wsSubprotocol: nil,
            proxyActive: proxyActive,
            headerKeyAvailable: true
        )
        return wsOverlayConnectPlanObject(snapshot)
    case "drive_ws_runtime_listener_peer":
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")
        let snapshot = try runtime.listenerPeerSnapshot(advertisedPayloadMode: "base64", inboundMessage: "AnBvbmc=", outgoingWire: Data([0x02]) + Data("pong".utf8))
        return [
            "payload_mode": snapshot.payloadMode,
            "decoded_hex": snapshot.decodedHex as Any,
            "sent_payload_kind": snapshot.sentPayloadKind,
            "sent_payload_value": snapshot.sentPayloadValue,
        ]
    case "drive_ws_runtime_proxy_helpers":
        let runtime = try ObstacleBridgeWebSocketOverlayRuntime(payloadMode: "binary")
        let parsedProxy = runtime.parseProxySpec("http=proxy-http:8080;https=proxy-https:8443", secure: true)
        let parsedProxyValue: Any = parsedProxy.map { [$0.host, $0.port] } ?? NSNull()
        return [
            "parsed_proxy": parsedProxyValue,
            "connect_request": runtime.buildProxyConnectRequest(targetHost: "2001:db8::1", targetPort: 443, authHeader: "Negotiate abc123"),
        ]
    case "drive_tcp_runtime_tx":
        let writerPresent = (request["writer_present"] as? Bool) ?? false
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let snapshot = runtime.sendApp(payload: Data("hello".utf8), writerPresent: writerPresent, peerConfigured: true)
        return [
            "tx_bytes": snapshot.txBytes,
            "peer_tx": snapshot.peerTxNotifications,
            "written_hex": snapshot.writtenHex,
            "early_buf_bytes": snapshot.earlyBufBytes,
            "early_buf_hex": snapshot.earlyBufHex as Any,
            "connect_requested": snapshot.connectRequested,
        ]
    case "drive_tcp_runtime_connect":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        _ = runtime.sendApp(payload: Data("hello".utf8), writerPresent: false, peerConfigured: true)
        let snapshot = runtime.connect(host: "127.0.0.1", port: 54321, socketPresent: true)
        return [
            "connected": snapshot.connected,
            "peer_host": snapshot.peerHost,
            "peer_port": snapshot.peerPort,
            "keepalive_enabled": snapshot.keepAliveEnabled,
            "overlay_connected": snapshot.overlayConnected,
            "bp_task_started": snapshot.bpTaskStarted,
            "flushed_hex": snapshot.flushedHex,
            "early_buf_bytes": snapshot.earlyBufBytes,
        ]
    case "drive_tcp_runtime_socket_config":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let snapshot = runtime.socketConfigSnapshot(socketPresent: true)
        return [
            "keepalive_enabled": snapshot.keepAliveEnabled,
        ]
    case "drive_tcp_runtime_reconnect":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let snapshot = runtime.requestReconnect(runFlag: true, peerConfigured: true, writerPresent: true, initiallyConnected: true)
        return [
            "requested": snapshot.requested,
            "writer_closed": snapshot.writerClosed,
            "writer_present": snapshot.writerPresent,
            "reader_present": snapshot.readerPresent,
            "overlay_connected": snapshot.overlayConnected,
            "reconnect_loop_started": snapshot.reconnectLoopStarted,
        ]
    case "drive_tcp_runtime_server_accept":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let snapshot = runtime.acceptServerPeer(peerHost: "127.0.0.1", peerPort: 54321, socketPresent: true)
        return [
            "peer_id": snapshot.peerID,
            "peer_host": snapshot.peerHost,
            "peer_port": snapshot.peerPort,
            "keepalive_enabled": snapshot.keepAliveEnabled,
            "overlay_connected": snapshot.overlayConnected,
            "server_peer_ids": snapshot.serverPeerIDs,
        ]
    case "drive_tcp_runtime_server_close":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let accepted = runtime.acceptServerPeer(peerHost: "127.0.0.1", peerPort: 54321, socketPresent: true)
        let snapshot = runtime.closeServerPeer(peerID: accepted.peerID)
        return [
            "overlay_connected": snapshot.overlayConnected,
            "server_peer_ids": snapshot.serverPeerIDs,
        ]
    case "drive_tcp_runtime_backpressure":
        let runtime = ObstacleBridgeTcpOverlayRuntime()
        let snapshot = runtime.backpressureSnapshot(writeBufferSize: 256, threshold: 128)
        return [
            "bp_signaled": snapshot.signaled,
        ]
    default:
        throw ChannelMuxCodecRunnerError.unsupportedAction
    }
}

@main
struct ChannelMuxCodecRunner {
    static func main() throws {
        do {
            let input = FileHandle.standardInput.readDataToEndOfFile()
            let raw = try JSONSerialization.jsonObject(with: input, options: [])
            let request = try jsonObject(raw)
            let response = try handle(request)
            let data = try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys])
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        } catch {
            let payload: [String: Any] = [
                "error": String(describing: error),
            ]
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
            Foundation.exit(1)
        }
    }
}
