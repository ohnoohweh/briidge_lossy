import Foundation

enum ChannelMuxComponentRunnerError: Error {
    case invalidRequest
    case invalidAction
}

private func dataFromHex(_ hex: String) -> Data? {
    let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.count % 2 == 0 else {
        return nil
    }
    var data = Data(capacity: trimmed.count / 2)
    var index = trimmed.startIndex
    while index < trimmed.endIndex {
        let next = trimmed.index(index, offsetBy: 2)
        guard let value = UInt8(trimmed[index..<next], radix: 16) else {
            return nil
        }
        data.append(value)
        index = next
    }
    return data
}

private func hexFromData(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func jsonObject(_ value: Any) throws -> [String: Any] {
    guard let object = value as? [String: Any] else {
        throw ChannelMuxComponentRunnerError.invalidRequest
    }
    return object
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
        throw ChannelMuxComponentRunnerError.invalidRequest
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

private func localTunSendSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.LocalTunSendSnapshot) -> [String: Any] {
    [
        "chan_id": snapshot.chanID,
        "allocated_channel": snapshot.allocatedChannel,
        "frames_hex": snapshot.frames.map(hexFromData),
        "next_tun_id": snapshot.nextTunID,
        "next_counter": snapshot.nextCounter,
    ]
}

private func inboundTunOpenSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunOpenSnapshot) -> [String: Any] {
    [
        "accepted": snapshot.accepted,
        "chan_id": snapshot.chanID,
        "preferred_chan_id": snapshot.preferredChanID ?? NSNull(),
        "remote_spec": snapshot.remoteSpec.map(serviceSpecObject) ?? NSNull(),
    ]
}

private func inboundTunFragmentSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.InboundTunFragmentSnapshot) -> [String: Any] {
    [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
        "datagram_id": snapshot.datagramID,
        "total_len": snapshot.totalLen,
        "received_bytes": snapshot.receivedBytes,
    ]
}

private func guardedInboundTunDataSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.GuardedInboundTunDataSnapshot) -> [String: Any] {
    [
        "delivered": snapshot.delivered,
        "packet_hex": snapshot.packet.map(hexFromData) ?? NSNull(),
        "ip_version": snapshot.ipVersion ?? NSNull(),
        "source_ip": snapshot.sourceIP ?? NSNull(),
        "destination_ip": snapshot.destinationIP ?? NSNull(),
        "drop_reason": snapshot.dropReason ?? NSNull(),
    ]
}

private func sharedTunOutboundRouteSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.SharedTunOutboundRouteSnapshot) -> [String: Any] {
    [
        "routed": snapshot.routed,
        "route_class": snapshot.routeClass ?? NSNull(),
        "selected_peer_ids": snapshot.selectedPeerIDs,
        "selected_chan_ids": snapshot.selectedChanIDs,
        "ip_version": snapshot.ipVersion ?? NSNull(),
        "destination_ip": snapshot.destinationIP ?? NSNull(),
        "drop_reason": snapshot.dropReason ?? NSNull(),
    ]
}

private func closeSnapshotObject(_ snapshot: ObstacleBridgeChannelMuxTunRuntime.CloseSnapshot) -> [String: Any] {
    [
        "closed": snapshot.closed,
        "chan_id": snapshot.chanID,
        "preferred_chan_id": snapshot.preferredChanID ?? NSNull(),
        "bound_chan_ids": snapshot.boundChanIDs,
    ]
}

private func run(_ request: [String: Any]) throws -> [String: Any] {
    guard let action = request["action"] as? String else {
        throw ChannelMuxComponentRunnerError.invalidRequest
    }
    switch action {
    case "shared_tun_ownership_snapshot":
        let spec = try parseServiceSpec(request["spec"] as Any)
        let snapshot = ObstacleBridgeChannelMuxCodec.sharedTunOwnershipSnapshot(for: spec)
        return ["snapshot": snapshot.map(ObstacleBridgeChannelMuxCodec.foundationObject(from:)) ?? NSNull()]
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
            throw ChannelMuxComponentRunnerError.invalidRequest
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
        return ["snapshot": snapshot.map(localTunSendSnapshotObject) ?? NSNull()]
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
            throw ChannelMuxComponentRunnerError.invalidRequest
        }
        let localSpec = try parseServiceSpec(specObject)
        let runtime = ObstacleBridgeChannelMuxTunRuntime(
            instanceID: instanceID.uint64Value,
            connectionSeq: connectionSeq.uint32Value,
            nextTunID: nextTunID.intValue,
            localSpec: localSpec
        )
        let openSnapshot = runtime.handleInboundTunOpen(chanID: openChanID.intValue, payload: openPayload)
        let localSnapshot = try runtime.handleLocalTunPacket(
            packet: packet,
            mtu: mtu.intValue,
            spec: localSpec,
            overlayConnected: overlayConnected,
            acceptingEnabled: acceptingEnabled
        )
        return [
            "open_snapshot": inboundTunOpenSnapshotObject(openSnapshot),
            "local_snapshot": localSnapshot.map(localTunSendSnapshotObject) ?? NSNull(),
        ]
    case "drive_channelmux_inbound_tun_fragment_sequence":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let fragmentsHex = request["fragments_hex"] as? [String],
            let mtu = request["mtu"] as? NSNumber
        else {
            throw ChannelMuxComponentRunnerError.invalidRequest
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
    case "drive_channelmux_inbound_tun_data_guarded":
        guard
            let chanID = request["chan_id"] as? NSNumber,
            let bodyHex = request["body_hex"] as? String,
            let body = dataFromHex(bodyHex),
            let mtu = request["mtu"] as? NSNumber
        else {
            throw ChannelMuxComponentRunnerError.invalidRequest
        }
        let runtime = ObstacleBridgeChannelMuxTunRuntime(instanceID: 0, connectionSeq: 0)
        let allowedSourceIPs = Set((request["allowed_source_ips"] as? [String]) ?? [])
        let snapshot = runtime.handleInboundTunDataGuarded(
            chanID: chanID.intValue,
            body: body,
            mtu: mtu.intValue,
            boundChanID: (request["bound_chan_id"] as? NSNumber)?.intValue,
            allowedSourceIPs: allowedSourceIPs.isEmpty ? nil : allowedSourceIPs
        )
        return ["snapshot": guardedInboundTunDataSnapshotObject(snapshot)]
    case "plan_shared_tun_outbound_route":
        guard
            let bodyHex = request["body_hex"] as? String,
            let body = dataFromHex(bodyHex),
            let ownerByIPv4 = request["owner_by_ipv4"] as? [String: String],
            let ownerByIPv6 = request["owner_by_ipv6"] as? [String: String],
            let peerIDByRefRaw = request["peer_id_by_ref"] as? [String: Any],
            let activePeerBindingsRaw = request["active_peer_bindings"] as? [[String: Any]]
        else {
            throw ChannelMuxComponentRunnerError.invalidRequest
        }
        var peerIDByRef: [String: Int] = [:]
        for (peerRef, value) in peerIDByRefRaw {
            guard let number = value as? NSNumber else {
                throw ChannelMuxComponentRunnerError.invalidRequest
            }
            peerIDByRef[peerRef] = number.intValue
        }
        let activePeerBindings = try activePeerBindingsRaw.map { entry in
            guard let peerID = entry["peer_id"] as? NSNumber else {
                throw ChannelMuxComponentRunnerError.invalidRequest
            }
            let preferredChanID = (entry["preferred_chan_id"] as? NSNumber)?.intValue
            return ObstacleBridgeChannelMuxTunRuntime.SharedTunActivePeerBinding(
                peerID: peerID.intValue,
                preferredChanID: preferredChanID
            )
        }
        let snapshot = ObstacleBridgeChannelMuxTunRuntime.planSharedTunOutboundRoute(
            ownerByIPv4: ownerByIPv4,
            ownerByIPv6: ownerByIPv6,
            peerIDByRef: peerIDByRef,
            activePeerBindings: activePeerBindings,
            packet: body
        )
        return ["snapshot": sharedTunOutboundRouteSnapshotObject(snapshot)]
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
            throw ChannelMuxComponentRunnerError.invalidRequest
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
            "local_snapshot": localSnapshot.map(localTunSendSnapshotObject) ?? NSNull(),
        ]
    default:
        throw ChannelMuxComponentRunnerError.invalidAction
    }
}

@main
struct ChannelMuxComponentRunnerMain {
    static func main() throws {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let object = try JSONSerialization.jsonObject(with: input, options: [])
        let request = try jsonObject(object)
        let response = try run(request)
        let data = try JSONSerialization.data(withJSONObject: response, options: [])
        FileHandle.standardOutput.write(data)
    }
}
