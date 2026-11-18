# iOS Runtime Buffer Ownership Inventory

## Purpose

This inventory maps each meaningful iOS traffic-path buffer owner to the code
where it retains a payload and the code where it relinquishes that payload.
It is the implementation reference for per-subsystem memory diagnostics.

Swift does not use manual `malloc`/`free` for these values. `Data`, `Array`,
and framework objects are normally reference-counted or value-managed by ARC.
The useful diagnostic boundary is therefore ownership: increment a counter when
a subsystem retains a payload, and decrement it when that subsystem transfers,
sends, drops, or removes its last owned reference. ARC and the allocator may
return physical pages later, so a zero live-byte counter does not imply an
immediate decrease in `phys_footprint`.

## Device Finding That Motivates This Inventory

Two independent device experiments terminated near 50 MiB
`TASK_VM_INFO.phys_footprint`, despite materially different resident and
default-zone malloc totals:

- A traffic-driven run last reported 47.9 MiB physical footprint, 190 MiB
  resident memory, and 201 MiB malloc in-use.
- A temporary controlled allocation run last reported 49.1 MiB physical
  footprint, 117 MiB resident memory, and 57.5 MiB malloc in-use.

This is evidence for an approximately 50 MiB extension physical-footprint
boundary on the test device, not proof of a fixed Apple quota or a substitute
for a system termination diagnostic. `phys_footprint` is the primary comparison
metric; resident size is not a safe budget proxy.

## Inventory

| Owner / candidate counter | Retain boundary | Release or transfer boundary | Notes |
| --- | --- | --- | --- |
| TUN ingress FIFO `incomingPackets` | `ObstacleBridgePacketFlowBridge.enqueueIncomingPacket` appends at `swift/Sources/ObstacleBridgeiOS/ObstacleBridgePacketFlowBridge.swift:377`. The source is `NEPacketTunnelFlow.readPackets` in `PacketTunnelProvider.swift:1163`. | `dequeueIncomingPacket` removes at `ObstacleBridgePacketFlowBridge.swift:406`; deactivate clears at `:343`. | Count bytes and items. The `NSData` return is a cross-language ownership transfer; Swift-only counters cannot observe references retained after this boundary. |
| TUN egress FIFO `outgoingPendingPackets` | Appended at `ObstacleBridgePacketFlowBridge.swift:454`. | Batched removal at `:702`, transfer to `packetFlow.writePackets` at `:717`, or deactivate clear at `:345`. | `tun_egress_fifo` measures the Swift queue. `NEPacketTunnelFlow.writePackets` has no completion callback, so framework-held bytes after that call are outside this counter contract. |
| ChannelMux egress sequencer | Generic queue append in `ObstacleBridgeChannelMuxEgressSequencer.enqueue` at `swift/Sources/ObstacleBridgeCore/ObstacleBridgeChannelMuxEgressSequencer.swift:59`. | `dequeueNext` at `:76`; `removeAll` at `:91`. | Instantiate byte accounting where `Element == Data`; count alone is insufficient. |
| TUN to ChannelMux frame generation | `ObstacleBridgeChannelMuxTunRuntime` builds `[Data]` at `swift/Sources/ObstacleBridgeCore/ObstacleBridgeChannelMuxTunRuntime.swift:522`; fragmented frames originate at `:1437`. | Frames are normally transferred to the egress owner in the same call path. | Not retained long-term, but record created bytes to expose allocation churn and copy amplification. |
| ChannelMux TUN fragment reassembly | `ObstacleBridgePacketReassembler.states[key].parts` receives payload at `swift/Sources/ObstacleBridgeCore/ObstacleBridgePacketModel.swift:331`. | State is removed on completion/rejection at `:320-341`, reset at `:349`, and withdrawn on channel close in `ObstacleBridgeChannelMuxTunRuntime.swift:1418`. | Bounded by `maximumDatagrams` and maximum packet length. Expose live bytes, datagram count, rejects, and high-water mark. |
| ChannelMux control-chunk reassembly | `ObstacleBridgeControlChunkReassembler.states[key].parts` stores chunks at `swift/Sources/ObstacleBridgeCore/ObstacleBridgeControlChunkCodec.swift:110`. | Completion removes at `:122`; TTL prune at `:127`; malformed input removes state earlier. | Bounded by maximum in-flight chunks and maximum reassembled bytes. Expose live bytes and expired/rejected totals. |
| Per-channel TCP service writes | `pendingServerOpenFrames` retains frames at `swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeChannelMuxTCPTransportOwner.swift:171`; `pendingTCPWrites[chanID].buffers` appends at `:544`. | One write is removed at `:556`; channel or owner teardown clears the maps. | Instrument per channel and aggregate; Network.framework may retain the submitted write after local dequeue. |
| SecureLink pending plaintext | `pendingPayloads.append(payload)` in `swift/Sources/ObstacleBridgeCore/ObstacleBridgeSecureLinkPskTransportAdapter.swift:225` and `:249`. | One pending payload is drained after the rekey/handshake barrier; disconnect clears at `:172`; authentication failure clears it. | Current WebAdmin already reports its queued byte count. Retain this metric and add high-water plus cumulative created bytes. |
| UDP overlay inbound payload FIFO | `pendingInboundOverlayPayloads.append(contentsOf:)` at `swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeUdpOverlayTransportOwner.swift:1111`. | `removeFirst` at `:1122`, then transfer into SecureLink or ChannelMux. | Current WebAdmin reports queued bytes and items. |
| UDP overlay outbound mux FIFO | `pendingOutboundMuxFrames.append(contentsOf:)` at `ObstacleBridgeUdpOverlayTransportOwner.swift:1461`. | `removeFirst` at `:1472`, then transfer into SecureLink or the lower transport. | Current WebAdmin reports queued bytes and items. |
| TCP and QUIC stream receive buffers | TCP appends to `receiveBuffer` at `swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeTcpOverlayTransportOwner.swift:856`; QUIC appends at `ObstacleBridgeQuicOverlayTransportOwner.swift:742`. | Parsed bytes are removed at `ObstacleBridgeQuicOverlayTransportOwner.swift:749`; reconnect/stop clears the full buffer in each owner. | `tcp_receive_buffer` and `quic_receive_buffer` track live bytes, high-water, parsed/released bytes, and teardown drops. |
| TCP and QUIC outbound wire FIFOs | TCP `pendingOutboundWires.append` at `ObstacleBridgeTcpOverlayTransportOwner.swift:1321`; QUIC append at `ObstacleBridgeQuicOverlayTransportOwner.swift:928`. | TCP removal at `:1334`; QUIC removal at `ObstacleBridgeQuicOverlayTransportOwner.swift:956`; errors and teardown clear remaining entries. | `tcp_outbound_wires` and `quic_outbound_wires` track queue ownership. Submission transfers into `network_send_inflight`. |
| WebSocket outbound messages | `pendingOutboundMessages.append` at `swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeWebSocketOverlayTransportOwner.swift:1458`. | `removeFirst` at `:1476`; failure and teardown clear the remainder. | `websocket_outbound_messages` tracks queued payloads; submitted payloads move to `network_send_inflight`. |
| Network.framework send in-flight data | Begins immediately before tracked overlay, per-channel service, local UDP-client, and WebAdmin sends. | Ends in the matching send completion callback, independently of owner teardown. | `network_send_inflight` remains the aggregate. `network_send_local_udp_client`, `network_send_channelmux_tcp`, `network_send_overlay_tcp`, `network_send_overlay_quic`, `network_send_overlay_websocket`, and `network_send_webadmin` separate the sources. For these owners, `created_*` means submitted sends, `released_*` means completion callbacks that ran, and `failed_*` means callbacks that carried an error. |
| UDP socket scratch and datagram copy | `drainSocket` creates a 65,535-byte `[UInt8]` at `swift/Sources/ObstacleBridgeAppleShared/ObstacleBridgeUdpOverlayTransportOwner.swift:851`, then constructs `Data` at `:869`. | Scope ends after the drain iteration; the datagram is then routed to the overlay path. | This is allocation churn rather than retained live memory. Count created bytes and receive iterations, not live bytes. |
| Overlay, crypto, compression, and framing temporaries | ChannelMux framing, SecureLink protection, compression, and overlay encoding create temporary `Data` values as each packet crosses a layer. | These temporary values leave scope or are transferred to the next layer. | Add cumulative created-byte counters at each layer boundary. Do not add per-packet logging or retained histories. |
| WebAdmin HTTP/WebSocket request and response buffers | `HTTPRequestReceiveState` and `LiveSession.receiveBuffer` retain request bytes; generated HTTP/WebSocket response frames are created immediately before send. | Request parsing, connection close, or send completion. | `webadmin_buffers` exposes active receive ownership and response allocation churn; `network_send_inflight` exposes submitted replies. |

## Counter Contract

Each inventory owner should report a bounded projection rather than allocation
history or packet content:

- `live_bytes` and `live_items`: current payloads owned by the component.
- `peak_live_bytes` and `peak_live_items`: high-water values since runtime
  start, reset only with the provider runtime.
- `created_bytes_total` and `created_items_total`: cumulative payload creation
  or copy volume. These identify churn when `live_bytes` stays near zero.
- `released_bytes_total` / `released_items_total`, `dropped_bytes_total` /
  `dropped_items_total`, and `failed_bytes_total` / `failed_items_total`.
- `in_flight_bytes` / `in_flight_items` and `peak_in_flight_bytes` /
  `peak_in_flight_items` for framework send operations, decremented by
  completion callbacks rather than local FIFO removal.

Counters must be updated at ownership transitions on the existing serial owner
queue or protected by a narrow lock/atomic primitive. They must not allocate
per-packet dictionaries, emit high-rate logs, retain payload history, or add
provider-state persistence to the packet path.

## Interpretation Rules

- `Data.count` is the logical payload size, not necessarily the allocator's
  exact allocation size. Copy-on-write, allocator overhead, bridging, and
  Network.framework internals are not represented exactly.
- A rising `live_bytes` identifies a retained ownership path or backlog.
- Rising `created_bytes_total` with stable `live_bytes` identifies allocation
  churn and possible allocator/VM retention.
- A stable application-level inventory with rising `phys_footprint` points
  toward allocator caching, framework-owned memory, compression/crypto
  internals, or an uninstrumented ownership path. Allocation Instruments or
  malloc stack logging is then required for exact attribution.
