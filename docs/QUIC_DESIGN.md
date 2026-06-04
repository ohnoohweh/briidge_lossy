# QUIC Design

## Current Mode

ObstacleBridge currently uses QUIC in reliable stream mode, not QUIC DATAGRAM mode.

That choice is intentional for the current overlay contract:

- `ChannelMux` TCP own-service and remote-service paths expect reliable delivery.
- buffered pre-connect data must survive until the remote TCP side is ready.
- the Python QUIC implementation uses stream semantics via `send_stream_data(...)`.
- the native Swift side targets the same reliable-stream contract through Apple's Network.framework QUIC path.

So the present parity target for Swift is:

- reliable QUIC stream transport
- same upper-layer framing model as the Python QUIC path
- no dependence on QUIC DATAGRAM support

QUIC DATAGRAM remains a future design option for message-oriented traffic, but it is not the transport model used for the current service-forwarding overlay.

## Implementation Boundary

The two QUIC implementations intentionally share an upper-layer protocol contract, but they do not share one transport library:

- Python QUIC uses `aioquic`
- native Swift QUIC on macOS and iOS uses Apple's Network.framework

That distinction matters because:

- `aioquic` is not the implementation model available to the native iOS Network Extension stack
- transport quirks can therefore differ even when the intended overlay semantics are the same
- parity has to be proven at the behavior level with mixed-runtime tests, not assumed from implementation similarity

So when Swift and Python differ on QUIC behavior, the first question should be:

- is the upper-layer protocol contract wrong?

and the second question should be:

- or is the native Network.framework transport boundary behaving differently from the `aioquic` path?

The 2026-06-04 large-write issue documented below turned out to be the second kind.

## Framing Model

The shared QUIC session framing is stream-oriented:

- 4-byte big-endian payload length
- 1-byte kind marker
- payload bytes

This is the same broad model used by the Python QUIC transport and the Swift QUIC runtime:

- [bridge_transport_quic.py](../src/obstacle_bridge/bridge_transport_quic.py)
- [ObstacleBridgeQuicOverlayRuntime.swift](../ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayRuntime.swift)

At the `ChannelMux` layer, the transport carries already-packed mux frames:

- `OPEN`
- `OPEN_CHUNK`
- `DATA`
- `DATA_FRAG`
- `CLOSE`

The QUIC transport itself is not supposed to reinterpret those mux frames. It is only responsible for carrying the byte stream faithfully.

## Certificates And Verification

QUIC here is also a TLS-based transport, so certificate behavior matters.

Current implementation split:

- Python QUIC listener/server uses configured certificate and key material
- Swift QUIC client path validates the remote peer through Network.framework unless `quic_insecure=true`

Relevant implementation points:

- Python:
  - [bridge_transport_quic.py](../src/obstacle_bridge/bridge_transport_quic.py)
  - `quic_cert`
  - `quic_key`
  - `quic_insecure`
- Swift:
  - [ObstacleBridgeQuicOverlayTransportOwner.swift](../ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayTransportOwner.swift)
  - `sec_protocol_options_set_verify_block(...)`

What `quic_insecure` means on the Swift/native side:

- the QUIC/TLS verification callback accepts the peer unconditionally
- this disables genuine certificate trust checking for that connection
- it is appropriate for:
  - localhost fixtures
  - lab setups
  - controlled parity tests
- it is not the normal production posture

So the intended rule is:

- use real certificate validation when the deployment expects genuine peer identity checking
- use `quic_insecure=true` only when the operator deliberately accepts the trust bypass

This distinction is important because the mixed Swift/Python localhost parity tests intentionally use the bypass in order to exercise transport behavior without introducing extra local CA/bootstrap work.

## Observed Swift Restriction

During mixed Swift/Python macOS QUIC parity work on 2026-06-04, we found a concrete Swift-side transport boundary problem:

- tiny QUIC service payloads worked
- larger payloads around 2 KB and above did not
- Python received `OPEN` frames but never the following `DATA` frames
- the same service path worked over:
  - `tcp`
  - `myudp`
  - `ws`
- the same logical QUIC service path also worked for small payloads

That narrowed the issue to the Swift QUIC transport interface rather than:

- `ChannelMux`
- service definitions
- Python QUIC behavior
- general mixed-runtime test design

## Current Workaround

The current Swift workaround lives in:

- [ObstacleBridgeQuicOverlayTransportOwner.swift](../ios/native/ObstacleBridgeShared/ObstacleBridgeQuicOverlayTransportOwner.swift)

Two defensive measures are now in place on the outbound Swift QUIC path:

1. each outbound wire is sent through its own explicit `NWConnection.ContentContext`
2. large outbound wires are split into smaller `1024`-byte pieces before `NWConnection.send(...)`

Why this is acceptable for now:

- QUIC is being used here as a reliable byte stream
- the receive side already reconstructs from a stream buffer
- splitting one logical wire into multiple stream writes does not change the upper-layer protocol
- the mux frame is still reconstructed as one logical payload by the receiver

This is intentionally documented as a workaround, not a final theoretical answer about Network.framework QUIC behavior.

## Why The Workaround Exists

Without the outbound chunking, the macOS Swift/Python QUIC mixed own-service path failed for larger payloads even though:

- connection establishment succeeded
- peer state reached `connected`
- local TCP sockets accepted successfully
- the same payload sizes worked on the WebSocket path

With the chunking workaround in place:

- the macOS Swift/Python QUIC mixed own-service parity test passes
- large payloads work in both directions
- the iOS/Python mixed QUIC service tests also pass with larger payloads

So the current design interpretation is:

- the Swift QUIC transport boundary has a practical large-write limitation or behavior quirk
- chunked stream writes are a safe compatibility layer above that boundary

## Validation Evidence

The workaround is defended by mixed-runtime tests rather than only local probes.

Relevant tests include:

- [ios/tests/test_macos_swift_host_runner.py](../ios/tests/test_macos_swift_host_runner.py)
  - `test_macos_swift_host_runner_tcp_ownserver_proxies_mixed_python_peer_for_ws_and_quic`
- [tests/integration/test_ios_e2e.py](../tests/integration/test_ios_e2e.py)
  - `test_ios_extension_shim_swift_udp_tcp_service_reaches_python_peer_for_ws_and_quic`

The validation focus is:

- `ws` and `quic`
- mixed Swift/Python runtime pairing
- larger TCP service payloads
- proof that large chunks work both directions:
  - Swift -> Python
  - Python -> Swift

## Future Direction

Possible future follow-ups:

1. understand the precise Network.framework QUIC write behavior that made large single writes fail
2. decide whether the `1024`-byte chunk size should become configurable or transport-tuned
3. evaluate whether some service classes should eventually use QUIC DATAGRAM mode
4. keep parity testing on the mixed Swift/Python QUIC service path so this behavior does not silently regress
5. define a cleaner certificate story for native Swift QUIC beyond the current localhost / `quic_insecure` testing posture where needed

One concrete future extension idea is:

- `myUDP` over QUIC DATAGRAM mode

Why it may be interesting:

- it would be closer in spirit to `myudp` than to TCP-own-service forwarding
- it could provide a plausible cloaking layer for environments with awkward or over-eager packet inspection
- it would allow the project to explore QUIC DATAGRAM where message-oriented loss-tolerant behavior is actually appropriate

Why it is not the current design:

- the current QUIC overlay is used for reliable service forwarding
- TCP own-service carriage and buffered pre-connect data need stream semantics
- introducing QUIC DATAGRAM should therefore be a separate mode, not a silent replacement of the existing reliable QUIC stream path

Until then, the design rule is simple:

- keep QUIC in reliable stream mode
- keep the outbound Swift chunking workaround in place
- treat it as a compatibility measure required for proven mixed-runtime correctness
