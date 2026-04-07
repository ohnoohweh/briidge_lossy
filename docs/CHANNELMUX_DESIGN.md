# ChannelMux Design

## Purpose

This note records the current `ChannelMux` design as implemented in [bridge.py](../src/obstacle_bridge/bridge.py).

`ChannelMux` is the runtime boundary between:

- plaintext overlay session payloads coming from the transport and optional secure-link layers
- local TCP and UDP service sockets that are exposed through the overlay

Its job is not only routing. It also owns the service-facing semantics that differ between TCP streams and UDP datagrams.

## Scope

This document covers:

- mux wire framing and channel identity
- local service publication and peer-installed services
- TCP stream chunking at the service boundary
- UDP datagram forwarding at the service boundary
- mux-level UDP fragmentation and reassembly
- explicit UDP service-datagram caps and diagnostics

It does not redefine:

- lower transport/session framing in [ARCHITECTURE.md](./ARCHITECTURE.md)
- secure-link authentication and protection in [SECURE_LINK_DESIGN.md](./SECURE_LINK_DESIGN.md)
- black-box requirements in [REQUIREMENTS.md](./REQUIREMENTS.md)

## Current boundary

`ChannelMux` currently owns:

- channel ids and mux headers
- `OPEN`, `DATA`, `CLOSE`, and remote-service catalog control messages
- local TCP/UDP listener lifecycle for configured services
- mapping between overlay channels and local TCP/UDP sockets
- TCP read chunking sized to the wrapped session budget
- UDP service datagram fragmentation when one mux `DATA` frame would exceed the effective session budget
- peer-side UDP service datagram reassembly before local `sendto(...)`
- per-channel counters and related diagnostics

`ChannelMux` does not own:

- transport-specific sockets for overlay carriage
- secure-link cryptography or identity policy
- `myudp` lower transport fragmentation and retransmission
- application-level protocol semantics above TCP or UDP payload forwarding

## Wire model

The primary mux header is:

- `chan_id:2`
- `proto:1`
- `counter:2`
- `mtype:1`
- `data_len:2`

That is an 8-byte header encoded as `>HBHBH`.

Current mux message types:

- `DATA`
- `OPEN`
- `CLOSE`
- `REMOTE_SERVICES_SET_V1`
- `REMOTE_SERVICES_SET_V2`
- `DATA_FRAG`

`DATA_FRAG` is the mux-level UDP service fragmentation message. Its payload starts with a fragment header:

- `datagram_id:4`
- `total_len:2`
- `offset:2`

followed by the fragment bytes for the original UDP service datagram.

## TCP service behavior

TCP services are stream-oriented at the local boundary.

Current model:

- read from the local TCP socket in chunks of at most `SAFE_TCP_READ`
- wrap each chunk in one mux `DATA` message
- deliver each received mux `DATA` chunk directly to the destination TCP stream with `writer.write(...)`

This means TCP does not require mux-level message reassembly. The destination TCP stack naturally reconstructs the byte stream.

## UDP service behavior

UDP services are datagram-oriented at the local boundary.

Current model:

- one local UDP datagram is treated as one logical service message
- if the full mux `DATA` message fits inside the effective session budget, it is sent directly
- if it would exceed the effective session budget, `ChannelMux` fragments the UDP service datagram into multiple `DATA_FRAG` mux messages
- the peer-side mux reassembles the original UDP service datagram before emitting one local UDP datagram with `sendto(...)`

This keeps the service-facing UDP contract intact even when the lower stack becomes tighter because of WebSocket text encoding, secure-link overhead, or other session-layer limits.

## Why mux-level UDP fragmentation exists

There are two different fragmentation problems in the system:

1. `ChannelMux` must preserve service-facing TCP/UDP semantics while respecting the wrapped session budget.
2. The `myudp` transport must carry one already-accepted session payload across unreliable UDP frames.

Those are different layers.

Mux-level UDP fragmentation solves the first problem.

`myudp` transport fragmentation solves the second problem.

Without mux-level UDP fragmentation, a local UDP service datagram that exceeded the current wrapped session budget would be dropped even though the lower transport might have been able to carry the resulting session payload across multiple packets.

## Explicit caps

The current implementation also enforces an explicit maximum UDP service datagram size.

Current cap inputs:

- local UDP payload ceiling: `65507`
- mux fragment header total-length field ceiling: `65535`

So the current maximum UDP service datagram that `ChannelMux` will accept or reassemble is:

$$
\min(65507, 65535) = 65507
$$

This cap is intentionally separate from the effective session payload budget.

The effective session payload budget determines:

- how large one mux `DATA` or `DATA_FRAG` message may be
- how large each UDP fragment chunk may be

The UDP service-datagram cap determines:

- the maximum size of the complete UDP datagram that the mux is willing to preserve end to end

## Diagnostics

At startup, `ChannelMux` logs:

- resolved session payload budget
- `SAFE_TCP_READ`
- UDP service datagram cap
- the active wrapped session stack description

That diagnostic is intended to make the effective runtime envelope explicit for operators.

Oversize UDP service datagrams are also logged when they are dropped:

- on local UDP ingress
- on direct overlay UDP delivery
- on UDP fragment reassembly

## Reassembly lifecycle and safety

Current UDP fragment reassembly state is keyed by:

- `chan_id`
- `datagram_id`

Safety controls currently include:

- TTL-based cleanup for incomplete reassemblies
- a cap on the number of in-flight reassembly entries
- bounds checks for `total_len`, `offset`, and fragment coverage
- cleanup on channel close and peer epoch reset

Current behavior is intentionally conservative:

- invalid fragment sequences are dropped
- oversize total lengths are dropped
- incomplete or expired reassemblies are discarded rather than partially delivered

## Open tradeoffs

The new mux-level UDP fragmentation makes the overlay safer by design, but it does not remove all lower-layer constraints.

Important remaining limits:

- the destination host must still be willing to accept the final reassembled UDP datagram size
- large UDP datagrams may still be a poor fit for real network paths even if the overlay can carry them internally
- memory usage and timeout policy for many concurrent fragmented UDP datagrams remain operational concerns

So the current design improves correctness at the overlay boundary, but it does not change the fundamental properties of UDP itself.